const crypto = require('crypto');
const {
  clampPositiveInt,
  normalizeMode,
  normalizeSessionValue,
  toObject,
} = require('../utils/primitives');

function sha256Prefix(value = '', length = 16) {
  return crypto.createHash('sha256').update(String(value || ''), 'utf8').digest('hex').slice(0, length);
}

function safeStdDev(m2 = 0, count = 0) {
  if (!Number.isFinite(Number(m2)) || !Number.isFinite(Number(count)) || count < 2) {
    return 0;
  }
  const variance = Number(m2) / (Number(count) - 1);
  if (!Number.isFinite(variance) || variance <= 0) {
    return 0;
  }
  return Math.sqrt(variance);
}

function safeZScore(value, mean, stdDev) {
  if (!Number.isFinite(Number(value)) || !Number.isFinite(Number(mean)) || !Number.isFinite(Number(stdDev)) || stdDev <= 0) {
    return 0;
  }
  return (Number(value) - Number(mean)) / Number(stdDev);
}

function updateWelford(profile, keyPrefix, value) {
  const safeValue = Number(value);
  if (!Number.isFinite(safeValue)) {
    return;
  }
  const countKey = 'count';
  const meanKey = `${keyPrefix}Mean`;
  const m2Key = `${keyPrefix}M2`;
  const nextCount = Number(profile[countKey] || 0) + 1;
  const mean = Number(profile[meanKey] || 0);
  const delta = safeValue - mean;
  const nextMean = mean + (delta / Math.max(1, nextCount));
  const delta2 = safeValue - nextMean;
  const nextM2 = Number(profile[m2Key] || 0) + (delta * delta2);
  profile[meanKey] = nextMean;
  profile[m2Key] = nextM2;
}

function detectToolCount(bodyJson) {
  const payload = toObject(bodyJson);
  const tools = Array.isArray(payload.tools) ? payload.tools : [];
  let count = tools.length;
  if (payload.tool && typeof payload.tool === 'object') {
    count += 1;
  }
  if (payload.tool_name || payload.toolName) {
    count += 1;
  }
  return Math.min(count, 256);
}

function boundedText(bodyText = '', maxChars = 4096) {
  return String(bodyText || '').slice(0, Math.max(1, maxChars));
}

class BehavioralFingerprint {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.ttlMs = clampPositiveInt(config.ttl_ms, 6 * 60 * 60 * 1000, 60_000, 7 * 24 * 60 * 60 * 1000);
    this.maxAgents = clampPositiveInt(config.max_agents, 5000, 16, 200000);
    this.maxStylesPerAgent = clampPositiveInt(config.max_styles_per_agent, 64, 4, 4096);
    this.maxTextChars = clampPositiveInt(config.max_text_chars, 4096, 128, 32768);
    this.maxImpersonationAgents = clampPositiveInt(config.max_impersonation_agents, 128, 8, 4096);
    this.warmupEvents = clampPositiveInt(config.warmup_events, 20, 3, 10000);
    this.zScoreThreshold = Number.isFinite(Number(config.z_score_threshold))
      ? Math.max(0.5, Math.min(12, Number(config.z_score_threshold)))
      : 3;
    this.impersonationMinHits = clampPositiveInt(config.impersonation_min_hits, 3, 1, 1000);
    this.blockOnAnomaly = config.block_on_anomaly === true;
    this.blockOnImpersonation = config.block_on_impersonation === true;
    this.observability = config.observability !== false;
    this.agentProfiles = new Map();
  }

  isEnabled() {
    return this.enabled === true;
  }

  prune(now = Date.now()) {
    const threshold = Number(now) - this.ttlMs;
    for (const [agentId, profile] of this.agentProfiles.entries()) {
      if (Number(profile.lastSeenAt || 0) < threshold) {
        this.agentProfiles.delete(agentId);
      }
    }
    while (this.agentProfiles.size > this.maxAgents) {
      const oldest = this.agentProfiles.keys().next().value;
      if (!oldest) {
        break;
      }
      this.agentProfiles.delete(oldest);
    }
  }

  getProfile(agentId, now = Date.now()) {
    const key = normalizeSessionValue(agentId || 'agent:unknown', 160) || 'agent:unknown';
    const existing = this.agentProfiles.get(key);
    if (existing) {
      existing.lastSeenAt = Number(now);
      return {
        key,
        profile: existing,
      };
    }

    const created = {
      count: 0,
      lengthMean: 0,
      lengthM2: 0,
      toolMean: 0,
      toolM2: 0,
      latencyMean: 0,
      latencyM2: 0,
      styleHashes: new Map(),
      lastSeenAt: Number(now),
    };
    this.agentProfiles.set(key, created);
    return {
      key,
      profile: created,
    };
  }

  updateStyleHashes(profile, styleHash) {
    if (!styleHash) {
      return;
    }
    const current = Number(profile.styleHashes.get(styleHash) || 0);
    profile.styleHashes.set(styleHash, current + 1);
    if (profile.styleHashes.size <= this.maxStylesPerAgent) {
      return;
    }
    const oldest = profile.styleHashes.keys().next().value;
    if (!oldest) {
      return;
    }
    profile.styleHashes.delete(oldest);
  }

  findStyleOwner(styleHash, currentAgentId) {
    if (!styleHash) {
      return '';
    }
    let scanned = 0;
    for (const [agentId, profile] of this.agentProfiles.entries()) {
      if (scanned >= this.maxImpersonationAgents) {
        break;
      }
      scanned += 1;
      if (agentId === currentAgentId) {
        continue;
      }
      if (Number(profile.count || 0) < this.warmupEvents) {
        continue;
      }
      const hits = Number(profile.styleHashes.get(styleHash) || 0);
      if (hits >= this.impersonationMinHits) {
        return agentId;
      }
    }
    return '';
  }

  evaluate({
    agentId = '',
    bodyText = '',
    bodyJson = null,
    latencyMs = 0,
    effectiveMode = 'monitor',
  } = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        detected: false,
        shouldBlock: false,
        reason: 'clean',
        findings: [],
      };
    }

    const now = Date.now();
    this.prune(now);
    const { key, profile } = this.getProfile(agentId, now);
    const text = boundedText(bodyText, this.maxTextChars);
    const textLength = Buffer.byteLength(text, 'utf8');
    const toolCount = detectToolCount(bodyJson);
    const safeLatencyMs = Number.isFinite(Number(latencyMs)) && Number(latencyMs) >= 0
      ? Number(latencyMs)
      : 0;
    const styleHash = textLength > 0 ? sha256Prefix(text, 16) : '';
    const findings = [];
    const baselineReady = Number(profile.count || 0) >= this.warmupEvents;
    const lengthStd = safeStdDev(profile.lengthM2, profile.count);
    const toolStd = safeStdDev(profile.toolM2, profile.count);
    const latencyStd = safeStdDev(profile.latencyM2, profile.count);
    const lengthZ = baselineReady ? safeZScore(textLength, profile.lengthMean, lengthStd) : 0;
    const toolZ = baselineReady ? safeZScore(toolCount, profile.toolMean, toolStd) : 0;
    const latencyZ = baselineReady ? safeZScore(safeLatencyMs, profile.latencyMean, latencyStd) : 0;

    if (baselineReady && Math.abs(lengthZ) >= this.zScoreThreshold) {
      findings.push({
        code: 'behavioral_length_anomaly',
        z_score: Number(lengthZ.toFixed(4)),
        threshold: this.zScoreThreshold,
        blockEligible: this.blockOnAnomaly,
      });
    }
    if (baselineReady && Math.abs(toolZ) >= this.zScoreThreshold) {
      findings.push({
        code: 'behavioral_tool_count_anomaly',
        z_score: Number(toolZ.toFixed(4)),
        threshold: this.zScoreThreshold,
        blockEligible: this.blockOnAnomaly,
      });
    }
    if (baselineReady && styleHash && Number(profile.styleHashes.get(styleHash) || 0) === 0) {
      const suspectedAgent = this.findStyleOwner(styleHash, key);
      if (suspectedAgent) {
        findings.push({
          code: 'behavioral_impersonation_suspected',
          suspected_agent: suspectedAgent,
          style_hash: styleHash,
          blockEligible: this.blockOnImpersonation,
        });
      }
    }

    profile.count = Number(profile.count || 0) + 1;
    updateWelford(profile, 'length', textLength);
    updateWelford(profile, 'tool', toolCount);
    updateWelford(profile, 'latency', safeLatencyMs);
    this.updateStyleHashes(profile, styleHash);
    profile.lastSeenAt = now;

    const detected = findings.length > 0;
    const shouldBlock =
      detected &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce' &&
      findings.some((item) => item.blockEligible === true);

    const anomalyMagnitude = Math.max(Math.abs(lengthZ), Math.abs(toolZ), Math.abs(latencyZ));
    const trustScore = baselineReady
      ? Math.max(0, Math.min(1, 1 - Math.min(6, anomalyMagnitude) / 6))
      : 1;

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      reason: detected ? String(findings[0].code || 'behavioral_anomaly') : 'clean',
      findings,
      agent_id: key,
      baseline_ready: baselineReady,
      observed: {
        text_chars: textLength,
        tool_count: toolCount,
        latency_ms: safeLatencyMs,
        style_hash: styleHash || null,
      },
      z_scores: {
        text_chars: Number(lengthZ.toFixed(4)),
        tool_count: Number(toolZ.toFixed(4)),
        latency_ms: Number(latencyZ.toFixed(4)),
      },
      trust_score: Number(trustScore.toFixed(4)),
      samples: Number(profile.count || 0),
    };
  }

  snapshot(agentId = '') {
    const key = normalizeSessionValue(agentId || '', 160);
    const profile = key ? this.agentProfiles.get(key) : null;
    if (!profile) {
      return {
        found: false,
      };
    }
    return {
      found: true,
      agent_id: key,
      samples: Number(profile.count || 0),
      means: {
        text_chars: Number(Number(profile.lengthMean || 0).toFixed(4)),
        tool_count: Number(Number(profile.toolMean || 0).toFixed(4)),
        latency_ms: Number(Number(profile.latencyMean || 0).toFixed(4)),
      },
      style_hashes: Array.from(profile.styleHashes.entries()).map(([hash, count]) => ({
        hash,
        count,
      })),
      updated_at_ms: Number(profile.lastSeenAt || 0),
    };
  }
}

module.exports = {
  BehavioralFingerprint,
};
