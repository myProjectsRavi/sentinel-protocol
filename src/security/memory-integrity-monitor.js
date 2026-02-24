const crypto = require('crypto');
const {
  clampPositiveInt,
  normalizeMode,
  normalizeSessionValue,
  toObject,
} = require('../utils/primitives');

function clampRatio(value, fallback, min = 1, max = 32) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) {
    return fallback;
  }
  return parsed;
}

function hashText(text = '') {
  return crypto.createHash('sha256').update(String(text || ''), 'utf8').digest('hex');
}

function collectMemoryPayload(bodyJson = {}, bodyText = '', maxChars = 32768) {
  const payload = toObject(bodyJson);
  const chunks = [];
  const directFields = ['memory', 'context', 'scratchpad', 'notes', 'state'];
  for (const field of directFields) {
    if (chunks.join('\n').length >= maxChars) {
      break;
    }
    const value = payload[field];
    if (typeof value === 'string') {
      chunks.push(value);
    } else if (value && typeof value === 'object') {
      chunks.push(JSON.stringify(value));
    }
  }
  if (Array.isArray(payload.messages)) {
    for (const message of payload.messages.slice(-16)) {
      const content = typeof message?.content === 'string' ? message.content : '';
      if (content) {
        chunks.push(content);
      }
      if (chunks.join('\n').length >= maxChars) {
        break;
      }
    }
  }
  if (chunks.length === 0) {
    chunks.push(String(bodyText || ''));
  }
  return chunks.join('\n').slice(0, maxChars);
}

class MemoryIntegrityMonitor {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.sessionHeader = String(config.session_header || 'x-sentinel-session-id').toLowerCase();
    this.agentHeader = String(config.agent_header || 'x-sentinel-agent-id').toLowerCase();
    this.chainHeader = String(config.chain_header || 'x-sentinel-memory-chain').toLowerCase();
    this.maxMemoryChars = clampPositiveInt(config.max_memory_chars, 32768, 256, 2 * 1024 * 1024);
    this.ttlMs = clampPositiveInt(config.ttl_ms, 6 * 3600 * 1000, 1000, 7 * 24 * 3600 * 1000);
    this.maxSessions = clampPositiveInt(config.max_sessions, 10000, 8, 1_000_000);
    this.maxGrowthRatio = clampRatio(config.max_growth_ratio, 4, 1, 64);
    this.blockOnChainBreak = config.block_on_chain_break === true;
    this.blockOnGrowth = config.block_on_growth === true;
    this.blockOnOwnerMismatch = config.block_on_owner_mismatch === true;
    this.observability = config.observability !== false;
    this.sessions = new Map();
  }

  isEnabled() {
    return this.enabled === true;
  }

  prune(nowMs) {
    const minUpdated = nowMs - this.ttlMs;
    for (const [sessionId, state] of this.sessions.entries()) {
      if (Number(state?.updatedAt || 0) < minUpdated) {
        this.sessions.delete(sessionId);
      }
    }
    while (this.sessions.size > this.maxSessions) {
      const oldest = this.sessions.keys().next().value;
      if (!oldest) {
        break;
      }
      this.sessions.delete(oldest);
    }
  }

  resolveSession(headers = {}, correlationId = '') {
    const direct = normalizeSessionValue(headers[this.sessionHeader] || '', 160);
    if (direct) {
      return direct;
    }
    const fallback = normalizeSessionValue(headers['x-sentinel-agent-id'] || '', 160);
    if (fallback) {
      return fallback;
    }
    return normalizeSessionValue(correlationId || 'anonymous', 160) || 'anonymous';
  }

  evaluate({
    headers = {},
    bodyJson = {},
    bodyText = '',
    correlationId = '',
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

    const nowMs = Date.now();
    this.prune(nowMs);

    const sessionId = this.resolveSession(headers, correlationId);
    const owner = normalizeSessionValue(headers[this.agentHeader] || '', 128) || 'agent:unknown';
    const payload = collectMemoryPayload(bodyJson, bodyText, this.maxMemoryChars);
    const memoryHash = hashText(payload);

    const previous = this.sessions.get(sessionId) || null;
    const previousChain = previous?.chainHash || '';
    const chainHash = hashText(`${previousChain}|${memoryHash}`);
    const externalChain = normalizeSessionValue(headers[this.chainHeader] || '', 128);

    const findings = [];
    if (externalChain && previous && previous.chainHash && externalChain !== previous.chainHash) {
      findings.push({
        code: 'memory_integrity_chain_break',
        expected: previous.chainHash.slice(0, 16),
        observed: externalChain.slice(0, 16),
        blockEligible: this.blockOnChainBreak,
      });
    }

    const previousChars = Number(previous?.chars || 0);
    const currentChars = payload.length;
    if (previousChars > 0) {
      const growthRatio = currentChars / Math.max(1, previousChars);
      if (growthRatio >= this.maxGrowthRatio) {
        findings.push({
          code: 'memory_integrity_growth_spike',
          previous_chars: previousChars,
          current_chars: currentChars,
          growth_ratio: Number(growthRatio.toFixed(6)),
          blockEligible: this.blockOnGrowth,
        });
      }
    }

    if (previous && previous.owner && previous.owner !== owner) {
      findings.push({
        code: 'memory_integrity_owner_mismatch',
        previous_owner: previous.owner,
        current_owner: owner,
        blockEligible: this.blockOnOwnerMismatch,
      });
    }

    this.sessions.set(sessionId, {
      owner,
      hash: memoryHash,
      chainHash,
      chars: currentChars,
      updatedAt: nowMs,
    });

    const detected = findings.length > 0;
    const shouldBlock =
      detected &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce' &&
      findings.some((finding) => finding.blockEligible === true);

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      reason: detected ? String(findings[0].code || 'memory_integrity_violation') : 'clean',
      findings,
      session_id: sessionId,
      owner,
      memory_hash_prefix: memoryHash.slice(0, 16),
      chain_hash_prefix: chainHash.slice(0, 16),
      chars: currentChars,
    };
  }
}

module.exports = {
  MemoryIntegrityMonitor,
};
