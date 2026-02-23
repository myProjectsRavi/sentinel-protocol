const crypto = require('crypto');
const {
  clampPositiveInt,
  normalizeMode,
} = require('../utils/primitives');

const MCP_SHADOW_TECHNIQUE_ID = 'ASI10.MCP_SHADOWING';

function toObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return value;
}

function stableObject(value) {
  if (value === null || value === undefined) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => stableObject(item));
  }
  if (typeof value !== 'object') {
    return value;
  }
  const out = {};
  for (const key of Object.keys(value).sort()) {
    out[key] = stableObject(value[key]);
  }
  return out;
}

function sha256(input = '') {
  return crypto.createHash('sha256').update(String(input || ''), 'utf8').digest('hex');
}

function normalizeToolName(input = '') {
  return String(input || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');
}

function summarizeToolSchema(tool = {}, maxBytes) {
  const safeTool = toObject(tool);
  const fn = toObject(safeTool.function);
  const summary = {
    type: String(safeTool.type || ''),
    name: String(fn.name || '').trim(),
    description_hash: sha256(String(fn.description || '')),
    parameters: stableObject(toObject(fn.parameters)),
  };
  let raw = '{}';
  try {
    raw = JSON.stringify(summary);
  } catch {
    raw = '{}';
  }
  const bytes = Buffer.byteLength(raw, 'utf8');
  if (bytes > maxBytes) {
    raw = Buffer.from(raw, 'utf8').subarray(0, maxBytes).toString('utf8');
  }
  return {
    name: summary.name,
    normalizedName: normalizeToolName(summary.name),
    hash: sha256(raw),
    bytes,
    truncated: bytes > maxBytes,
  };
}

function levenshteinWithin(a = '', b = '', maxDistance = 1) {
  if (a === b) {
    return 0;
  }
  const left = String(a || '');
  const right = String(b || '');
  if (!left || !right) {
    return Math.max(left.length, right.length);
  }
  if (Math.abs(left.length - right.length) > maxDistance) {
    return maxDistance + 1;
  }

  const prev = new Array(right.length + 1);
  const cur = new Array(right.length + 1);
  for (let j = 0; j <= right.length; j += 1) {
    prev[j] = j;
  }
  for (let i = 1; i <= left.length; i += 1) {
    cur[0] = i;
    let rowMin = cur[0];
    for (let j = 1; j <= right.length; j += 1) {
      const cost = left.charCodeAt(i - 1) === right.charCodeAt(j - 1) ? 0 : 1;
      cur[j] = Math.min(
        prev[j] + 1,
        cur[j - 1] + 1,
        prev[j - 1] + cost
      );
      if (cur[j] < rowMin) {
        rowMin = cur[j];
      }
    }
    if (rowMin > maxDistance) {
      return maxDistance + 1;
    }
    for (let j = 0; j <= right.length; j += 1) {
      prev[j] = cur[j];
    }
  }
  return prev[right.length];
}

class MCPShadowDetector {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.detectSchemaDriftEnabled = config.detect_schema_drift !== false;
    this.detectLateRegistrationEnabled = config.detect_late_registration !== false;
    this.detectNameCollisionsEnabled = config.detect_name_collisions !== false;
    this.blockOnSchemaDrift = config.block_on_schema_drift === true;
    this.blockOnLateRegistration = config.block_on_late_registration === true;
    this.blockOnNameCollision = config.block_on_name_collision === true;
    this.maxTools = clampPositiveInt(config.max_tools, 64, 1, 10_000);
    this.maxSnapshotBytes = clampPositiveInt(config.max_tool_snapshot_bytes, 131072, 1024, 8_388_608);
    this.ttlMs = clampPositiveInt(config.ttl_ms, 3600000, 1000, 7 * 24 * 3600000);
    this.maxServerEntries = clampPositiveInt(config.max_server_entries, 2000, 16, 100_000);
    this.maxFindings = clampPositiveInt(config.max_findings, 16, 1, 256);
    this.minNameLength = clampPositiveInt(config.min_tool_name_length, 4, 1, 128);
    this.nameSimilarityDistance = clampPositiveInt(config.name_similarity_distance, 1, 1, 8);
    this.maxNameCandidates = clampPositiveInt(config.max_name_candidates, 128, 1, 10_000);
    this.observability = config.observability !== false;
    this.serverSnapshots = new Map();
  }

  isEnabled() {
    return this.enabled === true;
  }

  prune(nowMs) {
    const minUpdatedAt = nowMs - this.ttlMs;
    for (const [serverId, entry] of this.serverSnapshots.entries()) {
      if (Number(entry?.updatedAt || 0) < minUpdatedAt) {
        this.serverSnapshots.delete(serverId);
      }
    }
    while (this.serverSnapshots.size > this.maxServerEntries) {
      const oldest = this.serverSnapshots.keys().next().value;
      if (!oldest) {
        break;
      }
      this.serverSnapshots.delete(oldest);
    }
  }

  buildCurrentToolMap(bodyJson = {}) {
    const toolsRaw = Array.isArray(bodyJson.tools) ? bodyJson.tools : [];
    const tools = toolsRaw.slice(0, this.maxTools);
    const truncated = toolsRaw.length > tools.length;
    const toolMap = new Map();
    const normalizedOrder = [];
    const findings = [];
    if (truncated) {
      findings.push({
        code: 'mcp_shadow_tools_truncated',
        message: `tool list truncated from ${toolsRaw.length} to ${tools.length}`,
        blockEligible: false,
        technique_id: MCP_SHADOW_TECHNIQUE_ID,
      });
    }
    for (const tool of tools) {
      const summary = summarizeToolSchema(tool, this.maxSnapshotBytes);
      const normalized = summary.normalizedName;
      if (!normalized || normalized.length < this.minNameLength) {
        continue;
      }
      toolMap.set(normalized, {
        name: summary.name,
        hash: summary.hash,
      });
      normalizedOrder.push(normalized);
      if (summary.truncated) {
        findings.push({
          code: 'mcp_shadow_tool_snapshot_truncated',
          message: `tool snapshot truncated for ${summary.name || 'unknown_tool'}`,
          blockEligible: false,
          technique_id: MCP_SHADOW_TECHNIQUE_ID,
        });
      }
      if (findings.length >= this.maxFindings) {
        break;
      }
    }
    return {
      toolMap,
      normalizedOrder,
      findings,
    };
  }

  detectSchemaDrift(serverEntry, currentToolMap) {
    const findings = [];
    if (!this.detectSchemaDriftEnabled || !serverEntry) {
      return findings;
    }
    for (const [normalizedName, current] of currentToolMap.entries()) {
      const previous = serverEntry.toolMap.get(normalizedName);
      if (!previous) {
        continue;
      }
      if (String(previous.hash) !== String(current.hash)) {
        findings.push({
          code: 'mcp_shadow_schema_drift',
          message: `tool schema drift for ${current.name || normalizedName}`,
          blockEligible: this.blockOnSchemaDrift,
          technique_id: MCP_SHADOW_TECHNIQUE_ID,
        });
        if (findings.length >= this.maxFindings) {
          break;
        }
      }
    }
    return findings;
  }

  detectLateRegistration(serverEntry, currentToolMap) {
    const findings = [];
    if (!this.detectLateRegistrationEnabled || !serverEntry) {
      return findings;
    }
    for (const [normalizedName, current] of currentToolMap.entries()) {
      if (serverEntry.toolMap.has(normalizedName)) {
        continue;
      }
      findings.push({
        code: 'mcp_shadow_late_registration',
        message: `late MCP tool registration for ${current.name || normalizedName}`,
        blockEligible: this.blockOnLateRegistration,
        technique_id: MCP_SHADOW_TECHNIQUE_ID,
      });
      if (findings.length >= this.maxFindings) {
        break;
      }
    }
    return findings;
  }

  detectNameCollisions(serverId, currentToolMap) {
    const findings = [];
    if (!this.detectNameCollisionsEnabled || currentToolMap.size === 0) {
      return findings;
    }

    const namesByServer = [];
    for (const [otherServerId, entry] of this.serverSnapshots.entries()) {
      if (otherServerId === serverId || !entry?.toolMap) {
        continue;
      }
      namesByServer.push({
        serverId: otherServerId,
        names: Array.from(entry.toolMap.keys()),
      });
    }

    let candidateChecks = 0;
    for (const [normalizedName, current] of currentToolMap.entries()) {
      for (const snapshot of namesByServer) {
        for (const otherName of snapshot.names) {
          if (candidateChecks >= this.maxNameCandidates) {
            findings.push({
              code: 'mcp_shadow_collision_scan_truncated',
              message: 'name collision candidate scan truncated',
              blockEligible: false,
              technique_id: MCP_SHADOW_TECHNIQUE_ID,
            });
            return findings.slice(0, this.maxFindings);
          }
          candidateChecks += 1;

          if (normalizedName === otherName) {
            findings.push({
              code: 'mcp_shadow_name_collision_exact',
              message: `exact tool collision for ${current.name || normalizedName} across servers`,
              blockEligible: this.blockOnNameCollision,
              technique_id: MCP_SHADOW_TECHNIQUE_ID,
            });
            if (findings.length >= this.maxFindings) {
              return findings;
            }
            continue;
          }

          const distance = levenshteinWithin(
            normalizedName,
            otherName,
            this.nameSimilarityDistance
          );
          if (distance > 0 && distance <= this.nameSimilarityDistance) {
            findings.push({
              code: 'mcp_shadow_name_collision_fuzzy',
              message: `fuzzy tool collision for ${current.name || normalizedName} (distance=${distance})`,
              blockEligible: this.blockOnNameCollision,
              technique_id: MCP_SHADOW_TECHNIQUE_ID,
            });
            if (findings.length >= this.maxFindings) {
              return findings;
            }
          }
        }
      }
    }
    return findings;
  }

  inspect({
    bodyJson = {},
    serverId = 'default',
    serverConfig = null,
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

    const key = String(serverId || 'default');
    const existing = this.serverSnapshots.get(key) || null;
    const currentTool = this.buildCurrentToolMap(toObject(bodyJson));
    const findings = [];
    findings.push(...currentTool.findings);
    findings.push(...this.detectSchemaDrift(existing, currentTool.toolMap));
    findings.push(...this.detectLateRegistration(existing, currentTool.toolMap));
    findings.push(...this.detectNameCollisions(key, currentTool.toolMap));

    const configStable = stableObject(toObject(serverConfig));
    let configRaw = '{}';
    try {
      configRaw = JSON.stringify(configStable);
    } catch {
      configRaw = '{}';
    }
    const snapshotHash = sha256(
      JSON.stringify({
        config_hash: sha256(configRaw),
        tools: currentTool.normalizedOrder.map((name) => [name, currentTool.toolMap.get(name)?.hash || '']),
      })
    );

    this.serverSnapshots.set(key, {
      updatedAt: nowMs,
      snapshotHash,
      toolMap: currentTool.toolMap,
    });

    const slicedFindings = findings.slice(0, this.maxFindings);
    const detected = slicedFindings.length > 0;
    const blockEligible = slicedFindings.some((finding) => finding?.blockEligible === true);
    const shouldBlock =
      blockEligible &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce';

    let reason = 'clean';
    if (detected) {
      if (slicedFindings.some((finding) => String(finding.code).includes('schema_drift'))) {
        reason = 'mcp_shadow_schema_drift';
      } else if (slicedFindings.some((finding) => String(finding.code).includes('late_registration'))) {
        reason = 'mcp_shadow_late_registration';
      } else if (slicedFindings.some((finding) => String(finding.code).includes('collision'))) {
        reason = 'mcp_shadow_name_collision';
      } else {
        reason = String(slicedFindings[0]?.code || 'mcp_shadow_detected');
      }
    }

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      reason,
      findings: slicedFindings,
      technique_id: MCP_SHADOW_TECHNIQUE_ID,
      snapshot_hash_prefix: String(snapshotHash).slice(0, 16),
      registry_size: this.serverSnapshots.size,
    };
  }
}

module.exports = {
  MCPShadowDetector,
  normalizeToolName,
  levenshteinWithin,
  MCP_SHADOW_TECHNIQUE_ID,
};
