const crypto = require('crypto');
const {
  clampPositiveInt,
  normalizeMode,
  normalizeSessionValue,
  toObject,
} = require('../utils/primitives');

const DANGEROUS_PARAM_RE = /(?:^|_)(?:cmd|command|shell|script|eval|exec|path|filepath|file_path|url|endpoint)(?:$|_)/i;
const DANGEROUS_DESC_RE = /\b(?:execute shell|run command|eval|execute arbitrary|write file|delete file|http request|network access)\b/i;

const CAPABILITY_RANK = Object.freeze({
  read: 1,
  write: 2,
  filesystem: 3,
  network: 4,
  execute: 5,
});

function stableTool(tool) {
  const safe = toObject(tool);
  const functionSpec = toObject(safe.function || safe);
  const parameters = toObject(functionSpec.parameters);
  const properties = toObject(parameters.properties);
  const sortedProps = {};
  for (const key of Object.keys(properties).sort()) {
    const item = toObject(properties[key]);
    sortedProps[key] = {
      type: String(item.type || ''),
      description: String(item.description || ''),
    };
  }
  return {
    name: String(functionSpec.name || ''),
    description: String(functionSpec.description || ''),
    required: Array.isArray(parameters.required)
      ? parameters.required.map((item) => String(item || '')).filter(Boolean).sort()
      : [],
    properties: sortedProps,
  };
}

function toolHash(tools = []) {
  const stable = tools.map((tool) => stableTool(tool));
  return crypto.createHash('sha256').update(JSON.stringify(stable), 'utf8').digest('hex');
}

function extractTools(bodyJson = {}, maxTools = 128) {
  const payload = toObject(bodyJson);
  if (!Array.isArray(payload.tools)) {
    return [];
  }
  const out = [];
  for (const tool of payload.tools) {
    if (out.length >= maxTools) {
      break;
    }
    if (!tool || typeof tool !== 'object') {
      continue;
    }
    out.push(tool);
  }
  return out;
}

function classifyCapability(tool = {}) {
  const stable = stableTool(tool);
  const merged = `${stable.name} ${stable.description}`.toLowerCase();
  if (/\b(exec|shell|bash|powershell|terminal|python)\b/.test(merged)) {
    return 'execute';
  }
  if (/\b(http|fetch|request|api|url|webhook|socket)\b/.test(merged)) {
    return 'network';
  }
  if (/\b(file|path|directory|read|write|delete|fs)\b/.test(merged)) {
    return 'filesystem';
  }
  if (/\b(update|create|insert|write|modify|delete)\b/.test(merged)) {
    return 'write';
  }
  return 'read';
}

function resolveServerId(headers = {}, provider = 'unknown', path = '/') {
  const headerValue = normalizeSessionValue(headers['x-sentinel-mcp-server-id'] || '', 160);
  if (headerValue) {
    return headerValue;
  }
  return `${String(provider || 'unknown').slice(0, 64)}:${String(path || '/').slice(0, 128)}`;
}

class ToolSchemaValidator {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.maxTools = clampPositiveInt(config.max_tools, 64, 1, 4096);
    this.maxSchemaBytes = clampPositiveInt(config.max_schema_bytes, 131072, 256, 4 * 1024 * 1024);
    this.maxParamNameChars = clampPositiveInt(config.max_param_name_chars, 128, 4, 1024);
    this.ttlMs = clampPositiveInt(config.ttl_ms, 3600000, 1000, 7 * 24 * 3600000);
    this.maxServers = clampPositiveInt(config.max_servers, 5000, 8, 1_000_000);
    this.blockOnDangerousParameter = config.block_on_dangerous_parameter === true;
    this.blockOnSchemaDrift = config.block_on_schema_drift === true;
    this.blockOnCapabilityBoundary = config.block_on_capability_boundary === true;
    this.detectSchemaDrift = config.detect_schema_drift !== false;
    this.sanitizeInMonitor = config.sanitize_in_monitor !== false;
    this.observability = config.observability !== false;
    this.snapshots = new Map();
  }

  isEnabled() {
    return this.enabled === true;
  }

  prune(nowMs) {
    const minUpdated = nowMs - this.ttlMs;
    for (const [serverId, state] of this.snapshots.entries()) {
      if (Number(state?.updatedAt || 0) < minUpdated) {
        this.snapshots.delete(serverId);
      }
    }
    while (this.snapshots.size > this.maxServers) {
      const oldest = this.snapshots.keys().next().value;
      if (!oldest) {
        break;
      }
      this.snapshots.delete(oldest);
    }
  }

  evaluate({
    headers = {},
    bodyJson = {},
    provider = 'unknown',
    path = '/',
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

    const tools = extractTools(bodyJson, this.maxTools);
    if (tools.length === 0) {
      return {
        enabled: true,
        mode: this.mode,
        detected: false,
        shouldBlock: false,
        reason: 'clean',
        findings: [],
      };
    }

    const serverId = resolveServerId(headers, provider, path);
    const nowMs = Date.now();
    this.prune(nowMs);

    const findings = [];
    const safeTools = [];
    let sanitized = false;
    let highestCapability = 'read';

    for (const tool of tools) {
      const stable = stableTool(tool);
      const schemaBytes = Buffer.byteLength(JSON.stringify(stable), 'utf8');
      if (schemaBytes > this.maxSchemaBytes) {
        findings.push({
          code: 'tool_schema_oversized',
          name: stable.name || 'unknown',
          bytes: schemaBytes,
          blockEligible: this.blockOnDangerousParameter,
        });
      }

      const capability = classifyCapability(stable);
      if (CAPABILITY_RANK[capability] > CAPABILITY_RANK[highestCapability]) {
        highestCapability = capability;
      }

      const params = toObject(stable.properties);
      const safeProps = {};
      for (const [name, spec] of Object.entries(params)) {
        const safeName = String(name || '').slice(0, this.maxParamNameChars);
        const risky = DANGEROUS_PARAM_RE.test(safeName) || DANGEROUS_DESC_RE.test(String(spec.description || ''));
        if (risky) {
          findings.push({
            code: 'tool_schema_dangerous_parameter',
            tool: stable.name || 'unknown',
            parameter: safeName,
            blockEligible: this.blockOnDangerousParameter,
          });
          if (this.sanitizeInMonitor) {
            sanitized = true;
            continue;
          }
        }
        safeProps[safeName] = spec;
      }

      const rebuilt = {
        type: 'function',
        function: {
          name: stable.name,
          description: stable.description,
          parameters: {
            type: 'object',
            properties: safeProps,
            required: stable.required.filter((item) => Object.prototype.hasOwnProperty.call(safeProps, item)),
          },
        },
      };
      safeTools.push(rebuilt);
    }

    const declaredBoundary = String(headers['x-sentinel-tool-capability'] || '').toLowerCase().trim();
    if (declaredBoundary && CAPABILITY_RANK[declaredBoundary] && CAPABILITY_RANK[highestCapability] > CAPABILITY_RANK[declaredBoundary]) {
      findings.push({
        code: 'tool_schema_capability_boundary_exceeded',
        declared: declaredBoundary,
        observed: highestCapability,
        blockEligible: this.blockOnCapabilityBoundary,
      });
    }

    if (this.detectSchemaDrift) {
      const currentHash = toolHash(safeTools);
      const previous = this.snapshots.get(serverId);
      if (previous && previous.hash !== currentHash) {
        findings.push({
          code: 'tool_schema_drift_detected',
          blockEligible: this.blockOnSchemaDrift,
        });
      }
      this.snapshots.set(serverId, {
        hash: currentHash,
        updatedAt: nowMs,
      });
    }

    const detected = findings.length > 0;
    const shouldBlock =
      detected &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce' &&
      findings.some((finding) => finding.blockEligible === true);

    const nextBody =
      sanitized && !shouldBlock
        ? {
          ...toObject(bodyJson),
          tools: safeTools,
        }
        : null;

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      reason: detected ? String(findings[0].code || 'tool_schema_violation') : 'clean',
      findings,
      sanitized,
      highest_capability: highestCapability,
      tool_count: tools.length,
      bodyJson: nextBody,
    };
  }
}

module.exports = {
  ToolSchemaValidator,
};
