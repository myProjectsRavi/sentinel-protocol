const crypto = require('crypto');
const {
  clampPositiveInt,
  clampProbability,
  normalizeMode,
} = require('../utils/primitives');
const { InjectionScanner } = require('../engines/injection-scanner');

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

function sha256(value) {
  return crypto.createHash('sha256').update(String(value || ''), 'utf8').digest('hex');
}

function toObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return value;
}

function hasSuspiciousControlChars(input = '') {
  return /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(String(input || ''));
}

function hasZeroWidthChars(input = '') {
  return /[\u200B-\u200D\uFEFF]/.test(String(input || ''));
}

function stripString(input = '') {
  return String(input || '')
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
}

function sanitizeValue(value, maxBytes, changedPaths, pathLabel = 'root') {
  if (typeof value === 'string') {
    const stripped = stripString(value);
    const withinLimit = Buffer.byteLength(stripped, 'utf8') <= maxBytes
      ? stripped
      : Buffer.from(stripped, 'utf8').subarray(0, maxBytes).toString('utf8');
    if (withinLimit !== value) {
      changedPaths.push(pathLabel);
    }
    return withinLimit;
  }
  if (Array.isArray(value)) {
    return value.map((item, idx) =>
      sanitizeValue(item, maxBytes, changedPaths, `${pathLabel}[${idx}]`)
    );
  }
  if (!value || typeof value !== 'object') {
    return value;
  }
  const out = {};
  for (const [key, nested] of Object.entries(value)) {
    out[key] = sanitizeValue(nested, maxBytes, changedPaths, `${pathLabel}.${key}`);
  }
  return out;
}

function boolFromFinding(finding, code, fallback = false) {
  return String(finding?.code || '') === code ? finding?.blockEligible === true : fallback;
}

class MCPPoisoningDetector {
  constructor(config = {}, deps = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.descriptionThreshold = clampProbability(config.description_threshold, 0.65);
    this.maxDescriptionScanBytes = clampPositiveInt(config.max_description_scan_bytes, 8192, 128, 1_048_576);
    this.maxArgumentBytes = clampPositiveInt(config.max_argument_bytes, 65536, 256, 4_194_304);
    this.maxTools = clampPositiveInt(config.max_tools, 64, 1, 10_000);
    this.maxDriftSnapshotBytes = clampPositiveInt(config.max_drift_snapshot_bytes, 131072, 1024, 8_388_608);
    this.blockOnConfigDrift = config.block_on_config_drift === true;
    this.detectConfigDrift = config.detect_config_drift !== false;
    this.driftTtlMs = clampPositiveInt(config.drift_ttl_ms, 3600000, 1000, 7 * 24 * 3600000);
    this.maxServerEntries = clampPositiveInt(config.max_server_entries, 2000, 16, 100000);
    this.sanitizeArguments = config.sanitize_arguments !== false;
    this.stripNonPrintable = config.strip_non_printable !== false;
    this.observability = config.observability !== false;
    this.injectionScanner = deps.injectionScanner || new InjectionScanner({
      maxScanBytes: this.maxDescriptionScanBytes,
    });
    this.serverHashes = new Map();
  }

  isEnabled() {
    return this.enabled === true;
  }

  prune(nowMs) {
    const minUpdatedAt = nowMs - this.driftTtlMs;
    for (const [serverId, entry] of this.serverHashes.entries()) {
      if (Number(entry?.updatedAt || 0) < minUpdatedAt) {
        this.serverHashes.delete(serverId);
      }
    }
    while (this.serverHashes.size > this.maxServerEntries) {
      const oldest = this.serverHashes.keys().next().value;
      if (!oldest) {
        break;
      }
      this.serverHashes.delete(oldest);
    }
  }

  validateToolSchema(tool, index) {
    const findings = [];
    if (!tool || typeof tool !== 'object' || Array.isArray(tool)) {
      findings.push({
        code: 'mcp_tool_schema_invalid',
        message: `tool[${index}] must be object`,
        blockEligible: true,
      });
      return findings;
    }
    const type = String(tool.type || '');
    if (type !== 'function') {
      findings.push({
        code: 'mcp_tool_schema_invalid',
        message: `tool[${index}].type must be "function"`,
        blockEligible: true,
      });
    }
    const fn = tool.function;
    if (!fn || typeof fn !== 'object' || Array.isArray(fn)) {
      findings.push({
        code: 'mcp_tool_schema_invalid',
        message: `tool[${index}].function must be object`,
        blockEligible: true,
      });
      return findings;
    }
    if (typeof fn.name !== 'string' || !fn.name.trim()) {
      findings.push({
        code: 'mcp_tool_schema_invalid',
        message: `tool[${index}].function.name must be non-empty string`,
        blockEligible: true,
      });
    }
    if (fn.parameters !== undefined) {
      const parameters = fn.parameters;
      if (!parameters || typeof parameters !== 'object' || Array.isArray(parameters)) {
        findings.push({
          code: 'mcp_tool_schema_invalid',
          message: `tool[${index}].function.parameters must be object`,
          blockEligible: true,
        });
      }
    }
    return findings;
  }

  scanDescriptions(tools = []) {
    const findings = [];
    tools.forEach((tool, idx) => {
      const description = String(tool?.function?.description || '');
      if (!description) {
        return;
      }
      if (
        this.stripNonPrintable &&
        (hasSuspiciousControlChars(description) || hasZeroWidthChars(description))
      ) {
        findings.push({
          code: 'mcp_description_poisoning',
          message: `tool[${idx}] contains non-printable or zero-width characters`,
          blockEligible: true,
        });
      }
      const result = this.injectionScanner.scan(description, {
        maxScanBytes: this.maxDescriptionScanBytes,
      });
      if (Number(result.score || 0) >= this.descriptionThreshold) {
        findings.push({
          code: 'mcp_description_poisoning',
          message: `tool[${idx}] description injection score ${result.score}`,
          score: result.score,
          signals: (result.matchedSignals || []).map((signal) => signal.id),
          blockEligible: true,
        });
      }
    });
    return findings;
  }

  summarizeToolForDrift(tool) {
    const safeTool = toObject(tool);
    const fn = toObject(safeTool.function);
    const description = String(fn.description || '');
    const parameters = toObject(fn.parameters);
    const stableParameters = stableObject(parameters);
    let parametersRaw = '{}';
    try {
      parametersRaw = JSON.stringify(stableParameters);
    } catch {
      parametersRaw = '{}';
    }
    const parametersTruncated = Buffer.byteLength(parametersRaw, 'utf8') > 4096;
    if (parametersTruncated) {
      parametersRaw = Buffer.from(parametersRaw, 'utf8').subarray(0, 4096).toString('utf8');
    }

    return {
      type: String(safeTool.type || ''),
      name: String(fn.name || ''),
      description_len: Buffer.byteLength(description, 'utf8'),
      description_hash: sha256(description.slice(0, this.maxDescriptionScanBytes)),
      parameters_hash: sha256(parametersRaw),
      parameters_truncated: parametersTruncated,
    };
  }

  buildDriftPayload({ tools = [], serverConfig = null } = {}) {
    const source = {
      serverConfig: stableObject(toObject(serverConfig)),
      tools: tools.map((tool) => this.summarizeToolForDrift(tool)),
    };
    let raw = '{}';
    try {
      raw = JSON.stringify(source);
    } catch {
      raw = '{}';
    }
    const rawBytes = Buffer.byteLength(raw, 'utf8');
    const truncated = rawBytes > this.maxDriftSnapshotBytes;
    if (truncated) {
      raw = Buffer.from(raw, 'utf8').subarray(0, this.maxDriftSnapshotBytes).toString('utf8');
    }
    return {
      hash: sha256(raw),
      truncated,
      bytes: rawBytes,
    };
  }

  detectDrift(serverId, payloadHash) {
    if (!this.detectConfigDrift) {
      return { drifted: false, previousHash: null };
    }
    const nowMs = Date.now();
    this.prune(nowMs);
    const key = String(serverId || 'default');
    const existing = this.serverHashes.get(key);
    if (!existing) {
      this.serverHashes.set(key, {
        hash: payloadHash,
        updatedAt: nowMs,
      });
      return { drifted: false, previousHash: null };
    }
    const previousHash = existing.hash;
    existing.hash = payloadHash;
    existing.updatedAt = nowMs;
    this.serverHashes.set(key, existing);
    return {
      drifted: previousHash !== payloadHash,
      previousHash,
    };
  }

  inspect({
    bodyJson = {},
    toolArgs = {},
    serverId = 'default',
    serverConfig = null,
    effectiveMode = 'monitor',
  } = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        detected: false,
        shouldBlock: false,
        findings: [],
        sanitizedArguments: toolArgs,
      };
    }

    const findings = [];
    const parsedBody = toObject(bodyJson);
    const allTools = Array.isArray(parsedBody.tools) ? parsedBody.tools : [];
    const tools = allTools.slice(0, this.maxTools);
    if (allTools.length > tools.length) {
      findings.push({
        code: 'mcp_tools_truncated',
        message: `tool list truncated from ${allTools.length} to ${tools.length}`,
        blockEligible: false,
      });
    }

    tools.forEach((tool, idx) => {
      findings.push(...this.validateToolSchema(tool, idx));
    });
    findings.push(...this.scanDescriptions(tools));

    const driftPayload = this.buildDriftPayload({ tools, serverConfig });
    if (driftPayload.truncated) {
      findings.push({
        code: 'mcp_drift_snapshot_truncated',
        message: `drift snapshot truncated at ${this.maxDriftSnapshotBytes} bytes`,
        blockEligible: false,
      });
    }
    const drift = this.detectDrift(serverId, driftPayload.hash);
    if (drift.drifted) {
      findings.push({
        code: 'mcp_config_drift_detected',
        message: 'MCP server configuration drift detected',
        previous_hash: drift.previousHash ? String(drift.previousHash).slice(0, 16) : null,
        current_hash: String(driftPayload.hash).slice(0, 16),
        blockEligible: this.blockOnConfigDrift,
      });
    }

    let sanitizedArguments = toolArgs;
    const changedPaths = [];
    if (this.sanitizeArguments) {
      sanitizedArguments = sanitizeValue(
        toObject(toolArgs),
        this.maxArgumentBytes,
        changedPaths,
        'arguments'
      );
      if (changedPaths.length > 0) {
        findings.push({
          code: 'mcp_tool_arguments_sanitized',
          message: 'tool arguments were sanitized',
          changed_paths: changedPaths.slice(0, 16),
          blockEligible: false,
        });
      }
    }

    const detected = findings.length > 0;
    const blockEligible = findings.some((finding) => finding?.blockEligible === true);
    const shouldBlock =
      blockEligible &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce';
    let reason = 'clean';
    if (detected) {
      const hasPoisoningFinding = findings.some((finding) =>
        boolFromFinding(finding, 'mcp_description_poisoning')
          || boolFromFinding(finding, 'mcp_tool_schema_invalid')
      );
      if (hasPoisoningFinding) {
        reason = 'mcp_poisoning_detected';
      } else {
        reason = String(findings[0]?.code || 'mcp_poisoning_detected');
      }
    }

    return {
      enabled: true,
      mode: this.mode,
      detected,
      blockEligible,
      shouldBlock,
      reason,
      findings,
      drift,
      driftPayload,
      sanitizedArguments,
    };
  }
}

module.exports = {
  MCPPoisoningDetector,
  sanitizeValue,
};
