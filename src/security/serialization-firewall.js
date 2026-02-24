const crypto = require('crypto');
const {
  clampPositiveInt,
  normalizeMode,
  toObject,
} = require('../utils/primitives');

const GADGET_PATTERNS = [
  /__reduce__\s*[:=]/i,
  /__class__\s*[:=]/i,
  /!!python\/object/i,
  /!!python\/name/i,
  /\bc__builtin__\b/i,
  /\bGLOBAL\b/i,
  /\bpickle\.loads\b/i,
];

const FORMAT_LABELS = new Set(['json', 'yaml', 'pickle', 'msgpack', 'protobuf', 'unknown']);

function clampRatio(value, fallback, min = 0, max = 16) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) {
    return fallback;
  }
  return parsed;
}

function detectFormat(contentType = '', buffer = Buffer.alloc(0), text = '') {
  const type = String(contentType || '').toLowerCase();
  if (type.includes('application/json') || type.endsWith('+json')) {
    return 'json';
  }
  if (type.includes('yaml') || type.includes('x-yaml')) {
    return 'yaml';
  }
  if (type.includes('pickle') || type.includes('python-serialized')) {
    return 'pickle';
  }
  if (type.includes('msgpack')) {
    return 'msgpack';
  }
  if (type.includes('protobuf') || type.includes('x-protobuf')) {
    return 'protobuf';
  }
  if (Buffer.isBuffer(buffer) && buffer.length > 0 && buffer[0] === 0x80) {
    return 'pickle';
  }
  const trimmed = String(text || '').trimStart();
  if (!trimmed) {
    return 'unknown';
  }
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    return 'json';
  }
  if (trimmed.startsWith('---') || trimmed.startsWith('!!')) {
    return 'yaml';
  }
  return 'unknown';
}

function estimateNestingDepthFromText(text = '', maxChars = 65536) {
  const bounded = String(text || '').slice(0, maxChars);
  let depth = 0;
  let maxDepth = 0;
  for (const ch of bounded) {
    if (ch === '{' || ch === '[') {
      depth += 1;
      if (depth > maxDepth) {
        maxDepth = depth;
      }
    } else if ((ch === '}' || ch === ']') && depth > 0) {
      depth -= 1;
    }
  }
  return maxDepth;
}

function estimateObjectDepth(root, maxNodes = 200000) {
  const safeRoot = root;
  const stack = [{ value: safeRoot, depth: 1 }];
  let seen = 0;
  let maxDepth = 1;
  while (stack.length > 0) {
    const current = stack.pop();
    seen += 1;
    if (seen > maxNodes) {
      return {
        depth: maxDepth,
        truncated: true,
      };
    }
    if (!current || typeof current.value !== 'object' || current.value === null) {
      continue;
    }
    if (current.depth > maxDepth) {
      maxDepth = current.depth;
    }
    if (Array.isArray(current.value)) {
      for (let i = 0; i < current.value.length; i += 1) {
        stack.push({
          value: current.value[i],
          depth: current.depth + 1,
        });
      }
    } else {
      for (const value of Object.values(current.value)) {
        stack.push({
          value,
          depth: current.depth + 1,
        });
      }
    }
  }
  return {
    depth: maxDepth,
    truncated: false,
  };
}

function metadataToContentRatio(text = '') {
  const value = String(text || '');
  if (!value) {
    return 0;
  }
  let metadata = 0;
  let content = 0;
  for (const ch of value) {
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {
      content += 1;
    } else {
      metadata += 1;
    }
  }
  return metadata / Math.max(1, content);
}

function sha256Text(value = '') {
  return crypto.createHash('sha256').update(String(value || ''), 'utf8').digest('hex');
}

class SerializationFirewall {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.maxScanBytes = clampPositiveInt(config.max_scan_bytes, 262144, 256, 8 * 1024 * 1024);
    this.maxNestingDepth = clampPositiveInt(config.max_nesting_depth, 50, 4, 2048);
    this.maxObjectNodes = clampPositiveInt(config.max_object_nodes, 200000, 128, 2_000_000);
    this.metadataRatioThreshold = clampRatio(config.metadata_ratio_threshold, 0.8, 0, 64);
    this.allowedFormats = Array.isArray(config.allowed_formats)
      ? config.allowed_formats
        .map((item) => String(item || '').toLowerCase().trim())
        .filter((item) => FORMAT_LABELS.has(item))
      : ['json', 'yaml', 'unknown'];
    this.expectedRootKeys = Array.isArray(config.expected_root_keys)
      ? config.expected_root_keys
        .map((item) => String(item || '').trim())
        .filter(Boolean)
        .slice(0, 128)
      : [];
    this.blockOnTypeConfusion = config.block_on_type_confusion === true;
    this.blockOnDepthBomb = config.block_on_depth_bomb === true;
    this.blockOnFormatViolation = config.block_on_format_violation === true;
    this.blockOnMetadataAnomaly = config.block_on_metadata_anomaly === true;
    this.blockOnSchemaMismatch = config.block_on_schema_mismatch === true;
    this.observability = config.observability !== false;
  }

  isEnabled() {
    return this.enabled === true;
  }

  evaluate({
    headers = {},
    rawBody = Buffer.alloc(0),
    bodyText = '',
    bodyJson = null,
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

    const contentType = String(headers['content-type'] || '').toLowerCase();
    const boundedBuffer = Buffer.isBuffer(rawBody) ? rawBody.subarray(0, this.maxScanBytes) : Buffer.alloc(0);
    const boundedText = String(bodyText || '').slice(0, this.maxScanBytes);
    const format = detectFormat(contentType, boundedBuffer, boundedText);

    const findings = [];
    if (this.allowedFormats.length > 0 && !this.allowedFormats.includes(format)) {
      findings.push({
        code: 'serialization_format_disallowed',
        format,
        blockEligible: this.blockOnFormatViolation,
      });
    }

    for (const pattern of GADGET_PATTERNS) {
      if (!pattern.test(boundedText)) {
        continue;
      }
      findings.push({
        code: 'serialization_type_confusion_gadget',
        pattern: String(pattern),
        blockEligible: this.blockOnTypeConfusion,
      });
      break;
    }

    let depthResult = {
      depth: estimateNestingDepthFromText(boundedText, this.maxScanBytes),
      truncated: false,
    };
    if (bodyJson && typeof bodyJson === 'object') {
      depthResult = estimateObjectDepth(bodyJson, this.maxObjectNodes);
    }
    if (Number(depthResult.depth) > this.maxNestingDepth) {
      findings.push({
        code: 'serialization_depth_bomb',
        depth: Number(depthResult.depth),
        limit: this.maxNestingDepth,
        truncated: depthResult.truncated === true,
        blockEligible: this.blockOnDepthBomb,
      });
    }

    const ratio = metadataToContentRatio(boundedText);
    if (ratio >= this.metadataRatioThreshold) {
      findings.push({
        code: 'serialization_metadata_anomaly',
        ratio: Number(ratio.toFixed(6)),
        threshold: this.metadataRatioThreshold,
        blockEligible: this.blockOnMetadataAnomaly,
      });
    }

    if (
      this.expectedRootKeys.length > 0 &&
      bodyJson &&
      typeof bodyJson === 'object' &&
      !Array.isArray(bodyJson)
    ) {
      const root = toObject(bodyJson);
      const missing = this.expectedRootKeys.filter((key) => !Object.prototype.hasOwnProperty.call(root, key));
      if (missing.length > 0) {
        findings.push({
          code: 'serialization_schema_skeleton_mismatch',
          missing: missing.slice(0, 16),
          blockEligible: this.blockOnSchemaMismatch,
        });
      }
    }

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
      reason: detected ? String(findings[0].code || 'serialization_violation') : 'clean',
      findings,
      format,
      payload_sha256_prefix: sha256Text(boundedText).slice(0, 16),
      depth: Number(depthResult.depth || 0),
      metadata_ratio: Number(ratio.toFixed(6)),
    };
  }
}

module.exports = {
  SerializationFirewall,
};
