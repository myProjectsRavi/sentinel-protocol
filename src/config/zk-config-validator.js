const crypto = require('crypto');
const { clampPositiveInt } = require('../utils/primitives');

const SECRET_KEY_PATTERN = /(secret|token|api[_-]?key|password|private[_-]?key|auth[_-]?token|bearer)/i;
const SECRET_VALUE_PATTERNS = [
  /sk-[a-z0-9]{16,}/i,
  /api[_-]?key[_:=\s]*[A-Za-z0-9_\-]{12,}/i,
  /bearer\s+[A-Za-z0-9\-_\.]{12,}/i,
  /-----BEGIN [A-Z ]+PRIVATE KEY-----/,
];

function stableStringify(value) {
  if (value === null || value === undefined) {
    return 'null';
  }
  if (typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  const pairs = keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`);
  return `{${pairs.join(',')}}`;
}

function sha256(value = '') {
  return crypto.createHash('sha256').update(String(value || ''), 'utf8').digest('hex');
}

function normalizeRuntimeKeys(value) {
  if (!Array.isArray(value)) {
    return new Set();
  }
  return new Set(
    value
      .map((item) => String(item || '').trim())
      .filter(Boolean)
  );
}

function isSecretValue(value) {
  const text = String(value || '');
  for (const pattern of SECRET_VALUE_PATTERNS) {
    if (pattern.test(text)) {
      return true;
    }
  }
  return false;
}

function toPath(parts = []) {
  return parts.length === 0 ? '$' : parts.join('.');
}

class ZKConfigValidator {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.hmacKey = String(config.hmac_key || process.env.SENTINEL_ZK_CONFIG_HMAC || '');
    this.maxFindings = clampPositiveInt(config.max_findings, 256, 16, 10000);
    this.maxNodes = clampPositiveInt(config.max_nodes, 50000, 128, 2_000_000);
    this.maxDepth = clampPositiveInt(config.max_depth, 64, 2, 1024);
    this.redactionText = String(config.redaction_text || '[REDACTED]');
    this.scorePenaltySecret = clampPositiveInt(config.score_penalty_secret, 8, 1, 100);
    this.scorePenaltyDeadKey = clampPositiveInt(config.score_penalty_dead_key, 4, 1, 100);
    this.scorePenaltyOverConfig = clampPositiveInt(config.score_penalty_over_config, 2, 1, 100);
    this.observability = config.observability !== false;
  }

  isEnabled() {
    return this.enabled === true;
  }

  createProof(configObj = {}) {
    const canonical = stableStringify(configObj || {});
    const hash = sha256(canonical);
    if (!this.hmacKey) {
      return {
        hash,
        signature: '',
        algorithm: 'sha256',
      };
    }
    const signature = crypto
      .createHmac('sha256', this.hmacKey)
      .update(hash, 'utf8')
      .digest('hex');
    return {
      hash,
      signature,
      algorithm: 'hmac-sha256',
    };
  }

  evaluate(configObj = {}, options = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        valid: true,
        score: 100,
        findings: [],
      };
    }

    const knownRuntimeKeys = normalizeRuntimeKeys(options.knownRuntimeKeys);
    const findings = [];
    let score = 100;
    let visited = 0;
    const stack = [{
      value: configObj,
      path: ['$'],
      depth: 0,
    }];

    while (stack.length > 0) {
      const current = stack.pop();
      visited += 1;
      if (visited > this.maxNodes) {
        findings.push({
          code: 'zk_config_scan_truncated',
          path: toPath(current.path),
          blockEligible: false,
        });
        break;
      }

      if (current.depth > this.maxDepth) {
        findings.push({
          code: 'zk_config_depth_exceeded',
          path: toPath(current.path),
          blockEligible: false,
        });
        continue;
      }

      const node = current.value;
      if (!node || typeof node !== 'object') {
        continue;
      }

      if (Array.isArray(node)) {
        for (let i = Math.min(node.length, 1024) - 1; i >= 0; i -= 1) {
          stack.push({
            value: node[i],
            path: [...current.path, `[${i}]`],
            depth: current.depth + 1,
          });
        }
        continue;
      }

      for (const [key, value] of Object.entries(node)) {
        const nextPath = [...current.path, key];
        const pathString = toPath(nextPath);
        const keyLooksSecret = SECRET_KEY_PATTERN.test(String(key || ''));
        if (keyLooksSecret && String(value || '').trim().length > 0) {
          findings.push({
            code: 'zk_config_secret_key_present',
            path: pathString,
            key,
            blockEligible: false,
          });
          score -= this.scorePenaltySecret;
        } else if (typeof value === 'string' && isSecretValue(value)) {
          findings.push({
            code: 'zk_config_secret_value_present',
            path: pathString,
            key,
            blockEligible: false,
          });
          score -= this.scorePenaltySecret;
        }

        if (
          current.path.length === 2 &&
          current.path[1] === 'runtime' &&
          knownRuntimeKeys.size > 0 &&
          !knownRuntimeKeys.has(String(key || ''))
        ) {
          findings.push({
            code: 'zk_config_dead_runtime_key',
            path: pathString,
            key,
            blockEligible: false,
          });
          score -= this.scorePenaltyDeadKey;
        }

        if (value && typeof value === 'object') {
          stack.push({
            value,
            path: nextPath,
            depth: current.depth + 1,
          });
        } else if (value === false && current.path.length >= 2 && current.path[1] === 'runtime') {
          findings.push({
            code: 'zk_config_engine_disabled',
            path: pathString,
            key,
            blockEligible: false,
          });
          score -= this.scorePenaltyOverConfig;
        }

        if (findings.length >= this.maxFindings) {
          break;
        }
      }
      if (findings.length >= this.maxFindings) {
        break;
      }
    }

    const proof = this.createProof(configObj);
    const normalizedScore = Math.max(0, Math.min(100, score));
    return {
      enabled: true,
      valid: findings.length === 0,
      score: normalizedScore,
      findings: findings.slice(0, this.maxFindings),
      proof,
      scanned_nodes: visited,
      truncated: visited > this.maxNodes || findings.length >= this.maxFindings,
    };
  }

  redact(configObj = {}) {
    const cloned = JSON.parse(JSON.stringify(configObj || {}));
    const stack = [{
      value: cloned,
      path: ['$'],
      depth: 0,
    }];
    let visited = 0;
    while (stack.length > 0) {
      const current = stack.pop();
      visited += 1;
      if (visited > this.maxNodes || current.depth > this.maxDepth) {
        break;
      }
      const node = current.value;
      if (!node || typeof node !== 'object') {
        continue;
      }
      if (Array.isArray(node)) {
        for (let i = 0; i < node.length; i += 1) {
          stack.push({
            value: node[i],
            path: [...current.path, `[${i}]`],
            depth: current.depth + 1,
          });
        }
        continue;
      }
      for (const [key, value] of Object.entries(node)) {
        if (SECRET_KEY_PATTERN.test(String(key || ''))) {
          node[key] = this.redactionText;
          continue;
        }
        if (typeof value === 'string' && isSecretValue(value)) {
          node[key] = this.redactionText;
          continue;
        }
        if (value && typeof value === 'object') {
          stack.push({
            value,
            path: [...current.path, key],
            depth: current.depth + 1,
          });
        }
      }
    }
    return cloned;
  }

  safeExport(configObj = {}, options = {}) {
    const evaluation = this.evaluate(configObj, options);
    return {
      ...evaluation,
      redacted_config: this.redact(configObj),
    };
  }
}

module.exports = {
  ZKConfigValidator,
};
