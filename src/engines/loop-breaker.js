const crypto = require('crypto');

function clampPositiveInteger(value, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  const normalized = Math.floor(parsed);
  if (normalized < min || normalized > max) {
    return fallback;
  }
  return normalized;
}

function normalizeAction(value, fallback = 'block') {
  const normalized = String(value || fallback).toLowerCase();
  return normalized === 'warn' ? 'warn' : 'block';
}

function toCanonicalObject(value) {
  if (value === null || value === undefined) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => toCanonicalObject(item));
  }
  if (typeof value !== 'object') {
    return value;
  }
  const out = {};
  for (const key of Object.keys(value).sort()) {
    out[key] = toCanonicalObject(value[key]);
  }
  return out;
}

function normalizeBody(bodyText, bodyJson) {
  if (bodyJson && typeof bodyJson === 'object') {
    try {
      return JSON.stringify(toCanonicalObject(bodyJson));
    } catch {
      // fall through to text normalization
    }
  }
  return String(bodyText || '')
    .replace(/\s+/g, ' ')
    .trim();
}

function extractAgentId(headers = {}, keyHeader = 'x-sentinel-agent-id') {
  if (headers[keyHeader]) {
    return String(headers[keyHeader]);
  }
  if (headers['x-forwarded-for']) {
    return String(headers['x-forwarded-for']).split(',')[0].trim();
  }
  if (headers['user-agent']) {
    return String(headers['user-agent']);
  }
  return 'anonymous';
}

function sha256(text) {
  return crypto.createHash('sha256').update(String(text)).digest('hex');
}

class LoopBreaker {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.action = normalizeAction(config.action, 'block');
    this.windowMs = clampPositiveInteger(config.window_ms, 30000, { min: 1000, max: 600000 });
    this.repeatThreshold = clampPositiveInteger(config.repeat_threshold, 4, { min: 2, max: 20 });
    this.maxRecent = clampPositiveInteger(config.max_recent, 5, { min: this.repeatThreshold, max: 100 });
    this.maxKeys = clampPositiveInteger(config.max_keys, 2048, { min: 64, max: 500000 });
    this.keyHeader = String(config.key_header || 'x-sentinel-agent-id').toLowerCase();
    this.state = new Map();
  }

  touch(key) {
    const entry = this.state.get(key);
    if (!entry) {
      return;
    }
    this.state.delete(key);
    this.state.set(key, entry);
  }

  ensureCapacity() {
    while (this.state.size > this.maxKeys) {
      const oldestKey = this.state.keys().next().value;
      if (!oldestKey) {
        break;
      }
      this.state.delete(oldestKey);
    }
  }

  pruneRecords(records, now) {
    const minTime = now - this.windowMs;
    const filtered = records.filter((item) => item.ts >= minTime);
    if (filtered.length <= this.maxRecent) {
      return filtered;
    }
    return filtered.slice(filtered.length - this.maxRecent);
  }

  detectRecentLoop(records, hash, now) {
    if (records.length < this.repeatThreshold) {
      return {
        detected: false,
        streak: 1,
      };
    }

    let streak = 0;
    for (let idx = records.length - 1; idx >= 0; idx -= 1) {
      if (records[idx].hash !== hash) {
        break;
      }
      streak += 1;
    }

    if (streak < this.repeatThreshold) {
      return {
        detected: false,
        streak,
      };
    }

    const thresholdIndex = records.length - this.repeatThreshold;
    const thresholdRecord = records[thresholdIndex];
    const withinWindow = thresholdRecord && now - thresholdRecord.ts <= this.windowMs;

    return {
      detected: Boolean(withinWindow),
      streak,
    };
  }

  evaluate(input = {}) {
    if (!this.enabled) {
      return {
        enabled: false,
        detected: false,
        shouldBlock: false,
      };
    }

    const now = Number(input.now || Date.now());
    const normalizedBody = normalizeBody(input.bodyText, input.bodyJson);
    if (!normalizedBody) {
      return {
        enabled: true,
        detected: false,
        shouldBlock: false,
        reason: 'empty_body',
      };
    }

    const agentId = extractAgentId(input.headers || {}, this.keyHeader);
    const provider = String(input.provider || 'unknown').toLowerCase();
    const path = String(input.path || '/');
    const method = String(input.method || 'POST').toUpperCase();
    const identityKey = `${provider}|${path}|${method}|${agentId}`;
    const hash = sha256(normalizedBody);

    const existing = this.state.get(identityKey) || [];
    existing.push({ hash, ts: now });
    const records = this.pruneRecords(existing, now);
    this.state.set(identityKey, records);
    this.touch(identityKey);
    this.ensureCapacity();

    const detection = this.detectRecentLoop(records, hash, now);
    return {
      enabled: true,
      detected: detection.detected,
      shouldBlock: detection.detected && this.action === 'block',
      action: this.action,
      streak: detection.streak,
      repeatThreshold: this.repeatThreshold,
      key: identityKey,
      hash_prefix: hash.slice(0, 12),
      within_ms: this.windowMs,
    };
  }
}

module.exports = {
  LoopBreaker,
  normalizeBody,
  extractAgentId,
};
