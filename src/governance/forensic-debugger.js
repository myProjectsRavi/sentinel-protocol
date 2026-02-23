const crypto = require('crypto');
const {
  clampPositiveInt,
} = require('../utils/primitives');

function sha256(input = '') {
  return crypto.createHash('sha256').update(String(input || ''), 'utf8').digest('hex');
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

function redactFields(input = {}, fields = []) {
  const data = stableObject(input);
  const out = JSON.parse(JSON.stringify(data));
  for (const field of fields) {
    const parts = String(field || '').split('.').filter(Boolean);
    if (parts.length === 0) {
      continue;
    }
    let cur = out;
    for (let i = 0; i < parts.length - 1; i += 1) {
      if (!cur || typeof cur !== 'object') {
        break;
      }
      cur = cur[parts[i]];
    }
    if (cur && typeof cur === 'object' && Object.prototype.hasOwnProperty.call(cur, parts[parts.length - 1])) {
      cur[parts[parts.length - 1]] = '[REDACTED]';
    }
  }
  return out;
}

class ForensicDebugger {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.maxSnapshots = clampPositiveInt(config.max_snapshots, 5000, 16, 500000);
    this.redactFields = Array.isArray(config.redact_fields)
      ? config.redact_fields.map((item) => String(item || '').trim()).filter(Boolean).slice(0, 128)
      : ['headers.authorization', 'headers.x-api-key', 'body.api_key', 'body.password'];
    this.snapshots = [];
  }

  isEnabled() {
    return this.enabled === true;
  }

  capture({
    request = {},
    decision = {},
    configVersion = 1,
    summaryOnly = false,
  } = {}) {
    if (!this.isEnabled()) {
      return null;
    }
    const safeRequest = summaryOnly
      ? {
          method: request.method,
          path: request.path,
          headers: request.headers ? Object.keys(request.headers) : [],
          body_hash: sha256(JSON.stringify(stableObject(request.body || {}))),
        }
      : redactFields(request, this.redactFields);
    const safeDecision = redactFields(decision, this.redactFields);
    const snapshot = {
      id: `snap_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
      captured_at: new Date().toISOString(),
      config_version: configVersion,
      request: safeRequest,
      decision: safeDecision,
      fingerprint: sha256(JSON.stringify(stableObject({ safeRequest, safeDecision }))),
    };
    this.snapshots.push(snapshot);
    if (this.snapshots.length > this.maxSnapshots) {
      this.snapshots = this.snapshots.slice(this.snapshots.length - this.maxSnapshots);
    }
    return snapshot;
  }

  replay(snapshot, evaluators = [], overrides = {}) {
    const snap = snapshot && typeof snapshot === 'object' ? snapshot : {};
    const results = [];
    for (const evaluator of Array.isArray(evaluators) ? evaluators : []) {
      if (!evaluator || typeof evaluator.run !== 'function') {
        continue;
      }
      const value = evaluator.run({
        request: snap.request || {},
        decision: snap.decision || {},
        overrides: overrides || {},
      });
      results.push({
        engine: String(evaluator.name || 'unknown'),
        result: value,
      });
    }
    return {
      snapshot_id: snap.id || null,
      replayed_at: new Date().toISOString(),
      overrides: stableObject(overrides || {}),
      results,
    };
  }

  diff(originalDecision = {}, replayDecision = {}) {
    const before = stableObject(originalDecision || {});
    const after = stableObject(replayDecision || {});
    const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
    const deltas = [];
    for (const key of Array.from(keys).sort()) {
      const left = JSON.stringify(before[key]);
      const right = JSON.stringify(after[key]);
      if (left === right) {
        continue;
      }
      deltas.push({
        key,
        before: before[key],
        after: after[key],
      });
    }
    return {
      changed: deltas.length > 0,
      deltas,
    };
  }
}

module.exports = {
  ForensicDebugger,
  redactFields,
};
