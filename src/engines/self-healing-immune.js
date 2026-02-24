const crypto = require('crypto');
const {
  clampPositiveInt,
  normalizeMode,
} = require('../utils/primitives');

function normalizeText(value = '') {
  return String(value || '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

function signatureFromText(value = '') {
  const normalized = normalizeText(value);
  if (!normalized) {
    return '';
  }
  return crypto.createHash('sha256').update(normalized, 'utf8').digest('hex');
}

class SelfHealingImmuneSystem {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.ttlMs = clampPositiveInt(config.ttl_ms, 30 * 24 * 60 * 60 * 1000, 60_000, 365 * 24 * 60 * 60 * 1000);
    this.maxSignatures = clampPositiveInt(config.max_signatures, 50_000, 64, 1_000_000);
    this.maxTextChars = clampPositiveInt(config.max_text_chars, 8192, 128, 262144);
    this.minLearnHits = clampPositiveInt(config.min_learn_hits, 3, 1, 1000);
    this.blockOnLearnedSignature = config.block_on_learned_signature === true;
    this.autoTuneEnabled = config.auto_tune_enabled === true;
    this.maxRecommendations = clampPositiveInt(config.max_recommendations, 32, 1, 1000);
    this.observability = config.observability !== false;
    this.signatures = new Map();
    this.recommendations = [];
  }

  isEnabled() {
    return this.enabled === true;
  }

  prune(now = Date.now()) {
    const staleBefore = Number(now) - this.ttlMs;
    for (const [signature, entry] of this.signatures.entries()) {
      if (Number(entry.lastSeenAt || 0) < staleBefore) {
        this.signatures.delete(signature);
      }
    }
    while (this.signatures.size > this.maxSignatures) {
      const oldest = this.signatures.keys().next().value;
      if (!oldest) {
        break;
      }
      this.signatures.delete(oldest);
    }
  }

  observeDetection({
    engine = 'unknown',
    reason = 'detected',
    text = '',
    blocked = false,
    severity = 'medium',
  } = {}) {
    if (!this.isEnabled()) {
      return null;
    }
    const now = Date.now();
    this.prune(now);
    const rawText = String(text || reason || '').slice(0, this.maxTextChars);
    const signature = signatureFromText(rawText);
    if (!signature) {
      return null;
    }
    const existing = this.signatures.get(signature);
    if (existing) {
      existing.hits = Number(existing.hits || 0) + 1;
      existing.blockedHits = Number(existing.blockedHits || 0) + (blocked ? 1 : 0);
      existing.lastSeenAt = now;
      existing.engine = String(engine || existing.engine || 'unknown');
      existing.reason = String(reason || existing.reason || 'detected').slice(0, 160);
      return existing;
    }
    const created = {
      signature,
      engine: String(engine || 'unknown').slice(0, 80),
      reason: String(reason || 'detected').slice(0, 160),
      severity: String(severity || 'medium').toLowerCase().slice(0, 16),
      hits: 1,
      blockedHits: blocked ? 1 : 0,
      firstSeenAt: now,
      lastSeenAt: now,
    };
    this.signatures.set(signature, created);
    return created;
  }

  observeAuditEvent(event = {}) {
    if (!this.isEnabled()) {
      return [];
    }
    const payload = event && typeof event === 'object' ? event : {};
    const reasons = Array.isArray(payload.reasons) ? payload.reasons : [];
    const blocked = String(payload.decision || '').startsWith('blocked');
    const engine = String(payload?.atlas?.engine || payload.engine || 'unknown');
    const updates = [];
    for (const reason of reasons.slice(0, 16)) {
      const entry = this.observeDetection({
        engine,
        reason,
        text: reason,
        blocked,
        severity: blocked ? 'high' : 'medium',
      });
      if (entry) {
        updates.push(entry.signature);
      }
    }
    if (typeof payload.request_body === 'string' && payload.request_body.trim()) {
      const entry = this.observeDetection({
        engine,
        reason: reasons[0] || 'request_body',
        text: payload.request_body,
        blocked,
        severity: blocked ? 'high' : 'medium',
      });
      if (entry) {
        updates.push(entry.signature);
      }
    }
    return updates;
  }

  evaluate({
    bodyText = '',
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
    this.prune(Date.now());
    const signature = signatureFromText(String(bodyText || '').slice(0, this.maxTextChars));
    if (!signature) {
      return {
        enabled: true,
        mode: this.mode,
        detected: false,
        shouldBlock: false,
        reason: 'clean',
        findings: [],
      };
    }
    const learned = this.signatures.get(signature);
    if (!learned) {
      return {
        enabled: true,
        mode: this.mode,
        detected: false,
        shouldBlock: false,
        reason: 'clean',
        findings: [],
        signature,
      };
    }

    const blockEligible = this.blockOnLearnedSignature && Number(learned.hits || 0) >= this.minLearnHits;
    const shouldBlock =
      blockEligible &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce';

    return {
      enabled: true,
      mode: this.mode,
      detected: true,
      shouldBlock,
      reason: 'self_healing_signature_match',
      findings: [{
        code: 'self_healing_signature_match',
        signature,
        engine: learned.engine,
        severity: learned.severity,
        reason: learned.reason,
        hits: Number(learned.hits || 0),
        blocked_hits: Number(learned.blockedHits || 0),
        blockEligible,
      }],
      signature,
    };
  }

  suggestAdjustment({
    metric = 'injection_threshold',
    currentValue = 0.5,
    falsePositiveRate = 0,
    falseNegativeRate = 0,
  } = {}) {
    if (!this.isEnabled() || !this.autoTuneEnabled) {
      return null;
    }
    const fp = Number.isFinite(Number(falsePositiveRate)) ? Number(falsePositiveRate) : 0;
    const fn = Number.isFinite(Number(falseNegativeRate)) ? Number(falseNegativeRate) : 0;
    const cur = Number.isFinite(Number(currentValue)) ? Number(currentValue) : 0.5;
    let next = cur;
    let reason = 'stable';
    if (fn > fp + 0.05) {
      next = Math.max(0.05, cur - 0.05);
      reason = 'increase_sensitivity';
    } else if (fp > fn + 0.05) {
      next = Math.min(0.99, cur + 0.05);
      reason = 'decrease_sensitivity';
    }
    const recommendation = {
      metric: String(metric || 'injection_threshold').slice(0, 80),
      current_value: Number(cur.toFixed(6)),
      proposed_value: Number(next.toFixed(6)),
      reason,
      false_positive_rate: Number(fp.toFixed(6)),
      false_negative_rate: Number(fn.toFixed(6)),
      created_at: new Date().toISOString(),
    };
    this.recommendations.push(recommendation);
    while (this.recommendations.length > this.maxRecommendations) {
      this.recommendations.shift();
    }
    return recommendation;
  }

  getStats() {
    return {
      enabled: this.isEnabled(),
      mode: this.mode,
      signatures_total: this.signatures.size,
      recommendations: this.recommendations.slice(),
      top_signatures: Array.from(this.signatures.values())
        .sort((a, b) => Number(b.hits || 0) - Number(a.hits || 0))
        .slice(0, 16)
        .map((entry) => ({
          signature: entry.signature,
          engine: entry.engine,
          reason: entry.reason,
          hits: Number(entry.hits || 0),
          blocked_hits: Number(entry.blockedHits || 0),
        })),
    };
  }
}

module.exports = {
  SelfHealingImmuneSystem,
};
