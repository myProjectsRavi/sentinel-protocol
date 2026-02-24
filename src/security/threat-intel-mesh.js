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

function sha256(value = '') {
  return crypto.createHash('sha256').update(String(value || ''), 'utf8').digest('hex');
}

function createFingerprints(text = '') {
  const normalized = normalizeText(text);
  if (!normalized) {
    return [];
  }
  const fingerprints = [];
  fingerprints.push(sha256(normalized));
  if (normalized.length > 256) {
    fingerprints.push(sha256(normalized.slice(0, 256)));
    fingerprints.push(sha256(normalized.slice(-256)));
  }
  return Array.from(new Set(fingerprints));
}

class ThreatIntelMesh {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.ttlMs = clampPositiveInt(config.ttl_ms, 7 * 24 * 60 * 60 * 1000, 60_000, 180 * 24 * 60 * 60 * 1000);
    this.maxSignatures = clampPositiveInt(config.max_signatures, 50_000, 32, 1_000_000);
    this.maxTextChars = clampPositiveInt(config.max_text_chars, 8192, 128, 262144);
    this.minHitsToBlock = clampPositiveInt(config.min_hits_to_block, 2, 1, 1000);
    this.blockOnMatch = config.block_on_match === true;
    this.allowAnonymousShare = config.allow_anonymous_share === true;
    this.observability = config.observability !== false;
    this.signatures = new Map();
    const bootstrap = Array.isArray(config.bootstrap_signatures) ? config.bootstrap_signatures : [];
    for (const signature of bootstrap.slice(0, 1000)) {
      const value = String(signature || '').trim().toLowerCase();
      if (value.length === 64 && /^[a-f0-9]{64}$/.test(value)) {
        this.signatures.set(value, {
          signature: value,
          source: 'bootstrap',
          reason: 'bootstrap',
          severity: 'medium',
          hits: 1,
          firstSeenAt: Date.now(),
          lastSeenAt: Date.now(),
        });
      }
    }
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

  ingestSignature({
    signature = '',
    text = '',
    source = 'local',
    reason = 'observed',
    severity = 'medium',
  } = {}) {
    if (!this.isEnabled()) {
      return null;
    }
    const now = Date.now();
    this.prune(now);
    let value = String(signature || '').trim().toLowerCase();
    if (!value && text) {
      value = createFingerprints(String(text || '').slice(0, this.maxTextChars))[0] || '';
    }
    if (value.length !== 64 || !/^[a-f0-9]{64}$/.test(value)) {
      return null;
    }
    const existing = this.signatures.get(value);
    if (existing) {
      existing.hits = Number(existing.hits || 0) + 1;
      existing.lastSeenAt = now;
      existing.source = source || existing.source;
      existing.reason = reason || existing.reason;
      return existing;
    }
    const created = {
      signature: value,
      source: String(source || 'local').slice(0, 64),
      reason: String(reason || 'observed').slice(0, 160),
      severity: String(severity || 'medium').toLowerCase().slice(0, 16),
      hits: 1,
      firstSeenAt: now,
      lastSeenAt: now,
    };
    this.signatures.set(value, created);
    return created;
  }

  ingestAuditEvent(event = {}) {
    if (!this.isEnabled()) {
      return [];
    }
    const payload = event && typeof event === 'object' ? event : {};
    const reasons = Array.isArray(payload.reasons) ? payload.reasons : [];
    const updates = [];
    for (const reason of reasons.slice(0, 16)) {
      const entry = this.ingestSignature({
        text: String(reason || ''),
        source: 'audit_reason',
        reason: String(reason || 'reason'),
        severity: payload.decision && String(payload.decision).startsWith('blocked') ? 'high' : 'medium',
      });
      if (entry) {
        updates.push(entry.signature);
      }
    }
    if (typeof payload.request_body === 'string' && payload.request_body.trim()) {
      for (const signature of createFingerprints(payload.request_body.slice(0, this.maxTextChars)).slice(0, 3)) {
        const entry = this.ingestSignature({
          signature,
          source: 'audit_body',
          reason: 'request_body',
          severity: 'high',
        });
        if (entry) {
          updates.push(entry.signature);
        }
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
    const fingerprints = createFingerprints(String(bodyText || '').slice(0, this.maxTextChars));
    const findings = [];
    for (const signature of fingerprints) {
      const hit = this.signatures.get(signature);
      if (!hit) {
        continue;
      }
      findings.push({
        code: 'threat_intel_signature_match',
        signature,
        source: hit.source,
        severity: hit.severity,
        reason: hit.reason,
        hits: Number(hit.hits || 0),
        blockEligible: this.blockOnMatch && Number(hit.hits || 0) >= this.minHitsToBlock,
      });
    }

    const detected = findings.length > 0;
    const shouldBlock =
      detected &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce' &&
      findings.some((item) => item.blockEligible === true);

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      reason: detected ? String(findings[0].code || 'threat_intel_match') : 'clean',
      findings,
      signatures_checked: fingerprints.length,
      signatures_total: this.signatures.size,
    };
  }

  exportSnapshot() {
    const top = Array.from(this.signatures.values())
      .sort((a, b) => Number(b.hits || 0) - Number(a.hits || 0))
      .slice(0, 32)
      .map((entry) => ({
        signature: entry.signature,
        source: entry.source,
        reason: entry.reason,
        severity: entry.severity,
        hits: Number(entry.hits || 0),
        first_seen_at: Number(entry.firstSeenAt || 0),
        last_seen_at: Number(entry.lastSeenAt || 0),
      }));

    return {
      enabled: this.isEnabled(),
      mode: this.mode,
      signatures_total: this.signatures.size,
      allow_anonymous_share: this.allowAnonymousShare,
      top_signatures: top,
    };
  }
}

module.exports = {
  ThreatIntelMesh,
};
