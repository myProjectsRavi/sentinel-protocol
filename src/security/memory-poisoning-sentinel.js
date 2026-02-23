const crypto = require('crypto');
const {
  clampPositiveInt,
  normalizeMode,
  normalizeSessionValue,
} = require('../utils/primitives');

const POISON_PATTERNS = [
  /\b(ignore\s+previous\s+instructions?)\b/i,
  /\b(override\s+policy|bypass\s+guardrails?)\b/i,
  /\b(system\s+prompt|developer\s+message)\s*[:=]/i,
  /\b(always\s+trust\s+this\s+memory)\b/i,
];

function sha256(input = '') {
  return crypto.createHash('sha256').update(String(input || ''), 'utf8').digest('hex');
}

function stableJson(value) {
  if (value === null || value === undefined) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => stableJson(item));
  }
  if (typeof value !== 'object') {
    return value;
  }
  const out = {};
  for (const key of Object.keys(value).sort()) {
    out[key] = stableJson(value[key]);
  }
  return out;
}

function toAnchorSet(input) {
  if (!Array.isArray(input)) {
    return [];
  }
  return input
    .map((item) => String(item || '').trim().toLowerCase())
    .filter(Boolean)
    .slice(0, 256);
}

class MemoryPoisoningSentinel {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.maxContentChars = clampPositiveInt(config.max_content_chars, 32768, 128, 1_048_576);
    this.ttlMs = clampPositiveInt(config.ttl_ms, 6 * 3600 * 1000, 1000, 7 * 24 * 3600 * 1000);
    this.maxSessions = clampPositiveInt(config.max_sessions, 5000, 8, 200000);
    this.maxWritesPerSession = clampPositiveInt(config.max_writes_per_session, 128, 1, 10000);
    this.detectContradictionsEnabled = config.detect_contradictions !== false;
    this.blockOnPoisoning = config.block_on_poisoning === true;
    this.blockOnContradiction = config.block_on_contradiction === true;
    this.quarantineOnDetect = config.quarantine_on_detect !== false;
    this.observability = config.observability !== false;
    this.policyAnchors = toAnchorSet(config.policy_anchors);
    this.sessions = new Map();
  }

  isEnabled() {
    return this.enabled === true;
  }

  prune(nowMs) {
    const cutoff = nowMs - this.ttlMs;
    for (const [sessionId, entry] of this.sessions.entries()) {
      if (Number(entry?.updatedAt || 0) < cutoff) {
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

  extractMemoryText(input) {
    const payload = input && typeof input === 'object' ? input : {};
    if (typeof payload.memory_write === 'string') {
      return payload.memory_write;
    }
    if (typeof payload.memory === 'string') {
      return payload.memory;
    }
    if (Array.isArray(payload.messages)) {
      const joined = payload.messages
        .slice(-8)
        .map((item) => (item && typeof item === 'object' ? String(item.content || '') : String(item || '')))
        .join('\n');
      if (joined.trim()) {
        return joined;
      }
    }
    return '';
  }

  detectPoisonPatterns(text) {
    const findings = [];
    for (const pattern of POISON_PATTERNS) {
      const match = pattern.exec(text);
      if (!match) {
        continue;
      }
      findings.push({
        code: 'memory_poisoning_pattern',
        signal: String(match[1] || match[0] || '').toLowerCase(),
        blockEligible: this.blockOnPoisoning,
      });
    }
    return findings;
  }

  detectContradictions(text, anchors = []) {
    if (!this.detectContradictionsEnabled) {
      return [];
    }
    const lower = String(text || '').toLowerCase();
    const findings = [];
    for (const anchor of anchors) {
      if (!anchor) {
        continue;
      }
      if (!lower.includes(anchor)) {
        continue;
      }
      if (/\b(ignore|override|disable|forget|discard)\b/i.test(lower)) {
        findings.push({
          code: 'memory_anchor_contradiction',
          anchor,
          blockEligible: this.blockOnContradiction,
        });
      }
    }
    return findings;
  }

  evaluate({
    sessionId,
    bodyJson = {},
    effectiveMode = 'monitor',
    anchors = null,
  } = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        detected: false,
        shouldBlock: false,
        quarantine: false,
        reason: 'clean',
        findings: [],
      };
    }

    const nowMs = Date.now();
    this.prune(nowMs);
    const sid = normalizeSessionValue(sessionId || 'anonymous', 256) || 'anonymous';
    const memoryText = this.extractMemoryText(bodyJson).slice(0, this.maxContentChars);
    if (!memoryText.trim()) {
      return {
        enabled: true,
        detected: false,
        shouldBlock: false,
        quarantine: false,
        reason: 'clean',
        findings: [],
      };
    }

    const entry = this.sessions.get(sid) || {
      updatedAt: nowMs,
      writes: [],
      hashChain: '',
    };

    const findings = [];
    findings.push(...this.detectPoisonPatterns(memoryText));
    findings.push(...this.detectContradictions(memoryText, anchors ? toAnchorSet(anchors) : this.policyAnchors));

    const memoryHash = sha256(memoryText);
    const stable = stableJson({ hash: memoryHash, text_len: memoryText.length });
    const chainInput = JSON.stringify(stable);
    entry.hashChain = sha256(`${entry.hashChain}:${chainInput}`);
    entry.updatedAt = nowMs;
    entry.writes.push({
      ts: nowMs,
      hash: memoryHash,
    });
    if (entry.writes.length > this.maxWritesPerSession) {
      entry.writes = entry.writes.slice(entry.writes.length - this.maxWritesPerSession);
    }
    this.sessions.set(sid, entry);

    const detected = findings.length > 0;
    const blockEligible = findings.some((item) => item.blockEligible === true);
    const shouldBlock =
      detected &&
      blockEligible &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce';
    const reason = detected ? String(findings[0].code || 'memory_poisoning_detected') : 'clean';

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      quarantine: detected && this.quarantineOnDetect,
      reason,
      findings,
      memory_hash_prefix: memoryHash.slice(0, 16),
      chain_hash_prefix: entry.hashChain.slice(0, 16),
      writes_tracked: entry.writes.length,
    };
  }
}

module.exports = {
  MemoryPoisoningSentinel,
};
