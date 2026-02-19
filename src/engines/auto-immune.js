const crypto = require('crypto');

function clampPositiveInt(value, fallback, min = 1, max = 86400000) {
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

function clampProbability(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  if (parsed < 0 || parsed > 1) {
    return fallback;
  }
  return parsed;
}

function normalizeMode(value, fallback = 'monitor') {
  const normalized = String(value || fallback).toLowerCase();
  return normalized === 'block' ? 'block' : 'monitor';
}

function normalizeForFingerprint(text = '') {
  let out = String(text || '');
  if (!out) {
    return '';
  }
  out = out.normalize('NFKC');
  out = out
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .replace(
      /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi,
      ' [uuid] '
    )
    .replace(/\b\d{4}-\d{2}-\d{2}t\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:z|[+-]\d{2}:\d{2})\b/gi, ' [timestamp] ')
    .replace(/\btrace[_-]?id\s*[:=]\s*[a-z0-9-]{8,}\b/gi, ' trace_id:[id] ')
    .replace(/\bspan[_-]?id\s*[:=]\s*[a-z0-9-]{8,}\b/gi, ' span_id:[id] ')
    .replace(/\breq(?:uest)?[_-]?id\s*[:=]\s*[a-z0-9-]{8,}\b/gi, ' request_id:[id] ')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
  return out;
}

function hashFingerprint(text) {
  return crypto.createHash('sha256').update(String(text || ''), 'utf8').digest('hex');
}

class AutoImmune {
  constructor(config = {}, deps = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor');
    this.ttlMs = clampPositiveInt(config.ttl_ms, 24 * 3600000, 1000, 30 * 24 * 3600000);
    this.maxEntries = clampPositiveInt(config.max_entries, 20000, 1, 1000000);
    this.maxScanBytes = clampPositiveInt(config.max_scan_bytes, 32768, 256, 10 * 1024 * 1024);
    this.minConfidenceToMatch = clampProbability(config.min_confidence_to_match, 0.85);
    this.learnMinScore = clampProbability(config.learn_min_score, 0.85);
    this.learnIncrement = clampProbability(config.learn_increment, 0.2);
    this.maxConfidence = clampProbability(config.max_confidence, 0.99);
    this.decayHalfLifeMs = clampPositiveInt(config.decay_half_life_ms, 6 * 3600000, 60000, 30 * 24 * 3600000);
    this.observability = config.observability !== false;

    this.now = typeof deps.now === 'function' ? deps.now : Date.now;
    this.entries = new Map();
    this.nextCleanupAt = 0;
    this.metrics = {
      learns: 0,
      hits: 0,
      blocks: 0,
      evictedLru: 0,
      evictedTtl: 0,
      maxEntriesSeen: 0,
      lastLearnAt: null,
      lastMatchAt: null,
    };
  }

  isEnabled() {
    return this.enabled === true;
  }

  touchEntry(fingerprint, entry) {
    if (!this.entries.has(fingerprint)) {
      return;
    }
    this.entries.delete(fingerprint);
    this.entries.set(fingerprint, entry);
  }

  cleanup(nowMs = Number(this.now())) {
    if (nowMs < this.nextCleanupAt && this.entries.size <= this.maxEntries) {
      return;
    }
    for (const [fingerprint, entry] of this.entries.entries()) {
      if (!entry || Number(entry.expiresAt || 0) <= nowMs) {
        this.entries.delete(fingerprint);
        this.metrics.evictedTtl += 1;
      }
    }
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (!oldest) {
        break;
      }
      this.entries.delete(oldest);
      this.metrics.evictedLru += 1;
    }
    this.nextCleanupAt = nowMs + Math.min(this.ttlMs, 5000);
  }

  normalizeInput(text) {
    const input = String(text || '');
    if (!input) {
      return {
        normalized: '',
        truncated: false,
      };
    }
    let truncated = false;
    let trimmed = input;
    if (Buffer.byteLength(trimmed, 'utf8') > this.maxScanBytes) {
      trimmed = Buffer.from(trimmed, 'utf8').subarray(0, this.maxScanBytes).toString('utf8');
      truncated = true;
    }
    return {
      normalized: normalizeForFingerprint(trimmed),
      truncated,
    };
  }

  decayConfidence(entry, nowMs) {
    if (!entry) {
      return 0;
    }
    const elapsed = Math.max(0, Number(nowMs) - Number(entry.lastSeenAt || nowMs));
    if (elapsed <= 0) {
      return clampProbability(entry.confidence, 0);
    }
    const decayFactor = Math.pow(0.5, elapsed / this.decayHalfLifeMs);
    return Math.max(0, Math.min(1, Number(entry.confidence || 0) * decayFactor));
  }

  scoreToConfidenceGain(score) {
    const safeScore = clampProbability(score, 0);
    if (safeScore < this.learnMinScore) {
      return 0;
    }
    if (this.learnMinScore >= 0.999) {
      return this.learnIncrement;
    }
    const normalized = (safeScore - this.learnMinScore) / (1 - this.learnMinScore);
    const bounded = Math.max(0, Math.min(1, normalized));
    return this.learnIncrement * (0.5 + bounded * 0.5);
  }

  getOrCreateEntry(fingerprint, nowMs) {
    let entry = this.entries.get(fingerprint);
    if (!entry) {
      entry = {
        confidence: 0,
        createdAt: nowMs,
        lastSeenAt: nowMs,
        expiresAt: nowMs + this.ttlMs,
        learns: 0,
        hits: 0,
        sourceCounts: {},
      };
      this.entries.set(fingerprint, entry);
    }
    return entry;
  }

  learn({ text, score, source = 'injection' } = {}) {
    if (!this.isEnabled()) {
      return { learned: false, reason: 'disabled' };
    }
    const nowMs = Number(this.now());
    const gain = this.scoreToConfidenceGain(score);
    if (gain <= 0) {
      return { learned: false, reason: 'below_learning_threshold' };
    }
    const prepared = this.normalizeInput(text);
    if (!prepared.normalized) {
      return { learned: false, reason: 'empty_input' };
    }

    this.cleanup(nowMs);
    const fingerprint = hashFingerprint(prepared.normalized);
    const existing = this.entries.get(fingerprint);
    if (!existing && this.entries.size >= this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (oldest) {
        this.entries.delete(oldest);
        this.metrics.evictedLru += 1;
      }
    }

    const entry = this.getOrCreateEntry(fingerprint, nowMs);
    const decayed = this.decayConfidence(entry, nowMs);
    entry.confidence = Math.min(this.maxConfidence, decayed + gain);
    entry.lastSeenAt = nowMs;
    entry.expiresAt = nowMs + this.ttlMs;
    entry.learns = Number(entry.learns || 0) + 1;
    const sourceKey = String(source || 'unknown').slice(0, 64);
    entry.sourceCounts[sourceKey] = Number(entry.sourceCounts[sourceKey] || 0) + 1;
    this.touchEntry(fingerprint, entry);

    this.metrics.learns += 1;
    this.metrics.lastLearnAt = nowMs;
    if (this.entries.size > this.metrics.maxEntriesSeen) {
      this.metrics.maxEntriesSeen = this.entries.size;
    }
    return {
      learned: true,
      fingerprint: fingerprint.slice(0, 16),
      confidence: Number(entry.confidence.toFixed(6)),
      truncated: prepared.truncated,
    };
  }

  check({ text, effectiveMode = 'monitor' } = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        matched: false,
        shouldBlock: false,
        reason: 'disabled',
      };
    }
    const nowMs = Number(this.now());
    this.cleanup(nowMs);

    const prepared = this.normalizeInput(text);
    if (!prepared.normalized) {
      return {
        enabled: true,
        matched: false,
        shouldBlock: false,
        reason: 'empty_input',
      };
    }
    const fingerprint = hashFingerprint(prepared.normalized);
    const entry = this.entries.get(fingerprint);
    if (!entry) {
      return {
        enabled: true,
        matched: false,
        shouldBlock: false,
        reason: 'miss',
      };
    }

    const decayed = this.decayConfidence(entry, nowMs);
    entry.confidence = decayed;
    entry.lastSeenAt = nowMs;
    entry.expiresAt = nowMs + this.ttlMs;
    entry.hits = Number(entry.hits || 0) + 1;
    this.touchEntry(fingerprint, entry);

    const matched = decayed >= this.minConfidenceToMatch;
    const shouldBlock = matched && this.mode === 'block' && String(effectiveMode || '') === 'enforce';
    if (matched) {
      this.metrics.hits += 1;
      this.metrics.lastMatchAt = nowMs;
      if (shouldBlock) {
        this.metrics.blocks += 1;
      }
    }
    return {
      enabled: true,
      matched,
      shouldBlock,
      mode: this.mode,
      reason: matched ? 'auto_immune_hit' : 'below_confidence',
      confidence: Number(decayed.toFixed(6)),
      threshold: this.minConfidenceToMatch,
      fingerprint: fingerprint.slice(0, 16),
      truncated: prepared.truncated,
    };
  }

  getStats() {
    return {
      entries: this.entries.size,
      max_entries: this.maxEntries,
      ttl_ms: this.ttlMs,
      min_confidence_to_match: this.minConfidenceToMatch,
      learns: this.metrics.learns,
      hits: this.metrics.hits,
      blocks: this.metrics.blocks,
      evicted_ttl: this.metrics.evictedTtl,
      evicted_lru: this.metrics.evictedLru,
      max_entries_seen: this.metrics.maxEntriesSeen,
      last_learn_at: this.metrics.lastLearnAt,
      last_match_at: this.metrics.lastMatchAt,
    };
  }
}

module.exports = {
  AutoImmune,
  normalizeForFingerprint,
  hashFingerprint,
};
