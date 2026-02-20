const crypto = require('crypto');
const { clampPositiveInt } = require('../utils/primitives');

function clampFiniteNumber(value, fallback, min = 0, max = Number.MAX_SAFE_INTEGER) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  if (parsed < min || parsed > max) {
    return fallback;
  }
  return parsed;
}

function normalizeSegment(value, fallback = 'default') {
  const normalized = String(value || '').trim();
  if (!normalized) {
    return fallback;
  }
  return normalized.toLowerCase();
}

function normalizeIdentity(value, fallback = 'default') {
  const normalized = String(value || '').trim();
  return normalized || fallback;
}

class InMemoryRateLimiter {
  constructor(options = {}) {
    this.buckets = new Map();
    this.defaultWindowMs = clampPositiveInt(options.default_window_ms, 60 * 1000, 1000, 24 * 60 * 60 * 1000);
    this.defaultLimit = clampPositiveInt(
      options.default_limit ?? options.default_requests_per_window,
      60,
      1,
      1_000_000_000
    );
    this.defaultBurst = clampPositiveInt(options.default_burst, this.defaultLimit, this.defaultLimit, 1_000_000_000);
    this.maxBuckets = clampPositiveInt(options.max_buckets, 100000, 100, 2000000);
    this.staleBucketTtlMs = clampPositiveInt(
      options.stale_bucket_ttl_ms,
      Math.max(this.defaultWindowMs * 4, 5 * 60 * 1000),
      1000,
      30 * 24 * 60 * 60 * 1000
    );
    this.maxKeyLength = clampPositiveInt(options.max_key_length, 256, 16, 4096);
    this.clock = typeof options.clock === 'function' ? options.clock : Date.now;
    this.pruneInterval = clampPositiveInt(options.prune_interval, 256, 1, 100000);
    this.opCount = 0;
  }

  normalizeConfig({ limit, windowMs, burst, cost }) {
    const effectiveWindowMs = clampPositiveInt(windowMs, this.defaultWindowMs, 1000, 24 * 60 * 60 * 1000);
    const baseLimit = clampPositiveInt(limit, this.defaultLimit, 1, 1_000_000_000);
    const burstLimit = clampPositiveInt(
      burst,
      Math.max(baseLimit, this.defaultBurst),
      baseLimit,
      1_000_000_000
    );
    const capacity = Math.max(baseLimit, burstLimit);
    const refillPerMs = capacity / effectiveWindowMs;
    const tokenCost = clampFiniteNumber(cost, 1, 0.000001, capacity);
    return {
      effectiveWindowMs,
      baseLimit,
      burstLimit,
      capacity,
      refillPerMs,
      tokenCost,
    };
  }

  normalizeBucketKey({ provider, scope, key }) {
    const providerSegment = normalizeSegment(provider, 'default');
    const scopeSegment = normalizeSegment(scope, 'default');
    const identity = normalizeIdentity(key, 'default');
    const identitySegment =
      identity.length > this.maxKeyLength
        ? `sha256:${crypto.createHash('sha256').update(identity).digest('hex')}`
        : identity;
    return `${providerSegment}::${scopeSegment}::${identitySegment}`;
  }

  consume({ key, limit, provider, windowMs, burst, cost, scope, keySource } = {}) {
    const now = this.clock();
    const {
      effectiveWindowMs,
      baseLimit,
      burstLimit,
      capacity,
      refillPerMs,
      tokenCost,
    } = this.normalizeConfig({ limit, windowMs, burst, cost });
    const bucketKey = this.normalizeBucketKey({ provider, scope, key });

    let bucket = this.buckets.get(bucketKey);
    if (!bucket) {
      bucket = {
        tokens: capacity,
        updatedAt: now,
        lastSeenAt: now,
      };
    }

    const elapsedMs = Math.max(0, now - Number(bucket.updatedAt || now));
    if (elapsedMs > 0) {
      bucket.tokens = Math.min(capacity, Number(bucket.tokens || 0) + elapsedMs * refillPerMs);
      bucket.updatedAt = now;
    }

    bucket.tokens = Number.isFinite(bucket.tokens) ? bucket.tokens : capacity;
    bucket.lastSeenAt = now;

    const hasTokens = bucket.tokens + 1e-12 >= tokenCost;
    if (hasTokens) {
      bucket.tokens = Math.max(0, bucket.tokens - tokenCost);
    }

    this.buckets.set(bucketKey, bucket);
    this.maybePrune(now);

    const remainingTokens = Math.max(0, Number(bucket.tokens || 0));
    const remaining = Math.floor(remainingTokens);
    const deficit = Math.max(0, tokenCost - remainingTokens);
    const retryAfterMs = hasTokens ? 0 : Math.max(0, Math.ceil(deficit / Math.max(refillPerMs, Number.EPSILON)));

    return {
      allowed: hasTokens,
      key: bucketKey,
      limit: baseLimit,
      burst: burstLimit,
      windowMs: effectiveWindowMs,
      scope: normalizeSegment(scope, 'default'),
      keySource: String(keySource || 'default'),
      remaining,
      remainingTokens: Number(remainingTokens.toFixed(6)),
      retryAfterMs,
    };
  }

  maybePrune(now) {
    this.opCount += 1;
    if (this.opCount % this.pruneInterval !== 0) {
      return;
    }
    this.pruneStale(now);
    if (this.buckets.size > this.maxBuckets) {
      this.pruneOverflow();
    }
    this.opCount = 0;
  }

  pruneStale(now) {
    const expiryCutoff = Number(now) - this.staleBucketTtlMs;
    for (const [bucketKey, bucket] of this.buckets.entries()) {
      const lastSeenAt = Number(bucket?.lastSeenAt || 0);
      if (lastSeenAt <= expiryCutoff) {
        this.buckets.delete(bucketKey);
      }
    }
  }

  pruneOverflow() {
    const entries = Array.from(this.buckets.entries());
    entries.sort((a, b) => (a[1].lastSeenAt || 0) - (b[1].lastSeenAt || 0));
    const removeCount = Math.max(0, this.buckets.size - this.maxBuckets);
    for (let i = 0; i < removeCount; i += 1) {
      this.buckets.delete(entries[i][0]);
    }
    // Safety fallback in case of inconsistent accounting.
    if (this.buckets.size > this.maxBuckets) {
      for (const key of this.buckets.keys()) {
        if (this.buckets.size <= this.maxBuckets) {
          break;
        }
        this.buckets.delete(key);
      }
    }
  }

  snapshot() {
    return {
      bucket_count: this.buckets.size,
      max_buckets: this.maxBuckets,
      stale_bucket_ttl_ms: this.staleBucketTtlMs,
      max_key_length: this.maxKeyLength,
      default_window_ms: this.defaultWindowMs,
      default_limit: this.defaultLimit,
      default_burst: this.defaultBurst,
    };
  }

  reset({ key, provider, scope } = {}) {
    const bucketKey = this.normalizeBucketKey({ provider, scope, key });
    this.buckets.delete(bucketKey);
  }
}

module.exports = {
  InMemoryRateLimiter,
};
