class InMemoryRateLimiter {
  constructor() {
    this.buckets = new Map();
  }

  consume({ key, limit }) {
    const now = Date.now();
    const windowMs = 60 * 1000;
    const bucketKey = String(key || 'default');

    let bucket = this.buckets.get(bucketKey);
    if (!bucket || now - bucket.windowStart >= windowMs) {
      bucket = {
        windowStart: now,
        used: 0,
      };
    }

    if (bucket.used >= limit) {
      this.buckets.set(bucketKey, bucket);
      return false;
    }

    bucket.used += 1;
    this.buckets.set(bucketKey, bucket);
    return true;
  }
}

module.exports = {
  InMemoryRateLimiter,
};
