function clampPositiveInt(value, fallback, min = 1, max = 600000) {
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

class LatencyNormalizer {
  constructor(config = {}, options = {}) {
    this.enabled = config.enabled === true;
    this.windowSize = clampPositiveInt(config.window_size, 10, 1, 200);
    this.minSamples = clampPositiveInt(config.min_samples, 3, 1, this.windowSize);
    this.maxDelayMs = clampPositiveInt(config.max_delay_ms, 2000, 1, 30000);
    this.jitterMs = clampPositiveInt(config.jitter_ms, 25, 0, 1000);
    this.statuses = new Set(
      Array.isArray(config.statuses)
        ? config.statuses.map((value) => Number(value)).filter((value) => Number.isInteger(value) && value >= 100 && value <= 599)
        : [402, 403, 429]
    );
    this.samples = [];
    this.random = typeof options.random === 'function' ? options.random : Math.random;
  }

  isEnabled() {
    return this.enabled === true;
  }

  recordSuccess(latencyMs) {
    if (!this.isEnabled()) {
      return;
    }
    const value = Number(latencyMs);
    if (!Number.isFinite(value) || value < 0) {
      return;
    }
    this.samples.push(Math.floor(value));
    if (this.samples.length > this.windowSize) {
      this.samples.splice(0, this.samples.length - this.windowSize);
    }
  }

  targetLatencyMs() {
    if (this.samples.length < this.minSamples) {
      return null;
    }
    const total = this.samples.reduce((sum, value) => sum + value, 0);
    return total / this.samples.length;
  }

  planDelay({ elapsedMs, statusCode } = {}) {
    if (!this.isEnabled()) {
      return {
        apply: false,
        delayMs: 0,
        reason: 'disabled',
      };
    }
    const status = Number(statusCode || 0);
    if (!this.statuses.has(status)) {
      return {
        apply: false,
        delayMs: 0,
        reason: 'status_not_eligible',
      };
    }
    const target = this.targetLatencyMs();
    if (!Number.isFinite(target)) {
      return {
        apply: false,
        delayMs: 0,
        reason: 'insufficient_samples',
      };
    }
    const elapsed = Number.isFinite(Number(elapsedMs)) ? Number(elapsedMs) : 0;
    const baseDelay = target - elapsed;
    if (baseDelay <= 0) {
      return {
        apply: false,
        delayMs: 0,
        targetMs: Math.round(target),
        reason: 'already_slow_enough',
      };
    }
    const jitter = this.jitterMs > 0
      ? Math.round((this.random() * 2 - 1) * this.jitterMs)
      : 0;
    const delayMs = Math.max(0, Math.min(this.maxDelayMs, Math.round(baseDelay + jitter)));
    if (delayMs <= 0) {
      return {
        apply: false,
        delayMs: 0,
        targetMs: Math.round(target),
        reason: 'jitter_cancelled',
      };
    }
    return {
      apply: true,
      delayMs,
      targetMs: Math.round(target),
      sampleCount: this.samples.length,
      reason: 'normalized',
    };
  }
}

module.exports = {
  LatencyNormalizer,
};
