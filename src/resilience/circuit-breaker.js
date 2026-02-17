class CircuitState {
  constructor(name, config) {
    this.name = name;
    this.config = config;
    this.state = 'closed';
    this.openUntil = 0;
    this.history = [];
    this.consecutiveTimeouts = 0;
    this.halfOpenProbeInFlight = false;
    this.halfOpenSuccesses = 0;
    this.totalForwarded = 0;
    this.totalFailures = 0;
  }

  now() {
    return Date.now();
  }

  trimHistory() {
    const size = this.config.window_size;
    if (this.history.length > size) {
      this.history = this.history.slice(this.history.length - size);
    }
  }

  recordHistory(success) {
    this.history.push(success);
    this.trimHistory();
  }

  failureRate() {
    if (this.history.length === 0) {
      return 0;
    }

    const failures = this.history.filter((item) => !item).length;
    return failures / this.history.length;
  }

  openCircuit() {
    this.state = 'open';
    this.openUntil = this.now() + this.config.open_seconds * 1000;
    this.halfOpenProbeInFlight = false;
    this.halfOpenSuccesses = 0;
  }

  canRequest() {
    if (!this.config.enabled) {
      return { allowed: true, state: 'disabled', retryAfterSeconds: 0 };
    }

    if (this.state === 'open') {
      if (this.now() < this.openUntil) {
        return {
          allowed: false,
          state: 'open',
          retryAfterSeconds: Math.ceil((this.openUntil - this.now()) / 1000),
        };
      }
      this.state = 'half-open';
      this.halfOpenProbeInFlight = false;
      this.halfOpenSuccesses = 0;
    }

    if (this.state === 'half-open') {
      if (this.halfOpenProbeInFlight) {
        return { allowed: false, state: 'half-open', retryAfterSeconds: 1 };
      }
      this.halfOpenProbeInFlight = true;
      return { allowed: true, state: 'half-open', retryAfterSeconds: 0 };
    }

    return { allowed: true, state: this.state, retryAfterSeconds: 0 };
  }

  recordUpstreamSuccess() {
    this.totalForwarded += 1;
    this.recordHistory(true);
    this.consecutiveTimeouts = 0;

    if (this.state === 'half-open') {
      this.halfOpenProbeInFlight = false;
      this.halfOpenSuccesses += 1;
      if (this.halfOpenSuccesses >= this.config.half_open_success_threshold) {
        this.state = 'closed';
        this.halfOpenSuccesses = 0;
      }
      return;
    }

    this.halfOpenSuccesses = 0;
  }

  recordUpstreamFailure(type) {
    this.totalForwarded += 1;
    this.totalFailures += 1;
    this.recordHistory(false);

    if (type === 'timeout') {
      this.consecutiveTimeouts += 1;
    } else {
      this.consecutiveTimeouts = 0;
    }

    if (this.state === 'half-open') {
      this.halfOpenProbeInFlight = false;
      this.openCircuit();
      return;
    }

    const failures = this.history.filter((item) => !item).length;
    const rate = this.failureRate();

    if (this.consecutiveTimeouts >= this.config.consecutive_timeout_threshold) {
      this.openCircuit();
      return;
    }

    if (failures >= this.config.min_failures_to_evaluate && rate >= this.config.failure_rate_threshold) {
      this.openCircuit();
    }
  }

  stats() {
    const failures = this.history.filter((item) => !item).length;
    return {
      circuit_state: this.state,
      failure_rate_window: this.history.length > 0 ? Number((failures / this.history.length).toFixed(4)) : 0,
      consecutive_timeouts: this.consecutiveTimeouts,
      total_forwarded: this.totalForwarded,
      total_failures: this.totalFailures,
      open_until: this.openUntil,
      half_open_successes: this.halfOpenSuccesses,
    };
  }
}

class CircuitBreakerManager {
  constructor(config) {
    this.config = config;
    this.providers = new Map();
  }

  getProviderState(provider) {
    if (!this.providers.has(provider)) {
      this.providers.set(provider, new CircuitState(provider, this.config));
    }
    return this.providers.get(provider);
  }

  canRequest(provider) {
    const state = this.getProviderState(provider);
    return state.canRequest();
  }

  recordUpstreamSuccess(provider) {
    this.getProviderState(provider).recordUpstreamSuccess();
  }

  recordUpstreamFailure(provider, type) {
    this.getProviderState(provider).recordUpstreamFailure(type);
  }

  snapshot() {
    const data = {};
    for (const [provider, state] of this.providers.entries()) {
      data[provider] = state.stats();
    }
    return data;
  }
}

module.exports = {
  CircuitBreakerManager,
};
