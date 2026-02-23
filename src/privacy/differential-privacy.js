const { clampPositiveInt } = require('../utils/primitives');

function laplaceNoise(scale, rng = Math.random) {
  const safeScale = Number(scale);
  if (!Number.isFinite(safeScale) || safeScale <= 0) {
    return 0;
  }
  const random = Number(rng());
  const bounded = Math.min(1 - Number.EPSILON, Math.max(Number.EPSILON, random));
  const centered = bounded - 0.5;
  const sign = centered < 0 ? -1 : 1;
  return -safeScale * sign * Math.log(1 - 2 * Math.abs(centered));
}

function normalizeConfig(config = {}) {
  const source = config && typeof config === 'object' && !Array.isArray(config) ? config : {};
  const epsilonBudget = Number(source.epsilon_budget ?? 1.0);
  const epsilonPerCall = Number(source.epsilon_per_call ?? 0.1);
  const sensitivity = Number(source.sensitivity ?? 1.0);
  return {
    enabled: source.enabled === true,
    epsilonBudget: Number.isFinite(epsilonBudget) && epsilonBudget > 0 ? epsilonBudget : 1.0,
    epsilonPerCall: Number.isFinite(epsilonPerCall) && epsilonPerCall > 0 ? epsilonPerCall : 0.1,
    sensitivity: Number.isFinite(sensitivity) && sensitivity > 0 ? sensitivity : 1.0,
    maxSimulationCalls: clampPositiveInt(source.max_simulation_calls, 1000, 1, 1000000),
    maxVectorLength: clampPositiveInt(source.max_vector_length, 8192, 1, 200000),
  };
}

class DifferentialPrivacyEngine {
  constructor(config = {}, options = {}) {
    this.config = normalizeConfig(config);
    this.remainingEpsilon = this.config.epsilonBudget;
    this.calls = 0;
    this.rng = typeof options.rng === 'function' ? options.rng : Math.random;
  }

  isEnabled() {
    return this.config.enabled === true;
  }

  snapshot() {
    return {
      enabled: this.isEnabled(),
      epsilon_budget: this.config.epsilonBudget,
      epsilon_remaining: Number(this.remainingEpsilon.toFixed(6)),
      epsilon_per_call: this.config.epsilonPerCall,
      sensitivity: this.config.sensitivity,
      calls: this.calls,
      exhausted: this.remainingEpsilon <= 0 || this.calls >= this.config.maxSimulationCalls,
    };
  }

  consumeBudget(epsilon = this.config.epsilonPerCall) {
    if (!this.isEnabled()) {
      return {
        consumed: 0,
        exhausted: false,
        allowed: true,
        remaining: this.remainingEpsilon,
      };
    }

    const spend = Number.isFinite(Number(epsilon)) && Number(epsilon) > 0
      ? Number(epsilon)
      : this.config.epsilonPerCall;

    if (this.calls >= this.config.maxSimulationCalls || this.remainingEpsilon <= 0 || spend > this.remainingEpsilon) {
      return {
        consumed: 0,
        exhausted: true,
        allowed: false,
        remaining: this.remainingEpsilon,
      };
    }

    this.calls += 1;
    this.remainingEpsilon = Number(Math.max(0, this.remainingEpsilon - spend).toFixed(12));

    return {
      consumed: spend,
      exhausted: this.remainingEpsilon <= 0 || this.calls >= this.config.maxSimulationCalls,
      allowed: true,
      remaining: this.remainingEpsilon,
    };
  }

  noisify(value, options = {}) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) {
      return {
        original: value,
        noisy: value,
        applied: false,
        budget: this.snapshot(),
      };
    }

    if (!this.isEnabled()) {
      return {
        original: numeric,
        noisy: numeric,
        applied: false,
        budget: this.snapshot(),
      };
    }

    const epsilon = Number.isFinite(Number(options.epsilon)) && Number(options.epsilon) > 0
      ? Number(options.epsilon)
      : this.config.epsilonPerCall;
    const sensitivity = Number.isFinite(Number(options.sensitivity)) && Number(options.sensitivity) > 0
      ? Number(options.sensitivity)
      : this.config.sensitivity;

    const budget = this.consumeBudget(epsilon);
    if (!budget.allowed) {
      return {
        original: numeric,
        noisy: numeric,
        applied: false,
        exhausted: true,
        budget: this.snapshot(),
      };
    }

    const scale = sensitivity / epsilon;
    const noise = laplaceNoise(scale, options.rng || this.rng);
    const noisy = Number((numeric + noise).toFixed(8));
    return {
      original: numeric,
      noisy,
      applied: true,
      exhausted: budget.exhausted,
      budget: this.snapshot(),
    };
  }

  noisifyEmbeddings(vector = [], options = {}) {
    if (!Array.isArray(vector)) {
      return {
        original: [],
        noisy: [],
        applied: false,
        budget: this.snapshot(),
      };
    }

    const bounded = vector.slice(0, this.config.maxVectorLength).map((item) => Number(item));
    if (!this.isEnabled()) {
      return {
        original: bounded,
        noisy: bounded,
        applied: false,
        budget: this.snapshot(),
      };
    }

    const result = [];
    let exhausted = false;
    for (const item of bounded) {
      const noisy = this.noisify(item, options);
      result.push(Number(noisy.noisy));
      if (noisy.exhausted) {
        exhausted = true;
      }
      if (!noisy.applied && noisy.exhausted) {
        exhausted = true;
        break;
      }
    }

    return {
      original: bounded,
      noisy: result,
      applied: true,
      exhausted,
      budget: this.snapshot(),
    };
  }

  simulatePayload(payload = {}) {
    const snapshotBefore = this.snapshot();
    const numericResults = [];
    const embeddingResults = [];

    const numericValues = Array.isArray(payload?.numeric_values) ? payload.numeric_values : [];
    for (const value of numericValues) {
      const result = this.noisify(value);
      numericResults.push({
        original: Number(value),
        noisy: Number(result.noisy),
        applied: result.applied,
      });
    }

    const embeddings = Array.isArray(payload?.embeddings) ? payload.embeddings : [];
    for (const vector of embeddings) {
      const result = this.noisifyEmbeddings(vector);
      embeddingResults.push({
        original_length: Array.isArray(vector) ? vector.length : 0,
        noisy_length: result.noisy.length,
        applied: result.applied,
      });
    }

    const snapshotAfter = this.snapshot();
    return {
      advisory_only: true,
      generated_at: new Date().toISOString(),
      enabled: this.isEnabled(),
      input_summary: {
        numeric_values: numericValues.length,
        embedding_vectors: embeddings.length,
      },
      results: {
        numeric_values: numericResults,
        embeddings: embeddingResults,
      },
      budget_before: snapshotBefore,
      budget_after: snapshotAfter,
      exhausted: snapshotAfter.exhausted,
    };
  }
}

module.exports = {
  DifferentialPrivacyEngine,
  laplaceNoise,
  normalizeDifferentialPrivacyConfig: normalizeConfig,
};
