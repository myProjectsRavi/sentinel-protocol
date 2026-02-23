const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { clampPositiveInt } = require('../utils/primitives');

const STATE_SCHEMA_VERSION = 'sentinel.dp.state.v1';

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
  const stateFileRaw = String(source.state_file || '').trim();
  const stateFile = stateFileRaw ? path.resolve(stateFileRaw) : '';
  return {
    enabled: source.enabled === true,
    epsilonBudget: Number.isFinite(epsilonBudget) && epsilonBudget > 0 ? epsilonBudget : 1.0,
    epsilonPerCall: Number.isFinite(epsilonPerCall) && epsilonPerCall > 0 ? epsilonPerCall : 0.1,
    sensitivity: Number.isFinite(sensitivity) && sensitivity > 0 ? sensitivity : 1.0,
    maxSimulationCalls: clampPositiveInt(source.max_simulation_calls, 1000, 1, 1000000),
    maxVectorLength: clampPositiveInt(source.max_vector_length, 8192, 1, 200000),
    persistState: source.persist_state === true,
    stateFile,
    stateHmacKey: String(source.state_hmac_key || ''),
    resetOnTamper: source.reset_on_tamper !== false,
  };
}

function stableStateString(value = {}) {
  const source = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  return JSON.stringify({
    schema_version: String(source.schema_version || STATE_SCHEMA_VERSION),
    epsilon_budget: Number(source.epsilon_budget || 0),
    epsilon_per_call: Number(source.epsilon_per_call || 0),
    sensitivity: Number(source.sensitivity || 0),
    max_simulation_calls: Number(source.max_simulation_calls || 0),
    max_vector_length: Number(source.max_vector_length || 0),
    remaining_epsilon: Number(source.remaining_epsilon || 0),
    calls: Number(source.calls || 0),
  });
}

class DifferentialPrivacyEngine {
  constructor(config = {}, options = {}) {
    this.config = normalizeConfig(config);
    this.remainingEpsilon = this.config.epsilonBudget;
    this.calls = 0;
    this.rng = typeof options.rng === 'function' ? options.rng : Math.random;
    this.now = typeof options.now === 'function' ? options.now : () => Date.now();
    this.persistenceError = null;
    this.tamperDetected = false;
    this.stateLoaded = false;
    if (this.config.persistState && this.config.stateFile) {
      this.loadPersistedState();
    }
  }

  isEnabled() {
    return this.config.enabled === true;
  }

  signStatePayload(statePayload = {}) {
    const canonical = stableStateString(statePayload);
    if (this.config.stateHmacKey) {
      return crypto.createHmac('sha256', this.config.stateHmacKey).update(canonical, 'utf8').digest('hex');
    }
    return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
  }

  stateAlgorithm() {
    return this.config.stateHmacKey ? 'hmac-sha256' : 'sha256';
  }

  buildStatePayload() {
    return {
      schema_version: STATE_SCHEMA_VERSION,
      epsilon_budget: Number(this.config.epsilonBudget),
      epsilon_per_call: Number(this.config.epsilonPerCall),
      sensitivity: Number(this.config.sensitivity),
      max_simulation_calls: Number(this.config.maxSimulationCalls),
      max_vector_length: Number(this.config.maxVectorLength),
      remaining_epsilon: Number(this.remainingEpsilon),
      calls: Number(this.calls),
    };
  }

  buildStateEnvelope() {
    const state = this.buildStatePayload();
    return {
      schema_version: STATE_SCHEMA_VERSION,
      algorithm: this.stateAlgorithm(),
      updated_at: new Date(this.now()).toISOString(),
      state,
      digest: this.signStatePayload(state),
    };
  }

  loadPersistedState() {
    try {
      if (!fs.existsSync(this.config.stateFile)) {
        return;
      }
      const parsed = JSON.parse(fs.readFileSync(this.config.stateFile, 'utf8'));
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('state_payload_invalid');
      }
      const state = parsed.state;
      if (!state || typeof state !== 'object' || Array.isArray(state)) {
        throw new Error('state_object_missing');
      }

      const expectedDigest = this.signStatePayload(state);
      const providedDigest = String(parsed.digest || '');
      if (!providedDigest || providedDigest !== expectedDigest) {
        this.tamperDetected = true;
        if (this.config.resetOnTamper) {
          return;
        }
        throw new Error('state_digest_mismatch');
      }

      const nextCalls = Number(state.calls);
      const nextRemaining = Number(state.remaining_epsilon);
      if (!Number.isInteger(nextCalls) || nextCalls < 0) {
        throw new Error('state_calls_invalid');
      }
      if (!Number.isFinite(nextRemaining) || nextRemaining < 0) {
        throw new Error('state_remaining_invalid');
      }

      this.calls = Math.min(this.config.maxSimulationCalls, nextCalls);
      this.remainingEpsilon = Math.max(0, Math.min(this.config.epsilonBudget, nextRemaining));
      this.stateLoaded = true;
    } catch (error) {
      this.persistenceError = String(error.message || error);
      if (this.config.resetOnTamper) {
        this.calls = 0;
        this.remainingEpsilon = this.config.epsilonBudget;
      } else {
        throw error;
      }
    }
  }

  persistState() {
    if (!this.config.persistState || !this.config.stateFile) {
      return;
    }
    try {
      const dir = path.dirname(this.config.stateFile);
      fs.mkdirSync(dir, { recursive: true });
      const envelope = this.buildStateEnvelope();
      const tmpPath = `${this.config.stateFile}.tmp-${process.pid}`;
      fs.writeFileSync(tmpPath, `${JSON.stringify(envelope, null, 2)}\n`, 'utf8');
      fs.renameSync(tmpPath, this.config.stateFile);
      this.persistenceError = null;
    } catch (error) {
      this.persistenceError = String(error.message || error);
    }
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
      state_persistence: {
        enabled: this.config.persistState,
        state_file: this.config.stateFile || null,
        algorithm: this.stateAlgorithm(),
        loaded: this.stateLoaded,
        tamper_detected: this.tamperDetected,
        error: this.persistenceError || null,
      },
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
    this.persistState();

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
  STATE_SCHEMA_VERSION,
  DifferentialPrivacyEngine,
  laplaceNoise,
  normalizeDifferentialPrivacyConfig: normalizeConfig,
};
