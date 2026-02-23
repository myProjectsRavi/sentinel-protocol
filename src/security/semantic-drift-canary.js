const {
  clampPositiveInt,
  clampProbability,
  normalizeMode,
} = require('../utils/primitives');

function toProvider(value) {
  return String(value || 'unknown')
    .trim()
    .toLowerCase()
    .slice(0, 64) || 'unknown';
}

function normalizeText(input = '', maxChars = 16384) {
  return String(input || '').slice(0, maxChars);
}

function textEntropy(input = '') {
  const text = String(input || '');
  if (!text) {
    return 0;
  }
  const counts = new Map();
  for (const ch of text) {
    counts.set(ch, (counts.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const value of counts.values()) {
    const p = value / text.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

class SemanticDriftCanary {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.sampleEveryRequests = clampPositiveInt(config.sample_every_requests, 100, 1, 1000000);
    this.maxProviders = clampPositiveInt(config.max_providers, 128, 1, 8192);
    this.maxSamplesPerProvider = clampPositiveInt(config.max_samples_per_provider, 256, 4, 65536);
    this.maxTextChars = clampPositiveInt(config.max_text_chars, 8192, 64, 1048576);
    this.warnDistanceThreshold = clampProbability(config.warn_distance_threshold, 0.45);
    this.blockDistanceThreshold = clampProbability(config.block_distance_threshold, 0.8);
    this.observability = config.observability !== false;

    this.requestCount = 0;
    this.providers = new Map();
  }

  isEnabled() {
    return this.enabled === true;
  }

  prune() {
    while (this.providers.size > this.maxProviders) {
      const oldest = this.providers.keys().next().value;
      if (!oldest) {
        break;
      }
      this.providers.delete(oldest);
    }
  }

  observe({
    provider,
    responseText,
    latencyMs,
    effectiveMode = 'monitor',
    forceSample = false,
  } = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        sampled: false,
        detected: false,
        shouldBlock: false,
        reason: 'clean',
        findings: [],
      };
    }

    this.requestCount += 1;
    const sampled = forceSample || this.requestCount % this.sampleEveryRequests === 0;
    if (!sampled) {
      return {
        enabled: true,
        mode: this.mode,
        sampled: false,
        detected: false,
        shouldBlock: false,
        reason: 'clean',
        findings: [],
      };
    }

    const providerKey = toProvider(provider);
    const text = normalizeText(responseText, this.maxTextChars);
    const length = text.length;
    const entropy = textEntropy(text);
    const latency = Number.isFinite(Number(latencyMs)) ? Number(latencyMs) : 0;

    const entry = this.providers.get(providerKey) || {
      count: 0,
      meanLength: 0,
      meanEntropy: 0,
      meanLatency: 0,
      recent: [],
    };

    const findings = [];
    if (entry.count >= 4) {
      const lengthDelta = Math.abs(length - entry.meanLength) / Math.max(1, entry.meanLength);
      const entropyDelta = Math.abs(entropy - entry.meanEntropy) / Math.max(1, entry.meanEntropy || 1);
      const latencyDelta = Math.abs(latency - entry.meanLatency) / Math.max(1, entry.meanLatency || 1);
      const distance = Number((0.5 * lengthDelta + 0.3 * entropyDelta + 0.2 * latencyDelta).toFixed(6));

      if (distance >= this.warnDistanceThreshold) {
        findings.push({
          code: 'semantic_drift_canary_deviation',
          distance,
          length_delta: Number(lengthDelta.toFixed(6)),
          entropy_delta: Number(entropyDelta.toFixed(6)),
          latency_delta: Number(latencyDelta.toFixed(6)),
          blockEligible: distance >= this.blockDistanceThreshold,
        });
      }
    }

    const nextCount = entry.count + 1;
    entry.meanLength = ((entry.meanLength * entry.count) + length) / nextCount;
    entry.meanEntropy = ((entry.meanEntropy * entry.count) + entropy) / nextCount;
    entry.meanLatency = ((entry.meanLatency * entry.count) + latency) / nextCount;
    entry.count = nextCount;
    entry.recent.push({ length, entropy, latency });
    if (entry.recent.length > this.maxSamplesPerProvider) {
      entry.recent = entry.recent.slice(entry.recent.length - this.maxSamplesPerProvider);
    }

    this.providers.set(providerKey, entry);
    this.prune();

    const detected = findings.length > 0;
    const shouldBlock =
      detected &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce' &&
      findings.some((item) => item.blockEligible === true);

    return {
      enabled: true,
      mode: this.mode,
      sampled: true,
      detected,
      shouldBlock,
      reason: detected ? String(findings[0].code || 'semantic_drift_detected') : 'clean',
      findings,
      provider: providerKey,
      baseline: {
        samples: entry.count,
        mean_length: Number(entry.meanLength.toFixed(4)),
        mean_entropy: Number(entry.meanEntropy.toFixed(4)),
        mean_latency: Number(entry.meanLatency.toFixed(4)),
      },
    };
  }
}

module.exports = {
  SemanticDriftCanary,
};
