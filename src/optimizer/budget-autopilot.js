const {
  clampPositiveInt,
  clampProbability,
  normalizeMode,
} = require('../utils/primitives');

class BudgetAutopilot {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'active']);
    this.ttlMs = clampPositiveInt(config.ttl_ms, 24 * 3600 * 1000, 1000, 30 * 24 * 3600 * 1000);
    this.maxProviders = clampPositiveInt(config.max_providers, 256, 1, 10000);
    this.minSamples = clampPositiveInt(config.min_samples, 8, 1, 1000);
    this.costWeight = clampProbability(config.cost_weight, 0.6);
    this.latencyWeight = clampProbability(config.latency_weight, 0.4);
    this.warnBudgetRatio = clampProbability(config.warn_budget_ratio, 0.2);
    this.observability = config.observability !== false;
    this.providers = new Map();
  }

  isEnabled() {
    return this.enabled === true;
  }

  prune(nowMs) {
    const cutoff = nowMs - this.ttlMs;
    for (const [provider, entry] of this.providers.entries()) {
      if (Number(entry?.updatedAt || 0) < cutoff) {
        this.providers.delete(provider);
      }
    }
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
    latencyMs,
    costUsd,
    timestampMs = Date.now(),
  } = {}) {
    if (!this.isEnabled()) {
      return;
    }
    const name = String(provider || '').trim().toLowerCase();
    if (!name) {
      return;
    }
    const nowMs = Number(timestampMs || Date.now());
    this.prune(nowMs);
    const entry = this.providers.get(name) || {
      updatedAt: nowMs,
      count: 0,
      latency: [],
      totalCostUsd: 0,
    };
    entry.updatedAt = nowMs;
    entry.count += 1;
    const latency = Number(latencyMs || 0);
    if (Number.isFinite(latency) && latency >= 0) {
      entry.latency.push(latency);
      if (entry.latency.length > 512) {
        entry.latency = entry.latency.slice(entry.latency.length - 512);
      }
    }
    const cost = Number(costUsd || 0);
    if (Number.isFinite(cost) && cost >= 0) {
      entry.totalCostUsd += cost;
    }
    this.providers.set(name, entry);
  }

  percentile(values, p) {
    if (!Array.isArray(values) || values.length === 0) {
      return 0;
    }
    const sorted = [...values].sort((a, b) => a - b);
    const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
    return sorted[idx];
  }

  snapshot() {
    const out = {};
    for (const [provider, entry] of this.providers.entries()) {
      out[provider] = {
        count: entry.count,
        avg_cost_usd: entry.count > 0 ? Number((entry.totalCostUsd / entry.count).toFixed(8)) : 0,
        p50_ms: Number(this.percentile(entry.latency, 50).toFixed(4)),
        p95_ms: Number(this.percentile(entry.latency, 95).toFixed(4)),
        p99_ms: Number(this.percentile(entry.latency, 99).toFixed(4)),
      };
    }
    return out;
  }

  recommend({
    budgetRemainingUsd = Infinity,
    slaP95Ms = Infinity,
    horizonHours = 24,
  } = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        recommendation: null,
        reason: 'disabled',
      };
    }
    const providers = this.snapshot();
    const candidates = Object.entries(providers)
      .filter(([, stats]) => stats.count >= this.minSamples)
      .map(([name, stats]) => ({
        provider: name,
        stats,
      }))
      .filter((candidate) => Number(candidate.stats.p95_ms || 0) <= Number(slaP95Ms || Infinity));

    if (candidates.length === 0) {
      return {
        enabled: true,
        recommendation: null,
        reason: 'no_sla_candidates',
        providers,
      };
    }

    let best = null;
    for (const candidate of candidates) {
      const costScore = Number(candidate.stats.avg_cost_usd || 0);
      const latencyScore = Number(candidate.stats.p95_ms || 0);
      const blended = (costScore * this.costWeight) + (latencyScore * this.latencyWeight);
      if (!best || blended < best.blended) {
        best = {
          provider: candidate.provider,
          blended,
          costScore,
          latencyScore,
        };
      }
    }

    const avgHourlySpend = candidates.reduce((sum, item) => sum + Number(item.stats.avg_cost_usd || 0), 0) / candidates.length;
    const exhaustionHours = avgHourlySpend > 0 ? Number(budgetRemainingUsd || 0) / avgHourlySpend : Infinity;
    const budgetWarning = Number.isFinite(exhaustionHours) && exhaustionHours <= Math.max(1, Number(horizonHours || 24));

    return {
      enabled: true,
      recommendation: best?.provider || null,
      mode: this.mode,
      providers,
      budget_warning: budgetWarning,
      estimated_exhaustion_hours: Number.isFinite(exhaustionHours)
        ? Number(exhaustionHours.toFixed(4))
        : null,
      recommendation_confidence: best
        ? Number((1 / (1 + Math.max(0.0001, best.blended))).toFixed(6))
        : 0,
      reason: best ? 'ok' : 'no_recommendation',
    };
  }
}

module.exports = {
  BudgetAutopilot,
};
