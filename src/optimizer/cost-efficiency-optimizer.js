const {
  clampPositiveInt,
  normalizeMode,
  toObject,
} = require('../utils/primitives');

function clampRatio(value, fallback, min = 0, max = 1) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) {
    return fallback;
  }
  return parsed;
}

function clampPositiveIntOrZero(value, fallback = 0, max = Number.MAX_SAFE_INTEGER) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  if (parsed <= 0) {
    return 0;
  }
  return Math.min(max, Math.floor(parsed));
}

function percentile(values = [], p = 0.95) {
  if (!Array.isArray(values) || values.length === 0) {
    return 0;
  }
  const sorted = values
    .map((value) => Number(value))
    .filter((value) => Number.isFinite(value) && value >= 0)
    .sort((a, b) => a - b);
  if (sorted.length === 0) {
    return 0;
  }
  const idx = Math.min(
    sorted.length - 1,
    Math.max(0, Math.floor((sorted.length - 1) * Math.min(1, Math.max(0, Number(p) || 0))))
  );
  return sorted[idx];
}

function collectPromptText(bodyJson, bodyText, maxChars = 16384) {
  const payload = toObject(bodyJson);
  const parts = [];
  if (Array.isArray(payload.messages)) {
    for (const message of payload.messages.slice(0, 64)) {
      if (!message || typeof message !== 'object') {
        continue;
      }
      if (typeof message.content === 'string' && message.content.trim()) {
        parts.push(message.content.trim());
      } else if (Array.isArray(message.content)) {
        for (const item of message.content.slice(0, 16)) {
          if (item && typeof item.text === 'string' && item.text.trim()) {
            parts.push(item.text.trim());
          }
        }
      }
    }
  }
  if (typeof payload.prompt === 'string' && payload.prompt.trim()) {
    parts.push(payload.prompt.trim());
  }
  if (parts.length === 0 && typeof bodyText === 'string') {
    parts.push(bodyText);
  }
  return parts.join('\n').slice(0, Math.max(64, maxChars));
}

function calculateRepetitionRatio(text) {
  const lines = String(text || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length <= 1) {
    return 0;
  }
  const counts = new Map();
  for (const line of lines) {
    counts.set(line, (counts.get(line) || 0) + 1);
  }
  let duplicateLines = 0;
  for (const count of counts.values()) {
    if (count > 1) {
      duplicateLines += count - 1;
    }
  }
  return duplicateLines / lines.length;
}

function boundedPush(array, value, maxItems) {
  if (!Array.isArray(array)) {
    return;
  }
  array.push(value);
  while (array.length > maxItems) {
    array.shift();
  }
}

class CostEfficiencyOptimizer {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'active']);
    this.ttlMs = clampPositiveInt(config.ttl_ms, 24 * 60 * 60 * 1000, 60_000, 30 * 24 * 60 * 60 * 1000);
    this.maxProviders = clampPositiveInt(config.max_providers, 256, 2, 4096);
    this.maxSamplesPerProvider = clampPositiveInt(config.max_samples_per_provider, 512, 8, 10000);
    this.maxPromptChars = clampPositiveInt(config.max_prompt_chars, 16384, 256, 262144);
    this.charsPerToken = Math.max(1, clampPositiveInt(config.chars_per_token, 4, 1, 32));
    this.promptBloatChars = clampPositiveInt(config.prompt_bloat_chars, 6000, 256, 200000);
    this.repetitionWarnRatio = clampRatio(config.repetition_warn_ratio, 0.2, 0, 1);
    this.lowBudgetUsd = Number.isFinite(Number(config.low_budget_usd))
      ? Math.max(0, Number(config.low_budget_usd))
      : 2;
    this.memoryWarnBytes = clampPositiveInt(config.memory_warn_bytes, 6 * 1024 * 1024 * 1024, 32 * 1024 * 1024, Number.MAX_SAFE_INTEGER);
    this.memoryCriticalBytes = clampPositiveInt(config.memory_critical_bytes, 7 * 1024 * 1024 * 1024, 64 * 1024 * 1024, Number.MAX_SAFE_INTEGER);
    this.memoryHardCapBytes = clampPositiveIntOrZero(config.memory_hard_cap_bytes, 0, Number.MAX_SAFE_INTEGER);
    this.shedOnMemoryPressure = config.shed_on_memory_pressure !== false;
    this.maxShedEngines = clampPositiveInt(config.max_shed_engines, 16, 1, 512);
    this.shedCooldownMs = clampPositiveInt(config.shed_cooldown_ms, 30000, 1000, 3600000);
    this.shedEngineOrder = Array.isArray(config.shed_engine_order)
      ? config.shed_engine_order.map((item) => String(item || '').trim()).filter(Boolean).slice(0, 256)
      : [];
    this.blockOnCriticalMemory = config.block_on_critical_memory === true;
    this.blockOnBudgetExhausted = config.block_on_budget_exhausted === true;
    this.observability = config.observability !== false;
    this.providers = new Map();
  }

  isEnabled() {
    return this.enabled === true;
  }

  prune(now = Date.now()) {
    const staleBefore = Number(now) - this.ttlMs;
    for (const [provider, state] of this.providers.entries()) {
      if (Number(state.updatedAt || 0) < staleBefore) {
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

  getProviderState(providerName, now = Date.now()) {
    const key = String(providerName || 'unknown').trim().toLowerCase().slice(0, 64) || 'unknown';
    const existing = this.providers.get(key);
    if (existing) {
      existing.updatedAt = Number(now);
      return {
        key,
        state: existing,
      };
    }
    const created = {
      latencies: [],
      inputTokens: [],
      costs: [],
      updatedAt: Number(now),
    };
    this.providers.set(key, created);
    return {
      key,
      state: created,
    };
  }

  observe({
    provider = 'unknown',
    latencyMs = 0,
    inputTokens = 0,
    costUsd = 0,
  } = {}) {
    if (!this.isEnabled()) {
      return;
    }
    const now = Date.now();
    this.prune(now);
    const { state } = this.getProviderState(provider, now);
    const safeLatency = Number.isFinite(Number(latencyMs)) && Number(latencyMs) >= 0 ? Number(latencyMs) : 0;
    const safeTokens = Number.isFinite(Number(inputTokens)) && Number(inputTokens) >= 0 ? Number(inputTokens) : 0;
    const safeCost = Number.isFinite(Number(costUsd)) && Number(costUsd) >= 0 ? Number(costUsd) : 0;
    boundedPush(state.latencies, safeLatency, this.maxSamplesPerProvider);
    boundedPush(state.inputTokens, safeTokens, this.maxSamplesPerProvider);
    boundedPush(state.costs, safeCost, this.maxSamplesPerProvider);
  }

  recommendRoute({
    slaP95Ms = 2000,
  } = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
      };
    }
    const candidates = [];
    for (const [provider, state] of this.providers.entries()) {
      if (!Array.isArray(state.latencies) || state.latencies.length === 0) {
        continue;
      }
      const p95 = percentile(state.latencies, 0.95);
      const avgCost = state.costs.length > 0
        ? state.costs.reduce((sum, value) => sum + Number(value || 0), 0) / state.costs.length
        : 0;
      const avgTokens = state.inputTokens.length > 0
        ? state.inputTokens.reduce((sum, value) => sum + Number(value || 0), 0) / state.inputTokens.length
        : 0;
      const slaPenalty = p95 > Number(slaP95Ms || 2000) ? 1 : 0;
      const score = (avgCost * 100) + (p95 / 1000) + (avgTokens / 10000) + slaPenalty;
      candidates.push({
        provider,
        score: Number(score.toFixed(6)),
        p95_ms: Number(p95.toFixed(4)),
        avg_cost_usd: Number(avgCost.toFixed(8)),
        avg_input_tokens: Number(avgTokens.toFixed(2)),
        meets_sla: p95 <= Number(slaP95Ms || 2000),
      });
    }
    candidates.sort((a, b) => a.score - b.score);
    return {
      enabled: true,
      recommendation: candidates[0] || null,
      candidates,
    };
  }

  evaluate({
    provider = 'unknown',
    bodyText = '',
    bodyJson = null,
    latencyMs = 0,
    budgetRemainingUsd = null,
    effectiveMode = 'monitor',
  } = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        detected: false,
        shouldBlock: false,
        reason: 'clean',
        findings: [],
      };
    }
    const promptText = collectPromptText(bodyJson, bodyText, this.maxPromptChars);
    const promptChars = Buffer.byteLength(promptText, 'utf8');
    const estimatedTokens = Math.ceil(promptChars / this.charsPerToken);
    const repetitionRatio = calculateRepetitionRatio(promptText);
    const rssBytes = Number(process.memoryUsage()?.rss || 0);
    const findings = [];
    let memoryLevel = 'normal';

    if (promptChars >= this.promptBloatChars) {
      findings.push({
        code: 'cost_prompt_bloat',
        prompt_chars: promptChars,
        threshold: this.promptBloatChars,
        blockEligible: false,
      });
    }
    if (repetitionRatio >= this.repetitionWarnRatio) {
      findings.push({
        code: 'cost_prompt_repetition',
        repetition_ratio: Number(repetitionRatio.toFixed(6)),
        threshold: this.repetitionWarnRatio,
        blockEligible: false,
      });
    }
    if (rssBytes >= this.memoryWarnBytes) {
      memoryLevel = 'warn';
      findings.push({
        code: 'cost_memory_pressure',
        rss_bytes: rssBytes,
        warn_threshold: this.memoryWarnBytes,
        critical_threshold: this.memoryCriticalBytes,
        blockEligible: this.blockOnCriticalMemory && rssBytes >= this.memoryCriticalBytes,
      });
    }
    if (rssBytes >= this.memoryCriticalBytes) {
      memoryLevel = 'critical';
    }
    if (this.memoryHardCapBytes > 0 && rssBytes >= this.memoryHardCapBytes) {
      memoryLevel = 'hard_cap';
      findings.push({
        code: 'cost_memory_hard_cap',
        rss_bytes: rssBytes,
        hard_cap_bytes: this.memoryHardCapBytes,
        blockEligible: true,
      });
    }
    if (Number.isFinite(Number(budgetRemainingUsd))) {
      const remaining = Number(budgetRemainingUsd);
      if (remaining <= this.lowBudgetUsd) {
        findings.push({
          code: 'cost_budget_low',
          remaining_usd: Number(remaining.toFixed(6)),
          threshold_usd: this.lowBudgetUsd,
          blockEligible: this.blockOnBudgetExhausted && remaining <= 0,
        });
      }
    }

    this.observe({
      provider,
      latencyMs,
      inputTokens: estimatedTokens,
      costUsd: 0,
    });
    const routeRecommendation = this.recommendRoute({});
    const detected = findings.length > 0;
    const hardCapExceeded = memoryLevel === 'hard_cap';
    const shouldBlock =
      detected &&
      this.mode === 'active' &&
      (hardCapExceeded || String(effectiveMode || '').toLowerCase() === 'enforce') &&
      findings.some((item) => item.blockEligible === true);
    const shedRecommended =
      this.shedOnMemoryPressure &&
      this.mode === 'active' &&
      (memoryLevel === 'critical' || memoryLevel === 'hard_cap');

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      reason: detected ? String(findings[0].code || 'cost_efficiency_signal') : 'clean',
      findings,
      estimated_input_tokens: estimatedTokens,
      prompt_chars: promptChars,
      repetition_ratio: Number(repetitionRatio.toFixed(6)),
      memory_rss_bytes: rssBytes,
      memory_level: memoryLevel,
      memory_hard_cap_bytes: this.memoryHardCapBytes,
      shed_recommended: shedRecommended,
      shed_max_engines: this.maxShedEngines,
      shed_cooldown_ms: this.shedCooldownMs,
      shed_engine_order: this.shedEngineOrder.slice(0, 64),
      route_recommendation: routeRecommendation.recommendation,
    };
  }

  snapshot() {
    const providers = [];
    for (const [provider, state] of this.providers.entries()) {
      providers.push({
        provider,
        samples: state.latencies.length,
        p95_ms: Number(percentile(state.latencies, 0.95).toFixed(4)),
        avg_cost_usd: state.costs.length > 0
          ? Number((state.costs.reduce((sum, value) => sum + Number(value || 0), 0) / state.costs.length).toFixed(8))
          : 0,
      });
    }
    return {
      enabled: this.isEnabled(),
      mode: this.mode,
      memory_warn_bytes: this.memoryWarnBytes,
      memory_critical_bytes: this.memoryCriticalBytes,
      memory_hard_cap_bytes: this.memoryHardCapBytes,
      shed_on_memory_pressure: this.shedOnMemoryPressure,
      max_shed_engines: this.maxShedEngines,
      shed_cooldown_ms: this.shedCooldownMs,
      providers,
    };
  }
}

module.exports = {
  CostEfficiencyOptimizer,
};
