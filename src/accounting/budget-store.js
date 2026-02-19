const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  countTokensFromBuffer,
  extractUsageFromResponseBody,
  estimateUsageFromBuffers,
  estimateUsageFromStream,
  computeCostUsd,
  roundCurrency,
} = require('./token-counter');

const DEFAULT_STORE_FILE = path.join(
  process.env.SENTINEL_HOME || path.join(os.homedir(), '.sentinel'),
  'budget-ledger.json'
);

function resolveUserPath(rawPath) {
  if (typeof rawPath !== 'string' || rawPath.length === 0) {
    return DEFAULT_STORE_FILE;
  }
  if (rawPath === '~') {
    return os.homedir();
  }
  if (rawPath.startsWith('~/') || rawPath.startsWith('~\\')) {
    return path.join(os.homedir(), rawPath.slice(2));
  }
  return rawPath;
}

function defaultState() {
  return {
    version: 1,
    days: {},
    updated_at: null,
  };
}

function normalizeAction(action) {
  return action === 'warn' ? 'warn' : 'block';
}

function normalizeTimezone(value) {
  return value === 'local' ? 'local' : 'utc';
}

function todayKey(resetTimezone, now = Date.now()) {
  const date = new Date(now);
  if (resetTimezone === 'local') {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  }
  return date.toISOString().slice(0, 10);
}

function ensureDayBucket(state, key) {
  if (!state.days[key]) {
    state.days[key] = {
      spent_usd: 0,
      requests: 0,
      input_tokens: 0,
      output_tokens: 0,
      providers: {},
      updated_at: null,
    };
  }
  return state.days[key];
}

function pruneOldDays(state, resetTimezone, retentionDays, now = Date.now()) {
  if (!Number.isInteger(retentionDays) || retentionDays <= 0) {
    return;
  }
  const keep = new Set();
  for (let i = 0; i < retentionDays; i += 1) {
    const ts = now - i * 24 * 60 * 60 * 1000;
    keep.add(todayKey(resetTimezone, ts));
  }
  for (const key of Object.keys(state.days || {})) {
    if (!keep.has(key)) {
      delete state.days[key];
    }
  }
}

function safeNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

class BudgetStore {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.action = normalizeAction(config.action);
    this.dailyLimitUsd = Math.max(0, safeNumber(config.daily_limit_usd, 5));
    this.storeFile = resolveUserPath(config.store_file);
    this.resetTimezone = normalizeTimezone(config.reset_timezone);
    this.charsPerToken = Math.max(1, Math.floor(safeNumber(config.chars_per_token, 4)));
    this.inputCostPer1k = Math.max(0, safeNumber(config.input_cost_per_1k_tokens, 0));
    this.outputCostPer1k = Math.max(0, safeNumber(config.output_cost_per_1k_tokens, 0));
    this.chargeReplayHits = config.charge_replay_hits === true;
    this.retentionDays = Math.max(1, Math.floor(safeNumber(config.retention_days, 90)));

    this.state = this.loadState();
    this.writeChain = Promise.resolve();
  }

  loadState() {
    const dir = path.dirname(this.storeFile);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    if (!fs.existsSync(this.storeFile)) {
      return defaultState();
    }

    try {
      const parsed = JSON.parse(fs.readFileSync(this.storeFile, 'utf8'));
      if (!parsed || typeof parsed !== 'object' || typeof parsed.days !== 'object') {
        return defaultState();
      }
      return {
        version: Number(parsed.version || 1),
        days: parsed.days,
        updated_at: parsed.updated_at || null,
      };
    } catch {
      return defaultState();
    }
  }

  persistStateSync() {
    const dir = path.dirname(this.storeFile);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const tempPath = `${this.storeFile}.tmp`;
    fs.writeFileSync(tempPath, JSON.stringify(this.state, null, 2), 'utf8');
    fs.renameSync(tempPath, this.storeFile);
  }

  queuePersist() {
    this.writeChain = this.writeChain.then(() => {
      this.persistStateSync();
    });
    return this.writeChain;
  }

  snapshot(now = Date.now()) {
    const dayKey = todayKey(this.resetTimezone, now);
    const bucket = ensureDayBucket(this.state, dayKey);
    const spentUsd = roundCurrency(bucket.spent_usd);
    const remainingUsd = roundCurrency(Math.max(0, this.dailyLimitUsd - spentUsd));

    return {
      enabled: this.enabled,
      action: this.action,
      dayKey,
      dailyLimitUsd: roundCurrency(this.dailyLimitUsd),
      spentUsd,
      remainingUsd,
      requests: Number(bucket.requests || 0),
      inputTokens: Number(bucket.input_tokens || 0),
      outputTokens: Number(bucket.output_tokens || 0),
    };
  }

  estimateRequest(input = {}) {
    if (!this.enabled) {
      return {
        applies: false,
        allowed: true,
        reason: 'disabled',
        estimatedInputTokens: 0,
        estimatedRequestCostUsd: 0,
        ...this.snapshot(),
      };
    }

    const method = String(input.method || '').toUpperCase();
    const isChargeableMethod = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
    if (!isChargeableMethod) {
      return {
        applies: false,
        allowed: true,
        reason: 'method_not_chargeable',
        estimatedInputTokens: 0,
        estimatedRequestCostUsd: 0,
        ...this.snapshot(),
      };
    }

    const estimatedInputTokens = countTokensFromBuffer(input.requestBodyBuffer, this.charsPerToken);
    const estimatedRequestCostUsd = computeCostUsd({
      inputTokens: estimatedInputTokens,
      outputTokens: 0,
      inputCostPer1k: this.inputCostPer1k,
      outputCostPer1k: this.outputCostPer1k,
    });
    const snapshot = this.snapshot(input.now);
    const projectedUsd = roundCurrency(snapshot.spentUsd + estimatedRequestCostUsd);
    const allowed = projectedUsd <= snapshot.dailyLimitUsd;

    return {
      applies: true,
      allowed,
      reason: allowed ? 'within_limit' : 'daily_limit_exceeded',
      estimatedInputTokens,
      estimatedRequestCostUsd,
      projectedUsd,
      ...snapshot,
    };
  }

  async recordBuffered(input = {}) {
    if (!this.enabled) {
      return { charged: false, reason: 'disabled', ...this.snapshot(input.now) };
    }
    if ((input.replayedFromVcr || input.replayedFromSemanticCache) && !this.chargeReplayHits) {
      return { charged: false, reason: 'replay_not_charged', ...this.snapshot(input.now) };
    }

    const usageFromProvider = extractUsageFromResponseBody(input.responseBodyBuffer);
    const usage = usageFromProvider
      || estimateUsageFromBuffers({
        requestBodyBuffer: input.requestBodyBuffer,
        responseBodyBuffer: input.responseBodyBuffer,
        charsPerToken: this.charsPerToken,
      });

    return this.recordUsage({
      provider: input.provider,
      inputTokens: usage.inputTokens,
      outputTokens: usage.outputTokens,
      source: usage.source,
      correlationId: input.correlationId,
      now: input.now,
    });
  }

  async recordStream(input = {}) {
    if (!this.enabled) {
      return { charged: false, reason: 'disabled', ...this.snapshot(input.now) };
    }
    if ((input.replayedFromVcr || input.replayedFromSemanticCache) && !this.chargeReplayHits) {
      return { charged: false, reason: 'replay_not_charged', ...this.snapshot(input.now) };
    }

    const usage = estimateUsageFromStream({
      requestBodyBuffer: input.requestBodyBuffer,
      streamedBytes: input.streamedBytes,
      charsPerToken: this.charsPerToken,
    });

    return this.recordUsage({
      provider: input.provider,
      inputTokens: usage.inputTokens,
      outputTokens: usage.outputTokens,
      source: usage.source,
      correlationId: input.correlationId,
      now: input.now,
    });
  }

  async recordUsage(input = {}) {
    const provider = String(input.provider || 'unknown');
    const inputTokens = Math.max(0, Number(input.inputTokens || 0));
    const outputTokens = Math.max(0, Number(input.outputTokens || 0));
    const costUsd = computeCostUsd({
      inputTokens,
      outputTokens,
      inputCostPer1k: this.inputCostPer1k,
      outputCostPer1k: this.outputCostPer1k,
    });

    const now = Number(input.now || Date.now());
    const key = todayKey(this.resetTimezone, now);
    pruneOldDays(this.state, this.resetTimezone, this.retentionDays, now);
    const bucket = ensureDayBucket(this.state, key);
    if (!bucket.providers || typeof bucket.providers !== 'object') {
      bucket.providers = {};
    }
    if (!bucket.providers[provider]) {
      bucket.providers[provider] = {
        requests: 0,
        spent_usd: 0,
        input_tokens: 0,
        output_tokens: 0,
      };
    }

    bucket.requests += 1;
    bucket.input_tokens += inputTokens;
    bucket.output_tokens += outputTokens;
    bucket.spent_usd = roundCurrency(bucket.spent_usd + costUsd);
    bucket.updated_at = new Date(now).toISOString();

    bucket.providers[provider].requests += 1;
    bucket.providers[provider].input_tokens += inputTokens;
    bucket.providers[provider].output_tokens += outputTokens;
    bucket.providers[provider].spent_usd = roundCurrency(bucket.providers[provider].spent_usd + costUsd);

    this.state.updated_at = new Date(now).toISOString();
    await this.queuePersist();

    const snapshot = this.snapshot(now);
    return {
      charged: true,
      provider,
      source: String(input.source || 'estimated'),
      correlationId: input.correlationId || null,
      inputTokens,
      outputTokens,
      totalTokens: inputTokens + outputTokens,
      chargedUsd: costUsd,
      overLimit: snapshot.spentUsd > snapshot.dailyLimitUsd,
      ...snapshot,
    };
  }

  async flush() {
    await this.writeChain;
  }
}

module.exports = {
  BudgetStore,
  todayKey,
  resolveUserPath,
};
