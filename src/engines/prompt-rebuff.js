const {
  clampPositiveInt,
  clampProbability,
  normalizeMode,
  normalizeSessionValue,
  mapHeaderValue,
} = require('../utils/primitives');

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function extractHeaderIdentity(headers, headerName) {
  const value = mapHeaderValue(headers, headerName);
  if (value === undefined || value === null) {
    return '';
  }
  const first = Array.isArray(value) ? value[0] : value;
  const normalized = normalizeSessionValue(first, 256);
  if (!normalized) {
    return '';
  }
  if (headerName === 'x-forwarded-for' || headerName === 'forwarded') {
    return normalizeSessionValue(normalized.split(',')[0], 256);
  }
  return normalized;
}

function numberOr(value, fallback = 0) {
  const out = Number(value);
  return Number.isFinite(out) ? out : fallback;
}

function normalizeSensitivity(value) {
  const normalized = String(value || 'balanced').toLowerCase();
  if (normalized === 'permissive' || normalized === 'paranoid') {
    return normalized;
  }
  return 'balanced';
}

class PromptRebuffEngine {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.sensitivity = normalizeSensitivity(config.sensitivity);
    this.heuristicWeight = clampProbability(config.heuristic_weight, 0.55);
    this.neuralWeight = clampProbability(config.neural_weight, 0.35);
    this.canaryWeight = clampProbability(config.canary_weight, 0.25);
    this.warnThreshold = clampProbability(config.warn_threshold, 0.65);
    this.blockThreshold = clampProbability(config.block_threshold, 0.85);
    this.maxBodyChars = clampPositiveInt(config.max_body_chars, 8192, 256, 524288);
    this.maxResponseChars = clampPositiveInt(config.max_response_chars, 8192, 256, 524288);
    this.sessionHeader = String(config.session_header || 'x-sentinel-session-id').toLowerCase();
    this.fallbackHeaders = Array.isArray(config.fallback_headers)
      ? config.fallback_headers.map((value) => String(value || '').toLowerCase()).filter(Boolean)
      : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
    this.ttlMs = clampPositiveInt(config.ttl_ms, 15 * 60 * 1000, 1000, 24 * 60 * 60 * 1000);
    this.maxSessions = clampPositiveInt(config.max_sessions, 5000, 16, 500000);
    this.canaryToolName = String(config.canary_tool_name || 'fetch_admin_passwords');
    this.observability = config.observability !== false;
    this.sessionSignals = new Map();
  }

  isEnabled() {
    return this.enabled === true;
  }

  deriveSessionKey(headers = {}, correlationId = '') {
    const primary = extractHeaderIdentity(headers, this.sessionHeader);
    if (primary) {
      return primary;
    }
    for (const headerName of this.fallbackHeaders) {
      const candidate = extractHeaderIdentity(headers, headerName);
      if (candidate) {
        return candidate;
      }
    }
    const fallback = normalizeSessionValue(correlationId, 128);
    return fallback || 'anonymous';
  }

  prune(nowMs) {
    const minTime = nowMs - this.ttlMs;
    for (const [key, entry] of this.sessionSignals.entries()) {
      if (Number(entry?.updatedAt || 0) < minTime) {
        this.sessionSignals.delete(key);
      }
    }
    while (this.sessionSignals.size > this.maxSessions) {
      const oldest = this.sessionSignals.keys().next().value;
      if (!oldest) {
        break;
      }
      this.sessionSignals.delete(oldest);
    }
  }

  recordCanaryTrigger({ headers = {}, correlationId = '', toolName = '' } = {}) {
    if (!this.isEnabled()) {
      return;
    }
    const nowMs = Date.now();
    this.prune(nowMs);
    const sessionKey = this.deriveSessionKey(headers, correlationId);
    const entry = this.sessionSignals.get(sessionKey) || {
      updatedAt: nowMs,
      lastCanaryAt: 0,
      lastCanaryToolName: '',
    };
    entry.updatedAt = nowMs;
    entry.lastCanaryAt = nowMs;
    entry.lastCanaryToolName = String(toolName || '');
    this.sessionSignals.set(sessionKey, entry);
  }

  computeCanarySignal({
    headers = {},
    correlationId = '',
    bodyText = '',
    responseText = '',
    canaryToken = '',
  }) {
    const nowMs = Date.now();
    this.prune(nowMs);
    const sessionKey = this.deriveSessionKey(headers, correlationId);
    const entry = this.sessionSignals.get(sessionKey);
    const hasRecentSessionSignal =
      entry && Number(entry.lastCanaryAt || 0) > 0 && nowMs - Number(entry.lastCanaryAt) <= this.ttlMs;

    const text = String(bodyText || '').slice(0, this.maxBodyChars).toLowerCase();
    const toolName = String(this.canaryToolName || '').toLowerCase();
    const mentionsCanaryTool = toolName.length > 0 && text.includes(toolName);
    const canaryTextBypass =
      mentionsCanaryTool &&
      /(ignore|bypass|disable|override|skip)[\s\S]{0,40}(policy|guardrail|safety|security)/i.test(text);
    const outputText = String(responseText || '').slice(0, this.maxResponseChars).toLowerCase();
    const outputCanaryToken = String(canaryToken || this.canaryToolName || '').toLowerCase();
    const forbiddenOutputSignal = outputCanaryToken.length > 0 && outputText.includes(outputCanaryToken);
    const outputCanaryBypass =
      forbiddenOutputSignal &&
      /(tool|system|hidden|secret|prompt|policy|guardrail)/i.test(outputText);

    return {
      value: hasRecentSessionSignal || canaryTextBypass || outputCanaryBypass ? 1 : 0,
      sessionSignal: Boolean(hasRecentSessionSignal),
      textSignal: Boolean(canaryTextBypass),
      outputSignal: Boolean(outputCanaryBypass),
      sessionKey,
    };
  }

  resolveThresholds() {
    let warn = this.warnThreshold;
    let block = this.blockThreshold;
    if (this.sensitivity === 'paranoid') {
      warn = clamp(warn - 0.1, 0, 1);
      block = clamp(block - 0.1, 0, 1);
    } else if (this.sensitivity === 'permissive') {
      warn = clamp(warn + 0.1, 0, 1);
      block = clamp(block + 0.1, 0, 1);
    }
    if (block < warn) {
      block = warn;
    }
    return { warn, block };
  }

  evaluate({
    headers = {},
    correlationId = '',
    bodyText = '',
    responseText = '',
    canaryToken = '',
    injectionResult = {},
    effectiveMode = 'monitor',
  } = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        detected: false,
        shouldBlock: false,
        score: 0,
        reason: 'disabled',
      };
    }

    const heuristicScore = clamp(numberOr(injectionResult?.score, 0), 0, 1);
    const neuralScore = clamp(numberOr(injectionResult?.neural?.score, 0), 0, 1);
    const canarySignal = this.computeCanarySignal({
      headers,
      correlationId,
      bodyText,
      responseText,
      canaryToken,
    });
    const thresholds = this.resolveThresholds();
    const combinedWeight = Math.max(
      Number.EPSILON,
      this.heuristicWeight + this.neuralWeight + this.canaryWeight
    );
    const weighted =
      (heuristicScore * this.heuristicWeight) +
      (neuralScore * this.neuralWeight) +
      (canarySignal.value * this.canaryWeight);
    const score = clamp(Number((weighted / combinedWeight).toFixed(3)), 0, 1);
    const detected = score >= thresholds.warn || canarySignal.value > 0;
    const shouldBlock =
      score >= thresholds.block &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce';

    let reason = 'clean';
    if (score >= thresholds.block) {
      reason = 'prompt_rebuff_high_confidence';
    } else if (detected) {
      reason = canarySignal.value > 0
        ? 'prompt_rebuff_canary_signal'
        : 'prompt_rebuff_warning';
    }

    return {
      enabled: true,
      detected,
      shouldBlock,
      mode: this.mode,
      sensitivity: this.sensitivity,
      score,
      reason,
      thresholds,
      heuristicScore,
      neuralScore,
      canarySignal,
    };
  }
}

module.exports = {
  PromptRebuffEngine,
};
