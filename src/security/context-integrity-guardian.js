const {
  clampPositiveInt,
  normalizeMode,
  normalizeSessionValue,
} = require('../utils/primitives');

function clampRatio(value, fallback, min = 0, max = 5) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) {
    return fallback;
  }
  return parsed;
}

function extractMessages(bodyJson = {}) {
  const safe = bodyJson && typeof bodyJson === 'object' && !Array.isArray(bodyJson) ? bodyJson : {};
  if (Array.isArray(safe.messages)) {
    return safe.messages.slice(0, 512);
  }
  if (Array.isArray(safe.history)) {
    return safe.history.slice(0, 512);
  }
  if (Array.isArray(safe.context)) {
    return safe.context.slice(0, 512);
  }
  return [];
}

function stringifyMessage(message) {
  if (!message || typeof message !== 'object') {
    return '';
  }
  if (typeof message.content === 'string') {
    return message.content;
  }
  if (Array.isArray(message.content)) {
    return message.content
      .map((item) => (typeof item?.text === 'string' ? item.text : ''))
      .join('\n');
  }
  return '';
}

function estimateTokens(text = '') {
  return Math.ceil(String(text || '').length / 4);
}

function normalizeLine(line) {
  return String(line || '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

class ContextIntegrityGuardian {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.sessionHeader = String(config.session_header || 'x-sentinel-session-id').toLowerCase();
    this.fallbackHeaders = Array.isArray(config.fallback_headers)
      ? config.fallback_headers.map((item) => String(item || '').toLowerCase()).filter(Boolean).slice(0, 16)
      : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
    this.requiredAnchors = Array.isArray(config.required_anchors)
      ? config.required_anchors.map((item) => normalizeLine(item)).filter(Boolean).slice(0, 64)
      : [];
    this.maxContextChars = clampPositiveInt(config.max_context_chars, 32768, 256, 2 * 1024 * 1024);
    this.maxSessions = clampPositiveInt(config.max_sessions, 10000, 8, 1_000_000);
    this.ttlMs = clampPositiveInt(config.ttl_ms, 6 * 3600 * 1000, 1000, 7 * 24 * 3600 * 1000);
    this.repetitionThreshold = clampRatio(config.repetition_threshold, 0.35, 0, 1);
    this.tokenBudgetWarnRatio = clampRatio(config.token_budget_warn_ratio, 0.85, 0, 1);
    this.providerTokenLimit = clampPositiveInt(config.provider_token_limit, 128000, 256, 8_000_000);
    this.blockOnAnchorLoss = config.block_on_anchor_loss === true;
    this.blockOnRepetition = config.block_on_repetition === true;
    this.observability = config.observability !== false;

    this.sessions = new Map();
  }

  isEnabled() {
    return this.enabled === true;
  }

  prune(nowMs) {
    const minUpdated = nowMs - this.ttlMs;
    for (const [sessionId, state] of this.sessions.entries()) {
      if (Number(state?.updatedAt || 0) < minUpdated) {
        this.sessions.delete(sessionId);
      }
    }
    while (this.sessions.size > this.maxSessions) {
      const oldest = this.sessions.keys().next().value;
      if (!oldest) {
        break;
      }
      this.sessions.delete(oldest);
    }
  }

  resolveSessionId(headers = {}, correlationId = '') {
    const direct = normalizeSessionValue(headers[this.sessionHeader] || '', 160);
    if (direct) {
      return direct;
    }
    for (const header of this.fallbackHeaders) {
      const candidate = normalizeSessionValue(headers[header] || '', 160);
      if (candidate) {
        return candidate;
      }
    }
    return normalizeSessionValue(correlationId || 'anonymous', 160) || 'anonymous';
  }

  evaluate({
    headers = {},
    bodyJson = {},
    bodyText = '',
    correlationId = '',
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

    const nowMs = Date.now();
    this.prune(nowMs);

    const sessionId = this.resolveSessionId(headers, correlationId);
    const messages = extractMessages(bodyJson);
    const contextText = messages.length > 0
      ? messages.map((message) => stringifyMessage(message)).join('\n')
      : String(bodyText || '');
    const boundedText = contextText.slice(0, this.maxContextChars);
    const lowered = normalizeLine(boundedText);

    const findings = [];
    const previous = this.sessions.get(sessionId) || null;

    const matchedAnchors = this.requiredAnchors.filter((anchor) => lowered.includes(anchor));
    const anchorCoverage = this.requiredAnchors.length > 0
      ? matchedAnchors.length / this.requiredAnchors.length
      : 1;

    if (this.requiredAnchors.length > 0 && matchedAnchors.length === 0) {
      findings.push({
        code: 'context_anchor_missing',
        blockEligible: this.blockOnAnchorLoss,
      });
    }
    if (previous?.anchorCoverage > 0 && anchorCoverage < previous.anchorCoverage) {
      findings.push({
        code: 'context_anchor_coverage_drop',
        previous_coverage: Number(previous.anchorCoverage.toFixed(4)),
        current_coverage: Number(anchorCoverage.toFixed(4)),
        blockEligible: this.blockOnAnchorLoss,
      });
    }

    const lines = boundedText
      .split(/\r?\n+/)
      .map((line) => normalizeLine(line))
      .filter(Boolean)
      .slice(0, 1024);
    const counts = new Map();
    for (const line of lines) {
      counts.set(line, (counts.get(line) || 0) + 1);
    }
    let repeated = 0;
    for (const count of counts.values()) {
      if (count > 1) {
        repeated += count;
      }
    }
    const repetitionRatio = lines.length > 0 ? repeated / lines.length : 0;
    if (repetitionRatio >= this.repetitionThreshold) {
      findings.push({
        code: 'context_repetition_stuffing',
        repetition_ratio: Number(repetitionRatio.toFixed(6)),
        threshold: this.repetitionThreshold,
        blockEligible: this.blockOnRepetition,
      });
    }

    const estimatedTokens = estimateTokens(boundedText);
    const budgetRatio = estimatedTokens / Math.max(1, this.providerTokenLimit);
    if (budgetRatio >= this.tokenBudgetWarnRatio) {
      findings.push({
        code: 'context_token_budget_risk',
        estimated_tokens: estimatedTokens,
        token_limit: this.providerTokenLimit,
        ratio: Number(budgetRatio.toFixed(6)),
        blockEligible: false,
      });
    }

    this.sessions.set(sessionId, {
      updatedAt: nowMs,
      anchorCoverage,
      estimatedTokens,
      textChars: boundedText.length,
    });

    const detected = findings.length > 0;
    const shouldBlock =
      detected &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce' &&
      findings.some((finding) => finding.blockEligible === true);

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      reason: detected ? String(findings[0].code || 'context_integrity_violation') : 'clean',
      findings,
      session_id: sessionId,
      anchor_coverage: Number(anchorCoverage.toFixed(6)),
      estimated_tokens: estimatedTokens,
      token_budget_ratio: Number(budgetRatio.toFixed(6)),
      repetition_ratio: Number(repetitionRatio.toFixed(6)),
    };
  }
}

module.exports = {
  ContextIntegrityGuardian,
};
