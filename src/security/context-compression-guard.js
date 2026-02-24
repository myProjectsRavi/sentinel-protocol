const {
  clampPositiveInt,
  normalizeMode,
  normalizeSessionValue,
  toObject,
} = require('../utils/primitives');

const SUMMARY_INJECTION_RE = /(ignore\s+previous|bypass\s+policy|disable\s+guard|reveal\s+secret|leak\s+token)/i;

function clampRatio(value, fallback, min = 0, max = 1) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) {
    return fallback;
  }
  return parsed;
}

function normalizeLine(line) {
  return String(line || '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

function resolvePathValue(input, dottedPath) {
  const root = toObject(input);
  const parts = String(dottedPath || '').split('.').map((item) => item.trim()).filter(Boolean);
  if (parts.length === 0) {
    return null;
  }

  let current = root;
  for (const part of parts) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) {
      return null;
    }
    current = current[part];
  }
  return current === undefined ? null : current;
}

function extractMessages(bodyJson = {}) {
  const payload = toObject(bodyJson);
  if (Array.isArray(payload.messages)) {
    return payload.messages.slice(0, 512);
  }
  if (Array.isArray(payload.history)) {
    return payload.history.slice(0, 512);
  }
  return [];
}

function messageToText(message) {
  if (!message || typeof message !== 'object') {
    return '';
  }
  if (typeof message.content === 'string') {
    return message.content;
  }
  if (Array.isArray(message.content)) {
    return message.content
      .map((part) => {
        if (typeof part === 'string') {
          return part;
        }
        if (part && typeof part.text === 'string') {
          return part.text;
        }
        return '';
      })
      .filter(Boolean)
      .join('\n');
  }
  return '';
}

function estimateTokens(text = '') {
  return Math.ceil(String(text || '').length / 4);
}

class ContextCompressionGuard {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.sessionHeader = String(config.session_header || 'x-sentinel-session-id').toLowerCase();
    this.fallbackHeaders = Array.isArray(config.fallback_headers)
      ? config.fallback_headers.map((item) => String(item || '').toLowerCase()).filter(Boolean).slice(0, 16)
      : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
    this.protectedAnchors = Array.isArray(config.protected_anchors)
      ? config.protected_anchors.map((item) => normalizeLine(item)).filter(Boolean).slice(0, 64)
      : [];
    this.summaryFields = Array.isArray(config.summary_fields)
      ? config.summary_fields.map((item) => String(item || '').trim()).filter(Boolean).slice(0, 32)
      : ['summary', 'context_summary', 'memory_summary', 'compressed_context', 'conversation_summary'];
    this.maxContextChars = clampPositiveInt(config.max_context_chars, 32768, 256, 2 * 1024 * 1024);
    this.maxSummaryChars = clampPositiveInt(config.max_summary_chars, 16384, 128, 1024 * 1024);
    this.maxSessions = clampPositiveInt(config.max_sessions, 10000, 8, 1_000_000);
    this.ttlMs = clampPositiveInt(config.ttl_ms, 6 * 3600 * 1000, 1000, 7 * 24 * 3600 * 1000);
    this.anchorLossRatio = clampRatio(config.anchor_loss_ratio, 0.75, 0, 1);
    this.shrinkSpikeRatio = clampRatio(config.shrink_spike_ratio, 0.35, 0, 1);
    this.tokenWarnRatio = clampRatio(config.token_budget_warn_ratio, 0.85, 0, 1);
    this.providerTokenLimit = clampPositiveInt(config.provider_token_limit, 128000, 256, 8_000_000);
    this.blockOnAnchorLoss = config.block_on_anchor_loss === true;
    this.blockOnSummaryInjection = config.block_on_summary_injection === true;
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

  extractSummaryText(bodyJson = {}) {
    const payload = toObject(bodyJson);
    const chunks = [];
    for (const field of this.summaryFields) {
      const value = resolvePathValue(payload, field);
      if (typeof value === 'string' && value.trim()) {
        chunks.push(value);
      }
    }
    return chunks.join('\n').slice(0, this.maxSummaryChars);
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
      ? messages.map((message) => messageToText(message)).join('\n')
      : String(bodyText || '');
    const boundedContext = String(contextText || '').slice(0, this.maxContextChars);
    const summaryText = this.extractSummaryText(bodyJson);

    const normalizedContext = normalizeLine(boundedContext);
    const normalizedSummary = normalizeLine(summaryText);
    const previous = this.sessions.get(sessionId) || null;

    const matchedContextAnchors = this.protectedAnchors.filter((anchor) => normalizedContext.includes(anchor));
    const matchedSummaryAnchors = this.protectedAnchors.filter((anchor) => normalizedSummary.includes(anchor));
    const anchorCoverage = this.protectedAnchors.length > 0
      ? matchedContextAnchors.length / this.protectedAnchors.length
      : 1;
    const summaryCoverage = this.protectedAnchors.length > 0
      ? matchedSummaryAnchors.length / this.protectedAnchors.length
      : 1;

    const contextTokens = estimateTokens(boundedContext);
    const tokenRatio = contextTokens / Math.max(1, this.providerTokenLimit);
    const findings = [];

    if (
      this.protectedAnchors.length > 0 &&
      previous &&
      Number(previous.anchorCoverage || 0) > 0 &&
      anchorCoverage < Number(previous.anchorCoverage) * this.anchorLossRatio
    ) {
      findings.push({
        code: 'context_compression_anchor_loss',
        previous_coverage: Number(Number(previous.anchorCoverage || 0).toFixed(6)),
        current_coverage: Number(anchorCoverage.toFixed(6)),
        threshold_ratio: this.anchorLossRatio,
        blockEligible: this.blockOnAnchorLoss,
      });
    }

    if (
      this.protectedAnchors.length > 0 &&
      summaryText.length > 0 &&
      matchedContextAnchors.length > 0 &&
      matchedSummaryAnchors.length < matchedContextAnchors.length
    ) {
      findings.push({
        code: 'context_compression_summary_anchor_loss',
        context_anchors: matchedContextAnchors.length,
        summary_anchors: matchedSummaryAnchors.length,
        blockEligible: this.blockOnAnchorLoss,
      });
    }

    if (
      previous &&
      Number(previous.contextChars || 0) > 0 &&
      boundedContext.length > 0
    ) {
      const shrinkRatio = boundedContext.length / Math.max(1, Number(previous.contextChars || 0));
      if (shrinkRatio <= this.shrinkSpikeRatio) {
        findings.push({
          code: 'context_compression_shrink_spike',
          previous_chars: Number(previous.contextChars || 0),
          current_chars: boundedContext.length,
          ratio: Number(shrinkRatio.toFixed(6)),
          threshold: this.shrinkSpikeRatio,
          blockEligible: false,
        });
      }
    }

    if (summaryText.length > 0 && SUMMARY_INJECTION_RE.test(summaryText)) {
      findings.push({
        code: 'context_compression_summary_injection_signal',
        blockEligible: this.blockOnSummaryInjection,
      });
    }

    if (tokenRatio >= this.tokenWarnRatio) {
      findings.push({
        code: 'context_compression_token_budget_risk',
        estimated_tokens: contextTokens,
        token_limit: this.providerTokenLimit,
        ratio: Number(tokenRatio.toFixed(6)),
        blockEligible: false,
      });
    }

    this.sessions.set(sessionId, {
      updatedAt: nowMs,
      contextChars: boundedContext.length,
      anchorCoverage,
      summaryCoverage,
      contextTokens,
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
      reason: detected ? String(findings[0].code || 'context_compression_violation') : 'clean',
      findings,
      session_id: sessionId,
      context_chars: boundedContext.length,
      summary_chars: summaryText.length,
      anchor_coverage: Number(anchorCoverage.toFixed(6)),
      summary_anchor_coverage: Number(summaryCoverage.toFixed(6)),
      token_budget_ratio: Number(tokenRatio.toFixed(6)),
    };
  }
}

module.exports = {
  ContextCompressionGuard,
};
