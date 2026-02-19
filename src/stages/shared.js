function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function tryParseJson(text) {
  try {
    return {
      ok: true,
      value: JSON.parse(text),
      error: null,
    };
  } catch (error) {
    return {
      ok: false,
      value: null,
      error,
    };
  }
}

function flattenFindings(findings) {
  return Array.from(new Set((findings || []).map((item) => item.id))).sort();
}

function highestSeverity(findings) {
  const rank = { low: 1, medium: 2, high: 3, critical: 4 };
  let current = null;
  for (const finding of findings || []) {
    if (!current || rank[finding.severity] > rank[current]) {
      current = finding.severity;
    }
  }
  return current;
}

function responseHeaderDiagnostics(res, diagnostics) {
  res.setHeader('x-sentinel-error-source', diagnostics.errorSource);
  res.setHeader('x-sentinel-upstream-error', String(Boolean(diagnostics.upstreamError)));
  res.setHeader('x-sentinel-provider', diagnostics.provider);
  res.setHeader('x-sentinel-retry-count', String(diagnostics.retryCount));
  res.setHeader('x-sentinel-circuit-state', diagnostics.circuitState);
  res.setHeader('x-sentinel-correlation-id', diagnostics.correlationId);
}

function formatBudgetUsd(value) {
  return Number(Number(value || 0).toFixed(6)).toString();
}

function setBudgetHeaders(res, budget) {
  if (!budget || budget.enabled !== true) {
    return;
  }
  res.setHeader('x-sentinel-budget-action', budget.action);
  res.setHeader('x-sentinel-budget-day', budget.dayKey);
  res.setHeader('x-sentinel-budget-limit-usd', formatBudgetUsd(budget.dailyLimitUsd));
  res.setHeader('x-sentinel-budget-spent-usd', formatBudgetUsd(budget.spentUsd));
  res.setHeader('x-sentinel-budget-remaining-usd', formatBudgetUsd(budget.remainingUsd));
}

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'trailers',
  'transfer-encoding',
  'upgrade',
]);

function scrubForwardHeaders(inputHeaders = {}) {
  const headers = { ...inputHeaders };
  const connectionTokens = new Set(
    String(headers.connection || '')
      .split(',')
      .map((token) => token.trim().toLowerCase())
      .filter(Boolean)
  );

  for (const key of Object.keys(headers)) {
    const lowered = key.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lowered) || connectionTokens.has(lowered)) {
      delete headers[key];
    }
  }

  return headers;
}

function filterUpstreamResponseHeaders(responseHeaders = {}) {
  const connectionTokens = new Set(
    String(responseHeaders.connection || '')
      .split(',')
      .map((token) => token.trim().toLowerCase())
      .filter(Boolean)
  );
  const filtered = {};
  for (const [key, value] of Object.entries(responseHeaders)) {
    const lowered = String(key).toLowerCase();
    if (lowered === 'content-length') {
      continue;
    }
    if (HOP_BY_HOP_HEADERS.has(lowered) || connectionTokens.has(lowered)) {
      continue;
    }
    filtered[key] = value;
  }
  return filtered;
}

function positiveIntOr(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

module.exports = {
  HOP_BY_HOP_HEADERS,
  safeJsonParse,
  tryParseJson,
  flattenFindings,
  highestSeverity,
  responseHeaderDiagnostics,
  formatBudgetUsd,
  setBudgetHeaders,
  scrubForwardHeaders,
  filterUpstreamResponseHeaders,
  positiveIntOr,
  sleep,
};
