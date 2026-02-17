const IDEMPOTENT_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);

function parseRetryAfterMs(headerValue) {
  if (!headerValue) {
    return null;
  }

  const numeric = Number(headerValue);
  if (Number.isFinite(numeric)) {
    return Math.max(0, numeric * 1000);
  }

  const date = Date.parse(headerValue);
  if (Number.isFinite(date)) {
    return Math.max(0, date - Date.now());
  }

  return null;
}

function jitterBackoffMs() {
  return 250 + Math.floor(Math.random() * 500);
}

function methodRetryEligible(method, config, headers = {}) {
  const upper = String(method || '').toUpperCase();
  if (IDEMPOTENT_METHODS.has(upper)) {
    return true;
  }

  if (upper !== 'POST') {
    return false;
  }

  if (!config.allow_post_with_idempotency_key) {
    return false;
  }

  return Boolean(headers['x-sentinel-idempotency-key']);
}

function shouldRetryResponse(statusCode) {
  return statusCode === 429 || statusCode === 503;
}

function shouldRetryError(errorType) {
  return errorType === 'timeout' || errorType === 'transport';
}

module.exports = {
  parseRetryAfterMs,
  jitterBackoffMs,
  methodRetryEligible,
  shouldRetryResponse,
  shouldRetryError,
};
