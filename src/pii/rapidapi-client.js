const { URL } = require('url');
const crypto = require('crypto');

function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function normalizeSeverity(value) {
  const raw = String(value || '').toLowerCase();
  if (raw === 'critical' || raw === 'high' || raw === 'medium' || raw === 'low') {
    return raw;
  }
  if (raw.includes('critical')) return 'critical';
  if (raw.includes('high')) return 'high';
  if (raw.includes('low')) return 'low';
  return 'medium';
}

function flattenFindings(input) {
  if (!Array.isArray(input)) {
    return [];
  }

  return input.map((item) => ({
    id: String(item?.type || item?.id || item?.label || 'rapidapi_match'),
    severity: normalizeSeverity(item?.severity || item?.risk || item?.classification),
    value: String(item?.value || item?.match || item?.text || ''),
  }));
}

function extractResponsePayload(json) {
  if (!json || typeof json !== 'object') {
    return { redactedText: null, findings: [] };
  }

  const directRedacted = json.redacted_text || json.redactedText || json.redacted || json.sanitized_text || json.sanitized;
  const directFindings = json.findings || json.entities || json.matches || json.pii;
  if (directRedacted || directFindings) {
    return {
      redactedText: typeof directRedacted === 'string' ? directRedacted : null,
      findings: flattenFindings(directFindings),
    };
  }

  const nested = json.data || json.result || json.output;
  if (nested && typeof nested === 'object') {
    const nestedRedacted = nested.redacted_text || nested.redactedText || nested.redacted || nested.sanitized_text || nested.sanitized;
    const nestedFindings = nested.findings || nested.entities || nested.matches || nested.pii;
    return {
      redactedText: typeof nestedRedacted === 'string' ? nestedRedacted : null,
      findings: flattenFindings(nestedFindings),
    };
  }

  return { redactedText: null, findings: [] };
}

function highestSeverity(findings) {
  const rank = { low: 1, medium: 2, high: 3, critical: 4 };
  let out = null;
  for (const finding of findings) {
    if (!out || rank[finding.severity] > rank[out]) {
      out = finding.severity;
    }
  }
  return out;
}

function deriveRapidApiHost(endpoint, configuredHost) {
  if (configuredHost) {
    return String(configuredHost);
  }
  const parsed = new URL(endpoint);
  return parsed.host;
}

function resolveRapidApiKey(requestHeaders, config) {
  return (
    requestHeaders['x-sentinel-rapidapi-key'] ||
    process.env.SENTINEL_RAPIDAPI_KEY ||
    config.api_key ||
    ''
  );
}

function classifyStatus(statusCode) {
  if (statusCode === 401 || statusCode === 403) {
    return 'rapidapi_auth';
  }
  if (statusCode === 429) {
    return 'rapidapi_quota';
  }
  if (statusCode >= 500) {
    return 'rapidapi_server';
  }
  return 'rapidapi_error';
}

function classifyFetchError(error) {
  const name = String(error?.name || '');
  if (name === 'TimeoutError' || name === 'AbortError') {
    return 'rapidapi_timeout';
  }
  return 'rapidapi_transport';
}

function hashText(input) {
  return crypto.createHash('sha256').update(String(input || ''), 'utf8').digest('hex');
}

class LruTtlCache {
  constructor(options = {}) {
    this.maxEntries = Number(options.maxEntries || 1024);
    this.ttlMs = Number(options.ttlMs || 300000);
    this.map = new Map();
  }

  get(key) {
    if (!this.map.has(key)) {
      return null;
    }
    const entry = this.map.get(key);
    if (Date.now() > entry.expiresAt) {
      this.map.delete(key);
      return null;
    }
    this.map.delete(key);
    this.map.set(key, entry);
    return entry.value;
  }

  set(key, value) {
    if (this.maxEntries <= 0 || this.ttlMs < 0) {
      return;
    }
    while (this.map.size >= this.maxEntries) {
      const oldest = this.map.keys().next().value;
      this.map.delete(oldest);
    }
    this.map.set(key, {
      value,
      expiresAt: Date.now() + this.ttlMs,
    });
  }
}

function validateEndpoint(endpoint, allowNonRapidApiHost) {
  let parsed;
  try {
    parsed = new URL(String(endpoint));
  } catch {
    throw new Error('Invalid RapidAPI endpoint URL');
  }

  if (parsed.protocol !== 'https:') {
    throw new Error('RapidAPI endpoint must use https');
  }

  if (!allowNonRapidApiHost) {
    const host = parsed.hostname.toLowerCase();
    const allowed = host.endsWith('.rapidapi.com') || host === 'rapidapi.com';
    if (!allowed) {
      throw new Error('RapidAPI endpoint host must be rapidapi.com or *.rapidapi.com');
    }
  }

  return parsed.toString();
}

class RapidApiPIIClient {
  constructor(config = {}) {
    this.config = config;
    this.maxTimeoutMs = Number(config.max_timeout_ms ?? 1500);
    this.timeoutMs = Math.min(Number(config.timeout_ms ?? 4000), this.maxTimeoutMs);
    this.cache = new LruTtlCache({
      maxEntries: Number(config.cache_max_entries ?? 1024),
      ttlMs: Number(config.cache_ttl_ms ?? 300000),
    });
  }

  buildCacheKey(text, field, endpoint) {
    const endpointKey = String(endpoint || '');
    const fieldKey = String(field || 'text');
    return `${endpointKey}|${fieldKey}|${hashText(text)}`;
  }

  async scan(text, requestHeaders = {}) {
    const endpoint = validateEndpoint(this.config.endpoint, Boolean(this.config.allow_non_rapidapi_host));
    const apiKey = resolveRapidApiKey(requestHeaders, this.config);
    if (!apiKey) {
      const error = new Error('RapidAPI key missing. Provide x-sentinel-rapidapi-key or SENTINEL_RAPIDAPI_KEY.');
      error.kind = 'rapidapi_no_key';
      throw error;
    }

    const host = deriveRapidApiHost(endpoint, this.config.host);
    const field = this.config.request_body_field || 'text';
    const cacheKey = this.buildCacheKey(text, field, endpoint);
    const cached = this.cache.get(cacheKey);
    if (cached) {
      return {
        ...cached,
        cacheHit: true,
      };
    }
    const payload = {
      [field]: text,
      ...(typeof this.config.extra_body === 'object' && this.config.extra_body ? this.config.extra_body : {}),
    };

    const signal = AbortSignal.timeout(this.timeoutMs);
    let response;
    try {
      response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-rapidapi-key': apiKey,
          'x-rapidapi-host': host,
        },
        body: JSON.stringify(payload),
        signal,
      });
    } catch (error) {
      error.kind = classifyFetchError(error);
      throw error;
    }

    const raw = await response.text();
    if (!response.ok) {
      const error = new Error(`RapidAPI request failed with status ${response.status}`);
      error.kind = classifyStatus(response.status);
      error.status = response.status;
      error.body = raw;
      throw error;
    }

    const json = safeJsonParse(raw);
    const extracted = extractResponsePayload(json);

    const result = {
      findings: extracted.findings,
      redactedText: extracted.redactedText || text,
      highestSeverity: highestSeverity(extracted.findings),
      scanTruncated: false,
      rawResponse: json,
      cacheHit: false,
    };
    this.cache.set(cacheKey, {
      findings: result.findings,
      redactedText: result.redactedText,
      highestSeverity: result.highestSeverity,
      scanTruncated: result.scanTruncated,
      rawResponse: result.rawResponse,
    });
    return result;
  }
}

module.exports = {
  RapidApiPIIClient,
  normalizeSeverity,
  extractResponsePayload,
};
