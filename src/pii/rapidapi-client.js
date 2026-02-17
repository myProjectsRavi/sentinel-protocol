const { URL } = require('url');

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
    this.timeoutMs = Number(config.timeout_ms ?? 4000);
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
    const payload = {
      [field]: text,
      ...(typeof this.config.extra_body === 'object' && this.config.extra_body ? this.config.extra_body : {}),
    };

    const signal = AbortSignal.timeout(this.timeoutMs);
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-rapidapi-key': apiKey,
        'x-rapidapi-host': host,
      },
      body: JSON.stringify(payload),
      signal,
    });

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

    return {
      findings: extracted.findings,
      redactedText: extracted.redactedText || text,
      highestSeverity: highestSeverity(extracted.findings),
      scanTruncated: false,
      rawResponse: json,
    };
  }
}

module.exports = {
  RapidApiPIIClient,
  normalizeSeverity,
  extractResponsePayload,
};
