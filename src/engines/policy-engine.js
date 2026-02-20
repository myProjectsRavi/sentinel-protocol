const { InjectionScanner } = require('./injection-scanner');

const DEFAULT_RATE_LIMIT_KEY_HEADERS = ['x-sentinel-agent-id', 'x-sentinel-session-id'];
const DEFAULT_RATE_LIMIT_FALLBACK_HEADERS = [
  'x-forwarded-for',
  'x-real-ip',
  'cf-connecting-ip',
  'x-client-ip',
  'user-agent',
];
const IP_HEADER_HINTS = new Set([
  'x-forwarded-for',
  'x-real-ip',
  'cf-connecting-ip',
  'x-client-ip',
  'forwarded',
]);

function normalizeHeaderName(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return normalized;
}

function normalizeHeaderList(value, fallback = []) {
  const source = Array.isArray(value) ? value : fallback;
  const out = [];
  const seen = new Set();
  for (const item of source) {
    const normalized = normalizeHeaderName(item);
    if (!normalized || seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    out.push(normalized);
  }
  return out;
}

function buildHeaderLookup(headers) {
  const lookup = new Map();
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) {
    return lookup;
  }
  for (const [name, value] of Object.entries(headers)) {
    const headerName = normalizeHeaderName(name);
    if (!headerName) {
      continue;
    }
    const normalizedValue = Array.isArray(value) ? value[0] : value;
    if (normalizedValue === undefined || normalizedValue === null) {
      continue;
    }
    const asText = String(normalizedValue).trim();
    if (!asText) {
      continue;
    }
    lookup.set(headerName, asText);
  }
  return lookup;
}

function extractFirstForwardedIp(value) {
  const first = String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)[0];
  return first || '';
}

function normalizeRateLimitIdentity(value) {
  const normalized = String(value || '').trim();
  if (!normalized) {
    return '';
  }
  return normalized.length > 512 ? normalized.slice(0, 512) : normalized;
}

class PolicyEngine {
  constructor(config, rateLimiter) {
    this.rules = Array.isArray(config.rules) ? config.rules : [];
    this.whitelistDomains = Array.isArray(config.whitelist?.domains) ? config.whitelist.domains : [];
    this.rateLimiter = rateLimiter;
    this.rateLimiterConfig =
      config.runtime?.rate_limiter && typeof config.runtime.rate_limiter === 'object'
        ? config.runtime.rate_limiter
        : {};
    this.rateLimiterKeyHeaders = normalizeHeaderList(
      this.rateLimiterConfig.key_headers,
      DEFAULT_RATE_LIMIT_KEY_HEADERS
    );
    this.rateLimiterFallbackHeaders = normalizeHeaderList(
      this.rateLimiterConfig.fallback_key_headers,
      DEFAULT_RATE_LIMIT_FALLBACK_HEADERS
    );
    this.rateLimiterIpHeader =
      normalizeHeaderName(this.rateLimiterConfig.ip_header) || DEFAULT_RATE_LIMIT_FALLBACK_HEADERS[0];
    this.injectionConfig = config.injection || {};
    this.injectionScanner = new InjectionScanner({
      maxScanBytes: this.injectionConfig.max_scan_bytes,
    });
  }

  isWhitelisted(hostname) {
    if (!hostname) {
      return false;
    }

    return this.whitelistDomains.some((entry) => {
      if (entry.startsWith('*.')) {
        const suffix = entry.slice(1);
        return hostname.endsWith(suffix);
      }
      return hostname === entry;
    });
  }

  matchDomain(pattern, hostname) {
    if (!pattern) {
      return true;
    }
    if (!hostname) {
      return false;
    }
    if (pattern.startsWith('*.')) {
      return hostname.endsWith(pattern.slice(1));
    }
    return hostname === pattern;
  }

  matchToolName(expected, bodyJson) {
    if (!expected) {
      return true;
    }
    const toolName = bodyJson?.tool?.name || bodyJson?.tool_name || bodyJson?.name;
    return toolName === expected;
  }

  scanInjection(bodyText, providedInjectionResult) {
    return this.injectionConfig.enabled === false
      ? { score: 0, matchedSignals: [], scanTruncated: false }
      : providedInjectionResult || this.injectionScanner.scan(bodyText || '', {
          maxScanBytes: this.injectionConfig.max_scan_bytes,
        });
  }

  headerIdentityValue(headerLookup, headerName) {
    const normalizedName = normalizeHeaderName(headerName);
    if (!normalizedName || !headerLookup.has(normalizedName)) {
      return '';
    }
    const raw = headerLookup.get(normalizedName);
    const value = IP_HEADER_HINTS.has(normalizedName) ? extractFirstForwardedIp(raw) : raw;
    return normalizeRateLimitIdentity(value);
  }

  resolveRateLimitIdentity({ rateLimitKey, headers, clientIp }) {
    const explicit = normalizeRateLimitIdentity(rateLimitKey);
    if (explicit) {
      return {
        key: explicit,
        source: 'explicit',
      };
    }

    const headerLookup = buildHeaderLookup(headers);
    for (const headerName of this.rateLimiterKeyHeaders) {
      const candidate = this.headerIdentityValue(headerLookup, headerName);
      if (candidate) {
        return {
          key: `${headerName}:${candidate}`,
          source: `header:${headerName}`,
        };
      }
    }

    const ipCandidate = this.headerIdentityValue(headerLookup, this.rateLimiterIpHeader);
    if (ipCandidate) {
      return {
        key: `ip:${ipCandidate}`,
        source: `header:${this.rateLimiterIpHeader}`,
      };
    }

    for (const headerName of this.rateLimiterFallbackHeaders) {
      if (headerName === this.rateLimiterIpHeader) {
        continue;
      }
      const candidate = this.headerIdentityValue(headerLookup, headerName);
      if (candidate) {
        return {
          key: `${headerName}:${candidate}`,
          source: `header:${headerName}`,
        };
      }
    }

    const clientIpIdentity = normalizeRateLimitIdentity(extractFirstForwardedIp(clientIp));
    if (clientIpIdentity) {
      return {
        key: `ip:${clientIpIdentity}`,
        source: 'client_ip',
      };
    }

    return {
      key: 'anonymous',
      source: 'anonymous',
    };
  }

  check(context) {
    const {
      method,
      hostname,
      pathname,
      bodyText,
      bodyJson,
      requestBytes,
      headers,
      provider,
      rateLimitKey,
      clientIp,
      injectionResult: providedInjectionResult,
    } = context;

    const injectionResult = this.scanInjection(bodyText, providedInjectionResult);

    if (this.isWhitelisted(hostname)) {
      return {
        matched: false,
        action: 'allow',
        allowed: true,
        reason: 'whitelisted',
        injection: injectionResult,
        rateLimit: null,
      };
    }

    for (const rule of this.rules) {
      const match = rule.match || {};

      if (match.method && String(match.method).toUpperCase() !== method.toUpperCase()) {
        continue;
      }
      if (match.domain && !this.matchDomain(match.domain, hostname)) {
        continue;
      }
      if (match.path_contains && !pathname.includes(match.path_contains)) {
        continue;
      }
      if (match.body_contains && !bodyText.includes(match.body_contains)) {
        continue;
      }
      if (!this.matchToolName(match.tool_name, bodyJson)) {
        continue;
      }
      if (match.body_size_mb && requestBytes / (1024 * 1024) <= Number(match.body_size_mb)) {
        continue;
      }
      if (match.injection_threshold !== undefined && injectionResult.score < Number(match.injection_threshold)) {
        continue;
      }

      if (match.requests_per_minute && this.rateLimiter) {
        const resolvedIdentity = this.resolveRateLimitIdentity({
          rateLimitKey,
          headers,
          clientIp,
        });
        const rateLimit = this.rateLimiter.consume({
          key: resolvedIdentity.key,
          keySource: resolvedIdentity.source,
          scope: rule.name || 'policy-rate-limit',
          limit: Number(match.requests_per_minute),
          provider,
          windowMs: match.rate_limit_window_ms,
          burst: match.rate_limit_burst,
        });
        if (rateLimit.allowed) {
          continue;
        }
        const action = rule.action || 'block';
        return {
          matched: true,
          action,
          allowed: action !== 'block',
          reason: 'rate_limit_exceeded',
          rule: rule.name,
          message: rule.message || `Rate limit exceeded for rule: ${rule.name}`,
          injection: injectionResult,
          rateLimit,
        };
      }

      const action = rule.action || 'allow';
      const allowed = action !== 'block';
      return {
        matched: true,
        action,
        allowed,
        reason:
          match.injection_threshold !== undefined
            ? 'prompt_injection_detected'
            : action === 'block'
              ? 'policy_violation'
              : 'policy_match',
        rule: rule.name,
        message: rule.message || `Policy rule matched: ${rule.name}`,
        injection: injectionResult,
        rateLimit: null,
      };
    }

    return {
      matched: false,
      action: 'allow',
      allowed: true,
      reason: 'no_matching_rule',
      injection: injectionResult,
      rateLimit: null,
    };
  }
}

module.exports = {
  PolicyEngine,
};
