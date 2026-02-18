const { InjectionScanner } = require('./injection-scanner');

class PolicyEngine {
  constructor(config, rateLimiter) {
    this.rules = Array.isArray(config.rules) ? config.rules : [];
    this.whitelistDomains = Array.isArray(config.whitelist?.domains) ? config.whitelist.domains : [];
    this.rateLimiter = rateLimiter;
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
        const allowed = this.rateLimiter.consume({
          key: rateLimitKey || headers['x-sentinel-agent-id'] || 'default',
          limit: Number(match.requests_per_minute),
          provider,
        });
        if (allowed) {
          continue;
        }
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
      };
    }

    return {
      matched: false,
      action: 'allow',
      allowed: true,
      reason: 'no_matching_rule',
      injection: injectionResult,
    };
  }
}

module.exports = {
  PolicyEngine,
};
