class PolicyEngine {
  constructor(config, rateLimiter) {
    this.rules = Array.isArray(config.rules) ? config.rules : [];
    this.whitelistDomains = Array.isArray(config.whitelist?.domains) ? config.whitelist.domains : [];
    this.rateLimiter = rateLimiter;
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
    } = context;

    if (this.isWhitelisted(hostname)) {
      return {
        matched: false,
        action: 'allow',
        allowed: true,
        reason: 'whitelisted',
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
        reason: action === 'block' ? 'policy_violation' : 'policy_match',
        rule: rule.name,
        message: rule.message || `Policy rule matched: ${rule.name}`,
      };
    }

    return {
      matched: false,
      action: 'allow',
      allowed: true,
      reason: 'no_matching_rule',
    };
  }
}

module.exports = {
  PolicyEngine,
};
