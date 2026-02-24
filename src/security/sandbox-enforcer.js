const { URL } = require('url');
const {
  clampPositiveInt,
  normalizeMode,
  toObject,
} = require('../utils/primitives');

const PATH_ESCAPE_RE = /(?:\.\.[/\\])|(?:^|[/\\])\.\.(?:[/\\]|$)/;
const SCHEME_RE = /\b(?:https?|ftp|file|ssh|tcp):\/\/[^\s'"<>]+/gi;

function normalizePathList(values = []) {
  if (!Array.isArray(values)) {
    return [];
  }
  return values
    .map((item) => String(item || '').trim())
    .filter(Boolean)
    .slice(0, 256);
}

function extractToolArguments(bodyJson = {}) {
  const payload = toObject(bodyJson);
  if (payload.tool_arguments && typeof payload.tool_arguments === 'object' && !Array.isArray(payload.tool_arguments)) {
    return payload.tool_arguments;
  }
  if (payload.arguments && typeof payload.arguments === 'object' && !Array.isArray(payload.arguments)) {
    return payload.arguments;
  }
  return {};
}

function flattenStringValues(value, out, maxItems = 1024) {
  if (out.length >= maxItems) {
    return;
  }
  if (typeof value === 'string') {
    out.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      flattenStringValues(item, out, maxItems);
      if (out.length >= maxItems) {
        break;
      }
    }
    return;
  }
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) {
      flattenStringValues(item, out, maxItems);
      if (out.length >= maxItems) {
        break;
      }
    }
  }
}

class SandboxEnforcer {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.maxArgumentBytes = clampPositiveInt(config.max_argument_bytes, 65536, 128, 8 * 1024 * 1024);
    this.allowedPaths = normalizePathList(config.allowed_paths || []);
    this.allowedDomains = normalizePathList(config.allowed_domains || []);
    this.blockedPorts = Array.isArray(config.blocked_ports)
      ? config.blocked_ports.map((value) => Number(value)).filter((value) => Number.isInteger(value) && value > 0 && value <= 65535).slice(0, 512)
      : [22, 2375, 3306, 5432];
    this.blockOnPathEscape = config.block_on_path_escape === true;
    this.blockOnNetworkEscape = config.block_on_network_escape === true;
    this.observability = config.observability !== false;
  }

  isEnabled() {
    return this.enabled === true;
  }

  evaluate({
    bodyJson = {},
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

    const args = extractToolArguments(bodyJson);
    const argsBytes = Buffer.byteLength(JSON.stringify(args), 'utf8');
    const findings = [];

    if (argsBytes > this.maxArgumentBytes) {
      findings.push({
        code: 'sandbox_argument_budget_exceeded',
        bytes: argsBytes,
        limit: this.maxArgumentBytes,
        blockEligible: this.blockOnPathEscape,
      });
    }

    const values = [];
    flattenStringValues(args, values, 1024);
    for (const value of values) {
      const candidate = String(value || '').slice(0, 4096);
      if (!candidate) {
        continue;
      }
      if (PATH_ESCAPE_RE.test(candidate)) {
        findings.push({
          code: 'sandbox_path_traversal_detected',
          sample: candidate.slice(0, 128),
          blockEligible: this.blockOnPathEscape,
        });
      }
      if (candidate.startsWith('/')) {
        const allowed = this.allowedPaths.some((prefix) => candidate.startsWith(prefix));
        if (!allowed && this.allowedPaths.length > 0) {
          findings.push({
            code: 'sandbox_path_outside_boundary',
            sample: candidate.slice(0, 128),
            blockEligible: this.blockOnPathEscape,
          });
        }
      }

      SCHEME_RE.lastIndex = 0;
      let match;
      while ((match = SCHEME_RE.exec(candidate)) !== null) {
        const urlText = String(match[0] || '');
        let parsed = null;
        try {
          parsed = new URL(urlText);
        } catch {
          parsed = null;
        }
        if (!parsed) {
          findings.push({
            code: 'sandbox_url_parse_failed',
            sample: urlText.slice(0, 128),
            blockEligible: this.blockOnNetworkEscape,
          });
          continue;
        }
        const host = String(parsed.hostname || '').toLowerCase();
        const port = parsed.port ? Number(parsed.port) : 0;
        if (this.allowedDomains.length > 0) {
          const domainAllowed = this.allowedDomains.some((domain) => host === domain || host.endsWith(`.${domain}`));
          if (!domainAllowed) {
            findings.push({
              code: 'sandbox_network_domain_outside_boundary',
              host,
              blockEligible: this.blockOnNetworkEscape,
            });
          }
        }
        if (port > 0 && this.blockedPorts.includes(port)) {
          findings.push({
            code: 'sandbox_network_blocked_port',
            host,
            port,
            blockEligible: this.blockOnNetworkEscape,
          });
        }
        if (String(match[0] || '').length === 0) {
          SCHEME_RE.lastIndex += 1;
        }
      }
      if (findings.length >= 32) {
        break;
      }
    }

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
      reason: detected ? String(findings[0].code || 'sandbox_enforcer_violation') : 'clean',
      findings: findings.slice(0, 32),
      args_bytes: argsBytes,
    };
  }
}

module.exports = {
  SandboxEnforcer,
};
