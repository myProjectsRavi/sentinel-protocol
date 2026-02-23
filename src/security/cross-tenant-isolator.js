const {
  clampPositiveInt,
  normalizeMode,
  normalizeSessionValue,
} = require('../utils/primitives');

function toObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return value;
}

function normalizeTenant(value) {
  return normalizeSessionValue(value || '', 128).toLowerCase();
}

class CrossTenantIsolator {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.tenantHeader = String(config.tenant_header || 'x-sentinel-tenant-id').toLowerCase();
    this.sessionHeader = String(config.session_header || 'x-sentinel-session-id').toLowerCase();
    this.fallbackHeaders = Array.isArray(config.fallback_headers)
      ? config.fallback_headers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
      : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
    this.ttlMs = clampPositiveInt(config.ttl_ms, 6 * 3600 * 1000, 1000, 7 * 24 * 3600 * 1000);
    this.maxSessions = clampPositiveInt(config.max_sessions, 20000, 32, 1000000);
    this.maxKnownTenants = clampPositiveInt(config.max_known_tenants, 20000, 8, 1000000);
    this.blockOnMismatch = config.block_on_mismatch === true;
    this.blockOnLeak = config.block_on_leak === true;
    this.observability = config.observability !== false;

    this.sessions = new Map();
    this.knownTenants = new Set();
  }

  isEnabled() {
    return this.enabled === true;
  }

  prune(nowMs) {
    const minUpdatedAt = nowMs - this.ttlMs;
    for (const [sessionId, entry] of this.sessions.entries()) {
      if (Number(entry?.updatedAt || 0) < minUpdatedAt) {
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
    while (this.knownTenants.size > this.maxKnownTenants) {
      const first = this.knownTenants.values().next().value;
      if (!first) {
        break;
      }
      this.knownTenants.delete(first);
    }
  }

  resolveSessionId(headers = {}, correlationId = '') {
    const safeHeaders = toObject(headers);
    const primary = normalizeSessionValue(safeHeaders[this.sessionHeader] || '', 160);
    if (primary) {
      return primary;
    }
    for (const header of this.fallbackHeaders) {
      const candidate = normalizeSessionValue(safeHeaders[header] || '', 160);
      if (candidate) {
        return candidate;
      }
    }
    return normalizeSessionValue(correlationId || 'anonymous', 160) || 'anonymous';
  }

  resolveTenant(headers = {}, bodyJson = {}) {
    const safeHeaders = toObject(headers);
    const payload = toObject(bodyJson);
    const fromHeader = normalizeTenant(safeHeaders[this.tenantHeader]);
    if (fromHeader) {
      return fromHeader;
    }
    const fromBody = normalizeTenant(payload.tenant_id || payload.tenantId || payload.account_id || payload.accountId);
    return fromBody;
  }

  evaluateIngress({
    headers = {},
    bodyJson = {},
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
        tenant_id: '',
      };
    }

    const nowMs = Date.now();
    this.prune(nowMs);

    const sessionId = this.resolveSessionId(headers, correlationId);
    const tenantId = this.resolveTenant(headers, bodyJson);
    const findings = [];

    if (!tenantId) {
      findings.push({
        code: 'cross_tenant_missing_tenant_id',
        blockEligible: this.blockOnMismatch,
      });
    }

    const existing = this.sessions.get(sessionId);
    if (existing && tenantId && existing.tenantId && existing.tenantId !== tenantId) {
      findings.push({
        code: 'cross_tenant_session_mismatch',
        expected: existing.tenantId,
        observed: tenantId,
        blockEligible: this.blockOnMismatch,
      });
    }

    if (tenantId) {
      this.sessions.set(sessionId, {
        tenantId,
        updatedAt: nowMs,
      });
      this.knownTenants.add(tenantId);
    }

    const detected = findings.length > 0;
    const shouldBlock =
      detected &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce' &&
      findings.some((item) => item.blockEligible === true);

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      reason: detected ? String(findings[0].code || 'cross_tenant_violation') : 'clean',
      findings,
      tenant_id: tenantId,
      session_id: sessionId,
    };
  }

  evaluateEgress({
    tenantId,
    bodyBuffer,
    text,
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

    const tenant = normalizeTenant(tenantId || '');
    const content = typeof text === 'string'
      ? text
      : Buffer.isBuffer(bodyBuffer)
        ? bodyBuffer.toString('utf8')
        : String(text || '');

    if (!content) {
      return {
        enabled: true,
        mode: this.mode,
        detected: false,
        shouldBlock: false,
        reason: 'clean',
        findings: [],
      };
    }

    const findings = [];
    let checked = 0;
    for (const known of this.knownTenants) {
      checked += 1;
      if (checked > 512) {
        break;
      }
      if (!known || known === tenant) {
        continue;
      }
      if (content.toLowerCase().includes(known)) {
        findings.push({
          code: 'cross_tenant_egress_leak',
          leaked_tenant: known,
          blockEligible: this.blockOnLeak,
        });
      }
      if (findings.length >= 8) {
        break;
      }
    }

    const detected = findings.length > 0;
    const shouldBlock =
      detected &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce' &&
      findings.some((item) => item.blockEligible === true);

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      reason: detected ? String(findings[0].code || 'cross_tenant_leak') : 'clean',
      findings,
      tenant_id: tenant,
    };
  }
}

module.exports = {
  CrossTenantIsolator,
};
