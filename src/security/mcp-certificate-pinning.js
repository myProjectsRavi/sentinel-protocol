const {
  clampPositiveInt,
  normalizeMode,
  normalizeSessionValue,
  toObject,
} = require('../utils/primitives');

function normalizeFingerprint(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (!raw) {
    return '';
  }
  const withoutPrefix = raw.startsWith('sha256:') ? raw.slice('sha256:'.length) : raw;
  const compact = withoutPrefix.replace(/[^a-f0-9]/g, '');
  if (compact.length !== 64) {
    return '';
  }
  return compact;
}

function normalizePinMap(input = {}) {
  const safe = toObject(input);
  const out = new Map();
  for (const [serverIdRaw, value] of Object.entries(safe)) {
    const serverId = normalizeSessionValue(serverIdRaw, 160);
    if (!serverId) {
      continue;
    }
    const pins = (Array.isArray(value) ? value : [value])
      .map((item) => normalizeFingerprint(item))
      .filter(Boolean)
      .slice(0, 32);
    if (pins.length === 0) {
      continue;
    }
    out.set(serverId, pins);
  }
  return out;
}

class MCPCertificatePinning {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.serverIdHeader = String(config.server_id_header || 'x-sentinel-mcp-server-id').toLowerCase();
    this.fingerprintHeader = String(config.fingerprint_header || 'x-sentinel-mcp-cert-sha256').toLowerCase();
    this.allowUnpinnedServers = config.allow_unpinned_servers !== false;
    this.requireFingerprintForPinnedServers = config.require_fingerprint_for_pinned_servers !== false;
    this.detectRotation = config.detect_rotation !== false;
    this.blockOnMismatch = config.block_on_mismatch === true;
    this.blockOnRotation = config.block_on_rotation === true;
    this.maxServers = clampPositiveInt(config.max_servers, 5000, 8, 1_000_000);
    this.ttlMs = clampPositiveInt(config.ttl_ms, 3600000, 1000, 7 * 24 * 3600000);
    this.observability = config.observability !== false;

    this.pins = normalizePinMap(config.pins || {});
    this.observed = new Map();
  }

  isEnabled() {
    return this.enabled === true;
  }

  prune(nowMs) {
    const minUpdated = nowMs - this.ttlMs;
    for (const [serverId, state] of this.observed.entries()) {
      if (Number(state?.updatedAt || 0) < minUpdated) {
        this.observed.delete(serverId);
      }
    }
    while (this.observed.size > this.maxServers) {
      const oldest = this.observed.keys().next().value;
      if (!oldest) {
        break;
      }
      this.observed.delete(oldest);
    }
  }

  resolveServerId(headers = {}, fallbackServerId = '') {
    const fromHeader = normalizeSessionValue(headers[this.serverIdHeader] || '', 160);
    if (fromHeader) {
      return fromHeader;
    }
    return normalizeSessionValue(fallbackServerId || '', 160) || 'unknown';
  }

  inspect({
    headers = {},
    serverId = '',
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

    const resolvedServerId = this.resolveServerId(headers, serverId);
    const fingerprint = normalizeFingerprint(headers[this.fingerprintHeader] || '');
    const findings = [];
    const expectedPins = this.pins.get(resolvedServerId) || [];

    if (expectedPins.length > 0) {
      if (!fingerprint && this.requireFingerprintForPinnedServers) {
        findings.push({
          code: 'mcp_certificate_missing',
          server_id: resolvedServerId,
          blockEligible: this.blockOnMismatch,
        });
      } else if (fingerprint && !expectedPins.includes(fingerprint)) {
        findings.push({
          code: 'mcp_certificate_pin_mismatch',
          server_id: resolvedServerId,
          observed_fingerprint_prefix: fingerprint.slice(0, 16),
          expected_pin_count: expectedPins.length,
          blockEligible: this.blockOnMismatch,
        });
      }
    } else if (!this.allowUnpinnedServers) {
      findings.push({
        code: 'mcp_certificate_unpinned_server',
        server_id: resolvedServerId,
        blockEligible: this.blockOnMismatch,
      });
    }

    if (this.detectRotation && fingerprint) {
      const previous = this.observed.get(resolvedServerId);
      if (previous && previous.fingerprint && previous.fingerprint !== fingerprint) {
        findings.push({
          code: 'mcp_certificate_rotation_detected',
          server_id: resolvedServerId,
          previous_fingerprint_prefix: String(previous.fingerprint).slice(0, 16),
          current_fingerprint_prefix: fingerprint.slice(0, 16),
          blockEligible: this.blockOnRotation,
        });
      }
      this.observed.set(resolvedServerId, {
        fingerprint,
        updatedAt: nowMs,
      });
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
      reason: detected ? String(findings[0].code || 'mcp_certificate_pinning_violation') : 'clean',
      findings,
      server_id: resolvedServerId,
      fingerprint_present: Boolean(fingerprint),
      fingerprint_prefix: fingerprint ? fingerprint.slice(0, 16) : '',
      expected_pin_count: expectedPins.length,
    };
  }
}

module.exports = {
  MCPCertificatePinning,
  normalizeFingerprint,
};
