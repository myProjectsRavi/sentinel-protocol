const crypto = require('crypto');
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

function stableObject(value) {
  if (value === null || value === undefined) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => stableObject(item));
  }
  if (typeof value !== 'object') {
    return value;
  }
  const out = {};
  for (const key of Object.keys(value).sort()) {
    out[key] = stableObject(value[key]);
  }
  return out;
}

function b64url(input) {
  return Buffer.from(String(input), 'utf8').toString('base64url');
}

function safeJsonParse(input) {
  try {
    return JSON.parse(String(input || ''));
  } catch {
    return null;
  }
}

class AgentIdentityFederation {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.tokenHeader = String(config.token_header || 'x-sentinel-agent-token').toLowerCase();
    this.agentIdHeader = String(config.agent_id_header || 'x-sentinel-agent-id').toLowerCase();
    this.correlationHeader = String(config.correlation_header || 'x-sentinel-correlation-id').toLowerCase();
    this.hmacSecret = String(config.hmac_secret || process.env.SENTINEL_AGENT_IDENTITY_HMAC || '');
    this.ttlMs = clampPositiveInt(config.ttl_ms, 900000, 1000, 7 * 24 * 3600 * 1000);
    this.maxChainDepth = clampPositiveInt(config.max_chain_depth, 8, 1, 128);
    this.maxReplayEntries = clampPositiveInt(config.max_replay_entries, 10000, 32, 1_000_000);
    this.blockOnInvalidToken = config.block_on_invalid_token === true;
    this.blockOnCapabilityWiden = config.block_on_capability_widen === true;
    this.blockOnReplay = config.block_on_replay === true;
    this.observability = config.observability !== false;
    this.replay = new Map();
  }

  isEnabled() {
    return this.enabled === true;
  }

  cleanupReplay(nowMs) {
    for (const [key, expiry] of this.replay.entries()) {
      if (Number(expiry || 0) <= nowMs) {
        this.replay.delete(key);
      }
    }
    while (this.replay.size > this.maxReplayEntries) {
      const oldest = this.replay.keys().next().value;
      if (!oldest) {
        break;
      }
      this.replay.delete(oldest);
    }
  }

  signature(payloadB64) {
    return crypto
      .createHmac('sha256', this.hmacSecret || 'sentinel-agent-identity-default')
      .update(String(payloadB64), 'utf8')
      .digest('base64url');
  }

  issueToken({
    agentId,
    capabilities = [],
    correlationId = '',
    parentCapabilities = null,
    expiresAt = null,
  } = {}) {
    const nowMs = Date.now();
    const payload = {
      v: 1,
      agent_id: normalizeSessionValue(agentId || '', 128),
      capabilities: Array.isArray(capabilities)
        ? capabilities.map((item) => String(item || '').trim()).filter(Boolean).slice(0, 128)
        : [],
      correlation_id: normalizeSessionValue(correlationId || '', 128),
      parent_capabilities: Array.isArray(parentCapabilities)
        ? parentCapabilities.map((item) => String(item || '').trim()).filter(Boolean).slice(0, 128)
        : null,
      iat_ms: nowMs,
      exp_ms:
        expiresAt !== null && expiresAt !== undefined && Number.isFinite(Number(expiresAt))
          ? Number(expiresAt)
          : nowMs + this.ttlMs,
    };
    const payloadB64 = b64url(JSON.stringify(stableObject(payload)));
    const sig = this.signature(payloadB64);
    return `${payloadB64}.${sig}`;
  }

  decodeToken(token) {
    const raw = String(token || '');
    const parts = raw.split('.');
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      return { ok: false, reason: 'token_format_invalid' };
    }
    const payloadJson = Buffer.from(parts[0], 'base64url').toString('utf8');
    const payload = safeJsonParse(payloadJson);
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return { ok: false, reason: 'token_payload_invalid' };
    }
    return {
      ok: true,
      payloadB64: parts[0],
      signature: parts[1],
      payload,
    };
  }

  evaluate({
    headers = {},
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
    this.cleanupReplay(nowMs);
    const lookup = toObject(headers);
    const token = String(lookup[this.tokenHeader] || '');
    const headerAgentId = normalizeSessionValue(lookup[this.agentIdHeader] || '', 128);
    const correlationId = normalizeSessionValue(lookup[this.correlationHeader] || '', 128);
    const findings = [];

    if (!token) {
      findings.push({
        code: 'agent_identity_token_missing',
        blockEligible: this.blockOnInvalidToken,
      });
    } else {
      const decoded = this.decodeToken(token);
      if (!decoded.ok) {
        findings.push({
          code: decoded.reason,
          blockEligible: this.blockOnInvalidToken,
        });
      } else {
        const expectedSig = this.signature(decoded.payloadB64);
        const sigBuf = Buffer.from(String(decoded.signature || ''));
        const expBuf = Buffer.from(String(expectedSig || ''));
        const validSig = sigBuf.length === expBuf.length
          && crypto.timingSafeEqual(sigBuf, expBuf);
        if (!validSig) {
          findings.push({
            code: 'agent_identity_signature_invalid',
            blockEligible: this.blockOnInvalidToken,
          });
        }

        const payload = decoded.payload;
        if (Number(payload.exp_ms || 0) <= nowMs) {
          findings.push({
            code: 'agent_identity_token_expired',
            blockEligible: this.blockOnInvalidToken,
          });
        }
        if (headerAgentId && String(payload.agent_id || '') !== headerAgentId) {
          findings.push({
            code: 'agent_identity_claim_mismatch',
            blockEligible: this.blockOnInvalidToken,
          });
        }
        if (correlationId && String(payload.correlation_id || '') !== correlationId) {
          findings.push({
            code: 'agent_identity_correlation_mismatch',
            blockEligible: this.blockOnInvalidToken,
          });
        }

        const caps = Array.isArray(payload.capabilities) ? payload.capabilities : [];
        const parentCaps = Array.isArray(payload.parent_capabilities) ? payload.parent_capabilities : null;
        if (parentCaps && caps.some((cap) => !parentCaps.includes(cap))) {
          findings.push({
            code: 'agent_identity_capability_widen',
            blockEligible: this.blockOnCapabilityWiden,
          });
        }

        const chainDepth = Number(payload.chain_depth || (parentCaps ? 2 : 1));
        if (chainDepth > this.maxChainDepth) {
          findings.push({
            code: 'agent_identity_chain_depth_exceeded',
            blockEligible: this.blockOnInvalidToken,
          });
        }

        const replayKey = `${payload.agent_id || ''}:${payload.iat_ms || ''}:${payload.correlation_id || ''}`;
        if (this.replay.has(replayKey)) {
          findings.push({
            code: 'agent_identity_replay_detected',
            blockEligible: this.blockOnReplay,
          });
        } else {
          this.replay.set(replayKey, Number(payload.exp_ms || nowMs + this.ttlMs));
        }
      }
    }

    const detected = findings.length > 0;
    const blockEligible = findings.some((item) => item.blockEligible === true);
    const shouldBlock =
      detected &&
      blockEligible &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce';

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      reason: detected ? String(findings[0].code || 'agent_identity_invalid') : 'clean',
      findings,
      replay_entries: this.replay.size,
    };
  }
}

module.exports = {
  AgentIdentityFederation,
};
