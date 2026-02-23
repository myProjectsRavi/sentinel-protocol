const crypto = require('crypto');
const os = require('os');
const { clampPositiveInt } = require('../utils/primitives');

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

function sha256(input = '') {
  return crypto.createHash('sha256').update(String(input || ''), 'utf8').digest('hex');
}

class ComputeAttestation {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.keyId = String(config.key_id || `sentinel-attestation-${process.pid}`);
    this.secret = String(config.secret || process.env.SENTINEL_ATTESTATION_SECRET || '');
    this.exposeVerifyEndpoint = config.expose_verify_endpoint !== false;
    this.maxConfigChars = clampPositiveInt(config.max_config_chars, 4096, 64, 262144);
    this.includeEnvironment = config.include_environment === true;
    this.version = 'v1';
    this.algorithm = 'hmac-sha256';
  }

  isEnabled() {
    return this.enabled === true;
  }

  buildPayload({
    configHash,
    policyHash,
    correlationId,
    provider,
  } = {}) {
    const payload = {
      v: this.version,
      alg: this.algorithm,
      key_id: this.keyId,
      ts: new Date().toISOString(),
      provider: String(provider || 'unknown'),
      correlation_id: String(correlationId || ''),
      runtime: {
        node: process.version,
        platform: process.platform,
        arch: process.arch,
        release: os.release(),
        hostname_hash: sha256(os.hostname()).slice(0, 16),
        pid: process.pid,
      },
      config_hash: String(configHash || ''),
      policy_hash: String(policyHash || ''),
    };

    if (this.includeEnvironment) {
      payload.environment = {
        sentinel_home_hash: sha256(String(process.env.HOME || '')).slice(0, 16),
        node_env: String(process.env.NODE_ENV || 'unknown').slice(0, 64),
      };
    }

    return payload;
  }

  signPayload(payload) {
    const canonical = JSON.stringify(stableObject(payload)).slice(0, this.maxConfigChars);
    const body = Buffer.from(canonical, 'utf8').toString('base64url');
    const secret = this.secret || `sentinel-attestation:${this.keyId}`;
    const sig = crypto
      .createHmac('sha256', secret)
      .update(body, 'utf8')
      .digest('base64url');
    return `${body}.${sig}`;
  }

  create({ configHash, policyHash, correlationId, provider } = {}) {
    if (!this.isEnabled()) {
      return null;
    }
    const payload = this.buildPayload({
      configHash,
      policyHash,
      correlationId,
      provider,
    });
    const envelope = this.signPayload(payload);
    return {
      envelope,
      payload,
    };
  }

  parse(envelope = '') {
    const raw = String(envelope || '').trim();
    const parts = raw.split('.');
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      return {
        ok: false,
        reason: 'attestation_format_invalid',
      };
    }

    let payload;
    try {
      payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    } catch {
      return {
        ok: false,
        reason: 'attestation_payload_invalid',
      };
    }

    return {
      ok: true,
      payload,
      payloadB64: parts[0],
      signature: parts[1],
    };
  }

  verify(envelope = '') {
    if (!this.isEnabled()) {
      return {
        valid: false,
        reason: 'attestation_disabled',
      };
    }

    const parsed = this.parse(envelope);
    if (!parsed.ok) {
      return {
        valid: false,
        reason: parsed.reason,
      };
    }

    const secret = this.secret || `sentinel-attestation:${this.keyId}`;
    const expected = crypto
      .createHmac('sha256', secret)
      .update(parsed.payloadB64, 'utf8')
      .digest('base64url');

    const sigBuf = Buffer.from(String(parsed.signature || ''), 'utf8');
    const expBuf = Buffer.from(String(expected || ''), 'utf8');
    const valid = sigBuf.length === expBuf.length && crypto.timingSafeEqual(sigBuf, expBuf);

    return {
      valid,
      reason: valid ? 'ok' : 'signature_invalid',
      payload: parsed.payload,
    };
  }
}

module.exports = {
  ComputeAttestation,
};
