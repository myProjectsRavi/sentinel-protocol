const crypto = require('crypto');
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

function sha256Buffer(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input || ''), 'utf8');
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function sha256Text(input = '') {
  return crypto.createHash('sha256').update(String(input || ''), 'utf8').digest('hex');
}

function safeJsonParse(input = '') {
  try {
    return JSON.parse(String(input || ''));
  } catch {
    return null;
  }
}

class OutputProvenanceSigner {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.keyId = String(config.key_id || `sentinel-output-${process.pid}`);
    this.algorithm = 'hmac-sha256';
    this.version = 'v1';
    this.secret = String(config.secret || process.env.SENTINEL_OUTPUT_PROVENANCE_SECRET || '');
    this.exposeVerifyEndpoint = config.expose_verify_endpoint !== false;
    this.maxEnvelopeBytes = clampPositiveInt(config.max_envelope_bytes, 2 * 1024 * 1024, 1024, 32 * 1024 * 1024);
  }

  isEnabled() {
    return this.enabled === true;
  }

  signPayload(payload = {}) {
    if (!this.isEnabled()) {
      return null;
    }
    const canonical = JSON.stringify(stableObject(payload));
    const payloadB64 = Buffer.from(canonical, 'utf8').toString('base64url');
    const secret = this.secret || `sentinel-output-provenance:${this.keyId}`;
    const signature = crypto
      .createHmac('sha256', secret)
      .update(payloadB64, 'utf8')
      .digest('base64url');
    return `${payloadB64}.${signature}`;
  }

  parseEnvelope(envelope = '') {
    const raw = String(envelope || '').trim();
    const parts = raw.split('.');
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      return {
        ok: false,
        reason: 'envelope_format_invalid',
      };
    }

    let payload = null;
    try {
      payload = safeJsonParse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    } catch {
      payload = null;
    }
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return {
        ok: false,
        reason: 'envelope_payload_invalid',
      };
    }

    return {
      ok: true,
      payload,
      payloadB64: parts[0],
      signature: parts[1],
    };
  }

  verifyEnvelope({
    envelope,
    expectedOutputSha256,
  } = {}) {
    if (!this.isEnabled()) {
      return {
        valid: false,
        reason: 'signer_disabled',
      };
    }

    const parsed = this.parseEnvelope(envelope);
    if (!parsed.ok) {
      return {
        valid: false,
        reason: parsed.reason,
      };
    }

    const secret = this.secret || `sentinel-output-provenance:${this.keyId}`;
    const expected = crypto
      .createHmac('sha256', secret)
      .update(parsed.payloadB64, 'utf8')
      .digest('base64url');

    const sigBuf = Buffer.from(String(parsed.signature || ''), 'utf8');
    const expBuf = Buffer.from(String(expected || ''), 'utf8');
    const sigValid = sigBuf.length === expBuf.length && crypto.timingSafeEqual(sigBuf, expBuf);
    if (!sigValid) {
      return {
        valid: false,
        reason: 'signature_invalid',
        payload: parsed.payload,
      };
    }

    if (
      expectedOutputSha256 &&
      String(parsed.payload.output_sha256 || '') !== String(expectedOutputSha256)
    ) {
      return {
        valid: false,
        reason: 'output_hash_mismatch',
        payload: parsed.payload,
      };
    }

    return {
      valid: true,
      reason: 'ok',
      payload: parsed.payload,
    };
  }

  createEnvelope({
    outputBuffer,
    outputSha256,
    statusCode,
    provider,
    modelId,
    correlationId,
    configHash,
  } = {}) {
    if (!this.isEnabled()) {
      return null;
    }
    const buffer = Buffer.isBuffer(outputBuffer) ? outputBuffer : Buffer.from(String(outputBuffer || ''), 'utf8');
    if (buffer.length > this.maxEnvelopeBytes) {
      return null;
    }

    const hash = outputSha256 || sha256Buffer(buffer);
    const payload = {
      v: this.version,
      alg: this.algorithm,
      key_id: this.keyId,
      ts: new Date().toISOString(),
      provider: String(provider || 'unknown'),
      status: Number(statusCode || 0),
      model_id: String(modelId || 'unknown'),
      correlation_id: String(correlationId || ''),
      config_hash: String(configHash || sha256Text('default_config')),
      output_sha256: String(hash || ''),
    };

    const envelope = this.signPayload(payload);
    if (!envelope) {
      return null;
    }

    return {
      envelope,
      payload,
    };
  }
}

module.exports = {
  OutputProvenanceSigner,
  sha256Text,
};
