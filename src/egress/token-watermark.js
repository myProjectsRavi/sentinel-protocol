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

class TokenWatermark {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.keyId = String(config.key_id || `sentinel-token-watermark-${process.pid}`);
    this.algorithm = 'hmac-sha256';
    this.version = 'v1';
    this.secret = String(config.secret || process.env.SENTINEL_TOKEN_WATERMARK_SECRET || '');
    this.exposeVerifyEndpoint = config.expose_verify_endpoint !== false;
    this.maxEnvelopeBytes = clampPositiveInt(config.max_envelope_bytes, 2 * 1024 * 1024, 1024, 32 * 1024 * 1024);
    this.maxTokenChars = clampPositiveInt(config.max_token_chars, 131072, 256, 2 * 1024 * 1024);
    this.maxTokens = clampPositiveInt(config.max_tokens, 4096, 32, 32768);
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
    const secret = this.secret || `sentinel-token-watermark:${this.keyId}`;
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

  extractTokens(input = '') {
    const text = String(input || '').slice(0, this.maxTokenChars);
    if (!text) {
      return [];
    }
    const parts = text.match(/[A-Za-z0-9_]+|[^\s]/g) || [];
    return parts.slice(0, this.maxTokens);
  }

  createTokenFingerprint(buffer = Buffer.alloc(0)) {
    const text = Buffer.isBuffer(buffer) ? buffer.toString('utf8') : String(buffer || '');
    const tokens = this.extractTokens(text);
    const normalized = tokens.join('\u241f');
    return {
      token_count: tokens.length,
      token_fingerprint_sha256: sha256Text(normalized),
    };
  }

  verifyEnvelope({
    envelope,
    expectedOutputSha256,
    expectedTokenFingerprint,
  } = {}) {
    if (!this.isEnabled()) {
      return {
        valid: false,
        reason: 'token_watermark_disabled',
      };
    }

    const parsed = this.parseEnvelope(envelope);
    if (!parsed.ok) {
      return {
        valid: false,
        reason: parsed.reason,
      };
    }

    const secret = this.secret || `sentinel-token-watermark:${this.keyId}`;
    const expected = crypto
      .createHmac('sha256', secret)
      .update(parsed.payloadB64, 'utf8')
      .digest('base64url');

    const actualBuf = Buffer.from(String(parsed.signature || ''), 'utf8');
    const expectedBuf = Buffer.from(String(expected || ''), 'utf8');
    const validSignature = actualBuf.length === expectedBuf.length && crypto.timingSafeEqual(actualBuf, expectedBuf);
    if (!validSignature) {
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

    if (
      expectedTokenFingerprint &&
      String(parsed.payload.token_fingerprint_sha256 || '') !== String(expectedTokenFingerprint)
    ) {
      return {
        valid: false,
        reason: 'token_fingerprint_mismatch',
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
    if (!outputSha256 && buffer.length > this.maxEnvelopeBytes) {
      return null;
    }
    const hash = outputSha256 || sha256Buffer(buffer);
    const tokenFingerprint = this.createTokenFingerprint(buffer);
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
      token_count: Number(tokenFingerprint.token_count || 0),
      token_fingerprint_sha256: String(tokenFingerprint.token_fingerprint_sha256 || ''),
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
  TokenWatermark,
};

