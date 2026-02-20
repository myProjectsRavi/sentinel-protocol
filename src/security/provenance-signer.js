const crypto = require('crypto');
const { clampPositiveInt } = require('../utils/primitives');

class ProvenanceSigner {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.algorithm = 'ed25519';
    this.signatureVersion = 'v1';
    this.keyId = String(config.key_id || `sentinel-${process.pid}`);
    this.signStreamTrailers = config.sign_stream_trailers !== false;
    this.exposePublicKeyEndpoint = config.expose_public_key_endpoint !== false;
    this.maxSignableBytes = clampPositiveInt(config.max_signable_bytes, 2 * 1024 * 1024, 1024, 32 * 1024 * 1024);
    this.privateKey = null;
    this.publicKeyPem = null;

    if (this.enabled) {
      const keyPair = crypto.generateKeyPairSync('ed25519');
      this.privateKey = keyPair.privateKey;
      this.publicKeyPem = keyPair.publicKey.export({
        type: 'spki',
        format: 'pem',
      }).toString();
    }
  }

  isEnabled() {
    return this.enabled === true && Boolean(this.privateKey);
  }

  getPublicMetadata() {
    if (!this.isEnabled()) {
      return {
        enabled: false,
      };
    }
    return {
      enabled: true,
      version: this.signatureVersion,
      algorithm: this.algorithm,
      key_id: this.keyId,
      public_key_pem: this.publicKeyPem,
    };
  }

  createSignatureInput({ payloadSha256, statusCode, provider, correlationId }) {
    return [
      `v=${this.signatureVersion}`,
      `sha256=${payloadSha256}`,
      `status=${Number(statusCode || 0)}`,
      `provider=${String(provider || 'unknown')}`,
      `correlation=${String(correlationId || '')}`,
    ].join('\n');
  }

  signInput(input) {
    return crypto.sign(null, Buffer.from(String(input), 'utf8'), this.privateKey).toString('base64');
  }

  computeHash(bodyBuffer) {
    const buffer = Buffer.isBuffer(bodyBuffer) ? bodyBuffer : Buffer.from(bodyBuffer || '');
    if (buffer.length > this.maxSignableBytes) {
      return null;
    }
    return crypto.createHash('sha256').update(buffer).digest('hex');
  }

  signBufferedResponse({ bodyBuffer, statusCode, provider, correlationId }) {
    if (!this.isEnabled()) {
      return null;
    }

    const payloadSha256 = this.computeHash(bodyBuffer);
    if (!payloadSha256) {
      return null;
    }

    const input = this.createSignatureInput({
      payloadSha256,
      statusCode,
      provider,
      correlationId,
    });

    return {
      version: this.signatureVersion,
      algorithm: this.algorithm,
      keyId: this.keyId,
      payloadSha256,
      signature: this.signInput(input),
      signatureInput: 'v,sha256,status,provider,correlation',
    };
  }

  createStreamContext({ statusCode, provider, correlationId }) {
    if (!this.isEnabled()) {
      return null;
    }
    const hasher = crypto.createHash('sha256');
    const maxSignableBytes = this.maxSignableBytes;
    let totalBytes = 0;
    let overflow = false;

    return {
      update(chunk) {
        if (!chunk) {
          return;
        }
        const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        totalBytes += data.length;
        if (totalBytes > maxSignableBytes) {
          overflow = true;
          return;
        }
        hasher.update(data);
      },
      finalize: () => {
        if (overflow) {
          return null;
        }
        const payloadSha256 = hasher.digest('hex');
        const input = this.createSignatureInput({
          payloadSha256,
          statusCode,
          provider,
          correlationId,
        });
        return {
          version: this.signatureVersion,
          algorithm: this.algorithm,
          keyId: this.keyId,
          payloadSha256,
          signature: this.signInput(input),
          signatureInput: 'v,sha256,status,provider,correlation',
          totalBytes,
        };
      },
      maxSignableBytes,
    };
  }

  static proofHeaders(proof) {
    if (!proof) {
      return {};
    }
    return {
      'x-sentinel-signature-v': proof.version,
      'x-sentinel-signature-alg': proof.algorithm,
      'x-sentinel-signature-key-id': proof.keyId,
      'x-sentinel-signature-input': proof.signatureInput,
      'x-sentinel-payload-sha256': proof.payloadSha256,
      'x-sentinel-signature': proof.signature,
    };
  }
}

module.exports = {
  ProvenanceSigner,
};
