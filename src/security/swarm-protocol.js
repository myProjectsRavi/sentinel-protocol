const crypto = require('crypto');

const SWARM_VERSION = 'v1';
const SWARM_HEADERS = Object.freeze({
  VERSION: 'x-sentinel-swarm-version',
  NODE_ID: 'x-sentinel-swarm-node-id',
  KEY_ID: 'x-sentinel-swarm-key-id',
  TS: 'x-sentinel-swarm-ts',
  NONCE: 'x-sentinel-swarm-nonce',
  PAYLOAD_SHA256: 'x-sentinel-swarm-payload-sha256',
  SIGNATURE_INPUT: 'x-sentinel-swarm-signature-input',
  SIGNATURE: 'x-sentinel-swarm-signature',
});

function clampPositiveInt(value, fallback, min = 1, max = 86400000) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  const normalized = Math.floor(parsed);
  if (normalized < min || normalized > max) {
    return fallback;
  }
  return normalized;
}

function normalizeMode(value, fallback = 'monitor') {
  const normalized = String(value || fallback).toLowerCase();
  return normalized === 'block' ? 'block' : 'monitor';
}

function toObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return value;
}

function findHeaderValue(headers = {}, wantedHeader) {
  const wanted = String(wantedHeader || '').toLowerCase();
  for (const [name, value] of Object.entries(headers || {})) {
    if (String(name).toLowerCase() === wanted) {
      return value;
    }
  }
  return undefined;
}

function setHeader(headers, headerName, headerValue) {
  const wanted = String(headerName || '').toLowerCase();
  for (const existing of Object.keys(headers)) {
    if (String(existing).toLowerCase() === wanted) {
      headers[existing] = headerValue;
      return;
    }
  }
  headers[headerName] = headerValue;
}

function normalizePathWithQuery(pathWithQuery = '/') {
  try {
    const parsed = new URL(String(pathWithQuery || '/'), 'http://localhost');
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    const text = String(pathWithQuery || '/');
    return text.startsWith('/') ? text : `/${text}`;
  }
}

function bodySha256(bodyBuffer) {
  const buffer = Buffer.isBuffer(bodyBuffer) ? bodyBuffer : Buffer.from(bodyBuffer || '');
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function createKeyObjectFromPem(pem, kind) {
  const text = String(pem || '').trim();
  if (!text) {
    return null;
  }
  return kind === 'private' ? crypto.createPrivateKey(text) : crypto.createPublicKey(text);
}

function resolveTrustedNodes(rawTrustedNodes = {}) {
  const trusted = new Map();
  const source = toObject(rawTrustedNodes);
  for (const [nodeId, rawConfig] of Object.entries(source)) {
    const normalizedNodeId = String(nodeId || '').trim();
    if (!normalizedNodeId) {
      continue;
    }
    try {
      let pem = '';
      if (typeof rawConfig === 'string') {
        pem = rawConfig;
      } else if (rawConfig && typeof rawConfig === 'object' && !Array.isArray(rawConfig)) {
        pem = String(rawConfig.public_key_pem || '');
      }
      const publicKey = createKeyObjectFromPem(pem, 'public');
      if (!publicKey) {
        continue;
      }
      trusted.set(normalizedNodeId, publicKey);
    } catch {
      // Ignore malformed node entries.
    }
  }
  return trusted;
}

class SwarmProtocol {
  constructor(config = {}, deps = {}) {
    const normalized = toObject(config);
    this.enabled = normalized.enabled === true;
    this.mode = normalizeMode(normalized.mode, 'monitor');
    this.nodeId = String(normalized.node_id || `sentinel-node-${process.pid}`).trim();
    this.keyId = String(normalized.key_id || this.nodeId).trim();
    this.verifyInbound = normalized.verify_inbound !== false;
    this.signOutbound = normalized.sign_outbound !== false;
    this.requireEnvelope = normalized.require_envelope === true;
    this.allowedClockSkewMs = clampPositiveInt(normalized.allowed_clock_skew_ms, 30000, 1000, 300000);
    this.nonceTtlMs = clampPositiveInt(normalized.nonce_ttl_ms, 300000, 1000, 3600000);
    this.maxNonceEntries = clampPositiveInt(normalized.max_nonce_entries, 50000, 100, 500000);
    this.signOnProviders = new Set(
      Array.isArray(normalized.sign_on_providers)
        ? normalized.sign_on_providers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
        : ['custom']
    );
    this.now = typeof deps.now === 'function' ? deps.now : Date.now;
    this.randomUuid = typeof deps.randomUuid === 'function' ? deps.randomUuid : crypto.randomUUID;
    this.nonceCache = new Map();
    this.nextNonceCleanupAt = 0;

    this.privateKey = null;
    this.publicKey = null;
    this.publicKeyPem = '';
    if (this.enabled) {
      this.initializeKeyPair(normalized);
    }

    this.trustedNodes = resolveTrustedNodes(normalized.trusted_nodes);
    if (this.publicKey && this.nodeId) {
      this.trustedNodes.set(this.nodeId, this.publicKey);
    }
  }

  initializeKeyPair(config = {}) {
    const configuredPrivateKeyPem = String(config.private_key_pem || '').trim();
    const configuredPublicKeyPem = String(config.public_key_pem || '').trim();

    if (configuredPrivateKeyPem) {
      this.privateKey = createKeyObjectFromPem(configuredPrivateKeyPem, 'private');
      this.publicKey = configuredPublicKeyPem
        ? createKeyObjectFromPem(configuredPublicKeyPem, 'public')
        : crypto.createPublicKey(this.privateKey);
    } else if (configuredPublicKeyPem) {
      this.publicKey = createKeyObjectFromPem(configuredPublicKeyPem, 'public');
    } else {
      const keyPair = crypto.generateKeyPairSync('ed25519');
      this.privateKey = keyPair.privateKey;
      this.publicKey = keyPair.publicKey;
    }

    if (this.publicKey) {
      this.publicKeyPem = this.publicKey.export({
        type: 'spki',
        format: 'pem',
      }).toString();
    }
  }

  isEnabled() {
    return this.enabled === true;
  }

  shouldSignForProvider(providerName) {
    if (!this.isEnabled() || this.signOutbound !== true) {
      return false;
    }
    const provider = String(providerName || '').toLowerCase();
    return this.signOnProviders.has(provider);
  }

  buildSignatureInput({ nodeId, keyId, ts, nonce, method, pathWithQuery, payloadSha256 }) {
    return [
      `v=${SWARM_VERSION}`,
      `node=${String(nodeId || '')}`,
      `key=${String(keyId || '')}`,
      `ts=${String(ts || '')}`,
      `nonce=${String(nonce || '')}`,
      `method=${String(method || '').toUpperCase()}`,
      `path=${normalizePathWithQuery(pathWithQuery || '/')}`,
      `sha256=${String(payloadSha256 || '')}`,
    ].join('\n');
  }

  signOutboundEnvelope({ method, pathWithQuery, bodyBuffer }) {
    if (!this.privateKey) {
      return {
        signed: false,
        reason: 'private_key_unavailable',
      };
    }

    const ts = Number(this.now());
    const nonce = this.randomUuid();
    const payloadSha256 = bodySha256(bodyBuffer);
    const signatureInput = this.buildSignatureInput({
      nodeId: this.nodeId,
      keyId: this.keyId,
      ts,
      nonce,
      method,
      pathWithQuery,
      payloadSha256,
    });
    const signature = crypto.sign(null, Buffer.from(signatureInput, 'utf8'), this.privateKey).toString('base64');

    return {
      signed: true,
      version: SWARM_VERSION,
      nodeId: this.nodeId,
      keyId: this.keyId,
      ts,
      nonce,
      payloadSha256,
      signatureInput: 'v,node,key,ts,nonce,method,path,sha256',
      signature,
    };
  }

  signOutboundHeaders({ headers = {}, provider, method, pathWithQuery, bodyBuffer }) {
    const outputHeaders = { ...(headers || {}) };
    if (!this.shouldSignForProvider(provider)) {
      return {
        headers: outputHeaders,
        meta: {
          signed: false,
          reason: 'provider_not_eligible',
        },
      };
    }

    const signedEnvelope = this.signOutboundEnvelope({
      method,
      pathWithQuery,
      bodyBuffer,
    });
    if (!signedEnvelope.signed) {
      return {
        headers: outputHeaders,
        meta: signedEnvelope,
      };
    }

    setHeader(outputHeaders, SWARM_HEADERS.VERSION, signedEnvelope.version);
    setHeader(outputHeaders, SWARM_HEADERS.NODE_ID, signedEnvelope.nodeId);
    setHeader(outputHeaders, SWARM_HEADERS.KEY_ID, signedEnvelope.keyId);
    setHeader(outputHeaders, SWARM_HEADERS.TS, String(signedEnvelope.ts));
    setHeader(outputHeaders, SWARM_HEADERS.NONCE, signedEnvelope.nonce);
    setHeader(outputHeaders, SWARM_HEADERS.PAYLOAD_SHA256, signedEnvelope.payloadSha256);
    setHeader(outputHeaders, SWARM_HEADERS.SIGNATURE_INPUT, signedEnvelope.signatureInput);
    setHeader(outputHeaders, SWARM_HEADERS.SIGNATURE, signedEnvelope.signature);

    return {
      headers: outputHeaders,
      meta: signedEnvelope,
    };
  }

  cleanupNonceCache(nowMs) {
    if (nowMs < this.nextNonceCleanupAt && this.nonceCache.size <= this.maxNonceEntries) {
      return;
    }
    for (const [nonceKey, expiresAt] of this.nonceCache.entries()) {
      if (expiresAt <= nowMs) {
        this.nonceCache.delete(nonceKey);
      }
    }
    while (this.nonceCache.size > this.maxNonceEntries) {
      const oldest = this.nonceCache.keys().next().value;
      if (!oldest) {
        break;
      }
      this.nonceCache.delete(oldest);
    }
    this.nextNonceCleanupAt = nowMs + Math.min(this.nonceTtlMs, 5000);
  }

  consumeNonce(nodeId, nonce, nowMs) {
    this.cleanupNonceCache(nowMs);
    const nonceKey = `${nodeId}:${nonce}`;
    const existingExpiry = this.nonceCache.get(nonceKey);
    if (existingExpiry && existingExpiry > nowMs) {
      return false;
    }
    this.nonceCache.set(nonceKey, nowMs + this.nonceTtlMs);
    return true;
  }

  verifyInboundEnvelope({ headers = {}, method, pathWithQuery, bodyBuffer }) {
    const nowMs = Number(this.now());
    if (!this.isEnabled() || this.verifyInbound !== true) {
      return {
        enabled: this.isEnabled(),
        present: false,
        verified: false,
        required: false,
        shouldBlock: false,
        reason: 'disabled',
      };
    }

    const version = String(findHeaderValue(headers, SWARM_HEADERS.VERSION) || '').trim();
    const nodeId = String(findHeaderValue(headers, SWARM_HEADERS.NODE_ID) || '').trim();
    const keyId = String(findHeaderValue(headers, SWARM_HEADERS.KEY_ID) || '').trim();
    const tsRaw = String(findHeaderValue(headers, SWARM_HEADERS.TS) || '').trim();
    const nonce = String(findHeaderValue(headers, SWARM_HEADERS.NONCE) || '').trim();
    const incomingPayloadSha = String(findHeaderValue(headers, SWARM_HEADERS.PAYLOAD_SHA256) || '').trim();
    const signature = String(findHeaderValue(headers, SWARM_HEADERS.SIGNATURE) || '').trim();

    const present = Boolean(version || nodeId || keyId || tsRaw || nonce || incomingPayloadSha || signature);
    if (!present) {
      const required = this.requireEnvelope === true;
      return {
        enabled: true,
        present: false,
        verified: false,
        required,
        shouldBlock: required && this.mode === 'block',
        reason: required ? 'missing_envelope' : 'not_present',
      };
    }

    const baseFailure = (reason) => ({
      enabled: true,
      present: true,
      verified: false,
      required: true,
      shouldBlock: this.mode === 'block',
      reason,
      nodeId: nodeId || undefined,
      keyId: keyId || undefined,
      nonce: nonce || undefined,
    });

    if (version !== SWARM_VERSION) {
      return baseFailure('version_mismatch');
    }
    if (!nodeId || !nonce || !signature) {
      return baseFailure('missing_required_fields');
    }
    if (!this.trustedNodes.has(nodeId)) {
      return baseFailure('unknown_node');
    }

    const ts = Number(tsRaw);
    if (!Number.isInteger(ts)) {
      return baseFailure('invalid_timestamp');
    }
    const ageMs = nowMs - ts;
    if (Math.abs(ageMs) > this.allowedClockSkewMs) {
      return baseFailure('timestamp_skew');
    }

    const payloadSha256 = bodySha256(bodyBuffer);
    if (incomingPayloadSha && incomingPayloadSha !== payloadSha256) {
      return baseFailure('payload_hash_mismatch');
    }

    const signatureInput = this.buildSignatureInput({
      nodeId,
      keyId: keyId || nodeId,
      ts,
      nonce,
      method,
      pathWithQuery,
      payloadSha256,
    });
    const publicKey = this.trustedNodes.get(nodeId);
    const signatureOk = crypto.verify(
      null,
      Buffer.from(signatureInput, 'utf8'),
      publicKey,
      Buffer.from(signature, 'base64')
    );
    if (!signatureOk) {
      return baseFailure('invalid_signature');
    }

    if (!this.consumeNonce(nodeId, nonce, nowMs)) {
      return baseFailure('replay_nonce');
    }

    return {
      enabled: true,
      present: true,
      verified: true,
      required: true,
      shouldBlock: false,
      reason: 'verified',
      nodeId,
      keyId: keyId || nodeId,
      nonce,
      ts,
      ageMs,
      payloadSha256,
    };
  }

  getPublicMetadata() {
    if (!this.isEnabled() || !this.publicKeyPem) {
      return {
        enabled: false,
      };
    }
    return {
      enabled: true,
      version: SWARM_VERSION,
      node_id: this.nodeId,
      key_id: this.keyId,
      public_key_pem: this.publicKeyPem,
      verify_inbound: this.verifyInbound,
      sign_outbound: this.signOutbound,
      require_envelope: this.requireEnvelope,
      sign_on_providers: Array.from(this.signOnProviders),
      mode: this.mode,
    };
  }
}

module.exports = {
  SwarmProtocol,
  SWARM_VERSION,
  SWARM_HEADERS,
};
