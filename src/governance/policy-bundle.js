const crypto = require('crypto');

function canonicalize(value) {
  if (value === null || value === undefined) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
  }
  if (typeof value !== 'object') {
    return value;
  }
  const out = {};
  for (const key of Object.keys(value).sort()) {
    out[key] = canonicalize(value[key]);
  }
  return out;
}

function stableStringify(value) {
  return JSON.stringify(canonicalize(value));
}

function toKeyObject(key, kind) {
  if (!key) {
    throw new Error(`${kind} key is required`);
  }
  if (typeof key === 'string') {
    return kind === 'private' ? crypto.createPrivateKey(key) : crypto.createPublicKey(key);
  }
  return key;
}

class PolicyBundle {
  static create(config, options = {}) {
    return {
      version: 1,
      created_at: options.createdAt || new Date().toISOString(),
      issuer: options.issuer || 'sentinel-local',
      key_id: options.keyId || 'sentinel-default',
      config: config || {},
    };
  }

  static payloadForSigning(bundle) {
    const unsigned = {
      version: Number(bundle?.version || 1),
      created_at: String(bundle?.created_at || ''),
      issuer: String(bundle?.issuer || ''),
      key_id: String(bundle?.key_id || ''),
      config: bundle?.config || {},
    };
    return Buffer.from(stableStringify(unsigned), 'utf8');
  }

  static sign(configOrBundle, privateKey, options = {}) {
    const bundle = configOrBundle?.config ? configOrBundle : PolicyBundle.create(configOrBundle, options);
    const key = toKeyObject(privateKey, 'private');
    const payload = PolicyBundle.payloadForSigning(bundle);
    const signature = crypto.sign(null, payload, key);
    return {
      ...bundle,
      algorithm: 'ed25519',
      signature: signature.toString('base64'),
      payload_sha256: crypto.createHash('sha256').update(payload).digest('hex'),
    };
  }

  static verify(bundle, publicKey) {
    if (!bundle || typeof bundle !== 'object') {
      return { valid: false, reason: 'invalid_bundle' };
    }
    if (typeof bundle.signature !== 'string' || !bundle.signature) {
      return { valid: false, reason: 'missing_signature' };
    }
    const key = toKeyObject(publicKey, 'public');
    const payload = PolicyBundle.payloadForSigning(bundle);
    const valid = crypto.verify(null, payload, key, Buffer.from(bundle.signature, 'base64'));
    return {
      valid,
      reason: valid ? 'ok' : 'signature_mismatch',
      config: valid ? bundle.config : null,
      payload_sha256: crypto.createHash('sha256').update(payload).digest('hex'),
    };
  }
}

module.exports = {
  PolicyBundle,
  stableStringify,
};
