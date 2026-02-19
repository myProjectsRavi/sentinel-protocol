const crypto = require('crypto');
const { PolicyBundle } = require('../../src/governance/policy-bundle');

describe('PolicyBundle', () => {
  test('signs and verifies bundle', () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    const bundle = PolicyBundle.sign(
      { version: 1, mode: 'monitor', rules: [] },
      privateKey.export({ type: 'pkcs8', format: 'pem' }),
      { issuer: 'test', keyId: 'k1' }
    );
    const verified = PolicyBundle.verify(
      bundle,
      publicKey.export({ type: 'spki', format: 'pem' })
    );
    expect(verified.valid).toBe(true);
    expect(verified.config.mode).toBe('monitor');
  });

  test('verification fails when payload is tampered', () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    const bundle = PolicyBundle.sign(
      { version: 1, mode: 'monitor', rules: [] },
      privateKey.export({ type: 'pkcs8', format: 'pem' }),
      { issuer: 'test', keyId: 'k1' }
    );
    bundle.config.mode = 'enforce';
    const verified = PolicyBundle.verify(
      bundle,
      publicKey.export({ type: 'spki', format: 'pem' })
    );
    expect(verified.valid).toBe(false);
  });
});
