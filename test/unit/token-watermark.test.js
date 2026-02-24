const { TokenWatermark } = require('../../src/egress/token-watermark');

describe('TokenWatermark', () => {
  test('creates and verifies deterministic envelope', () => {
    const engine = new TokenWatermark({
      enabled: true,
      key_id: 'wm-key',
      secret: 'wm-secret',
    });
    const signed = engine.createEnvelope({
      outputBuffer: Buffer.from('hello world from sentinel'),
      statusCode: 200,
      provider: 'openai',
      modelId: 'gpt-test',
      correlationId: 'corr-1',
      configHash: 'cfg-hash',
    });

    expect(signed).toBeTruthy();
    expect(typeof signed.envelope).toBe('string');
    const verification = engine.verifyEnvelope({
      envelope: signed.envelope,
      expectedOutputSha256: signed.payload.output_sha256,
      expectedTokenFingerprint: signed.payload.token_fingerprint_sha256,
    });
    expect(verification.valid).toBe(true);
    expect(verification.reason).toBe('ok');
  });

  test('rejects tampered envelope', () => {
    const engine = new TokenWatermark({
      enabled: true,
      key_id: 'wm-key',
      secret: 'wm-secret',
    });
    const signed = engine.createEnvelope({
      outputBuffer: Buffer.from('abc def ghi'),
      statusCode: 200,
      provider: 'openai',
      correlationId: 'corr-2',
      configHash: 'cfg',
    });
    const tampered = `${signed.envelope.slice(0, -4)}abcd`;
    const verification = engine.verifyEnvelope({
      envelope: tampered,
    });
    expect(verification.valid).toBe(false);
  });

  test('supports hash-only stream mode', () => {
    const engine = new TokenWatermark({
      enabled: true,
      key_id: 'wm-key',
      secret: 'wm-secret',
    });
    const signed = engine.createEnvelope({
      outputSha256: 'a'.repeat(64),
      statusCode: 200,
      provider: 'openai',
      correlationId: 'corr-stream',
      configHash: 'cfg',
    });
    expect(signed).toBeTruthy();
    expect(signed.payload.output_sha256).toBe('a'.repeat(64));
  });
});

