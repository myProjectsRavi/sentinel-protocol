const { OutputProvenanceSigner } = require('../../src/egress/output-provenance-signer');

describe('OutputProvenanceSigner', () => {
  test('signs and verifies deterministic envelope', () => {
    const signer = new OutputProvenanceSigner({
      enabled: true,
      key_id: 'test-key',
      secret: 'test-secret',
    });

    const signed = signer.createEnvelope({
      outputBuffer: Buffer.from('hello world'),
      statusCode: 200,
      provider: 'openai',
      correlationId: 'corr-1',
      modelId: 'gpt-test',
      configHash: 'cfg',
    });

    expect(signed).toBeTruthy();
    const verification = signer.verifyEnvelope({
      envelope: signed.envelope,
      expectedOutputSha256: signed.payload.output_sha256,
    });
    expect(verification.valid).toBe(true);
  });

  test('rejects tampered envelope', () => {
    const signer = new OutputProvenanceSigner({
      enabled: true,
      key_id: 'test-key',
      secret: 'test-secret',
    });

    const signed = signer.createEnvelope({
      outputBuffer: Buffer.from('abc'),
      statusCode: 200,
      provider: 'openai',
      correlationId: 'corr',
      configHash: 'cfg',
    });
    const tampered = `${signed.envelope.slice(0, -2)}zz`;
    const verification = signer.verifyEnvelope({ envelope: tampered });
    expect(verification.valid).toBe(false);
  });
});
