const { ComputeAttestation } = require('../../src/governance/compute-attestation');

describe('ComputeAttestation', () => {
  test('creates and verifies attestation envelope', () => {
    const attestation = new ComputeAttestation({
      enabled: true,
      key_id: 'attest-key',
      secret: 'attest-secret',
    });

    const signed = attestation.create({
      configHash: 'cfg-hash',
      policyHash: 'policy-hash',
      correlationId: 'corr-id',
      provider: 'openai',
    });

    expect(signed).toBeTruthy();
    const verification = attestation.verify(signed.envelope);
    expect(verification.valid).toBe(true);
    expect(verification.payload.provider).toBe('openai');
  });

  test('rejects invalid envelope', () => {
    const attestation = new ComputeAttestation({
      enabled: true,
      key_id: 'attest-key',
      secret: 'attest-secret',
    });

    const verification = attestation.verify('bad.envelope.payload');
    expect(verification.valid).toBe(false);
  });
});
