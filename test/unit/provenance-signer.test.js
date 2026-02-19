const { ProvenanceSigner } = require('../../src/security/provenance-signer');

describe('ProvenanceSigner', () => {
  test('signs buffered payload when enabled', () => {
    const signer = new ProvenanceSigner({
      enabled: true,
      key_id: 'test-key',
      max_signable_bytes: 1024,
    });

    const proof = signer.signBufferedResponse({
      bodyBuffer: Buffer.from('hello world', 'utf8'),
      statusCode: 200,
      provider: 'openai',
      correlationId: 'corr-1',
    });

    expect(proof).toBeTruthy();
    expect(proof.keyId).toBe('test-key');
    expect(proof.algorithm).toBe('ed25519');

    const headers = ProvenanceSigner.proofHeaders(proof);
    expect(headers['x-sentinel-signature']).toBeTruthy();
    expect(headers['x-sentinel-payload-sha256']).toHaveLength(64);
  });

  test('skips proof when payload exceeds max_signable_bytes', () => {
    const signer = new ProvenanceSigner({
      enabled: true,
      key_id: 'test-key',
      max_signable_bytes: 1024,
    });

    const proof = signer.signBufferedResponse({
      bodyBuffer: Buffer.alloc(2048, 0x61),
      statusCode: 200,
      provider: 'openai',
      correlationId: 'corr-2',
    });

    expect(proof).toBeNull();
  });

  test('computes stream proof when chunks are updated', () => {
    const signer = new ProvenanceSigner({
      enabled: true,
      key_id: 'stream-key',
      max_signable_bytes: 1024,
    });

    const context = signer.createStreamContext({
      statusCode: 200,
      provider: 'openai',
      correlationId: 'corr-stream',
    });
    context.update(Buffer.from('chunk-1', 'utf8'));
    context.update(Buffer.from('chunk-2', 'utf8'));
    const proof = context.finalize();

    expect(proof).toBeTruthy();
    expect(proof.totalBytes).toBe('chunk-1chunk-2'.length);
    expect(proof.signature).toBeTruthy();
  });
});
