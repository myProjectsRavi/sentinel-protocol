const { SwarmProtocol, SWARM_HEADERS } = require('../../src/security/swarm-protocol');

describe('SwarmProtocol', () => {
  test('signs outbound envelopes and verifies inbound with trusted node', () => {
    let now = 1700000000000;
    const signer = new SwarmProtocol(
      {
        enabled: true,
        mode: 'block',
        node_id: 'node-a',
        key_id: 'node-a-key',
        verify_inbound: false,
        sign_outbound: true,
        sign_on_providers: ['custom'],
      },
      {
        now: () => now,
        randomUuid: () => 'nonce-123',
      }
    );
    const signerPublicKey = signer.getPublicMetadata().public_key_pem;

    const verifier = new SwarmProtocol(
      {
        enabled: true,
        mode: 'block',
        node_id: 'node-b',
        key_id: 'node-b-key',
        verify_inbound: true,
        sign_outbound: false,
        require_envelope: true,
        trusted_nodes: {
          'node-a': {
            public_key_pem: signerPublicKey,
          },
        },
      },
      {
        now: () => now,
      }
    );

    const body = Buffer.from(JSON.stringify({ hello: 'world' }), 'utf8');
    const signed = signer.signOutboundHeaders({
      headers: {},
      provider: 'custom',
      method: 'POST',
      pathWithQuery: '/v1/chat/completions?stream=false',
      bodyBuffer: body,
    });
    expect(signed.meta.signed).toBe(true);
    expect(signed.headers[SWARM_HEADERS.SIGNATURE]).toBeTruthy();

    const verified = verifier.verifyInboundEnvelope({
      headers: signed.headers,
      method: 'POST',
      pathWithQuery: '/v1/chat/completions?stream=false',
      bodyBuffer: body,
    });
    expect(verified.verified).toBe(true);
    expect(verified.reason).toBe('verified');
    expect(verified.nodeId).toBe('node-a');
  });

  test('detects replay nonce and blocks in block mode', () => {
    let now = 1700000000000;
    const signer = new SwarmProtocol(
      {
        enabled: true,
        node_id: 'node-a',
        key_id: 'node-a-key',
        verify_inbound: false,
        sign_outbound: true,
        sign_on_providers: ['custom'],
      },
      {
        now: () => now,
        randomUuid: () => 'nonce-replay',
      }
    );
    const verifier = new SwarmProtocol(
      {
        enabled: true,
        mode: 'block',
        node_id: 'node-b',
        verify_inbound: true,
        sign_outbound: false,
        require_envelope: true,
        trusted_nodes: {
          'node-a': {
            public_key_pem: signer.getPublicMetadata().public_key_pem,
          },
        },
      },
      {
        now: () => now,
      }
    );

    const body = Buffer.from('ping');
    const signed = signer.signOutboundHeaders({
      headers: {},
      provider: 'custom',
      method: 'POST',
      pathWithQuery: '/api/swarm',
      bodyBuffer: body,
    });

    const first = verifier.verifyInboundEnvelope({
      headers: signed.headers,
      method: 'POST',
      pathWithQuery: '/api/swarm',
      bodyBuffer: body,
    });
    expect(first.verified).toBe(true);

    const second = verifier.verifyInboundEnvelope({
      headers: signed.headers,
      method: 'POST',
      pathWithQuery: '/api/swarm',
      bodyBuffer: body,
    });
    expect(second.verified).toBe(false);
    expect(second.reason).toBe('replay_nonce');
    expect(second.shouldBlock).toBe(true);
  });

  test('require_envelope enforces missing envelope rejection', () => {
    const verifier = new SwarmProtocol({
      enabled: true,
      mode: 'block',
      verify_inbound: true,
      sign_outbound: false,
      require_envelope: true,
      trusted_nodes: {},
    });

    const result = verifier.verifyInboundEnvelope({
      headers: {},
      method: 'POST',
      pathWithQuery: '/v1/chat/completions',
      bodyBuffer: Buffer.from('{}'),
    });
    expect(result.verified).toBe(false);
    expect(result.reason).toBe('missing_envelope');
    expect(result.shouldBlock).toBe(true);
  });

  test('does not sign non-eligible providers', () => {
    const signer = new SwarmProtocol({
      enabled: true,
      node_id: 'node-a',
      sign_outbound: true,
      sign_on_providers: ['custom'],
    });
    const signed = signer.signOutboundHeaders({
      headers: {},
      provider: 'openai',
      method: 'POST',
      pathWithQuery: '/v1/chat/completions',
      bodyBuffer: Buffer.from('{}'),
    });
    expect(signed.meta.signed).toBe(false);
    expect(signed.meta.reason).toBe('provider_not_eligible');
  });
});
