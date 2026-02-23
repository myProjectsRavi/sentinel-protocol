const { AgentIdentityFederation } = require('../../src/security/agent-identity-federation');

describe('AgentIdentityFederation', () => {
  test('issues signed capability token and verifies signature', () => {
    const federation = new AgentIdentityFederation({
      enabled: true,
      mode: 'monitor',
      hmac_secret: 'unit-test-secret',
    });
    const token = federation.issueToken({
      agentId: 'agent-alpha',
      capabilities: ['read_docs'],
      correlationId: 'corr-1',
    });

    const decision = federation.evaluate({
      headers: {
        'x-sentinel-agent-token': token,
        'x-sentinel-agent-id': 'agent-alpha',
        'x-sentinel-correlation-id': 'corr-1',
      },
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(false);
    expect(decision.reason).toBe('clean');
  });

  test('rejects widened capability on delegated token chain', () => {
    const federation = new AgentIdentityFederation({
      enabled: true,
      mode: 'monitor',
      hmac_secret: 'unit-test-secret',
      block_on_capability_widen: true,
    });
    const token = federation.issueToken({
      agentId: 'agent-alpha',
      capabilities: ['read_docs', 'write_docs'],
      parentCapabilities: ['read_docs'],
      correlationId: 'corr-2',
    });

    const decision = federation.evaluate({
      headers: {
        'x-sentinel-agent-token': token,
        'x-sentinel-agent-id': 'agent-alpha',
        'x-sentinel-correlation-id': 'corr-2',
      },
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.findings.some((item) => item.code === 'agent_identity_capability_widen')).toBe(true);
  });

  test('rejects replay across different correlation id', () => {
    const federation = new AgentIdentityFederation({
      enabled: true,
      mode: 'block',
      hmac_secret: 'unit-test-secret',
      block_on_replay: true,
    });
    const token = federation.issueToken({
      agentId: 'agent-alpha',
      capabilities: ['read_docs'],
      correlationId: 'corr-3',
    });

    const first = federation.evaluate({
      headers: {
        'x-sentinel-agent-token': token,
        'x-sentinel-agent-id': 'agent-alpha',
        'x-sentinel-correlation-id': 'corr-3',
      },
      effectiveMode: 'enforce',
    });
    const second = federation.evaluate({
      headers: {
        'x-sentinel-agent-token': token,
        'x-sentinel-agent-id': 'agent-alpha',
        'x-sentinel-correlation-id': 'corr-3',
      },
      effectiveMode: 'enforce',
    });

    expect(first.detected).toBe(false);
    expect(second.detected).toBe(true);
    expect(second.findings.some((item) => item.code === 'agent_identity_replay_detected')).toBe(true);
    expect(second.shouldBlock).toBe(true);
  });

  test('detects impersonation claim mismatch', () => {
    const federation = new AgentIdentityFederation({
      enabled: true,
      mode: 'monitor',
      hmac_secret: 'unit-test-secret',
      block_on_invalid_token: true,
    });
    const token = federation.issueToken({
      agentId: 'agent-alpha',
      capabilities: ['read_docs'],
      correlationId: 'corr-4',
    });

    const decision = federation.evaluate({
      headers: {
        'x-sentinel-agent-token': token,
        'x-sentinel-agent-id': 'agent-beta',
        'x-sentinel-correlation-id': 'corr-4',
      },
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.findings.some((item) => item.code === 'agent_identity_claim_mismatch')).toBe(true);
  });
});
