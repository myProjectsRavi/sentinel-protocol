const { A2ACardVerifier } = require('../../src/security/a2a-card-verifier');

describe('A2ACardVerifier', () => {
  test('detects card drift and missing auth enforcement', () => {
    const verifier = new A2ACardVerifier({
      enabled: true,
      mode: 'block',
      block_on_drift: true,
      block_on_auth_mismatch: true,
      block_on_invalid_schema: true,
    });

    const first = verifier.evaluate({
      headers: {
        'x-a2a-agent-card': Buffer.from(JSON.stringify({
          id: 'agent-alpha',
          capabilities: ['search_docs'],
          auth: { schemes: ['oauth2'] },
        })).toString('base64url'),
      },
      bodyJson: {
        action: 'search_docs',
      },
      effectiveMode: 'enforce',
    });
    expect(first.detected).toBe(true);
    expect(first.reason).toBe('a2a_card_auth_oauth_not_enforced');

    const second = verifier.evaluate({
      headers: {
        'x-a2a-agent-card': Buffer.from(JSON.stringify({
          id: 'agent-alpha',
          capabilities: ['search_docs', 'delete_data'],
          auth: { schemes: ['oauth2'] },
        })).toString('base64url'),
        authorization: 'Bearer test',
      },
      bodyJson: {
        action: 'search_docs',
      },
      effectiveMode: 'enforce',
    });

    expect(second.detected).toBe(true);
    expect(second.findings.some((item) => item.code === 'a2a_card_drift_detected')).toBe(true);
    expect(second.shouldBlock).toBe(true);
  });

  test('returns clean decision when disabled', () => {
    const verifier = new A2ACardVerifier({ enabled: false });
    const decision = verifier.evaluate({});
    expect(decision.enabled).toBe(false);
    expect(decision.detected).toBe(false);
  });
});
