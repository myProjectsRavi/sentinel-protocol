const crypto = require('crypto');

const { AgenticThreatShield } = require('../../src/security/agentic-threat-shield');

describe('AgenticThreatShield', () => {
  test('allows request when depth and delegation stay below thresholds', () => {
    const shield = new AgenticThreatShield({
      enabled: true,
      mode: 'block',
      max_tool_call_depth: 4,
      max_agent_delegations: 4,
    });
    const decision = shield.evaluate({
      headers: {
        'x-sentinel-session-id': 'sess-1',
        'x-sentinel-agent-id': 'agent-a',
      },
      bodyJson: {
        messages: [
          {
            role: 'user',
            content: 'summarize this document',
          },
        ],
      },
      effectiveMode: 'enforce',
      correlationId: 'corr-1',
    });

    expect(decision.detected).toBe(false);
    expect(decision.shouldBlock).toBe(false);
  });

  test('monitor mode detects depth excess but does not block', () => {
    const shield = new AgenticThreatShield({
      enabled: true,
      mode: 'monitor',
      max_tool_call_depth: 1,
      max_agent_delegations: 5,
    });
    const decision = shield.evaluate({
      headers: {
        'x-sentinel-session-id': 'sess-2',
        'x-sentinel-agent-id': 'agent-a',
      },
      bodyJson: {
        tool_calls: [
          {
            function: {
              name: 'search_docs',
              arguments: '{}',
            },
            nested: {
              tool_calls: [
                {
                  function: {
                    name: 'search_docs',
                    arguments: '{}',
                  },
                },
              ],
            },
          },
        ],
      },
      effectiveMode: 'enforce',
      correlationId: 'corr-2',
    });

    expect(decision.detected).toBe(true);
    expect(decision.reasons).toContain('tool_call_depth_exceeded');
    expect(decision.shouldBlock).toBe(false);
  });

  test('enforce mode blocks when depth exceeds threshold in block mode', () => {
    const shield = new AgenticThreatShield({
      enabled: true,
      mode: 'block',
      max_tool_call_depth: 1,
      max_agent_delegations: 5,
    });
    const decision = shield.evaluate({
      headers: {
        'x-sentinel-session-id': 'sess-3',
        'x-sentinel-agent-id': 'agent-a',
      },
      bodyJson: {
        tool_calls: [
          {
            function: {
              name: 'search_docs',
              arguments: '{}',
            },
            nested: {
              tool_calls: [
                {
                  function: {
                    name: 'search_docs',
                    arguments: '{}',
                  },
                },
              ],
            },
          },
        ],
      },
      effectiveMode: 'enforce',
      correlationId: 'corr-3',
    });

    expect(decision.detected).toBe(true);
    expect(decision.shouldBlock).toBe(true);
    expect(decision.reasons).toContain('tool_call_depth_exceeded');
  });

  test('detects cycle in delegation graph', () => {
    const shield = new AgenticThreatShield({
      enabled: true,
      mode: 'block',
      max_tool_call_depth: 10,
      max_agent_delegations: 10,
      detect_cycles: true,
    });
    const decision = shield.evaluate({
      headers: {
        'x-sentinel-session-id': 'sess-cycle',
        'x-sentinel-agent-id': 'agent-a',
      },
      bodyJson: {
        tool_calls: [
          {
            function: {
              name: 'delegate_agent',
              arguments: '{"delegate_to":"agent-b"}',
            },
            nested: {
              tool_calls: [
                {
                  function: {
                    name: 'delegate_agent',
                    arguments: '{"delegate_to":"agent-a"}',
                  },
                },
              ],
            },
          },
        ],
      },
      effectiveMode: 'enforce',
      correlationId: 'corr-cycle',
    });

    expect(decision.detected).toBe(true);
    expect(decision.cycleDetected).toBe(true);
    expect(decision.reasons).toContain('agentic_cycle_detected');
  });

  test('verifies valid HMAC agent identity token', () => {
    const shield = new AgenticThreatShield({
      enabled: true,
      mode: 'block',
      verify_identity_tokens: true,
      hmac_secret: 'test-secret',
    });
    const sessionKey = 'sess-identity';
    const agentId = 'agent-identity';
    const token = crypto
      .createHmac('sha256', 'test-secret')
      .update(`${agentId}:${sessionKey}`)
      .digest('hex');
    const decision = shield.evaluate({
      headers: {
        'x-sentinel-session-id': sessionKey,
        'x-sentinel-agent-id': agentId,
        'x-sentinel-agent-token': `v1:${token}`,
      },
      bodyJson: {
        messages: [{ role: 'user', content: 'hello' }],
      },
      effectiveMode: 'enforce',
      correlationId: 'corr-identity',
    });

    expect(decision.detected).toBe(false);
    expect(decision.identity.verified).toBe(true);
  });

  test('rejects invalid identity token in enforce mode', () => {
    const shield = new AgenticThreatShield({
      enabled: true,
      mode: 'block',
      verify_identity_tokens: true,
      hmac_secret: 'test-secret',
    });
    const decision = shield.evaluate({
      headers: {
        'x-sentinel-session-id': 'sess-identity-2',
        'x-sentinel-agent-id': 'agent-identity',
        'x-sentinel-agent-token': 'v1:not-valid',
      },
      bodyJson: {
        messages: [{ role: 'user', content: 'hello' }],
      },
      effectiveMode: 'enforce',
      correlationId: 'corr-identity-2',
    });

    expect(decision.detected).toBe(true);
    expect(decision.shouldBlock).toBe(true);
    expect(decision.reasons).toContain('identity_token_invalid');
  });

  test('caps in-memory session graph by ttl and max entries', () => {
    const now = jest.spyOn(Date, 'now');
    now.mockReturnValue(1_000);
    const shield = new AgenticThreatShield({
      enabled: true,
      mode: 'monitor',
      ttl_ms: 1000,
      max_sessions: 16,
    });

    for (let i = 0; i < 17; i += 1) {
      shield.evaluate({
        headers: { 'x-sentinel-session-id': `sess-${i}`, 'x-sentinel-agent-id': `agent-${i}` },
        bodyJson: { messages: [{ role: 'user', content: String(i) }] },
        effectiveMode: 'monitor',
      });
    }
    shield.prune(1_000);
    expect(shield.sessions.size).toBe(16);
    expect(shield.sessions.has('sess-0')).toBe(false);

    shield.prune(2_500);
    expect(shield.sessions.size).toBe(0);
    now.mockRestore();
  });

  test('reports analysis budget truncation without blocking by default', () => {
    const shield = new AgenticThreatShield({
      enabled: true,
      mode: 'block',
      max_analysis_nodes: 128,
      max_tool_calls_analyzed: 1,
      block_on_analysis_truncation: false,
    });
    const decision = shield.evaluate({
      headers: {
        'x-sentinel-session-id': 'sess-truncate',
        'x-sentinel-agent-id': 'agent-truncate',
      },
      bodyJson: {
        tool_calls: [
          { function: { name: 'delegate_agent', arguments: '{"delegate_to":"agent-b"}' } },
          { function: { name: 'delegate_agent', arguments: '{"delegate_to":"agent-c"}' } },
        ],
      },
      effectiveMode: 'enforce',
      correlationId: 'corr-truncate',
    });

    expect(decision.analysisTruncated).toBe(true);
    expect(decision.reasons).toContain('analysis_tool_call_budget_exceeded');
    expect(decision.shouldBlock).toBe(false);
  });
});
