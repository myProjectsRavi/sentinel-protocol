const { ShadowOS, extractHighRiskToolCalls } = require('../../src/sandbox/shadow-os');

describe('ShadowOS', () => {
  test('extracts tool names from request body variants', () => {
    const tools = extractHighRiskToolCalls({
      tool_name: 'execute_shell',
      messages: [
        {
          role: 'assistant',
          tool_calls: [{ function: { name: 'grant_permissions' } }],
        },
      ],
    });
    expect(tools).toContain('execute_shell');
    expect(tools).toContain('grant_permissions');
  });

  test('detects and blocks causal sequence violations in enforce mode', () => {
    const shadow = new ShadowOS({
      enabled: true,
      mode: 'block',
      high_risk_tools: ['create_user', 'grant_permissions', 'delete_log'],
      sequence_rules: [
        {
          id: 'privilege_escalation_coverup',
          requires: ['create_user', 'grant_permissions', 'delete_log'],
          order_required: true,
        },
      ],
    });

    const headers = { 'x-sentinel-session-id': 's1' };
    shadow.evaluate({
      headers,
      bodyJson: { tool_name: 'create_user' },
      method: 'POST',
      path: '/v1/chat/completions',
      provider: 'openai',
      effectiveMode: 'enforce',
      correlationId: 'c1',
    });
    shadow.evaluate({
      headers,
      bodyJson: { tool_name: 'grant_permissions' },
      method: 'POST',
      path: '/v1/chat/completions',
      provider: 'openai',
      effectiveMode: 'enforce',
      correlationId: 'c2',
    });
    const decision = shadow.evaluate({
      headers,
      bodyJson: { tool_name: 'delete_log' },
      method: 'POST',
      path: '/v1/chat/completions',
      provider: 'openai',
      effectiveMode: 'enforce',
      correlationId: 'c3',
    });

    expect(decision.detected).toBe(true);
    expect(decision.shouldBlock).toBe(true);
    expect(decision.violations[0].rule).toBe('privilege_escalation_coverup');
  });

  test('monitor mode detects but does not block', () => {
    const shadow = new ShadowOS({
      enabled: true,
      mode: 'monitor',
      high_risk_tools: ['execute_shell'],
      repeat_threshold: 2,
      sequence_rules: [],
    });
    const headers = { 'x-sentinel-session-id': 's2' };
    shadow.evaluate({
      headers,
      bodyJson: { tool_name: 'execute_shell' },
      method: 'POST',
      path: '/v1/chat/completions',
      provider: 'openai',
      effectiveMode: 'enforce',
      correlationId: 'c4',
    });
    const decision = shadow.evaluate({
      headers,
      bodyJson: { tool_name: 'execute_shell' },
      method: 'POST',
      path: '/v1/chat/completions',
      provider: 'openai',
      effectiveMode: 'enforce',
      correlationId: 'c5',
    });

    expect(decision.detected).toBe(true);
    expect(decision.shouldBlock).toBe(false);
  });
});
