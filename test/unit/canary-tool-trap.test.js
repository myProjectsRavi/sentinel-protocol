const { CanaryToolTrap } = require('../../src/engines/canary-tool-trap');

describe('CanaryToolTrap', () => {
  test('injects canary tool in monitor mode when tools array exists', () => {
    const trap = new CanaryToolTrap({
      enabled: true,
      mode: 'monitor',
      tool_name: 'fetch_admin_passwords',
    });

    const result = trap.inject(
      {
        model: 'gpt-4o-mini',
        tools: [
          {
            type: 'function',
            function: {
              name: 'search_docs',
              description: 'Search docs',
              parameters: { type: 'object', properties: {} },
            },
          },
        ],
      },
      { provider: 'openai' }
    );

    expect(result.applied).toBe(true);
    expect(result.bodyJson.tools.some((tool) => tool?.function?.name === 'fetch_admin_passwords')).toBe(true);
  });

  test('detects triggered canary tool call in openai response payload', () => {
    const trap = new CanaryToolTrap({
      enabled: true,
      mode: 'monitor',
      tool_name: 'fetch_admin_passwords',
    });

    const payload = Buffer.from(
      JSON.stringify({
        choices: [
          {
            message: {
              tool_calls: [
                {
                  id: 'call_1',
                  type: 'function',
                  function: {
                    name: 'fetch_admin_passwords',
                    arguments: '{"scope":"all"}',
                  },
                },
              ],
            },
          },
        ],
      }),
      'utf8'
    );

    const detection = trap.detectTriggered(payload, 'application/json');
    expect(detection.triggered).toBe(true);
    expect(detection.toolName).toBe('fetch_admin_passwords');
  });

  test('does not inject when disabled', () => {
    const trap = new CanaryToolTrap({
      enabled: false,
    });
    const result = trap.inject({ tools: [] }, { provider: 'openai' });
    expect(result.applied).toBe(false);
    expect(result.reason).toBe('disabled');
  });
});
