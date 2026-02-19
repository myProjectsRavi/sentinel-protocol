const { CognitiveRollback } = require('../../src/runtime/cognitive-rollback');

describe('CognitiveRollback', () => {
  test('returns suggestion in monitor mode for enabled trigger', () => {
    const engine = new CognitiveRollback({
      enabled: true,
      mode: 'monitor',
      triggers: ['canary_tool_triggered'],
      target_roles: ['assistant', 'user'],
      drop_messages: 2,
      min_messages_remaining: 2,
    });

    const result = engine.suggest({
      trigger: 'canary_tool_triggered',
      bodyJson: {
        messages: [
          { role: 'system', content: 'policy' },
          { role: 'user', content: 'q1' },
          { role: 'assistant', content: 'a1' },
          { role: 'user', content: 'q2' },
          { role: 'assistant', content: 'a2' },
        ],
      },
    });

    expect(result.applicable).toBe(true);
    expect(result.mode).toBe('monitor');
    expect(result.droppedMessages).toBeGreaterThan(0);
    expect(Array.isArray(result.bodyJson.messages)).toBe(true);
    expect(result.bodyJson.messages[0].role).toBe('system');
  });

  test('respects trigger allowlist', () => {
    const engine = new CognitiveRollback({
      enabled: true,
      mode: 'auto',
      triggers: ['parallax_veto'],
    });

    const result = engine.suggest({
      trigger: 'canary_tool_triggered',
      bodyJson: { messages: [{ role: 'user', content: 'q' }, { role: 'assistant', content: 'a' }] },
    });

    expect(result.applicable).toBe(false);
    expect(result.reason).toBe('trigger_not_enabled');
  });
});
