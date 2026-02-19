const { PolymorphicPromptEngine } = require('../../src/security/polymorphic-prompt');

describe('PolymorphicPromptEngine', () => {
  test('is disabled by default', () => {
    const engine = new PolymorphicPromptEngine();
    const result = engine.mutate({
      bodyJson: {
        messages: [{ role: 'system', content: 'You are a helpful assistant.' }],
      },
    });
    expect(result.applied).toBe(false);
    expect(result.reason).toBe('disabled');
  });

  test('mutates target role prompts deterministically per epoch', () => {
    let now = 1700000000000;
    const engine = new PolymorphicPromptEngine(
      {
        enabled: true,
        rotation_seconds: 1800,
        target_roles: ['system'],
        max_mutations_per_message: 2,
        seed: 'seed-1',
      },
      {
        now: () => now,
      }
    );

    const input = {
      bodyJson: {
        messages: [
          { role: 'system', content: 'You are a helpful assistant. Follow safety policy.' },
          { role: 'user', content: 'write code' },
        ],
      },
      headers: {},
    };

    const first = engine.mutate(input);
    const second = engine.mutate(input);
    expect(first.applied).toBe(true);
    expect(second.applied).toBe(true);
    expect(first.bodyJson.messages[0].content).toBe(second.bodyJson.messages[0].content);
    expect(first.bodyJson.messages[1].content).toBe('write code');
  });

  test('bypass header prevents mutation for rollback safety', () => {
    const engine = new PolymorphicPromptEngine({
      enabled: true,
      bypass_header: 'x-sentinel-polymorph-disable',
    });
    const result = engine.mutate({
      bodyJson: {
        messages: [{ role: 'system', content: 'You are a helpful assistant.' }],
      },
      headers: {
        'x-sentinel-polymorph-disable': 'true',
      },
    });
    expect(result.applied).toBe(false);
    expect(result.reason).toBe('bypass_header');
  });
});
