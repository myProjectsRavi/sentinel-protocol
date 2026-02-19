const { HoneytokenInjector, encodeInvisibleToken } = require('../../src/security/honeytoken-injector');

describe('HoneytokenInjector', () => {
  test('does not inject when disabled', () => {
    const injector = new HoneytokenInjector({
      enabled: false,
    });

    const result = injector.inject({
      bodyJson: {
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(result.applied).toBe(false);
    expect(result.reason).toBe('disabled');
  });

  test('injects invisible marker for user message when enabled', () => {
    const injector = new HoneytokenInjector(
      {
        enabled: true,
        mode: 'zero_width',
        injection_rate: 1,
        max_insertions_per_request: 1,
      },
      {
        random: () => 0,
      }
    );

    const result = injector.inject({
      bodyJson: {
        messages: [
          { role: 'system', content: 'sys' },
          { role: 'user', content: 'hello' },
        ],
      },
    });

    expect(result.applied).toBe(true);
    expect(result.meta.mode).toBe('zero_width');
    expect(result.meta.token_hash).toHaveLength(64);
    expect(result.bodyJson.messages[1].content).toContain('hello');
    expect(result.bodyJson.messages[1].content).not.toBe('hello');
  });

  test('supports uuid suffix mode', () => {
    const injector = new HoneytokenInjector(
      {
        enabled: true,
        mode: 'uuid_suffix',
        injection_rate: 1,
      },
      {
        random: () => 0,
      }
    );

    const result = injector.inject({
      bodyJson: {
        messages: [{ role: 'user', content: 'check status' }],
      },
    });

    expect(result.applied).toBe(true);
    expect(result.bodyJson.messages[0].content).toMatch(/SNTL-/);
  });

  test('invisible encoding yields zero-width only marker', () => {
    const marker = encodeInvisibleToken('abc');
    expect(marker.length).toBeGreaterThan(2);
    // marker should not contain visible ascii alphanumerics
    expect(/[a-z0-9]/i.test(marker)).toBe(false);
  });
});
