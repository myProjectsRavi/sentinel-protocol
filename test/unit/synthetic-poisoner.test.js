const { SyntheticPoisoner, DEFAULT_ACKNOWLEDGEMENT } = require('../../src/security/synthetic-poisoner');

describe('SyntheticPoisoner', () => {
  test('does not inject in monitor mode', () => {
    const poisoner = new SyntheticPoisoner({
      enabled: true,
      mode: 'monitor',
    });
    const result = poisoner.inject({
      trigger: 'intent_velocity_exceeded',
      bodyJson: {
        messages: [{ role: 'system', content: 'Policy' }],
      },
    });
    expect(result.applied).toBe(false);
    expect(result.reason).toBe('monitor_mode');
  });

  test('requires acknowledgement before inject mode can activate', () => {
    const poisoner = new SyntheticPoisoner({
      enabled: true,
      mode: 'inject',
      required_acknowledgement: DEFAULT_ACKNOWLEDGEMENT,
      acknowledgement: '',
      allowed_triggers: ['intent_velocity_exceeded'],
    });
    const result = poisoner.inject({
      trigger: 'intent_velocity_exceeded',
      bodyJson: {
        messages: [{ role: 'system', content: 'Policy' }],
      },
    });
    expect(result.applied).toBe(false);
    expect(result.reason).toBe('acknowledgement_missing');
  });

  test('injects synthetic context when explicitly enabled and acknowledged', () => {
    const poisoner = new SyntheticPoisoner(
      {
        enabled: true,
        mode: 'inject',
        required_acknowledgement: DEFAULT_ACKNOWLEDGEMENT,
        acknowledgement: DEFAULT_ACKNOWLEDGEMENT,
        allowed_triggers: ['intent_velocity_exceeded'],
        target_roles: ['system'],
      },
      {
        randomUuid: () => 'decoy-uuid-1',
      }
    );
    const result = poisoner.inject({
      trigger: 'intent_velocity_exceeded',
      bodyJson: {
        messages: [{ role: 'system', content: 'Policy' }, { role: 'user', content: 'hello' }],
      },
    });
    expect(result.applied).toBe(true);
    expect(result.bodyJson.messages[0].role).toBe('system');
    expect(result.bodyJson.messages[0].content).toContain('Synthetic context injected by Sentinel');
    expect(result.meta.insertions).toBeGreaterThan(0);
  });
});
