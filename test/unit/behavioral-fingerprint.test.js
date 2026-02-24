const { BehavioralFingerprint } = require('../../src/security/behavioral-fingerprint');

describe('BehavioralFingerprint', () => {
  test('detects tool-count anomaly after warmup', () => {
    const engine = new BehavioralFingerprint({
      enabled: true,
      mode: 'block',
      warmup_events: 4,
      z_score_threshold: 1.5,
      block_on_anomaly: true,
    });
    for (let i = 0; i < 6; i += 1) {
      engine.evaluate({
        agentId: 'agent-a',
        bodyJson: { tool_name: 'search' },
        bodyText: 'normal request',
        effectiveMode: 'enforce',
      });
    }

    const decision = engine.evaluate({
      agentId: 'agent-a',
      bodyJson: {
        tools: [{ function: { name: 'a' } }, { function: { name: 'b' } }, { function: { name: 'c' } }],
      },
      bodyText: 'abnormal request',
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.shouldBlock).toBe(true);
    expect(decision.findings.some((item) => item.code === 'behavioral_tool_count_anomaly')).toBe(true);
  });

  test('detects impersonation when style matches another trained agent', () => {
    const engine = new BehavioralFingerprint({
      enabled: true,
      mode: 'monitor',
      warmup_events: 3,
      impersonation_min_hits: 2,
      z_score_threshold: 99,
    });
    for (let i = 0; i < 5; i += 1) {
      engine.evaluate({
        agentId: 'agent-primary',
        bodyText: 'stable writing profile alpha',
        bodyJson: {},
      });
    }
    for (let i = 0; i < 4; i += 1) {
      engine.evaluate({
        agentId: 'agent-secondary',
        bodyText: 'other writing profile beta',
        bodyJson: {},
      });
    }

    const decision = engine.evaluate({
      agentId: 'agent-secondary',
      bodyText: 'stable writing profile alpha',
      bodyJson: {},
    });

    expect(decision.detected).toBe(true);
    expect(decision.findings.some((item) => item.code === 'behavioral_impersonation_suspected')).toBe(true);
  });
});
