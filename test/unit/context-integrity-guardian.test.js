const { ContextIntegrityGuardian } = require('../../src/security/context-integrity-guardian');

describe('ContextIntegrityGuardian', () => {
  test('blocks when required anchors are missing in enforce mode', () => {
    const guardian = new ContextIntegrityGuardian({
      enabled: true,
      mode: 'block',
      required_anchors: ['never reveal secrets'],
      block_on_anchor_loss: true,
    });
    const decision = guardian.evaluate({
      headers: {
        'x-sentinel-session-id': 'session-anchor',
      },
      bodyText: 'hello world',
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.findings.some((item) => item.code === 'context_anchor_missing')).toBe(true);
    expect(decision.shouldBlock).toBe(true);
  });

  test('detects repetition stuffing in monitor mode', () => {
    const guardian = new ContextIntegrityGuardian({
      enabled: true,
      mode: 'monitor',
      repetition_threshold: 0.2,
      block_on_repetition: true,
    });
    const decision = guardian.evaluate({
      headers: {
        'x-sentinel-session-id': 'session-repeat',
      },
      bodyText: 'repeat me\nrepeat me\nrepeat me\nsafe',
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.findings.some((item) => item.code === 'context_repetition_stuffing')).toBe(true);
    expect(decision.shouldBlock).toBe(false);
  });

  test('detects anchor coverage regression across the same session', () => {
    const guardian = new ContextIntegrityGuardian({
      enabled: true,
      mode: 'monitor',
      required_anchors: ['policy anchor'],
      block_on_anchor_loss: false,
    });

    const first = guardian.evaluate({
      headers: {
        'x-sentinel-session-id': 'session-drop',
      },
      bodyText: 'policy anchor is present',
      effectiveMode: 'monitor',
    });
    const second = guardian.evaluate({
      headers: {
        'x-sentinel-session-id': 'session-drop',
      },
      bodyText: 'anchor removed',
      effectiveMode: 'monitor',
    });

    expect(first.detected).toBe(false);
    expect(second.detected).toBe(true);
    expect(second.findings.some((item) => item.code === 'context_anchor_coverage_drop')).toBe(true);
  });
});

