const { LFRLEngine } = require('../../src/engines/lfrl-engine');

describe('LFRLEngine', () => {
  test('matches comparison rules and blocks in enforce mode', () => {
    const engine = new LFRLEngine({
      enabled: true,
      mode: 'block',
      rules: [
        'RULE high_injection WHEN metrics.injection_score >= 0.8 AND request.method == POST THEN BLOCK',
      ],
    });

    const decision = engine.evaluate({
      context: {
        metrics: {
          injection_score: 0.95,
        },
        request: {
          method: 'POST',
        },
      },
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.shouldBlock).toBe(true);
    expect(decision.findings[0].rule_id).toBe('high_injection');
  });

  test('supports temporal tool call counters', () => {
    const engine = new LFRLEngine({
      enabled: true,
      mode: 'monitor',
      rules: [
        'RULE tool_abuse WHEN tool_calls("shell_exec") > 2 WITHIN 10m THEN WARN',
      ],
    });
    engine.observe({ tool_name: 'shell_exec' });
    engine.observe({ tool_name: 'shell_exec' });
    engine.observe({ tool_name: 'shell_exec' });

    const decision = engine.evaluate({
      context: {},
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.shouldBlock).toBe(false);
    expect(decision.findings[0].action).toBe('warn');
  });
});
