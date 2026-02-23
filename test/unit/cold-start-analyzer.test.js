const { ColdStartAnalyzer } = require('../../src/security/cold-start-analyzer');

describe('ColdStartAnalyzer', () => {
  test('detects cold-start window and reports progress', () => {
    const analyzer = new ColdStartAnalyzer({
      enabled: true,
      mode: 'monitor',
      cold_start_window_ms: 600000,
      warmup_request_threshold: 10,
    });

    const decision = analyzer.evaluate({
      effectiveMode: 'monitor',
      engineStates: { semantic_cache: false },
    });

    expect(decision.detected).toBe(true);
    expect(decision.reason).toBe('cold_start_active');
    expect(decision.progress).toBeGreaterThanOrEqual(0);
  });

  test('blocks when configured in enforce mode', () => {
    const analyzer = new ColdStartAnalyzer({
      enabled: true,
      mode: 'block',
      block_during_cold_start: true,
      warmup_request_threshold: 100,
      cold_start_window_ms: 600000,
    });

    const decision = analyzer.evaluate({ effectiveMode: 'enforce' });
    expect(decision.shouldBlock).toBe(true);
  });
});
