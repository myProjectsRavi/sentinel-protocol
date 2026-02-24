const { CostEfficiencyOptimizer } = require('../../src/optimizer/cost-efficiency-optimizer');

describe('CostEfficiencyOptimizer', () => {
  test('flags prompt bloat and repetition signals', () => {
    const optimizer = new CostEfficiencyOptimizer({
      enabled: true,
      mode: 'monitor',
      prompt_bloat_chars: 300,
      repetition_warn_ratio: 0.2,
    });
    const longRepeated = Array.from({ length: 80 }, () => 'repeat line').join('\n');
    const decision = optimizer.evaluate({
      provider: 'openai',
      bodyText: longRepeated,
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.findings.some((item) => item.code === 'cost_prompt_bloat')).toBe(true);
    expect(decision.findings.some((item) => item.code === 'cost_prompt_repetition')).toBe(true);
  });

  test('provides route recommendation from observed provider samples', () => {
    const optimizer = new CostEfficiencyOptimizer({
      enabled: true,
      mode: 'monitor',
    });
    for (let i = 0; i < 10; i += 1) {
      optimizer.observe({ provider: 'fast-provider', latencyMs: 120 + i, inputTokens: 200, costUsd: 0.001 });
      optimizer.observe({ provider: 'slow-provider', latencyMs: 700 + i, inputTokens: 200, costUsd: 0.001 });
    }
    const recommendation = optimizer.recommendRoute({
      slaP95Ms: 400,
    });
    expect(recommendation.enabled).toBe(true);
    expect(recommendation.recommendation.provider).toBe('fast-provider');
  });

  test('emits hard-cap memory signal and shedding recommendation in active mode', () => {
    const optimizer = new CostEfficiencyOptimizer({
      enabled: true,
      mode: 'active',
      memory_warn_bytes: 1,
      memory_critical_bytes: 2,
      memory_hard_cap_bytes: 3,
      shed_on_memory_pressure: true,
      max_shed_engines: 7,
      shed_cooldown_ms: 2500,
      shed_engine_order: ['anomaly_telemetry', 'output_classifier'],
    });

    const originalMemoryUsage = process.memoryUsage;
    process.memoryUsage = jest.fn(() => ({ rss: 4 }));
    try {
      const decision = optimizer.evaluate({
        provider: 'openai',
        bodyText: 'hello world',
        effectiveMode: 'enforce',
      });
      expect(decision.memory_level).toBe('hard_cap');
      expect(decision.shed_recommended).toBe(true);
      expect(decision.shouldBlock).toBe(true);
      expect(decision.findings.some((item) => item.code === 'cost_memory_hard_cap')).toBe(true);
      const snapshot = optimizer.snapshot();
      expect(snapshot.memory_hard_cap_bytes).toBe(3);
      expect(snapshot.max_shed_engines).toBe(7);
      expect(snapshot.shed_cooldown_ms).toBe(2500);
    } finally {
      process.memoryUsage = originalMemoryUsage;
    }
  });
});
