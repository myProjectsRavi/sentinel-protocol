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
});
