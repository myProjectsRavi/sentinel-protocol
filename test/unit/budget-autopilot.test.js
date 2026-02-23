const { BudgetAutopilot } = require('../../src/optimizer/budget-autopilot');

describe('BudgetAutopilot', () => {
  test('computes per-provider blended cost/latency score', () => {
    const autopilot = new BudgetAutopilot({
      enabled: true,
      mode: 'monitor',
      min_samples: 2,
      cost_weight: 0.6,
      latency_weight: 0.4,
    });
    autopilot.observe({ provider: 'openai', latencyMs: 180, costUsd: 0.04, timestampMs: 1000 });
    autopilot.observe({ provider: 'openai', latencyMs: 220, costUsd: 0.05, timestampMs: 2000 });
    autopilot.observe({ provider: 'ollama', latencyMs: 90, costUsd: 0.0, timestampMs: 2000 });
    autopilot.observe({ provider: 'ollama', latencyMs: 95, costUsd: 0.0, timestampMs: 3000 });

    const recommendation = autopilot.recommend({
      budgetRemainingUsd: 10,
      slaP95Ms: 300,
    });

    expect(recommendation.enabled).toBe(true);
    expect(['openai', 'ollama']).toContain(recommendation.recommendation);
    expect(recommendation.providers.openai.count).toBe(2);
  });

  test('predicts exhaustion hours for configured budget window', () => {
    const autopilot = new BudgetAutopilot({
      enabled: true,
      min_samples: 1,
    });
    autopilot.observe({ provider: 'openai', latencyMs: 150, costUsd: 0.5, timestampMs: 1000 });
    const recommendation = autopilot.recommend({
      budgetRemainingUsd: 1,
      horizonHours: 24,
    });

    expect(recommendation.estimated_exhaustion_hours).not.toBeNull();
    expect(recommendation.estimated_exhaustion_hours).toBeGreaterThan(0);
    expect(typeof recommendation.budget_warning).toBe('boolean');
  });

  test('returns advisory recommendation without forcing route change', () => {
    const autopilot = new BudgetAutopilot({
      enabled: true,
      mode: 'monitor',
      min_samples: 1,
    });
    autopilot.observe({ provider: 'openai', latencyMs: 110, costUsd: 0.03, timestampMs: 1000 });
    const recommendation = autopilot.recommend({
      budgetRemainingUsd: 3,
      slaP95Ms: 200,
    });
    expect(recommendation.mode).toBe('monitor');
    expect(recommendation.recommendation).toBe('openai');
  });

  test('deterministic output for fixed input counters', () => {
    const config = {
      enabled: true,
      mode: 'monitor',
      min_samples: 1,
      cost_weight: 0.6,
      latency_weight: 0.4,
    };
    const run = () => {
      const autopilot = new BudgetAutopilot(config);
      autopilot.observe({ provider: 'openai', latencyMs: 100, costUsd: 0.02, timestampMs: 1000 });
      autopilot.observe({ provider: 'openai', latencyMs: 120, costUsd: 0.02, timestampMs: 2000 });
      autopilot.observe({ provider: 'ollama', latencyMs: 90, costUsd: 0.0, timestampMs: 2000 });
      autopilot.observe({ provider: 'ollama', latencyMs: 95, costUsd: 0.0, timestampMs: 3000 });
      return autopilot.recommend({
        budgetRemainingUsd: 2,
        slaP95Ms: 200,
        horizonHours: 24,
      });
    };
    const first = run();
    const second = run();
    expect(first.recommendation).toBe(second.recommendation);
    expect(first.providers).toEqual(second.providers);
  });
});
