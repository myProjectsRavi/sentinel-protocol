const { SemanticDriftCanary } = require('../../src/security/semantic-drift-canary');

describe('SemanticDriftCanary', () => {
  test('detects drift when sampled response deviates strongly', () => {
    const canary = new SemanticDriftCanary({
      enabled: true,
      mode: 'block',
      sample_every_requests: 1,
      warn_distance_threshold: 0.1,
      block_distance_threshold: 0.2,
    });

    for (let i = 0; i < 6; i += 1) {
      canary.observe({
        provider: 'openai',
        responseText: 'stable baseline response',
        latencyMs: 80,
        effectiveMode: 'enforce',
      });
    }

    const decision = canary.observe({
      provider: 'openai',
      responseText: 'X'.repeat(4000),
      latencyMs: 2500,
      effectiveMode: 'enforce',
    });

    expect(decision.sampled).toBe(true);
    expect(decision.detected).toBe(true);
    expect(decision.shouldBlock).toBe(true);
  });
});
