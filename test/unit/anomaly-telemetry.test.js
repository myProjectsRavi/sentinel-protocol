const { AnomalyTelemetry } = require('../../src/telemetry/anomaly-telemetry');

describe('AnomalyTelemetry', () => {
  test('records events and builds heatmap snapshot', () => {
    const telemetry = new AnomalyTelemetry({
      enabled: true,
      max_events: 100,
    });

    telemetry.record({
      timestamp: new Date().toISOString(),
      decision: 'blocked_prompt_rebuff',
      reasons: ['prompt_rebuff:high_confidence'],
      provider: 'openai',
      duration_ms: 21,
    });
    telemetry.record({
      timestamp: new Date().toISOString(),
      decision: 'allowed',
      reasons: ['context_integrity:warn'],
      provider: 'anthropic',
      duration_ms: 15,
    });

    const snapshot = telemetry.snapshot();
    expect(snapshot.enabled).toBe(true);
    expect(snapshot.total_events).toBe(2);
    expect(snapshot.engine_heatmap.length).toBeGreaterThan(0);
    expect(snapshot.timeline.length).toBeGreaterThan(0);
  });
});
