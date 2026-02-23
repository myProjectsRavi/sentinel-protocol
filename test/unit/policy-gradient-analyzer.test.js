const { PolicyGradientAnalyzer } = require('../../src/governance/policy-gradient-analyzer');

describe('PolicyGradientAnalyzer', () => {
  test('computes delta between thresholds', () => {
    const analyzer = new PolicyGradientAnalyzer({ enabled: true });
    const report = analyzer.analyze({
      events: [
        { decision: 'forwarded', injection_score: 0.2 },
        { decision: 'forwarded', injection_score: 0.4 },
        { decision: 'blocked_policy', injection_score: 0.9 },
      ],
      current: { injection_threshold: 0.5 },
      proposed: { injection_threshold: 0.3 },
    });

    expect(report.evaluated_events).toBe(3);
    expect(report.delta_blocked).toBeGreaterThanOrEqual(1);
    expect(report.recommendation).toBeTruthy();
  });
});
