const { HallucinationTripwire } = require('../../src/egress/hallucination-tripwire');

describe('HallucinationTripwire', () => {
  test('detects suspicious URLs and overconfident claims', () => {
    const detector = new HallucinationTripwire({
      enabled: true,
      mode: 'block',
      block_on_detect: true,
      warn_threshold: 0.2,
      block_threshold: 0.3,
    });

    const text = '100% accurate source: https://internal.example/ghost and doi 10.1234/unknown';
    const decision = detector.analyzeText(text, { effectiveMode: 'enforce' });
    expect(decision.detected).toBe(true);
    expect(decision.shouldBlock).toBe(true);
    expect(decision.score).toBeGreaterThan(0.2);
  });

  test('returns clean on normal content', () => {
    const detector = new HallucinationTripwire({ enabled: true });
    const decision = detector.analyzeText('Documentation response with neutral content.');
    expect(decision.detected).toBe(false);
  });
});
