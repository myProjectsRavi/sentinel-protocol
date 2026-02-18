const { mergeInjectionResults } = require('../../src/engines/injection-merge');

describe('mergeInjectionResults', () => {
  test('uses max mode by default', () => {
    const merged = mergeInjectionResults(
      { score: 0.42, matchedSignals: [] },
      { enabled: true, score: 0.9, error: null, scanTruncated: false, attackPrototype: 'a', benignPrototype: 'b' },
      { mode: 'max', weight: 1 }
    );

    expect(merged.score).toBe(0.9);
    expect(merged.matchedSignals.some((signal) => signal.id === 'neural_injection_classifier')).toBe(true);
  });

  test('supports blend mode', () => {
    const merged = mergeInjectionResults(
      { score: 0.6, matchedSignals: [] },
      { enabled: true, score: 0.2, error: null, scanTruncated: false, attackPrototype: null, benignPrototype: null },
      { mode: 'blend', weight: 1 }
    );

    expect(merged.score).toBe(0.4);
  });
});
