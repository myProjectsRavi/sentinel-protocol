const { DifferentialPrivacyEngine } = require('../../src/privacy/differential-privacy');

describe('differential privacy', () => {
  test('laplace noisify returns deterministic output when seeded rng is supplied', () => {
    const config = {
      enabled: true,
      epsilon_budget: 10,
      epsilon_per_call: 0.5,
      sensitivity: 1,
    };
    const rng = () => 0.75;

    const firstEngine = new DifferentialPrivacyEngine(config, { rng });
    const secondEngine = new DifferentialPrivacyEngine(config, { rng });

    const first = firstEngine.noisify(42, { epsilon: 0.5, sensitivity: 1, rng });
    const second = secondEngine.noisify(42, { epsilon: 0.5, sensitivity: 1, rng });

    expect(first.noisy).toBe(second.noisy);
  });

  test('noisifyEmbeddings preserves vector length and numeric type', () => {
    const engine = new DifferentialPrivacyEngine({
      enabled: true,
      epsilon_budget: 10,
      epsilon_per_call: 0.1,
      sensitivity: 1,
    });

    const result = engine.noisifyEmbeddings([0.1, 0.2, -0.3, 0.4]);
    expect(result.noisy.length).toBe(4);
    expect(result.noisy.every((value) => typeof value === 'number')).toBe(true);
  });

  test('privacy budget decreases on each simulation call', () => {
    const engine = new DifferentialPrivacyEngine({
      enabled: true,
      epsilon_budget: 1,
      epsilon_per_call: 0.25,
      sensitivity: 1,
    });

    const before = engine.snapshot();
    engine.noisify(1);
    const after = engine.snapshot();

    expect(after.epsilon_remaining).toBeLessThan(before.epsilon_remaining);
  });

  test('returns exhausted state when epsilon budget reaches zero', () => {
    const engine = new DifferentialPrivacyEngine({
      enabled: true,
      epsilon_budget: 0.2,
      epsilon_per_call: 0.2,
      sensitivity: 1,
    });

    const first = engine.noisify(10);
    const second = engine.noisify(10);

    expect(first.applied).toBe(true);
    expect(second.applied).toBe(false);
    expect(second.exhausted).toBe(true);
  });

  test('disabled mode returns passthrough values with no mutation', () => {
    const engine = new DifferentialPrivacyEngine({
      enabled: false,
      epsilon_budget: 1,
      epsilon_per_call: 0.1,
      sensitivity: 1,
    });

    const scalar = engine.noisify(25);
    const vector = engine.noisifyEmbeddings([0.1, 0.2]);

    expect(scalar.applied).toBe(false);
    expect(scalar.noisy).toBe(25);
    expect(vector.applied).toBe(false);
    expect(vector.noisy).toEqual([0.1, 0.2]);
  });
});
