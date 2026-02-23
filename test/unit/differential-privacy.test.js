const fs = require('fs');
const os = require('os');
const path = require('path');
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

  test('persists budget state and restores across restarts', () => {
    const stateFile = path.join(os.tmpdir(), `sentinel-dp-state-${Date.now()}-restore.json`);
    const config = {
      enabled: true,
      epsilon_budget: 1,
      epsilon_per_call: 0.2,
      sensitivity: 1,
      persist_state: true,
      state_file: stateFile,
      state_hmac_key: 'unit-test-key',
    };

    const first = new DifferentialPrivacyEngine(config, { rng: () => 0.75 });
    first.noisify(10);
    first.noisify(11);
    const firstSnapshot = first.snapshot();
    expect(fs.existsSync(stateFile)).toBe(true);

    const second = new DifferentialPrivacyEngine(config, { rng: () => 0.75 });
    const secondSnapshot = second.snapshot();
    expect(secondSnapshot.calls).toBe(firstSnapshot.calls);
    expect(secondSnapshot.epsilon_remaining).toBe(firstSnapshot.epsilon_remaining);
    expect(secondSnapshot.state_persistence.loaded).toBe(true);
  });

  test('detects tampering and resets budget when reset_on_tamper is true', () => {
    const stateFile = path.join(os.tmpdir(), `sentinel-dp-state-${Date.now()}-tamper-reset.json`);
    const config = {
      enabled: true,
      epsilon_budget: 1,
      epsilon_per_call: 0.2,
      sensitivity: 1,
      persist_state: true,
      state_file: stateFile,
      state_hmac_key: 'unit-test-key',
      reset_on_tamper: true,
    };

    const engine = new DifferentialPrivacyEngine(config, { rng: () => 0.75 });
    engine.noisify(10);

    const tampered = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
    tampered.state.remaining_epsilon = 999;
    fs.writeFileSync(stateFile, `${JSON.stringify(tampered, null, 2)}\n`, 'utf8');

    const reloaded = new DifferentialPrivacyEngine(config, { rng: () => 0.75 });
    const snapshot = reloaded.snapshot();
    expect(snapshot.calls).toBe(0);
    expect(snapshot.epsilon_remaining).toBe(1);
    expect(snapshot.state_persistence.tamper_detected).toBe(true);
  });

  test('throws on tampering when reset_on_tamper is false', () => {
    const stateFile = path.join(os.tmpdir(), `sentinel-dp-state-${Date.now()}-tamper-throw.json`);
    const config = {
      enabled: true,
      epsilon_budget: 1,
      epsilon_per_call: 0.2,
      sensitivity: 1,
      persist_state: true,
      state_file: stateFile,
      state_hmac_key: 'unit-test-key',
      reset_on_tamper: false,
    };

    const engine = new DifferentialPrivacyEngine(config, { rng: () => 0.75 });
    engine.noisify(10);

    const tampered = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
    tampered.digest = '0000';
    fs.writeFileSync(stateFile, `${JSON.stringify(tampered, null, 2)}\n`, 'utf8');

    expect(() => new DifferentialPrivacyEngine(config, { rng: () => 0.75 })).toThrow();
  });
});
