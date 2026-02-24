const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const { applyConfigProfile } = require('../../src/config/profiles');

const PROJECT_DEFAULT_CONFIG = path.join(__dirname, '..', '..', 'src', 'config', 'default.yaml');

function readDefaultConfig() {
  return yaml.load(fs.readFileSync(PROJECT_DEFAULT_CONFIG, 'utf8'));
}

describe('config profiles', () => {
  test('applies minimal profile with strict memory budget defaults', () => {
    const base = readDefaultConfig();
    const result = applyConfigProfile(base, 'minimal');

    expect(result.profile).toBe('minimal');
    expect(result.config.mode).toBe('monitor');
    expect(result.config.runtime.cost_efficiency_optimizer.enabled).toBe(true);
    expect(result.config.runtime.cost_efficiency_optimizer.mode).toBe('active');
    expect(result.config.runtime.cost_efficiency_optimizer.memory_hard_cap_bytes).toBe(512 * 1024 * 1024);
    expect(result.enabledRuntimeEngines).toBeGreaterThanOrEqual(8);
  });

  test('applies paranoid profile and forces enforce mode', () => {
    const base = readDefaultConfig();
    const result = applyConfigProfile(base, 'paranoid');

    expect(result.profile).toBe('paranoid');
    expect(result.config.mode).toBe('enforce');
    expect(result.config.injection.action).toBe('block');
    expect(result.enabledRuntimeEngines).toBeGreaterThan(20);
  });

  test('rejects invalid profile names', () => {
    const base = readDefaultConfig();
    expect(() => applyConfigProfile(base, 'unknown-profile')).toThrow(/Invalid profile/);
  });
});
