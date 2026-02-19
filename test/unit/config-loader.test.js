const fs = require('fs');
const os = require('os');
const path = require('path');
const yaml = require('js-yaml');

process.env.SENTINEL_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-home-config-'));

const {
  PROJECT_DEFAULT_CONFIG,
  loadAndValidateConfig,
  readYamlConfig,
  writeYamlConfig,
} = require('../../src/config/loader');

describe('config loader and migration', () => {
  test('migrates legacy string version and writes backup', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-config-'));
    const configPath = path.join(tmpDir, 'sentinel.yaml');

    const base = yaml.load(fs.readFileSync(PROJECT_DEFAULT_CONFIG, 'utf8'));
    base.version = '1.0';
    writeYamlConfig(configPath, base);

    const loaded = loadAndValidateConfig({
      configPath,
      allowMigration: true,
      writeMigrated: true,
    });

    expect(loaded.migration.migrated).toBe(true);
    expect(loaded.backupPath).toContain('.bak.');
    expect(fs.existsSync(loaded.backupPath)).toBe(true);

    const migrated = readYamlConfig(configPath);
    expect(migrated.version).toBe(1);
  });

  test('fails loudly on unsupported version', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-config-'));
    const configPath = path.join(tmpDir, 'sentinel.yaml');

    const base = yaml.load(fs.readFileSync(PROJECT_DEFAULT_CONFIG, 'utf8'));
    base.version = 999;
    writeYamlConfig(configPath, base);

    expect(() => {
      loadAndValidateConfig({ configPath });
    }).toThrow(/Unsupported config version/);
  });

  test('fails validation when custom targets enabled without allowlist', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-config-'));
    const configPath = path.join(tmpDir, 'sentinel.yaml');

    const base = yaml.load(fs.readFileSync(PROJECT_DEFAULT_CONFIG, 'utf8'));
    base.runtime.upstream.custom_targets.enabled = true;
    base.runtime.upstream.custom_targets.allowlist = [];
    writeYamlConfig(configPath, base);

    expect(() => {
      loadAndValidateConfig({ configPath, allowMigration: false, writeMigrated: false });
    }).toThrow(/allowlist/);
  });

  test('fails validation on unknown keys to avoid silent typos', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-config-'));
    const configPath = path.join(tmpDir, 'sentinel.yaml');

    const base = yaml.load(fs.readFileSync(PROJECT_DEFAULT_CONFIG, 'utf8'));
    base.pii_enable = true;
    writeYamlConfig(configPath, base);

    expect(() => {
      loadAndValidateConfig({ configPath, allowMigration: false, writeMigrated: false });
    }).toThrow(/Unknown key: config.pii_enable/);
  });

  test('fails validation when dashboard remote mode has no auth token', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-config-'));
    const configPath = path.join(tmpDir, 'sentinel.yaml');

    const base = yaml.load(fs.readFileSync(PROJECT_DEFAULT_CONFIG, 'utf8'));
    base.runtime.dashboard.enabled = true;
    base.runtime.dashboard.allow_remote = true;
    base.runtime.dashboard.auth_token = '';
    writeYamlConfig(configPath, base);

    expect(() => {
      loadAndValidateConfig({ configPath, allowMigration: false, writeMigrated: false });
    }).toThrow(/dashboard\.auth_token.*allow_remote=true/);
  });

  test('fails validation when auth vault provider key is unknown', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-config-'));
    const configPath = path.join(tmpDir, 'sentinel.yaml');

    const base = yaml.load(fs.readFileSync(PROJECT_DEFAULT_CONFIG, 'utf8'));
    base.runtime.upstream.auth_vault.enabled = true;
    base.runtime.upstream.auth_vault.providers.custom = {
      enabled: true,
      api_key: 'abc',
      env_var: 'SENTINEL_CUSTOM_KEY',
    };
    writeYamlConfig(configPath, base);

    expect(() => {
      loadAndValidateConfig({ configPath, allowMigration: false, writeMigrated: false });
    }).toThrow(/auth_vault\.providers\.custom is not supported/);
  });

  test('accepts intent throttle configuration with explicit clusters', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-config-'));
    const configPath = path.join(tmpDir, 'sentinel.yaml');

    const base = yaml.load(fs.readFileSync(PROJECT_DEFAULT_CONFIG, 'utf8'));
    base.runtime.intent_throttle = {
      enabled: true,
      mode: 'block',
      key_header: 'x-sentinel-agent-id',
      window_ms: 60000,
      cooldown_ms: 30000,
      max_events_per_window: 3,
      min_similarity: 0.8,
      max_prompt_chars: 3000,
      max_sessions: 2500,
      model_id: 'Xenova/all-MiniLM-L6-v2',
      cache_dir: '~/.sentinel/models',
      clusters: [
        {
          name: 'credential_exfiltration',
          phrases: ['extract api keys'],
          min_similarity: 0.81,
        },
      ],
    };
    writeYamlConfig(configPath, base);

    const loaded = loadAndValidateConfig({ configPath, allowMigration: false, writeMigrated: false });
    expect(loaded.config.runtime.intent_throttle.enabled).toBe(true);
    expect(loaded.config.runtime.intent_throttle.mode).toBe('block');
    expect(loaded.config.runtime.intent_throttle.clusters[0].name).toBe('credential_exfiltration');
  });
});
