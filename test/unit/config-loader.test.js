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
});
