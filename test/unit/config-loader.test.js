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

  test('accepts swarm + polymorphic + synthetic poisoning config in strict mode', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-config-'));
    const configPath = path.join(tmpDir, 'sentinel.yaml');
    const base = yaml.load(fs.readFileSync(PROJECT_DEFAULT_CONFIG, 'utf8'));
    base.runtime.swarm = {
      enabled: true,
      mode: 'monitor',
      node_id: 'node-a',
      key_id: 'node-a',
      private_key_pem: '',
      public_key_pem: '',
      verify_inbound: true,
      sign_outbound: true,
      require_envelope: false,
      allowed_clock_skew_ms: 30000,
      nonce_ttl_ms: 300000,
      max_nonce_entries: 10000,
      sign_on_providers: ['custom'],
      trusted_nodes: {},
    };
    base.runtime.polymorphic_prompt = {
      enabled: true,
      rotation_seconds: 1800,
      max_mutations_per_message: 3,
      target_roles: ['system'],
      bypass_header: 'x-sentinel-polymorph-disable',
      seed: 'seed',
      observability: true,
      lexicon: {},
    };
    base.runtime.synthetic_poisoning = {
      enabled: true,
      mode: 'inject',
      required_acknowledgement: 'I_UNDERSTAND_SYNTHETIC_DATA_RISK',
      acknowledgement: 'I_UNDERSTAND_SYNTHETIC_DATA_RISK',
      allowed_triggers: ['intent_velocity_exceeded'],
      target_roles: ['system'],
      decoy_label: 'SYNTH',
      max_insertions_per_request: 1,
      observability: true,
    };
    base.runtime.cognitive_rollback = {
      enabled: true,
      mode: 'monitor',
      triggers: ['canary_tool_triggered', 'parallax_veto'],
      target_roles: ['user', 'assistant'],
      drop_messages: 2,
      min_messages_remaining: 2,
      system_message: 'resume from last safe checkpoint',
      observability: true,
    };
    base.runtime.omni_shield = {
      enabled: true,
      mode: 'monitor',
      max_image_bytes: 5 * 1024 * 1024,
      allow_remote_image_urls: false,
      allow_base64_images: true,
      block_on_any_image: false,
      max_findings: 20,
      target_roles: ['user'],
      observability: true,
    };
    writeYamlConfig(configPath, base);

    const loaded = loadAndValidateConfig({ configPath, allowMigration: false, writeMigrated: false });
    expect(loaded.config.runtime.swarm.enabled).toBe(true);
    expect(loaded.config.runtime.polymorphic_prompt.enabled).toBe(true);
    expect(loaded.config.runtime.synthetic_poisoning.enabled).toBe(true);
    expect(loaded.config.runtime.cognitive_rollback.enabled).toBe(true);
    expect(loaded.config.runtime.omni_shield.enabled).toBe(true);
  });

  test('accepts egress entropy analyzer config in strict mode', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-config-'));
    const configPath = path.join(tmpDir, 'sentinel.yaml');
    const base = yaml.load(fs.readFileSync(PROJECT_DEFAULT_CONFIG, 'utf8'));
    base.pii.egress.entropy = {
      enabled: true,
      mode: 'block',
      threshold: 4.6,
      min_token_length: 24,
      max_scan_bytes: 32768,
      max_findings: 6,
      min_unique_ratio: 0.35,
      detect_base64: true,
      detect_hex: true,
      detect_generic: true,
      redact_replacement: '[REDACTED_HIGH_ENTROPY]',
    };
    writeYamlConfig(configPath, base);

    const loaded = loadAndValidateConfig({ configPath, allowMigration: false, writeMigrated: false });
    expect(loaded.config.pii.egress.entropy.enabled).toBe(true);
    expect(loaded.config.pii.egress.entropy.mode).toBe('block');
    expect(loaded.config.pii.egress.entropy.threshold).toBe(4.6);
  });
});
