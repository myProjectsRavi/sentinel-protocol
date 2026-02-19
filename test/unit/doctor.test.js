const {
  runDoctorChecks,
  detectRapidApiKeySource,
  detectAuthVaultKeySource,
} = require('../../src/runtime/doctor');

function configForMode(mode, overrides = {}) {
  const rapidapiOverrides = overrides.rapidapi || {};
  const semanticOverrides = overrides.semantic || {};
  const runtimeOverrides = overrides.runtime || {};
  return {
    pii: {
      provider_mode: mode,
      rapidapi: {
        endpoint: 'https://pii-firewall-edge.p.rapidapi.com/redact',
        host: 'pii-firewall-edge.p.rapidapi.com',
        fallback_to_local: true,
        allow_non_rapidapi_host: false,
        api_key: '',
        ...rapidapiOverrides,
      },
      semantic: {
        enabled: false,
        model_id: 'Xenova/bert-base-NER',
        cache_dir: '~/.sentinel/models',
        score_threshold: 0.6,
        max_scan_bytes: 32768,
        ...semanticOverrides,
      },
    },
    runtime: {
      worker_pool: {
        enabled: true,
      },
      semantic_cache: {
        enabled: false,
      },
      ...runtimeOverrides,
    },
  };
}

describe('doctor checks', () => {
  test('passes in local mode', () => {
    const report = runDoctorChecks(configForMode('local'), {});
    expect(report.ok).toBe(true);
    expect(report.summary.fail).toBe(0);
  });

  test('fails in rapidapi mode with fallback disabled and no key', () => {
    const report = runDoctorChecks(configForMode('rapidapi', { rapidapi: { fallback_to_local: false, api_key: '' } }), {});
    expect(report.ok).toBe(false);
    expect(report.checks.some((check) => check.id === 'rapidapi-key-source' && check.status === 'fail')).toBe(true);
  });

  test('warns in hybrid mode with no key but stays healthy', () => {
    const report = runDoctorChecks(configForMode('hybrid', { rapidapi: { api_key: '' } }), {});
    expect(report.ok).toBe(true);
    expect(report.summary.warn).toBeGreaterThan(0);
  });

  test('detects env key source', () => {
    expect(detectRapidApiKeySource({ api_key: 'config-key' }, { SENTINEL_RAPIDAPI_KEY: 'env-key' })).toBe('env');
  });

  test('detects auth vault key source from env first', () => {
    expect(
      detectAuthVaultKeySource(
        { api_key: 'config-key', env_var: 'SENTINEL_OPENAI_API_KEY' },
        { SENTINEL_OPENAI_API_KEY: 'env-key' }
      )
    ).toBe('env');
  });

  test('fails invalid rapidapi endpoint in non-local mode', () => {
    const report = runDoctorChecks(configForMode('rapidapi', { rapidapi: { endpoint: 'http://example.com/redact', api_key: 'abc' } }), {});
    expect(report.ok).toBe(false);
    expect(report.checks.some((check) => check.id === 'rapidapi-endpoint' && check.status === 'fail')).toBe(true);
  });

  test('warns when NODE_ENV is not production', () => {
    const report = runDoctorChecks(configForMode('local'), { NODE_ENV: 'development' });
    expect(report.checks.some((check) => check.id === 'node-env' && check.status === 'warn')).toBe(true);
  });

  test('passes NODE_ENV check when set to production', () => {
    const report = runDoctorChecks(configForMode('local'), { NODE_ENV: 'production' });
    expect(report.checks.some((check) => check.id === 'node-env' && check.status === 'pass')).toBe(true);
  });

  test('fails when semantic scanner is enabled without dependency installed', () => {
    const report = runDoctorChecks(configForMode('local', {
      semantic: {
        enabled: true,
        model_id: 'Xenova/bert-base-NER',
        cache_dir: '~/.sentinel/models',
        score_threshold: 0.6,
        max_scan_bytes: 32768,
      },
    }), { NODE_ENV: 'production' });
    expect(report.checks.some((check) => check.id === 'semantic-scanner-dependency')).toBe(true);
  });

  test('fails when semantic cache enabled but worker pool disabled', () => {
    const report = runDoctorChecks(configForMode('local', {
      runtime: {
        worker_pool: { enabled: false },
        semantic_cache: { enabled: true },
      },
    }), { NODE_ENV: 'production' });
    expect(report.ok).toBe(false);
    expect(report.checks.some((check) => check.id === 'semantic-cache-worker-pool' && check.status === 'fail')).toBe(true);
  });

  test('warns when semantic cache embed timeout is too low for cold starts', () => {
    const report = runDoctorChecks(configForMode('local', {
      runtime: {
        worker_pool: {
          enabled: true,
          embed_task_timeout_ms: 2000,
        },
        semantic_cache: { enabled: true },
      },
    }), { NODE_ENV: 'production' });
    expect(report.checks.some((check) => check.id === 'semantic-cache-embed-timeout' && check.status === 'warn')).toBe(true);
  });

  test('fails when intent throttle enabled but worker pool disabled', () => {
    const report = runDoctorChecks(configForMode('local', {
      runtime: {
        worker_pool: { enabled: false },
        intent_throttle: { enabled: true },
      },
    }), { NODE_ENV: 'production' });
    expect(report.ok).toBe(false);
    expect(report.checks.some((check) => check.id === 'intent-throttle-worker-pool' && check.status === 'fail')).toBe(true);
  });

  test('warns when budget enabled with zero pricing model', () => {
    const report = runDoctorChecks(configForMode('local', {
      runtime: {
        budget: {
          enabled: true,
          action: 'block',
          daily_limit_usd: 5,
          input_cost_per_1k_tokens: 0,
          output_cost_per_1k_tokens: 0,
        },
      },
    }), { NODE_ENV: 'production' });

    expect(report.checks.some((check) => check.id === 'budget-limit' && check.status === 'pass')).toBe(true);
    expect(report.checks.some((check) => check.id === 'budget-cost-model' && check.status === 'warn')).toBe(true);
  });

  test('warns when canary is enabled without mesh groups', () => {
    const report = runDoctorChecks(configForMode('local', {
      runtime: {
        upstream: {
          resilience_mesh: {
            enabled: false,
            groups: {},
          },
          canary: {
            enabled: true,
            splits: [],
          },
        },
      },
    }), { NODE_ENV: 'production' });

    expect(report.checks.some((check) => check.id === 'canary-mesh-dependency' && check.status === 'warn')).toBe(true);
    expect(report.checks.some((check) => check.id === 'canary-splits' && check.status === 'warn')).toBe(true);
  });

  test('fails doctor when auth vault enforce mode has no provider key', () => {
    const report = runDoctorChecks(configForMode('local', {
      runtime: {
        upstream: {
          auth_vault: {
            enabled: true,
            mode: 'enforce',
            dummy_key: 'sk-sentinel-local',
            providers: {
              openai: { enabled: true, api_key: '', env_var: 'SENTINEL_OPENAI_API_KEY' },
              anthropic: { enabled: false, api_key: '', env_var: 'SENTINEL_ANTHROPIC_API_KEY' },
              google: { enabled: false, api_key: '', env_var: 'SENTINEL_GOOGLE_API_KEY' },
            },
          },
        },
      },
    }), { NODE_ENV: 'production' });

    expect(report.ok).toBe(false);
    expect(report.checks.some((check) => check.id === 'auth-vault-key-openai' && check.status === 'fail')).toBe(true);
  });

  test('warns doctor when auth vault replace_dummy mode has missing key', () => {
    const report = runDoctorChecks(configForMode('local', {
      runtime: {
        upstream: {
          auth_vault: {
            enabled: true,
            mode: 'replace_dummy',
            dummy_key: 'sk-sentinel-local',
            providers: {
              openai: { enabled: true, api_key: '', env_var: 'SENTINEL_OPENAI_API_KEY' },
              anthropic: { enabled: false, api_key: '', env_var: 'SENTINEL_ANTHROPIC_API_KEY' },
              google: { enabled: false, api_key: '', env_var: 'SENTINEL_GOOGLE_API_KEY' },
            },
          },
        },
      },
    }), { NODE_ENV: 'production' });

    expect(report.ok).toBe(true);
    expect(report.checks.some((check) => check.id === 'auth-vault-key-openai' && check.status === 'warn')).toBe(true);
  });
});
