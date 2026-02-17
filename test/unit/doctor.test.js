const { runDoctorChecks, detectRapidApiKeySource } = require('../../src/runtime/doctor');

function configForMode(mode, overrides = {}) {
  return {
    pii: {
      provider_mode: mode,
      rapidapi: {
        endpoint: 'https://pii-firewall-edge.p.rapidapi.com/redact',
        host: 'pii-firewall-edge.p.rapidapi.com',
        fallback_to_local: true,
        allow_non_rapidapi_host: false,
        api_key: '',
        ...overrides,
      },
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
    const report = runDoctorChecks(configForMode('rapidapi', { fallback_to_local: false, api_key: '' }), {});
    expect(report.ok).toBe(false);
    expect(report.checks.some((check) => check.id === 'rapidapi-key-source' && check.status === 'fail')).toBe(true);
  });

  test('warns in hybrid mode with no key but stays healthy', () => {
    const report = runDoctorChecks(configForMode('hybrid', { api_key: '' }), {});
    expect(report.ok).toBe(true);
    expect(report.summary.warn).toBeGreaterThan(0);
  });

  test('detects env key source', () => {
    expect(detectRapidApiKeySource({ api_key: 'config-key' }, { SENTINEL_RAPIDAPI_KEY: 'env-key' })).toBe('env');
  });

  test('fails invalid rapidapi endpoint in non-local mode', () => {
    const report = runDoctorChecks(configForMode('rapidapi', { endpoint: 'http://example.com/redact', api_key: 'abc' }), {});
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
});
