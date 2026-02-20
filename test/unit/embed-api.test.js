const { createSentinel } = require('../../src/embed');

function baseConfig() {
  return {
    version: 1,
    mode: 'monitor',
    proxy: {
      host: '127.0.0.1',
      port: 8787,
      timeout_ms: 30000,
      max_body_bytes: 1048576,
    },
    runtime: {
      fail_open: false,
      scanner_error_action: 'allow',
      upstream: {
        retry: {
          enabled: true,
          max_attempts: 1,
          allow_post_with_idempotency_key: false,
        },
        circuit_breaker: {
          enabled: true,
          window_size: 20,
          min_failures_to_evaluate: 8,
          failure_rate_threshold: 0.5,
          consecutive_timeout_threshold: 5,
          open_seconds: 20,
          half_open_success_threshold: 3,
        },
        custom_targets: {
          enabled: false,
          allowlist: [],
          block_private_networks: true,
        },
      },
    },
    pii: {
      enabled: true,
      provider_mode: 'local',
      max_scan_bytes: 262144,
      regex_safety_cap_bytes: 51200,
      severity_actions: {
        critical: 'block',
        high: 'block',
        medium: 'redact',
        low: 'log',
      },
      rapidapi: {
        endpoint: 'https://pii-firewall-edge.p.rapidapi.com/redact',
        host: 'pii-firewall-edge.p.rapidapi.com',
        timeout_ms: 4000,
        request_body_field: 'text',
        fallback_to_local: true,
        allow_non_rapidapi_host: false,
        api_key: '',
        extra_body: {},
      },
    },
    injection: {
      enabled: true,
      threshold: 0.8,
      max_scan_bytes: 131072,
      action: 'block',
    },
    rules: [],
    whitelist: { domains: [] },
    logging: { level: 'info' },
  };
}

describe('createSentinel embed API', () => {
  test('creates middleware wrapper and supports plugin registration', () => {
    const embedded = createSentinel(baseConfig());
    expect(typeof embedded.middleware()).toBe('function');
    expect(typeof embedded.use).toBe('function');
    embedded.use({
      name: 'unit-test-plugin',
      hooks: {},
    });
  });

  test('scan returns local provider metadata and pii findings for sensitive input', async () => {
    const embedded = createSentinel(baseConfig());

    const result = await embedded.scan('Contact me at john@example.com');
    expect(Array.isArray(result.pii.findings)).toBe(true);
    expect(result.pii.findings.length).toBeGreaterThan(0);
    expect(result.provider.providerMode).toBe('local');
    expect(result.provider.providerUsed).toBe('local');
    expect(result.provider.fallbackUsed).toBe(false);
  });

  test('scan safely stringifies object payloads', async () => {
    const embedded = createSentinel(baseConfig());

    const result = await embedded.scan({
      note: 'secure',
      secret: 'john@example.com',
    });
    expect(Array.isArray(result.pii.findings)).toBe(true);
    expect(result.provider.providerMode).toBe('local');
  });
});
