const { createSentinel } = require('../../src/embed');

function baseConfig() {
  return {
    version: 1,
    mode: 'enforce',
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
      redaction: { mode: 'placeholder', salt: 'x' },
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
        cache_max_entries: 512,
        cache_ttl_ms: 300000,
        max_timeout_ms: 1500,
      },
      semantic: { enabled: false, model_id: 'x', cache_dir: 'x', score_threshold: 0.5, max_scan_bytes: 1000 },
      egress: {
        enabled: false,
        max_scan_bytes: 1000,
        stream_enabled: false,
        sse_line_max_bytes: 1000,
        stream_block_mode: 'redact',
        entropy: {
          enabled: false,
          mode: 'monitor',
          threshold: 4.5,
          min_token_length: 24,
          max_scan_bytes: 1000,
          max_findings: 8,
          min_unique_ratio: 0.3,
          detect_base64: true,
          detect_hex: true,
          detect_generic: true,
          redact_replacement: '[REDACTED]',
        },
      },
    },
    injection: {
      enabled: true,
      threshold: 0.8,
      max_scan_bytes: 131072,
      action: 'block',
      neural: { enabled: false, model_id: 'x', cache_dir: 'x', max_scan_bytes: 1000, timeout_ms: 1000, weight: 1, mode: 'max' },
    },
    rules: [],
    whitelist: { domains: [] },
    logging: { level: 'info', audit_file: '~/.sentinel/audit.jsonl' },
  };
}

describe('embed secureFetch', () => {
  test('secureFetch injects sentinel headers and returns governed response', async () => {
    const config = baseConfig();
    config.rules = [
      {
        name: 'block-forbidden',
        match: {
          method: 'POST',
          body_contains: 'forbidden',
        },
        action: 'block',
        message: 'blocked by policy',
      },
    ];
    const embedded = createSentinel(config);
    let seenHeaders = null;
    const response = await embedded.secureFetch('https://example.com/v1/test', {
      method: 'POST',
      body: JSON.stringify({ prompt: 'forbidden payload' }),
      headers: {
        'content-type': 'application/json',
      },
      fetchImpl: async (url, options) => {
        seenHeaders = options.headers;
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      },
    });

    expect(response.status).toBe(403);
    expect(response.headers.get('x-sentinel-blocked-by')).toBe('embed_policy');
    expect(seenHeaders).toBeNull();
  });

  test('secureFetch forwards request when policy allows and injects x-sentinel-embed header', async () => {
    const embedded = createSentinel(baseConfig());
    let seenHeaders = null;
    const response = await embedded.secureFetch('https://example.com/v1/test', {
      method: 'POST',
      body: JSON.stringify({ prompt: 'safe payload' }),
      headers: {
        'content-type': 'application/json',
      },
      fetchImpl: async (url, options) => {
        seenHeaders = options.headers;
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      },
    });

    expect(response.status).toBe(200);
    expect(seenHeaders['x-sentinel-embed']).toBe('1');
  });
});
