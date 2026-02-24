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

describe('embed framework callbacks', () => {
  test('langchain callback emits lifecycle events without mutation side effects', async () => {
    const events = [];
    const embedded = createSentinel(baseConfig(), {
      framework: {
        onEvent: (event) => events.push(event),
      },
    });
    const callback = embedded.langchainCallback();
    await callback.handleLLMStart({ modelName: 'gpt-4o-mini' }, ['hello'], 'run-1');
    await callback.handleLLMEnd({ generations: [[]] }, 'run-1');
    await callback.handleLLMError(new Error('boom'), 'run-1');

    expect(events.length).toBe(3);
    expect(events[0].event).toBe('agent.start');
    expect(events[1].event).toBe('agent.complete');
    expect(events[2].event).toBe('agent.error');
    expect(events[0].payload.framework).toBe('langchain');
  });

  test('frameworkCallbacks() returns both adapters', () => {
    const embedded = createSentinel(baseConfig());
    const callbacks = embedded.frameworkCallbacks();
    expect(typeof callbacks.langchainCallback).toBe('function');
    expect(typeof callbacks.llamaIndexCallback).toBe('function');
    expect(typeof callbacks.crewaiCallback).toBe('function');
  });

  test('crewai callback emits lifecycle events', async () => {
    const events = [];
    const embedded = createSentinel(baseConfig(), {
      framework: {
        onEvent: (event) => events.push(event),
      },
    });
    const callback = embedded.crewaiCallback();
    await callback.onTaskStart({ description: 'Analyze policy drift' }, 'crew-1');
    await callback.onTaskComplete({ result: 'done' }, 'crew-1');
    await callback.onTaskError(new Error('fail'), 'crew-1');

    expect(events.length).toBe(3);
    expect(events[0].payload.framework).toBe('crewai');
    expect(events[0].event).toBe('agent.start');
    expect(events[2].event).toBe('agent.error');
  });
});
