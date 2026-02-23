const { compileRule, compileRules } = require('../../src/policy/semantic-firewall-dsl');
const { PolicyEngine } = require('../../src/engines/policy-engine');

function baseConfig() {
  return {
    version: 1,
    mode: 'enforce',
    proxy: { host: '127.0.0.1', port: 8787, timeout_ms: 30000, max_body_bytes: 1048576 },
    runtime: {
      fail_open: false,
      scanner_error_action: 'allow',
      rate_limiter: {
        default_window_ms: 60000,
        default_limit: 60,
        default_burst: 60,
        max_buckets: 1000,
        prune_interval: 64,
        stale_bucket_ttl_ms: 300000,
        max_key_length: 128,
        key_headers: ['x-sentinel-agent-id'],
        fallback_key_headers: ['x-forwarded-for'],
        ip_header: 'x-forwarded-for',
      },
      upstream: {
        retry: { enabled: true, max_attempts: 1, allow_post_with_idempotency_key: false },
        circuit_breaker: {
          enabled: true,
          window_size: 20,
          min_failures_to_evaluate: 8,
          failure_rate_threshold: 0.5,
          consecutive_timeout_threshold: 5,
          open_seconds: 20,
          half_open_success_threshold: 3,
        },
        custom_targets: { enabled: false, allowlist: [], block_private_networks: true },
      },
      semantic_firewall_dsl: {
        enabled: true,
        rules: ['BLOCK WHEN request.method == "POST" AND injection.score >= 0.8'],
        max_rules: 8,
      },
    },
    pii: {
      enabled: true,
      provider_mode: 'local',
      max_scan_bytes: 262144,
      regex_safety_cap_bytes: 51200,
      redaction: { mode: 'placeholder', salt: 'x' },
      severity_actions: { critical: 'block', high: 'block', medium: 'redact', low: 'log' },
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
      max_scan_bytes: 8192,
      action: 'block',
      neural: { enabled: false, model_id: 'x', cache_dir: 'x', max_scan_bytes: 1000, timeout_ms: 1000, weight: 1, mode: 'max' },
    },
    rules: [],
    whitelist: { domains: [] },
    logging: { level: 'info', audit_file: '~/.sentinel/audit.jsonl' },
  };
}

describe('semantic firewall dsl', () => {
  test('compiles valid DSL rule into executable predicate', () => {
    const rule = compileRule('BLOCK WHEN request.method == "POST" AND injection.score >= 0.5');
    expect(rule.action).toBe('block');
    expect(rule.matches({
      request: { method: 'POST' },
      injection: { score: 0.7 },
    })).toBe(true);
  });

  test('rejects invalid token sequence with explicit error', () => {
    expect(() => compileRule('BLOCK WHEN request.method === "POST"')).toThrow(/dsl_parse_operator_invalid|dsl_token_invalid/);
  });

  test('evaluates compound condition deterministically', () => {
    const [rule] = compileRules([
      'WARN WHEN request.method == "POST" AND NOT injection.score < 0.4',
    ]);
    const context = {
      request: { method: 'POST' },
      injection: { score: 0.6 },
    };
    const first = rule.matches(context);
    const second = rule.matches(context);
    expect(first).toBe(true);
    expect(second).toBe(true);
  });

  test('preserves legacy YAML rule behavior when DSL absent', () => {
    const config = baseConfig();
    config.runtime.semantic_firewall_dsl.enabled = false;
    config.rules = [
      {
        name: 'legacy-block-shell',
        match: { tool_name: 'execute_shell' },
        action: 'block',
        message: 'blocked',
      },
    ];
    const policy = new PolicyEngine(config, null);
    const decision = policy.check({
      method: 'POST',
      hostname: 'api.openai.com',
      pathname: '/v1/chat/completions',
      bodyText: JSON.stringify({ tool_name: 'execute_shell' }),
      bodyJson: { tool_name: 'execute_shell' },
      requestBytes: 64,
      headers: {},
      provider: 'openai',
      injectionResult: { score: 0, matchedSignals: [], scanTruncated: false },
    });
    expect(decision.matched).toBe(true);
    expect(decision.rule).toBe('legacy-block-shell');
    expect(decision.dsl_matched).toBe(false);
  });
});
