const { PrometheusExporter } = require('../../src/telemetry/prometheus');

describe('PrometheusExporter', () => {
  test('renders exposition with counters and histogram', () => {
    const exporter = new PrometheusExporter({ version: '1.0.0' });
    exporter.observeRequestDuration(12);
    exporter.observeRequestDuration(120);
    const text = exporter.renderMetrics({
      counters: {
        requests_total: 2,
        blocked_total: 1,
        upstream_errors: 0,
        mcp_shadow_detected: 3,
        mcp_shadow_blocked: 1,
      },
      providers: {
        openai: { circuit_state: 'closed' },
        anthropic: { circuit_state: 'open' },
      },
    });
    expect(text).toContain('sentinel_requests_total 2');
    expect(text).toContain('sentinel_blocked_total 1');
    expect(text).toContain('sentinel_request_duration_ms_bucket');
    expect(text).toContain('provider="openai"');
    expect(text).toContain('provider="anthropic"');
    expect(text).toContain('sentinel_mcp_shadow_detected_total 3');
    expect(text).toContain('sentinel_mcp_shadow_blocked_total 1');
  });
});
