function nowSeconds() {
  return Date.now() / 1000;
}

function metricLine(name, labels, value) {
  const safeValue = Number.isFinite(Number(value)) ? Number(value) : 0;
  if (!labels || Object.keys(labels).length === 0) {
    return `${name} ${safeValue}`;
  }
  const renderedLabels = Object.entries(labels)
    .map(([key, val]) => `${key}="${String(val).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`)
    .join(',');
  return `${name}{${renderedLabels}} ${safeValue}`;
}

class PrometheusExporter {
  constructor(options = {}) {
    this.startedAt = Date.now();
    this.version = String(options.version || '1.0.0');
    this.histogramBuckets = Array.isArray(options.buckets) && options.buckets.length > 0
      ? options.buckets.map((value) => Number(value)).filter((value) => Number.isFinite(value) && value > 0).sort((a, b) => a - b)
      : [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];
    this.requestDurationBuckets = new Map();
    this.requestDurationSumMs = 0;
    this.requestDurationCount = 0;
  }

  observeRequestDuration(ms) {
    const value = Number(ms);
    if (!Number.isFinite(value) || value < 0) {
      return;
    }
    this.requestDurationCount += 1;
    this.requestDurationSumMs += value;
    for (const bucket of this.histogramBuckets) {
      if (value <= bucket) {
        this.requestDurationBuckets.set(bucket, (this.requestDurationBuckets.get(bucket) || 0) + 1);
      }
    }
  }

  renderMetrics(input = {}) {
    const counters = input.counters || {};
    const providers = input.providers || {};
    const lines = [];

    lines.push('# HELP sentinel_info Sentinel build information');
    lines.push('# TYPE sentinel_info gauge');
    lines.push(metricLine('sentinel_info', { version: this.version }, 1));

    lines.push('# HELP sentinel_uptime_seconds Sentinel process uptime in seconds');
    lines.push('# TYPE sentinel_uptime_seconds gauge');
    lines.push(metricLine('sentinel_uptime_seconds', null, nowSeconds() - this.startedAt / 1000));

    lines.push('# HELP sentinel_requests_total Total requests handled by Sentinel');
    lines.push('# TYPE sentinel_requests_total counter');
    lines.push(metricLine('sentinel_requests_total', null, counters.requests_total || 0));

    lines.push('# HELP sentinel_blocked_total Total requests blocked by Sentinel');
    lines.push('# TYPE sentinel_blocked_total counter');
    lines.push(metricLine('sentinel_blocked_total', null, counters.blocked_total || 0));

    lines.push('# HELP sentinel_upstream_errors_total Total upstream errors observed');
    lines.push('# TYPE sentinel_upstream_errors_total counter');
    lines.push(metricLine('sentinel_upstream_errors_total', null, counters.upstream_errors || 0));

    lines.push('# HELP sentinel_request_duration_ms Request duration histogram in milliseconds');
    lines.push('# TYPE sentinel_request_duration_ms histogram');
    for (const bucket of this.histogramBuckets) {
      lines.push(metricLine('sentinel_request_duration_ms_bucket', { le: bucket }, this.requestDurationBuckets.get(bucket) || 0));
    }
    lines.push(metricLine('sentinel_request_duration_ms_bucket', { le: '+Inf' }, this.requestDurationCount));
    lines.push(metricLine('sentinel_request_duration_ms_sum', null, this.requestDurationSumMs));
    lines.push(metricLine('sentinel_request_duration_ms_count', null, this.requestDurationCount));

    lines.push('# HELP sentinel_provider_circuit_state Per-provider circuit breaker state (0=closed,1=half-open,2=open)');
    lines.push('# TYPE sentinel_provider_circuit_state gauge');
    for (const [provider, detail] of Object.entries(providers)) {
      const state = String(detail?.circuit_state || '').toLowerCase();
      const numeric = state === 'open' ? 2 : state === 'half-open' ? 1 : 0;
      lines.push(metricLine('sentinel_provider_circuit_state', { provider }, numeric));
    }

    return `${lines.join('\n')}\n`;
  }
}

module.exports = {
  PrometheusExporter,
};
