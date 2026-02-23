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
    const agentObservability = input.agentObservability || {};
    const lines = [];
    const appendCounter = (name, help, value) => {
      lines.push(`# HELP ${name} ${help}`);
      lines.push(`# TYPE ${name} counter`);
      lines.push(metricLine(name, null, value || 0));
    };

    lines.push('# HELP sentinel_info Sentinel build information');
    lines.push('# TYPE sentinel_info gauge');
    lines.push(metricLine('sentinel_info', { version: this.version }, 1));

    lines.push('# HELP sentinel_uptime_seconds Sentinel process uptime in seconds');
    lines.push('# TYPE sentinel_uptime_seconds gauge');
    lines.push(metricLine('sentinel_uptime_seconds', null, nowSeconds() - this.startedAt / 1000));

    appendCounter('sentinel_requests_total', 'Total requests handled by Sentinel', counters.requests_total);
    appendCounter('sentinel_blocked_total', 'Total requests blocked by Sentinel', counters.blocked_total);
    appendCounter('sentinel_upstream_errors_total', 'Total upstream errors observed', counters.upstream_errors);
    appendCounter(
      'sentinel_agentic_threat_detected_total',
      'Total requests where agentic threat shield detected risk',
      counters.agentic_threat_detected
    );
    appendCounter(
      'sentinel_agentic_threat_blocked_total',
      'Total requests blocked by agentic threat shield',
      counters.agentic_threat_blocked
    );
    appendCounter(
      'sentinel_agentic_threat_errors_total',
      'Total agentic threat shield evaluation errors',
      counters.agentic_threat_errors
    );
    appendCounter(
      'sentinel_agentic_analysis_truncated_total',
      'Total requests where agentic analysis budget was truncated',
      counters.agentic_analysis_truncated
    );
    appendCounter(
      'sentinel_mcp_poisoning_detected_total',
      'Total requests where MCP poisoning signals were detected',
      counters.mcp_poisoning_detected
    );
    appendCounter(
      'sentinel_mcp_poisoning_blocked_total',
      'Total requests blocked by MCP poisoning detector',
      counters.mcp_poisoning_blocked
    );
    appendCounter(
      'sentinel_mcp_config_drift_total',
      'Total MCP configuration drift detections',
      counters.mcp_config_drift
    );
    appendCounter(
      'sentinel_prompt_rebuff_detected_total',
      'Total requests where prompt rebuff detected elevated risk',
      counters.prompt_rebuff_detected
    );
    appendCounter(
      'sentinel_prompt_rebuff_blocked_total',
      'Total requests blocked by prompt rebuff',
      counters.prompt_rebuff_blocked
    );
    appendCounter(
      'sentinel_prompt_rebuff_errors_total',
      'Total prompt rebuff evaluation errors',
      counters.prompt_rebuff_errors
    );
    appendCounter(
      'sentinel_output_classifier_detected_total',
      'Total responses flagged by output content classifier',
      counters.output_classifier_detected
    );
    appendCounter(
      'sentinel_output_classifier_blocked_total',
      'Total responses blocked by output content classifier',
      counters.output_classifier_blocked
    );
    appendCounter(
      'sentinel_output_classifier_toxicity_detected_total',
      'Total output classifier toxicity detections',
      counters.output_classifier_toxicity_detected
    );
    appendCounter(
      'sentinel_output_classifier_code_execution_detected_total',
      'Total output classifier dangerous code detections',
      counters.output_classifier_code_execution_detected
    );
    appendCounter(
      'sentinel_output_classifier_hallucination_detected_total',
      'Total output classifier hallucination signal detections',
      counters.output_classifier_hallucination_detected
    );
    appendCounter(
      'sentinel_output_classifier_unauthorized_disclosure_detected_total',
      'Total output classifier unauthorized disclosure detections',
      counters.output_classifier_unauthorized_disclosure_detected
    );
    appendCounter(
      'sentinel_output_schema_validator_detected_total',
      'Total responses flagged by output schema validator',
      counters.output_schema_validator_detected
    );
    appendCounter(
      'sentinel_output_schema_validator_blocked_total',
      'Total responses blocked by output schema validator',
      counters.output_schema_validator_blocked
    );

    const agentCounters =
      agentObservability.counters &&
      typeof agentObservability.counters === 'object' &&
      !Array.isArray(agentObservability.counters)
        ? agentObservability.counters
        : {};
    lines.push('# HELP sentinel_agent_observability_event_total Agent observability lifecycle event counters');
    lines.push('# TYPE sentinel_agent_observability_event_total counter');
    const agentEvents = new Set([
      'agent.start',
      'agent.tool_call',
      'agent.delegate',
      'agent.complete',
      'agent.error',
      ...Object.keys(agentCounters),
    ]);
    for (const eventName of Array.from(agentEvents).sort((a, b) => String(a).localeCompare(String(b)))) {
      lines.push(
        metricLine(
          'sentinel_agent_observability_event_total',
          { event: eventName },
          agentCounters[eventName] || 0
        )
      );
    }

    const agentDuration =
      agentObservability.duration &&
      typeof agentObservability.duration === 'object' &&
      !Array.isArray(agentObservability.duration)
        ? agentObservability.duration
        : {};
    const agentBuckets =
      agentDuration.buckets &&
      typeof agentDuration.buckets === 'object' &&
      !Array.isArray(agentDuration.buckets)
        ? agentDuration.buckets
        : {};
    lines.push('# HELP sentinel_agent_observability_duration_ms Agent observability request duration histogram');
    lines.push('# TYPE sentinel_agent_observability_duration_ms histogram');
    const sortedAgentBuckets = Object.keys(agentBuckets)
      .map((value) => Number(value))
      .filter((value) => Number.isFinite(value) && value > 0)
      .sort((a, b) => a - b);
    const bucketSource = sortedAgentBuckets.length > 0 ? sortedAgentBuckets : this.histogramBuckets;
    for (const bucket of bucketSource) {
      lines.push(
        metricLine(
          'sentinel_agent_observability_duration_ms_bucket',
          { le: bucket },
          agentBuckets[bucket] || 0
        )
      );
    }
    lines.push(
      metricLine(
        'sentinel_agent_observability_duration_ms_bucket',
        { le: '+Inf' },
        Number(agentDuration.count || 0)
      )
    );
    lines.push(metricLine('sentinel_agent_observability_duration_ms_sum', null, Number(agentDuration.sumMs || 0)));
    lines.push(metricLine('sentinel_agent_observability_duration_ms_count', null, Number(agentDuration.count || 0)));

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
