const { trace, metrics, SpanStatusCode } = require('@opentelemetry/api');

class Telemetry {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.serviceName = options.serviceName || 'sentinel-protocol';
    this.serviceVersion = options.serviceVersion || '1.0.0';

    this.tracer = trace.getTracer(this.serviceName, this.serviceVersion);
    this.meter = metrics.getMeter(this.serviceName, this.serviceVersion);

    this.requestCounter = this.meter.createCounter('sentinel.requests.total', {
      description: 'Total requests handled by Sentinel',
    });
    this.blockedCounter = this.meter.createCounter('sentinel.requests.blocked', {
      description: 'Requests blocked by Sentinel policy or PII controls',
    });
    this.upstreamErrorCounter = this.meter.createCounter('sentinel.upstream.errors', {
      description: 'Upstream errors observed by Sentinel',
    });
    this.requestLatencyHistogram = this.meter.createHistogram('sentinel.request.duration.ms', {
      description: 'Request processing latency in milliseconds',
      unit: 'ms',
    });
  }

  sanitizeAttrs(attrs = {}) {
    const out = {};
    for (const [key, value] of Object.entries(attrs)) {
      if (value === undefined || value === null) {
        continue;
      }
      if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'string') {
        out[key] = value;
      } else {
        out[key] = String(value);
      }
    }
    return out;
  }

  startSpan(name, attrs = {}) {
    if (!this.enabled) {
      return null;
    }
    const attributes = this.sanitizeAttrs(attrs);
    const span = this.tracer.startSpan(name, { attributes });
    return span;
  }

  endSpan(span, attrs = {}, error) {
    if (!this.enabled || !span) {
      return;
    }

    const attributes = this.sanitizeAttrs(attrs);
    for (const [key, value] of Object.entries(attributes)) {
      span.setAttribute(key, value);
    }

    if (error) {
      span.recordException(error);
      span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
    } else {
      span.setStatus({ code: SpanStatusCode.OK });
    }
    span.end();
  }

  addRequest(attrs = {}) {
    if (!this.enabled) {
      return;
    }
    this.requestCounter.add(1, this.sanitizeAttrs(attrs));
  }

  addBlocked(attrs = {}) {
    if (!this.enabled) {
      return;
    }
    this.blockedCounter.add(1, this.sanitizeAttrs(attrs));
  }

  addUpstreamError(attrs = {}) {
    if (!this.enabled) {
      return;
    }
    this.upstreamErrorCounter.add(1, this.sanitizeAttrs(attrs));
  }

  recordLatencyMs(ms, attrs = {}) {
    if (!this.enabled) {
      return;
    }
    this.requestLatencyHistogram.record(ms, this.sanitizeAttrs(attrs));
  }
}

function createTelemetry(options) {
  return new Telemetry(options);
}

module.exports = {
  createTelemetry,
  Telemetry,
};
