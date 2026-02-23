const crypto = require('crypto');
const { clampPositiveInt } = require('../utils/primitives');

const TRACEPARENT_RE = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/i;
const SENSITIVE_KEY_RE = /(prompt|content|messages?|body|raw|token|secret|password|api[_-]?key)/i;
const DEFAULT_EVENT_COUNTERS = {
  'agent.start': 0,
  'agent.tool_call': 0,
  'agent.delegate': 0,
  'agent.complete': 0,
  'agent.error': 0,
};

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString('hex');
}

function isAllZeroHex(value) {
  return /^0+$/.test(String(value || ''));
}

function parseTraceparent(value) {
  const normalized = String(value || '').trim();
  const match = TRACEPARENT_RE.exec(normalized);
  if (!match) {
    return null;
  }
  const traceId = String(match[1] || '').toLowerCase();
  const parentId = String(match[2] || '').toLowerCase();
  const flags = String(match[3] || '').toLowerCase();
  if (isAllZeroHex(traceId) || isAllZeroHex(parentId)) {
    return null;
  }
  return {
    version: '00',
    traceId,
    parentId,
    flags,
  };
}

function buildTraceparent({ traceId, parentId, flags = '01' }) {
  return `00-${String(traceId).toLowerCase()}-${String(parentId).toLowerCase()}-${String(flags).toLowerCase()}`;
}

function readHeader(headers = {}, wanted) {
  const key = String(wanted || '').toLowerCase();
  for (const [name, value] of Object.entries(headers || {})) {
    if (String(name).toLowerCase() === key) {
      return Array.isArray(value) ? String(value[0] || '') : String(value || '');
    }
  }
  return '';
}

function sanitizeValue(value, maxFieldLength, depth = 0) {
  if (value === null || value === undefined) {
    return value;
  }
  if (depth > 3) {
    return '[TRUNCATED_DEPTH]';
  }
  if (typeof value === 'string') {
    return value.length > maxFieldLength ? `${value.slice(0, maxFieldLength)}...` : value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.slice(0, 8).map((item) => sanitizeValue(item, maxFieldLength, depth + 1));
  }
  if (typeof value === 'object') {
    const out = {};
    for (const [key, child] of Object.entries(value)) {
      if (SENSITIVE_KEY_RE.test(key)) {
        out[key] = '[REDACTED]';
      } else {
        out[key] = sanitizeValue(child, maxFieldLength, depth + 1);
      }
    }
    return out;
  }
  return String(value);
}

function normalizeConfig(config = {}) {
  const source = config && typeof config === 'object' && !Array.isArray(config) ? config : {};
  return {
    enabled: source.enabled === true,
    maxEventsPerRequest: clampPositiveInt(source.max_events_per_request, 32, 1, 256),
    maxFieldLength: clampPositiveInt(source.max_field_length, 160, 32, 4096),
    histogramBuckets: [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000],
  };
}

class AgentObservability {
  constructor(config = {}) {
    this.config = normalizeConfig(config);
    this.eventCounters = {
      ...DEFAULT_EVENT_COUNTERS,
    };
    this.durationBuckets = new Map();
    this.durationCount = 0;
    this.durationSumMs = 0;
  }

  isEnabled() {
    return this.config.enabled === true;
  }

  startRequest(input = {}) {
    const requestStart = Number(input.requestStart || Date.now());
    const parsed = parseTraceparent(readHeader(input.headers || {}, 'traceparent'));
    const traceId = parsed?.traceId || randomHex(16);
    const parentId = randomHex(8);
    const flags = parsed?.flags || '01';
    const traceparent = buildTraceparent({ traceId, parentId, flags });
    const tracestateRaw = readHeader(input.headers || {}, 'tracestate').trim();
    const tracestate = tracestateRaw.length > 512 ? tracestateRaw.slice(0, 512) : tracestateRaw;

    const context = {
      correlationId: String(input.correlationId || ''),
      traceId,
      traceparent,
      tracestate,
      startMs: requestStart,
      eventCount: 0,
      droppedEvents: 0,
      events: [],
    };

    this.emitLifecycle(context, 'agent.start', {
      method: String(input.method || '').toUpperCase(),
      path: String(input.path || '/'),
      trace_id: traceId,
      correlation_id: String(input.correlationId || ''),
    });

    return context;
  }

  injectForwardHeaders(headers = {}, context = null) {
    if (!this.isEnabled() || !context) {
      return headers;
    }
    const out = {
      ...(headers || {}),
    };
    out.traceparent = context.traceparent;
    if (context.tracestate) {
      out.tracestate = context.tracestate;
    }
    return out;
  }

  emitLifecycle(context, eventName, payload = {}) {
    if (!this.isEnabled() || !context) {
      return null;
    }
    const event = String(eventName || '').trim().toLowerCase();
    if (!event) {
      return null;
    }
    if (context.eventCount >= this.config.maxEventsPerRequest) {
      context.droppedEvents += 1;
      return null;
    }

    const sanitized = sanitizeValue(payload, this.config.maxFieldLength);
    const entry = {
      event,
      at: new Date().toISOString(),
      trace_id: context.traceId,
      correlation_id: context.correlationId,
      payload: sanitized,
    };
    context.events.push(entry);
    context.eventCount += 1;

    if (Object.prototype.hasOwnProperty.call(this.eventCounters, event)) {
      this.eventCounters[event] += 1;
    } else {
      this.eventCounters[event] = 1;
    }

    return entry;
  }

  observeDuration(ms) {
    const value = Number(ms);
    if (!Number.isFinite(value) || value < 0) {
      return;
    }
    this.durationCount += 1;
    this.durationSumMs += value;
    for (const bucket of this.config.histogramBuckets) {
      if (value <= bucket) {
        this.durationBuckets.set(bucket, (this.durationBuckets.get(bucket) || 0) + 1);
      }
    }
  }

  finishRequest(context, input = {}) {
    if (!this.isEnabled() || !context) {
      return;
    }
    const statusCode = Number(input.statusCode || 0);
    const decision = String(input.decision || 'unknown');
    const provider = String(input.provider || 'unknown');
    const latencyMs = Math.max(0, Date.now() - Number(context.startMs || Date.now()));

    if (input.error) {
      this.emitLifecycle(context, 'agent.error', {
        status_code: statusCode,
        decision,
        provider,
        error: String(input.error?.message || input.error),
      });
    } else {
      this.emitLifecycle(context, 'agent.complete', {
        status_code: statusCode,
        decision,
        provider,
      });
    }

    this.observeDuration(latencyMs);
  }

  snapshotMetrics() {
    return {
      enabled: this.isEnabled(),
      counters: {
        ...this.eventCounters,
      },
      duration: {
        buckets: this.config.histogramBuckets.reduce((acc, bucket) => {
          acc[bucket] = this.durationBuckets.get(bucket) || 0;
          return acc;
        }, {}),
        count: this.durationCount,
        sumMs: this.durationSumMs,
      },
    };
  }
}

module.exports = {
  AgentObservability,
  parseTraceparent,
  buildTraceparent,
};
