const { clampPositiveInt } = require('../utils/primitives');

function inferEngine(event = {}) {
  const decision = String(event.decision || '').toLowerCase();
  if (decision.startsWith('blocked_')) {
    return decision.replace(/^blocked_/, '').slice(0, 80) || 'policy';
  }
  const reasons = Array.isArray(event.reasons) ? event.reasons : [];
  if (reasons.length > 0) {
    const first = String(reasons[0] || '');
    const idx = first.indexOf(':');
    if (idx > 0) {
      return first.slice(0, idx).toLowerCase().slice(0, 80);
    }
    return first.toLowerCase().replace(/[^a-z0-9_]+/g, '_').slice(0, 80) || 'unknown';
  }
  return 'unknown';
}

function inferSeverity(event = {}) {
  const decision = String(event.decision || '').toLowerCase();
  if (decision.startsWith('blocked')) {
    return 'critical';
  }
  if (decision.includes('warn')) {
    return 'medium';
  }
  return 'low';
}

class AnomalyTelemetry {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.maxEvents = clampPositiveInt(config.max_events, 20_000, 100, 2_000_000);
    this.windowMs = clampPositiveInt(config.window_ms, 24 * 60 * 60 * 1000, 60_000, 365 * 24 * 60 * 60 * 1000);
    this.maxEngineBuckets = clampPositiveInt(config.max_engine_buckets, 512, 8, 10000);
    this.maxTimelineEvents = clampPositiveInt(config.max_timeline_events, 500, 16, 10000);
    this.observability = config.observability !== false;
    this.events = [];
    this.engineCounters = new Map();
    this.severityCounters = new Map();
  }

  isEnabled() {
    return this.enabled === true;
  }

  prune(now = Date.now()) {
    const minTimestamp = Number(now) - this.windowMs;
    while (this.events.length > 0) {
      const head = this.events[0];
      if (Number(head.timestampMs || 0) >= minTimestamp && this.events.length <= this.maxEvents) {
        break;
      }
      this.events.shift();
    }
    if (this.events.length > this.maxEvents) {
      this.events.splice(0, this.events.length - this.maxEvents);
    }
  }

  incrementCounter(map, key) {
    const safeKey = String(key || 'unknown').slice(0, 80) || 'unknown';
    map.set(safeKey, Number(map.get(safeKey) || 0) + 1);
    while (map.size > this.maxEngineBuckets) {
      const oldest = map.keys().next().value;
      if (!oldest) {
        break;
      }
      map.delete(oldest);
    }
  }

  record(event = {}) {
    if (!this.isEnabled()) {
      return null;
    }
    const timestampMs = Date.parse(String(event.timestamp || '')) || Date.now();
    const engine = inferEngine(event);
    const severity = inferSeverity(event);
    const record = {
      timestampMs,
      timestamp: new Date(timestampMs).toISOString(),
      engine,
      severity,
      decision: String(event.decision || 'observed').slice(0, 120),
      reason: Array.isArray(event.reasons) && event.reasons.length > 0
        ? String(event.reasons[0] || '').slice(0, 160)
        : '',
      provider: String(event.provider || 'unknown').slice(0, 64),
      durationMs: Number.isFinite(Number(event.duration_ms)) ? Number(event.duration_ms) : 0,
      correlationId: String(event.correlation_id || '').slice(0, 80),
    };

    this.events.push(record);
    this.incrementCounter(this.engineCounters, engine);
    this.incrementCounter(this.severityCounters, severity);
    this.prune(Date.now());
    return record;
  }

  snapshot() {
    const now = Date.now();
    this.prune(now);
    const minRecent = now - (5 * 60 * 1000);
    let recentCount = 0;
    const timeline = [];
    for (let i = this.events.length - 1; i >= 0; i -= 1) {
      const event = this.events[i];
      if (event.timestampMs >= minRecent) {
        recentCount += 1;
      }
      if (timeline.length < this.maxTimelineEvents) {
        timeline.push({
          timestamp: event.timestamp,
          engine: event.engine,
          severity: event.severity,
          decision: event.decision,
          reason: event.reason,
        });
      }
      if (timeline.length >= this.maxTimelineEvents && event.timestampMs < minRecent) {
        break;
      }
    }

    const engineHeatmap = Array.from(this.engineCounters.entries())
      .sort((a, b) => Number(b[1]) - Number(a[1]))
      .slice(0, this.maxEngineBuckets)
      .map(([engine, count]) => ({
        engine,
        count: Number(count),
      }));

    const severity = Object.fromEntries(this.severityCounters.entries());

    return {
      enabled: this.isEnabled(),
      total_events: this.events.length,
      recent_5m_events: recentCount,
      engine_heatmap: engineHeatmap,
      severity,
      timeline,
    };
  }
}

module.exports = {
  AnomalyTelemetry,
};
