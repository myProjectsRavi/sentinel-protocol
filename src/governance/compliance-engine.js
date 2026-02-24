const fs = require('fs');
const crypto = require('crypto');
const { clampPositiveInt } = require('../utils/primitives');
const { summarizeAtlas } = require('./atlas-tracker');

const DEFAULT_LIMIT = 200000;
const DEFAULT_MAX_READ_BYTES = 32 * 1024 * 1024;
const DEFAULT_CHUNK_READ_BYTES = 64 * 1024;
const DEFAULT_SAMPLE_LIMIT = 5;

function normalizeReadOptions(options) {
  if (typeof options === 'number') {
    return {
      limit: options,
      maxReadBytes: DEFAULT_MAX_READ_BYTES,
      chunkReadBytes: DEFAULT_CHUNK_READ_BYTES,
    };
  }
  return {
    limit: options?.limit,
    maxReadBytes: options?.maxReadBytes,
    chunkReadBytes: options?.chunkReadBytes,
  };
}

function countByteOccurrences(buffer, byte) {
  let total = 0;
  for (let i = 0; i < buffer.length; i += 1) {
    if (buffer[i] === byte) {
      total += 1;
    }
  }
  return total;
}

function hashBuffer(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return null;
  }
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function readTailBuffer(filePath, options = {}) {
  if (!fs.existsSync(filePath)) {
    return {
      text: '',
      bytesRead: 0,
      truncated: false,
      tailSha256: null,
      windowSha256: null,
      linesScanned: 0,
      linesConsidered: 0,
      malformedLines: 0,
    };
  }
  const stats = fs.statSync(filePath);
  if (!stats.isFile() || stats.size <= 0) {
    return {
      text: '',
      bytesRead: 0,
      truncated: false,
      tailSha256: null,
      windowSha256: null,
      linesScanned: 0,
      linesConsidered: 0,
      malformedLines: 0,
    };
  }

  const safeMaxBytes = clampPositiveInt(options.maxReadBytes, DEFAULT_MAX_READ_BYTES, 1024, 512 * 1024 * 1024);
  const safeChunkReadBytes = clampPositiveInt(options.chunkReadBytes, DEFAULT_CHUNK_READ_BYTES, 1024, 8 * 1024 * 1024);
  const safeLimit = clampPositiveInt(options.limit, DEFAULT_LIMIT, 1, 2000000);
  const bytesToRead = Math.min(stats.size, safeMaxBytes);
  const targetNewlineCount = safeLimit + 1;
  let position = stats.size;
  let consumedBytes = 0;
  let newlineCount = 0;
  const chunks = [];
  let fd;
  try {
    fd = fs.openSync(filePath, 'r');
    while (position > 0 && consumedBytes < bytesToRead) {
      const readSize = Math.min(safeChunkReadBytes, position, bytesToRead - consumedBytes);
      position -= readSize;
      const chunk = Buffer.allocUnsafe(readSize);
      const read = fs.readSync(fd, chunk, 0, readSize, position);
      if (read <= 0) {
        break;
      }
      const slice = read === readSize ? chunk : chunk.subarray(0, read);
      chunks.unshift(slice);
      consumedBytes += read;
      newlineCount += countByteOccurrences(slice, 0x0a);
      if (newlineCount >= targetNewlineCount && consumedBytes >= safeChunkReadBytes) {
        break;
      }
    }

    const merged = chunks.length > 0 ? Buffer.concat(chunks) : Buffer.alloc(0);
    let text = merged.toString('utf8');
    const truncated = position > 0;
    if (truncated) {
      // The slice may begin mid-line; skip to the next full JSONL entry.
      const firstNewline = text.indexOf('\n');
      text = firstNewline === -1 ? '' : text.slice(firstNewline + 1);
    }
    return {
      text,
      bytesRead: consumedBytes,
      truncated,
      tailSha256: hashBuffer(merged),
      windowSha256: null,
      linesScanned: 0,
      linesConsidered: 0,
      malformedLines: 0,
    };
  } finally {
    if (fd !== undefined) {
      fs.closeSync(fd);
    }
  }
}

function readJsonLinesDetailed(filePath, options = {}) {
  const normalized = normalizeReadOptions(options);
  const limit = clampPositiveInt(normalized.limit, DEFAULT_LIMIT, 1, 2000000);
  const tail = readTailBuffer(filePath, {
    limit,
    maxReadBytes: normalized.maxReadBytes,
    chunkReadBytes: normalized.chunkReadBytes,
  });
  if (!tail.text) {
    return {
      events: [],
      metadata: {
        limit,
        bytes_scanned: tail.bytesRead,
        truncated: tail.truncated,
        lines_scanned: tail.linesScanned,
        lines_considered: tail.linesConsidered,
        parsed_events: 0,
        malformed_lines: tail.malformedLines,
        tail_sha256: tail.tailSha256,
        window_sha256: tail.windowSha256,
      },
    };
  }
  const lines = tail.text.split('\n').filter(Boolean);
  const start = Math.max(0, lines.length - limit);
  const events = [];
  let malformedLines = 0;
  for (let i = start; i < lines.length; i += 1) {
    const line = lines[i];
    if (!line) {
      continue;
    }
    try {
      const parsed = JSON.parse(line);
      if (parsed && typeof parsed === 'object') {
        events.push(parsed);
      }
    } catch {
      // skip malformed lines
      malformedLines += 1;
    }
  }

  const consideredLines = lines.slice(start);
  const windowPayload = consideredLines.join('\n');
  const windowSha256 = windowPayload.length > 0
    ? crypto.createHash('sha256').update(Buffer.from(windowPayload, 'utf8')).digest('hex')
    : null;

  return {
    events,
    metadata: {
      limit,
      bytes_scanned: tail.bytesRead,
      truncated: tail.truncated,
      lines_scanned: lines.length,
      lines_considered: consideredLines.length,
      parsed_events: events.length,
      malformed_lines: malformedLines,
      tail_sha256: tail.tailSha256,
      window_sha256: windowSha256,
    },
  };
}

function readJsonLines(filePath, options = {}) {
  return readJsonLinesDetailed(filePath, options).events;
}

function extractReasons(event) {
  const out = [];
  const source = Array.isArray(event?.reasons)
    ? event.reasons
    : event?.reason !== undefined
      ? [event.reason]
      : [];
  for (const item of source) {
    const reason = String(item || '').trim();
    if (reason) {
      out.push(reason.slice(0, 96));
    }
  }
  return out;
}

function percentile(sortedValues, percentileValue) {
  if (!Array.isArray(sortedValues) || sortedValues.length === 0) {
    return null;
  }
  if (sortedValues.length === 1) {
    return Number(sortedValues[0]);
  }
  const index = Math.min(
    sortedValues.length - 1,
    Math.max(0, Math.ceil((percentileValue / 100) * sortedValues.length) - 1)
  );
  return Number(sortedValues[index]);
}

function summarize(events) {
  const summary = {
    total_events: events.length,
    blocked_events: 0,
    upstream_errors: 0,
    pii_related_events: 0,
    distinct_decisions: {},
    provider_totals: {},
    top_reasons: [],
    latency_ms: {
      count: 0,
      min: null,
      max: null,
      avg: null,
      p50: null,
      p95: null,
      p99: null,
    },
    budget_charged_usd_total: 0,
    window_start: null,
    window_end: null,
    atlas_top_techniques: [],
    atlas_mapped_events: 0,
    atlas_unmapped_events: 0,
  };

  const reasonCounts = {};
  const latencySamples = [];
  let latencyTotal = 0;

  for (const event of events) {
    const decision = String(event.decision || 'unknown');
    summary.distinct_decisions[decision] = (summary.distinct_decisions[decision] || 0) + 1;
    if (decision.startsWith('blocked')) {
      summary.blocked_events += 1;
    }
    if (decision === 'upstream_error') {
      summary.upstream_errors += 1;
    }
    if (Array.isArray(event.pii_types) && event.pii_types.length > 0) {
      summary.pii_related_events += 1;
    }

    const provider = String(event.provider || 'unknown');
    summary.provider_totals[provider] = (summary.provider_totals[provider] || 0) + 1;

    const reasons = extractReasons(event);
    for (const reason of reasons) {
      reasonCounts[reason] = (reasonCounts[reason] || 0) + 1;
    }

    const durationMs = Number(event.duration_ms);
    if (Number.isFinite(durationMs) && durationMs >= 0) {
      latencySamples.push(durationMs);
      latencyTotal += durationMs;
    }

    const budgetCharge = Number(event.budget_charged_usd);
    if (Number.isFinite(budgetCharge)) {
      summary.budget_charged_usd_total = Number((summary.budget_charged_usd_total + budgetCharge).toFixed(6));
    }

    const timestampMs = Date.parse(String(event.timestamp || ''));
    if (Number.isFinite(timestampMs)) {
      if (!summary.window_start || timestampMs < Date.parse(summary.window_start)) {
        summary.window_start = new Date(timestampMs).toISOString();
      }
      if (!summary.window_end || timestampMs > Date.parse(summary.window_end)) {
        summary.window_end = new Date(timestampMs).toISOString();
      }
    }
  }

  const sortedLatency = latencySamples.slice().sort((a, b) => a - b);
  if (sortedLatency.length > 0) {
    summary.latency_ms = {
      count: sortedLatency.length,
      min: Number(sortedLatency[0]),
      max: Number(sortedLatency[sortedLatency.length - 1]),
      avg: Number((latencyTotal / sortedLatency.length).toFixed(2)),
      p50: percentile(sortedLatency, 50),
      p95: percentile(sortedLatency, 95),
      p99: percentile(sortedLatency, 99),
    };
  }

  summary.top_reasons = Object.entries(reasonCounts)
    .sort((left, right) => {
      const countDiff = Number(right[1]) - Number(left[1]);
      if (countDiff !== 0) {
        return countDiff;
      }
      return String(left[0]).localeCompare(String(right[0]));
    })
    .slice(0, 10)
    .map(([reason, count]) => ({ reason, count }));

  const atlasSummary = summarizeAtlas(events, { topLimit: 10 });
  summary.atlas_top_techniques = Array.isArray(atlasSummary.top_techniques)
    ? atlasSummary.top_techniques.map((item) => ({
        technique_id: item.technique_id,
        tactic: item.tactic,
        name: item.name,
        severity: item.severity,
        count: Number(item.count || 0),
      }))
    : [];
  summary.atlas_mapped_events = Number(atlasSummary.mapped_events || 0);
  summary.atlas_unmapped_events = Number(atlasSummary.unmapped_events || 0);

  return summary;
}

function pickSampleFields(event) {
  return {
    timestamp: event.timestamp,
    correlation_id: event.correlation_id,
    decision: event.decision,
    provider: event.provider,
    response_status: event.response_status,
    reasons: event.reasons,
    pii_types: event.pii_types,
    duration_ms: event.duration_ms,
  };
}

function collectEvidenceSamples(events, sampleLimit) {
  const safeSampleLimit = clampPositiveInt(sampleLimit, DEFAULT_SAMPLE_LIMIT, 1, 200);
  const samples = {
    blocked: [],
    upstream_errors: [],
  };

  for (const event of events || []) {
    if (samples.blocked.length < safeSampleLimit && String(event.decision || '').startsWith('blocked')) {
      samples.blocked.push(pickSampleFields(event));
    }
    if (samples.upstream_errors.length < safeSampleLimit && String(event.decision || '') === 'upstream_error') {
      samples.upstream_errors.push(pickSampleFields(event));
    }
    if (samples.blocked.length >= safeSampleLimit && samples.upstream_errors.length >= safeSampleLimit) {
      break;
    }
  }

  return samples;
}

function summarizeEUAIActArticle12(events = []) {
  let withCorrelationId = 0;
  let withProvider = 0;
  let withReasons = 0;
  let withIntegrityMarkers = 0;
  let withBlockingAction = 0;
  let withForensicSignals = 0;

  for (const event of events) {
    if (String(event?.correlation_id || '').trim()) {
      withCorrelationId += 1;
    }
    if (String(event?.provider || '').trim()) {
      withProvider += 1;
    }
    if (Array.isArray(event?.reasons) && event.reasons.length > 0) {
      withReasons += 1;
    }
    const decision = String(event?.decision || '').toLowerCase();
    if (decision.startsWith('blocked')) {
      withBlockingAction += 1;
    }
    if (
      decision.includes('forensic')
      || decision.includes('dashboard_access')
      || event?.forensic_snapshot_id
      || event?.forensic_replay_id
    ) {
      withForensicSignals += 1;
    }
    if (
      event?.provenance_signature
      || event?.token_watermark
      || event?.policy_bundle_signature
      || event?.evidence_entry_hash
      || event?.swarm_signature
    ) {
      withIntegrityMarkers += 1;
    }
  }

  const total = Math.max(1, events.length);
  return {
    events_total: events.length,
    events_with_correlation_id: withCorrelationId,
    events_with_provider: withProvider,
    events_with_reasons: withReasons,
    events_with_integrity_markers: withIntegrityMarkers,
    blocked_or_constrained_events: withBlockingAction,
    forensic_or_audit_events: withForensicSignals,
    coverage_ratio: Number(((withCorrelationId + withProvider + withReasons) / (3 * total)).toFixed(6)),
  };
}

class ComplianceEngine {
  constructor(options = {}) {
    this.auditPath = options.auditPath;
    this.maxReadBytes = clampPositiveInt(options.maxReadBytes, DEFAULT_MAX_READ_BYTES, 1024, 512 * 1024 * 1024);
    this.chunkReadBytes = clampPositiveInt(
      options.chunkReadBytes,
      DEFAULT_CHUNK_READ_BYTES,
      1024,
      8 * 1024 * 1024
    );
    this.sampleLimit = clampPositiveInt(options.sampleLimit, DEFAULT_SAMPLE_LIMIT, 1, 200);
  }

  loadEvents(limit) {
    return this.loadEventsWithMeta({ limit }).events;
  }

  loadEventsWithMeta(options = {}) {
    const detailed = readJsonLinesDetailed(this.auditPath, {
      limit: options.limit,
      maxReadBytes: options.maxReadBytes || this.maxReadBytes,
      chunkReadBytes: options.chunkReadBytes || this.chunkReadBytes,
    });
    return detailed;
  }

  generateEvidence(framework, options = {}, details = {}) {
    const data = this.loadEventsWithMeta({
      limit: options.limit,
      maxReadBytes: options.maxReadBytes,
      chunkReadBytes: options.chunkReadBytes,
    });
    const events = data.events;
    const metadata = data.metadata;
    const samples = collectEvidenceSamples(events, options.sampleLimit || this.sampleLimit);
    const summary = summarize(events);

    return {
      framework,
      generated_at: new Date().toISOString(),
      ...details,
      summary,
      sample_size: events.length,
      source: {
        audit_path: this.auditPath,
        limit: metadata.limit,
        bytes_scanned: metadata.bytes_scanned,
        truncated: metadata.truncated,
        lines_scanned: metadata.lines_scanned,
        lines_considered: metadata.lines_considered,
        parsed_events: metadata.parsed_events,
        malformed_lines: metadata.malformed_lines,
      },
      integrity: {
        tail_sha256: metadata.tail_sha256,
        window_sha256: metadata.window_sha256,
      },
      samples,
    };
  }

  generateSOC2Evidence(options = {}) {
    return this.generateEvidence('SOC2', options, {
      control_domain: 'Security/Availability',
    });
  }

  generateGDPREvidence(options = {}) {
    return this.generateEvidence('GDPR', options, {
      article: 'Article 35 (DPIA support)',
    });
  }

  generateHIPAAEvidence(options = {}) {
    return this.generateEvidence('HIPAA', options, {
      safeguards: 'Administrative/Technical',
    });
  }

  generateEUAIActArticle12Evidence(options = {}) {
    const data = this.loadEventsWithMeta({
      limit: options.limit,
      maxReadBytes: options.maxReadBytes,
      chunkReadBytes: options.chunkReadBytes,
    });
    const events = data.events;
    const metadata = data.metadata;
    const samples = collectEvidenceSamples(events, options.sampleLimit || this.sampleLimit);
    const summary = summarize(events);

    return {
      framework: 'EU_AI_ACT_ARTICLE_12',
      generated_at: new Date().toISOString(),
      regulation: 'EU AI Act',
      article: 'Article 12',
      title: 'Record-keeping and logging',
      summary,
      article_12: summarizeEUAIActArticle12(events),
      sample_size: events.length,
      source: {
        audit_path: this.auditPath,
        limit: metadata.limit,
        bytes_scanned: metadata.bytes_scanned,
        truncated: metadata.truncated,
        lines_scanned: metadata.lines_scanned,
        lines_considered: metadata.lines_considered,
        parsed_events: metadata.parsed_events,
        malformed_lines: metadata.malformed_lines,
      },
      integrity: {
        tail_sha256: metadata.tail_sha256,
        window_sha256: metadata.window_sha256,
      },
      samples,
    };
  }

  static signReport(report, privateKeyPem) {
    const payload = Buffer.from(JSON.stringify(report), 'utf8');
    const signature = crypto.sign(null, payload, crypto.createPrivateKey(privateKeyPem)).toString('base64');
    return {
      report,
      signature,
      algorithm: 'ed25519',
      payload_sha256: crypto.createHash('sha256').update(payload).digest('hex'),
    };
  }
}

module.exports = {
  ComplianceEngine,
  readJsonLines,
  readJsonLinesDetailed,
  summarize,
  summarizeEUAIActArticle12,
};
