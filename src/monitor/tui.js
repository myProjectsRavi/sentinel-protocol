const fs = require('fs');
const blessed = require('blessed');

const { STATUS_FILE_PATH, AUDIT_LOG_PATH } = require('../utils/paths');

const DEFAULT_TAIL_READ_CHUNK_BYTES = 64 * 1024;
const DEFAULT_INITIAL_READ_BYTES = 1024 * 1024;

function safeReadJson(filePath) {
  try {
    if (!fs.existsSync(filePath)) {
      return null;
    }
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

class LogTailer {
  constructor(filePath, options = {}) {
    this.filePath = filePath;
    this.maxEntries = Number(options.maxEntries || 500);
    this.initialReadBytes = Number(options.initialReadBytes || DEFAULT_INITIAL_READ_BYTES);
    this.readChunkBytes = Number(options.readChunkBytes || DEFAULT_TAIL_READ_CHUNK_BYTES);

    this.cursor = 0;
    this.entries = [];
    this.carry = '';
    this.dropUntilNewline = false;
  }

  resetCursor() {
    this.cursor = 0;
    this.carry = '';
    this.dropUntilNewline = false;
  }

  appendEntry(entry) {
    this.entries.push(entry);
    const overflow = this.entries.length - this.maxEntries;
    if (overflow > 0) {
      this.entries.splice(0, overflow);
    }
  }

  consumeChunk(chunkText) {
    if (!chunkText) {
      return;
    }

    let text = `${this.carry}${chunkText}`;
    this.carry = '';

    if (this.dropUntilNewline) {
      const firstNewline = text.indexOf('\n');
      if (firstNewline === -1) {
        return;
      }
      text = text.slice(firstNewline + 1);
      this.dropUntilNewline = false;
    }

    const lines = text.split('\n');
    this.carry = lines.pop() || '';

    for (const line of lines) {
      if (!line) {
        continue;
      }
      try {
        this.appendEntry(JSON.parse(line));
      } catch {
        // Skip malformed JSON lines.
      }
    }
  }

  tick() {
    let stat;
    try {
      stat = fs.statSync(this.filePath);
    } catch {
      this.resetCursor();
      return this.entries;
    }

    const size = stat.size;
    if (size < this.cursor) {
      // Log rotation/truncation.
      this.resetCursor();
    }

    if (this.cursor === 0 && size > this.initialReadBytes) {
      // Avoid loading very large history on first render.
      this.cursor = size - this.initialReadBytes;
      this.dropUntilNewline = this.cursor > 0;
    }

    if (size <= this.cursor) {
      return this.entries;
    }

    let fd;
    try {
      fd = fs.openSync(this.filePath, 'r');
      while (this.cursor < size) {
        const remaining = size - this.cursor;
        const chunkSize = Math.min(remaining, this.readChunkBytes);
        const buffer = Buffer.allocUnsafe(chunkSize);
        const bytesRead = fs.readSync(fd, buffer, 0, chunkSize, this.cursor);
        if (bytesRead <= 0) {
          break;
        }
        this.cursor += bytesRead;
        this.consumeChunk(buffer.subarray(0, bytesRead).toString('utf8'));
      }
    } catch {
      // Keep last good snapshot if file is temporarily unreadable.
    } finally {
      if (typeof fd === 'number') {
        try {
          fs.closeSync(fd);
        } catch {
          // Ignore close errors.
        }
      }
    }

    return this.entries;
  }
}

function parseAuditEntries(limit = 500) {
  const tailer = new LogTailer(AUDIT_LOG_PATH, { maxEntries: limit });
  return tailer.tick();
}

function summarizePIITypes(entries) {
  const counts = new Map();
  for (const entry of entries) {
    for (const type of entry.pii_types || []) {
      counts.set(type, (counts.get(type) || 0) + 1);
    }
  }
  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);
}

function colorStatusCode(code) {
  if (code >= 500) return '{red-fg}';
  if (code >= 400) return '{yellow-fg}';
  return '{green-fg}';
}

class SentinelMonitorTUI {
  constructor(options = {}) {
    this.refreshMs = Number(options.refreshMs || 1000);
    this.maxRows = Number(options.maxRows || 10);
    this.lastRequestsTotal = null;
    this.lastTick = Date.now();
    this.interval = null;
    this.auditTailer = new LogTailer(AUDIT_LOG_PATH, {
      maxEntries: Number(options.maxAuditEntries || 500),
    });

    this.screen = blessed.screen({
      smartCSR: true,
      title: 'Sentinel Monitor',
    });

    this.headerBox = blessed.box({
      top: 0,
      left: 0,
      width: '100%',
      height: 3,
      content: '{bold}Sentinel Monitor{/bold}  (q to quit)',
      tags: true,
      border: 'line',
      style: { border: { fg: 'cyan' } },
    });

    this.statsBox = blessed.box({
      top: 3,
      left: 0,
      width: '50%',
      height: 8,
      tags: true,
      border: 'line',
      label: ' Runtime ',
      style: { border: { fg: 'green' } },
    });

    this.piiBox = blessed.box({
      top: 3,
      left: '50%',
      width: '50%',
      height: 8,
      tags: true,
      border: 'line',
      label: ' PII Types ',
      style: { border: { fg: 'magenta' } },
    });

    this.requestsTable = blessed.listtable({
      top: 11,
      left: 0,
      width: '100%',
      height: '100%-11',
      border: 'line',
      label: ' Last Requests ',
      tags: true,
      style: {
        border: { fg: 'yellow' },
        header: { bold: true },
      },
      data: [['Time', 'Status', 'Decision', 'Provider', 'Reason']],
    });

    this.screen.append(this.headerBox);
    this.screen.append(this.statsBox);
    this.screen.append(this.piiBox);
    this.screen.append(this.requestsTable);

    this.screen.key(['q', 'C-c'], () => {
      this.stop();
    });
  }

  renderRuntime(status) {
    const counters = status?.counters || {};
    const now = Date.now();
    const elapsedSec = Math.max((now - this.lastTick) / 1000, 0.001);
    const requestsTotal = Number(counters.requests_total || 0);
    const blockedTotal = Number(counters.blocked_total || 0);

    const reqDelta = this.lastRequestsTotal === null ? 0 : requestsTotal - this.lastRequestsTotal;
    const rps = reqDelta <= 0 ? 0 : reqDelta / elapsedSec;
    const blockedPct = requestsTotal > 0 ? (blockedTotal / requestsTotal) * 100 : 0;

    this.lastRequestsTotal = requestsTotal;
    this.lastTick = now;

    this.statsBox.setContent(
      [
        `Service: {bold}${status?.service_status || 'stopped'}{/bold}`,
        `Mode: ${status?.effective_mode || 'unknown'}  Provider mode: ${status?.pii_provider_mode || 'unknown'}`,
        `Req/s: ${rps.toFixed(2)}   Requests: ${requestsTotal}`,
        `Blocked: ${blockedTotal} (${blockedPct.toFixed(2)}%)`,
        `PII blocked: ${counters.pii_blocked || 0}   Injection blocked: ${counters.injection_blocked || 0}`,
        `Upstream errors: ${counters.upstream_errors || 0}   RapidAPI errors: ${status?.rapidapi_error_count || 0}`,
      ].join('\n')
    );
  }

  renderPII(entries) {
    const topTypes = summarizePIITypes(entries);
    if (topTypes.length === 0) {
      this.piiBox.setContent('No PII findings yet.');
      return;
    }
    this.piiBox.setContent(topTypes.map(([type, count]) => `${type}: ${count}`).join('\n'));
  }

  renderRequests(entries) {
    const rows = [['Time', 'Status', 'Decision', 'Provider', 'Reason']];
    const tail = entries.slice(Math.max(0, entries.length - this.maxRows));

    for (const entry of tail.reverse()) {
      const time = String(entry.timestamp || '').split('T')[1]?.replace('Z', '') || '--';
      const status = Number(entry.response_status || 0);
      const color = colorStatusCode(status);
      const reason = Array.isArray(entry.reasons) ? entry.reasons.join(',') : '';
      rows.push([
        time,
        `${color}${status}{/}`,
        entry.decision || '--',
        entry.provider || '--',
        reason || '--',
      ]);
    }

    this.requestsTable.setData(rows);
  }

  tick() {
    const status = safeReadJson(STATUS_FILE_PATH);
    const entries = this.auditTailer.tick();
    this.renderRuntime(status);
    this.renderPII(entries);
    this.renderRequests(entries);
    this.screen.render();
  }

  start() {
    this.tick();
    this.interval = setInterval(() => this.tick(), this.refreshMs);
  }

  stop() {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
    this.screen.destroy();
    process.exit(0);
  }
}

function startMonitorTUI(options = {}) {
  const monitor = new SentinelMonitorTUI(options);
  monitor.start();
  return monitor;
}

module.exports = {
  SentinelMonitorTUI,
  startMonitorTUI,
  parseAuditEntries,
  LogTailer,
  summarizePIITypes,
};
