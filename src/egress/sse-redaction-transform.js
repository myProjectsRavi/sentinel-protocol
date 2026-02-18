const { Transform } = require('stream');
const { StringDecoder } = require('string_decoder');

function highestSeverity(findings) {
  const rank = { low: 1, medium: 2, high: 3, critical: 4 };
  let current = null;
  for (const finding of findings || []) {
    if (!current || rank[finding.severity] > rank[current]) {
      current = finding.severity;
    }
  }
  return current;
}

function resolveAction({ severity, severityActions, effectiveMode, streamBlockMode }) {
  const configured = severityActions?.[severity] || 'log';
  if (configured === 'block' && effectiveMode === 'enforce') {
    return streamBlockMode === 'terminate' ? 'block' : 'redact';
  }
  return configured;
}

class SSERedactionTransform extends Transform {
  constructor(options = {}) {
    super();
    this.scanner = options.scanner;
    this.maxScanBytes = Number(options.maxScanBytes || 65536);
    this.maxLineBytes = Number(options.maxLineBytes || 16384);
    this.severityActions = options.severityActions || {};
    this.effectiveMode = options.effectiveMode || 'monitor';
    this.streamBlockMode = options.streamBlockMode === 'terminate' ? 'terminate' : 'redact';
    this.onDetection = typeof options.onDetection === 'function' ? options.onDetection : null;

    this.decoder = new StringDecoder('utf8');
    this.pending = '';
  }

  processLine(line) {
    const normalized = String(line || '');
    if (!normalized.startsWith('data:')) {
      return normalized;
    }

    const hasCrLf = normalized.endsWith('\r\n');
    const hasLf = !hasCrLf && normalized.endsWith('\n');
    const newline = hasCrLf ? '\r\n' : hasLf ? '\n' : '';
    const withoutNewline = newline ? normalized.slice(0, -newline.length) : normalized;

    const payload = withoutNewline.slice(5);
    const payloadTrimmed = payload.startsWith(' ') ? payload.slice(1) : payload;
    if (!payloadTrimmed) {
      return normalized;
    }

    const payloadBudgeted = Buffer.byteLength(payloadTrimmed, 'utf8') > this.maxLineBytes
      ? Buffer.from(payloadTrimmed, 'utf8').subarray(0, this.maxLineBytes).toString('utf8')
      : payloadTrimmed;
    const scan = this.scanner.scan(payloadBudgeted, {
      maxScanBytes: this.maxScanBytes,
    });
    if (!scan.findings || scan.findings.length === 0) {
      return normalized;
    }

    const severity = highestSeverity(scan.findings);
    const action = resolveAction({
      severity,
      severityActions: this.severityActions,
      effectiveMode: this.effectiveMode,
      streamBlockMode: this.streamBlockMode,
    });
    const redactedPayload = action === 'redact' ? scan.redactedText : payloadTrimmed;
    const spacer = payload.startsWith(' ') ? ' ' : '';

    if (this.onDetection) {
      this.onDetection({
        severity,
        action,
        findings: scan.findings,
      });
    }

    if (action === 'block') {
      return '';
    }

    const outLine = `data:${spacer}${redactedPayload}${newline}`;
    return outLine;
  }

  processDecoded(decoded) {
    this.pending += decoded;
    let cursor = 0;
    while (true) {
      const newlineIndex = this.pending.indexOf('\n', cursor);
      if (newlineIndex === -1) {
        break;
      }
      const line = this.pending.slice(cursor, newlineIndex + 1);
      const outLine = this.processLine(line);
      this.push(outLine);
      cursor = newlineIndex + 1;
    }
    this.pending = this.pending.slice(cursor);
  }

  _transform(chunk, encoding, callback) {
    try {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
      const decoded = this.decoder.write(buffer);
      if (decoded) {
        this.processDecoded(decoded);
      }
      callback();
    } catch (error) {
      callback(error);
    }
  }

  _flush(callback) {
    try {
      const flushed = this.decoder.end();
      if (flushed) {
        this.processDecoded(flushed);
      }
      if (this.pending) {
        const outLine = this.processLine(this.pending);
        this.push(outLine);
        this.pending = '';
      }
      callback();
    } catch (error) {
      callback(error);
    }
  }
}

module.exports = {
  SSERedactionTransform,
};
