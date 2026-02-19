const { analyzeEntropyText } = require('./entropy-analyzer');

function isTextualContentType(contentType) {
  const value = String(contentType || '').toLowerCase();
  if (!value) {
    return false;
  }
  return (
    value.includes('application/json') ||
    value.includes('application/problem+json') ||
    value.includes('application/xml') ||
    value.includes('application/javascript') ||
    value.includes('application/x-www-form-urlencoded') ||
    value.includes('text/') ||
    value.includes('text/event-stream')
  );
}

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

function flattenFindings(findings) {
  return Array.from(new Set((findings || []).map((item) => String(item.id)))).sort();
}

function resolveAction({ severity, severityActions }) {
  if (!severity) {
    return 'log';
  }
  return severityActions?.[severity] || 'log';
}

function scanBufferedResponse(options = {}) {
  const {
    bodyBuffer,
    contentType,
    scanner,
    maxScanBytes,
    severityActions,
    effectiveMode,
    entropyConfig,
  } = options;

  if (!Buffer.isBuffer(bodyBuffer) || bodyBuffer.length === 0 || !scanner || !isTextualContentType(contentType)) {
    return {
      detected: false,
      blocked: false,
      redacted: false,
      redactionSkipped: false,
      bodyBuffer,
      findings: [],
      piiTypes: [],
      severity: null,
      action: 'log',
      entropy: {
        detected: false,
        blocked: false,
        action: 'monitor',
        findings: [],
        threshold: Number(entropyConfig?.threshold || 4.5),
        truncated: false,
      },
    };
  }

  const text = bodyBuffer.toString('utf8');
  const entropyResult = analyzeEntropyText(text, entropyConfig || {});
  const entropyBlocked =
    entropyResult.detected === true &&
    entropyResult.mode === 'block' &&
    effectiveMode === 'enforce';

  const scan = scanner.scan(text, { maxScanBytes });
  if (!scan.findings || scan.findings.length === 0) {
    return {
      detected: false,
      blocked: false,
      redacted: false,
      redactionSkipped: false,
      bodyBuffer,
      findings: [],
      piiTypes: [],
      severity: null,
      action: 'log',
      entropy: {
        detected: entropyResult.detected,
        blocked: entropyBlocked,
        action: entropyBlocked ? 'block' : entropyResult.mode,
        findings: entropyResult.findings || [],
        threshold: entropyResult.threshold,
        truncated: entropyResult.truncated === true,
      },
    };
  }

  const severity = highestSeverity(scan.findings);
  const action = resolveAction({ severity, severityActions });
  const blocked = action === 'block' && effectiveMode === 'enforce';
  const canSafelyRedact = scan.scanTruncated !== true;
  const redactedRequested = action === 'redact' || (action === 'block' && effectiveMode !== 'enforce');
  const redacted = redactedRequested && canSafelyRedact;
  const redactionSkipped = redactedRequested && !canSafelyRedact;
  const outBody = redacted ? Buffer.from(scan.redactedText, 'utf8') : bodyBuffer;

  return {
    detected: true,
    blocked,
    redacted,
    redactionSkipped,
    bodyBuffer: outBody,
    findings: scan.findings,
    piiTypes: flattenFindings(scan.findings),
    severity,
    action,
    entropy: {
      detected: entropyResult.detected,
      blocked: entropyBlocked,
      action: entropyBlocked ? 'block' : entropyResult.mode,
      findings: entropyResult.findings || [],
      threshold: entropyResult.threshold,
      truncated: entropyResult.truncated === true,
    },
  };
}

module.exports = {
  isTextualContentType,
  scanBufferedResponse,
};
