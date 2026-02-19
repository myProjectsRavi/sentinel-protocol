const fs = require('fs');
const crypto = require('crypto');

function readJsonLines(filePath, limit = 200000) {
  if (!fs.existsSync(filePath)) {
    return [];
  }
  const lines = fs.readFileSync(filePath, 'utf8').split('\n').filter(Boolean).slice(-limit);
  const events = [];
  for (const line of lines) {
    try {
      const parsed = JSON.parse(line);
      if (parsed && typeof parsed === 'object') {
        events.push(parsed);
      }
    } catch {
      // skip malformed lines
    }
  }
  return events;
}

function summarize(events) {
  const summary = {
    total_events: events.length,
    blocked_events: 0,
    upstream_errors: 0,
    pii_related_events: 0,
    distinct_decisions: {},
  };
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
  }
  return summary;
}

class ComplianceEngine {
  constructor(options = {}) {
    this.auditPath = options.auditPath;
  }

  loadEvents(limit) {
    return readJsonLines(this.auditPath, limit);
  }

  generateSOC2Evidence(options = {}) {
    const events = this.loadEvents(options.limit);
    return {
      framework: 'SOC2',
      generated_at: new Date().toISOString(),
      control_domain: 'Security/Availability',
      summary: summarize(events),
      sample_size: events.length,
    };
  }

  generateGDPREvidence(options = {}) {
    const events = this.loadEvents(options.limit);
    return {
      framework: 'GDPR',
      generated_at: new Date().toISOString(),
      article: 'Article 35 (DPIA support)',
      summary: summarize(events),
      sample_size: events.length,
    };
  }

  generateHIPAAEvidence(options = {}) {
    const events = this.loadEvents(options.limit);
    return {
      framework: 'HIPAA',
      generated_at: new Date().toISOString(),
      safeguards: 'Administrative/Technical',
      summary: summarize(events),
      sample_size: events.length,
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
  summarize,
};
