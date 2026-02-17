const { RapidApiPIIClient } = require('./rapidapi-client');
const { SEVERITY_RANK } = require('../engines/pii-scanner');

function mergeFindings(primary, secondary) {
  const out = [];
  const seen = new Set();
  const all = [...(primary || []), ...(secondary || [])];
  for (const finding of all) {
    const key = `${finding.id}:${finding.value}:${finding.severity}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(finding);
  }
  return out;
}

function maxSeverity(a, b) {
  if (!a) return b;
  if (!b) return a;
  return SEVERITY_RANK[b] > SEVERITY_RANK[a] ? b : a;
}

class PIIProviderEngine {
  constructor({ piiConfig, localScanner, telemetry, rapidClient }) {
    this.config = piiConfig || {};
    this.localScanner = localScanner;
    this.telemetry = telemetry;
    this.rapidClient = rapidClient || new RapidApiPIIClient(this.config.rapidapi || {});
  }

  scanLocal(text) {
    return this.localScanner.scan(text, {
      maxScanBytes: this.config.max_scan_bytes,
    });
  }

  async scanRapid(text, headers = {}) {
    return this.rapidClient.scan(text, headers);
  }

  async scan(text, headers = {}) {
    const mode = String(this.config.provider_mode || 'local').toLowerCase();
    const fallbackEnabled = this.config.rapidapi?.fallback_to_local !== false;

    if (mode === 'local') {
      return {
        result: this.scanLocal(text),
        meta: {
          providerMode: 'local',
          providerUsed: 'local',
          fallbackUsed: false,
          fallbackReason: null,
        },
      };
    }

    if (mode === 'rapidapi') {
      try {
        const rapid = await this.scanRapid(text, headers);
        return {
          result: rapid,
          meta: {
            providerMode: 'rapidapi',
            providerUsed: 'rapidapi',
            fallbackUsed: false,
            fallbackReason: null,
          },
        };
      } catch (error) {
        if (!fallbackEnabled) {
          throw error;
        }
        this.telemetry?.addUpstreamError({ provider: 'rapidapi', reason: error.kind || 'rapidapi_error' });
        return {
          result: this.scanLocal(text),
          meta: {
            providerMode: 'rapidapi',
            providerUsed: 'local',
            fallbackUsed: true,
            fallbackReason: error.kind || 'rapidapi_error',
          },
        };
      }
    }

    // hybrid mode: local always + rapidapi best effort
    const local = this.scanLocal(text);
    try {
      const rapid = await this.scanRapid(text, headers);
      return {
        result: {
          findings: mergeFindings(local.findings, rapid.findings),
          redactedText: rapid.redactedText || local.redactedText,
          highestSeverity: maxSeverity(local.highestSeverity, rapid.highestSeverity),
          scanTruncated: local.scanTruncated || rapid.scanTruncated,
        },
        meta: {
          providerMode: 'hybrid',
          providerUsed: 'hybrid',
          fallbackUsed: false,
          fallbackReason: null,
        },
      };
    } catch (error) {
      this.telemetry?.addUpstreamError({ provider: 'rapidapi', reason: error.kind || 'rapidapi_error' });
      return {
        result: local,
        meta: {
          providerMode: 'hybrid',
          providerUsed: 'local',
          fallbackUsed: true,
          fallbackReason: error.kind || 'rapidapi_error',
        },
      };
    }
  }
}

module.exports = {
  PIIProviderEngine,
};
