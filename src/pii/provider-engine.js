const { RapidApiPIIClient } = require('./rapidapi-client');
const { SEVERITY_RANK } = require('../engines/pii-scanner');
const { SemanticScanner } = require('../engines/semantic-scanner');

function normalizeValue(value) {
  return String(value || '').trim().toLowerCase();
}

function findingKey(finding) {
  const id = String(finding?.id || 'unknown');
  const severity = String(finding?.severity || 'low');
  const hasRange =
    Number.isInteger(finding?.start) && Number.isInteger(finding?.end) && Number(finding.end) >= Number(finding.start);
  const value = normalizeValue(finding?.value);

  if (hasRange && value) {
    return `${id}:${severity}:range:${finding.start}-${finding.end}:value:${value}`;
  }
  if (hasRange) {
    return `${id}:${severity}:range:${finding.start}-${finding.end}`;
  }
  if (value) {
    return `${id}:${severity}:value:${value}`;
  }
  return `${id}:${severity}:raw:${JSON.stringify(finding)}`;
}

function mergeFindings(primary, secondary) {
  const out = [];
  const seen = new Set();
  const all = [...(primary || []), ...(secondary || [])];
  for (const finding of all) {
    const key = findingKey(finding);
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
  constructor({ piiConfig, localScanner, telemetry, rapidClient, semanticScanner }) {
    this.config = piiConfig || {};
    this.localScanner = localScanner;
    this.telemetry = telemetry;
    this.rapidClient = rapidClient || new RapidApiPIIClient(this.config.rapidapi || {});
    this.semanticScanner = semanticScanner || new SemanticScanner(this.config.semantic || {});
  }

  async applySemanticLayer(text, baseResult) {
    if (!this.semanticScanner || this.semanticScanner.enabled !== true) {
      return {
        result: baseResult,
        meta: {
          semanticEnabled: false,
          semanticUsed: false,
          semanticError: null,
        },
      };
    }

    try {
      const semantic = await this.semanticScanner.scan(text, {
        maxScanBytes: this.config.semantic?.max_scan_bytes,
      });
      if (!semantic.findings || semantic.findings.length === 0) {
        return {
          result: baseResult,
          meta: {
            semanticEnabled: true,
            semanticUsed: true,
            semanticError: semantic.error || null,
          },
        };
      }

      return {
        result: {
          findings: mergeFindings(baseResult.findings, semantic.findings),
          redactedText: semantic.redactedText || baseResult.redactedText,
          highestSeverity: maxSeverity(baseResult.highestSeverity, semantic.highestSeverity),
          scanTruncated: baseResult.scanTruncated || semantic.scanTruncated,
        },
        meta: {
          semanticEnabled: true,
          semanticUsed: true,
          semanticError: semantic.error || null,
        },
      };
    } catch (error) {
      return {
        result: baseResult,
        meta: {
          semanticEnabled: true,
          semanticUsed: false,
          semanticError: error.message,
        },
      };
    }
  }

  async scanLocal(text, options = {}) {
    const local = options.precomputedLocal || this.localScanner.scan(text, {
      maxScanBytes: this.config.max_scan_bytes,
      regexSafetyCapBytes: this.config.regex_safety_cap_bytes,
    });
    const semanticMerged = await this.applySemanticLayer(text, local);
    return semanticMerged;
  }

  async scanRapid(text, headers = {}) {
    return this.rapidClient.scan(text, headers);
  }

  async scan(text, headers = {}, options = {}) {
    const mode = String(this.config.provider_mode || 'local').toLowerCase();
    const fallbackEnabled = this.config.rapidapi?.fallback_to_local !== false;

    if (mode === 'local') {
      const local = await this.scanLocal(text, options);
      return {
        result: local.result,
        meta: {
          providerMode: 'local',
          providerUsed: 'local',
          fallbackUsed: false,
          fallbackReason: null,
          ...local.meta,
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
        const local = await this.scanLocal(text, options);
        return {
          result: local.result,
          meta: {
            providerMode: 'rapidapi',
            providerUsed: 'local',
            fallbackUsed: true,
            fallbackReason: error.kind || 'rapidapi_error',
            ...local.meta,
          },
        };
      }
    }

    // hybrid mode: local always + rapidapi best effort
    const local = await this.scanLocal(text, options);
    try {
      const rapid = await this.scanRapid(text, headers);
      return {
        result: {
          findings: mergeFindings(local.result.findings, rapid.findings),
          redactedText: rapid.redactedText || local.result.redactedText,
          highestSeverity: maxSeverity(local.result.highestSeverity, rapid.highestSeverity),
          scanTruncated: local.result.scanTruncated || rapid.scanTruncated,
        },
        meta: {
          providerMode: 'hybrid',
          providerUsed: 'hybrid',
          fallbackUsed: false,
          fallbackReason: null,
          ...local.meta,
        },
      };
    } catch (error) {
      this.telemetry?.addUpstreamError({ provider: 'rapidapi', reason: error.kind || 'rapidapi_error' });
      return {
        result: local.result,
        meta: {
          providerMode: 'hybrid',
          providerUsed: 'local',
          fallbackUsed: true,
          fallbackReason: error.kind || 'rapidapi_error',
          ...local.meta,
        },
      };
    }
  }
}

module.exports = {
  PIIProviderEngine,
};
