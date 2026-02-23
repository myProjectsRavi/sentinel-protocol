const {
  clampPositiveInt,
  clampProbability,
  normalizeMode,
} = require('../utils/primitives');
const { isTextualContentType } = require('./response-scanner');

const URL_RE = /https?:\/\/[\w.-]+(?:\/[\w\-./?%&=#]*)?/gi;
const DOI_RE = /\b10\.\d{4,9}\/[A-Za-z0-9._;()/:+-]+\b/g;
const JS_IMPORT_RE = /\bimport\s+[^\n;]+?from\s+['"]([^'"]+)['"]/gi;
const PY_IMPORT_RE = /\b(?:from\s+([A-Za-z0-9_.-]+)\s+import|import\s+([A-Za-z0-9_.-]+))/gi;

function suspiciousDomain(host) {
  const domain = String(host || '').toLowerCase();
  if (!domain) {
    return true;
  }
  if (domain.includes('example') || domain.includes('invalid') || domain.includes('localhost') || domain.includes('.local')) {
    return true;
  }
  const parts = domain.split('.').filter(Boolean);
  if (parts.length < 2) {
    return true;
  }
  const tld = parts[parts.length - 1];
  if (tld.length < 2 || tld.length > 24) {
    return true;
  }
  return false;
}

function parseHost(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

function extractPackageNames(text, maxItems = 64) {
  const packages = [];
  let match;
  JS_IMPORT_RE.lastIndex = 0;
  while ((match = JS_IMPORT_RE.exec(text)) !== null) {
    packages.push(String(match[1] || ''));
    if (packages.length >= maxItems) {
      break;
    }
    if (String(match[0] || '').length === 0) {
      JS_IMPORT_RE.lastIndex += 1;
    }
  }

  PY_IMPORT_RE.lastIndex = 0;
  while ((match = PY_IMPORT_RE.exec(text)) !== null) {
    const pkg = String(match[1] || match[2] || '');
    if (pkg) {
      packages.push(pkg);
    }
    if (packages.length >= maxItems) {
      break;
    }
    if (String(match[0] || '').length === 0) {
      PY_IMPORT_RE.lastIndex += 1;
    }
  }

  return packages;
}

function normalizeNumberSignals(text, maxEntries = 64) {
  const out = [];
  const regex = /(\d{1,9})\s+(users?|records?|items?|entries?|requests?|tokens?)/gi;
  let match;
  while ((match = regex.exec(text)) !== null) {
    out.push({
      value: Number(match[1]),
      noun: String(match[2] || '').toLowerCase(),
    });
    if (out.length >= maxEntries) {
      break;
    }
    if (String(match[0] || '').length === 0) {
      regex.lastIndex += 1;
    }
  }
  return out;
}

class HallucinationTripwire {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.maxScanChars = clampPositiveInt(config.max_scan_chars, 16384, 256, 1048576);
    this.maxFindings = clampPositiveInt(config.max_findings, 24, 1, 512);
    this.warnThreshold = clampProbability(config.warn_threshold, 0.45);
    this.blockThreshold = clampProbability(config.block_threshold, 0.8);
    this.blockOnDetect = config.block_on_detect === true;
    this.observability = config.observability !== false;
  }

  isEnabled() {
    return this.enabled === true;
  }

  analyzeText(text, { effectiveMode = 'monitor' } = {}) {
    const enabled = this.isEnabled();
    const bounded = String(text || '').slice(0, this.maxScanChars);
    if (!enabled || !bounded) {
      return {
        enabled,
        detected: false,
        shouldBlock: false,
        score: 0,
        reason: 'clean',
        findings: [],
      };
    }

    const findings = [];
    let score = 0;

    const urls = bounded.match(URL_RE) || [];
    for (const url of urls.slice(0, this.maxFindings)) {
      const host = parseHost(url);
      if (!suspiciousDomain(host)) {
        continue;
      }
      score += 0.18;
      findings.push({
        code: 'hallucination_suspicious_url',
        url,
        host,
        weight: 0.18,
        blockEligible: this.blockOnDetect,
      });
    }

    const dois = bounded.match(DOI_RE) || [];
    for (const doi of dois.slice(0, this.maxFindings)) {
      if (/\b(unknown|none|na|n\/a)\b/i.test(doi)) {
        score += 0.2;
        findings.push({
          code: 'hallucination_invalid_doi',
          doi,
          weight: 0.2,
          blockEligible: this.blockOnDetect,
        });
      }
    }

    const packages = extractPackageNames(bounded, this.maxFindings);
    for (const pkg of packages) {
      if (!pkg || pkg.length > 214) {
        continue;
      }
      if (/[^a-z0-9_./@-]/i.test(pkg) || /\s/.test(pkg) || /[A-Z]{3,}/.test(pkg)) {
        score += 0.12;
        findings.push({
          code: 'hallucination_suspicious_import',
          package: pkg,
          weight: 0.12,
          blockEligible: false,
        });
      }
    }

    const numberSignals = normalizeNumberSignals(bounded, this.maxFindings);
    const byNoun = new Map();
    for (const signal of numberSignals) {
      const bucket = byNoun.get(signal.noun) || [];
      bucket.push(signal.value);
      byNoun.set(signal.noun, bucket);
    }
    for (const [noun, values] of byNoun.entries()) {
      if (values.length < 2) {
        continue;
      }
      const min = Math.min(...values);
      const max = Math.max(...values);
      if (min <= 0) {
        continue;
      }
      const ratio = max / min;
      if (ratio >= 5) {
        score += 0.14;
        findings.push({
          code: 'hallucination_numeric_inconsistency',
          noun,
          min,
          max,
          ratio: Number(ratio.toFixed(3)),
          weight: 0.14,
          blockEligible: false,
        });
      }
    }

    if (/\b(100%\s+accurate|absolutely\s+verified|guaranteed\s+factual)\b/i.test(bounded)) {
      score += 0.18;
      findings.push({
        code: 'hallucination_overconfident_claim',
        weight: 0.18,
        blockEligible: false,
      });
    }

    const normalizedScore = Number(Math.min(1, score).toFixed(4));
    const detected = normalizedScore >= this.warnThreshold && findings.length > 0;
    const shouldBlock =
      detected &&
      normalizedScore >= this.blockThreshold &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce' &&
      findings.some((item) => item.blockEligible === true);

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      score: normalizedScore,
      reason: detected ? String(findings[0].code || 'hallucination_tripwire_detected') : 'clean',
      findings: findings.slice(0, this.maxFindings),
    };
  }

  analyzeBuffer({ bodyBuffer, contentType, effectiveMode = 'monitor' } = {}) {
    if (!Buffer.isBuffer(bodyBuffer) || bodyBuffer.length === 0 || !isTextualContentType(contentType)) {
      return {
        enabled: this.isEnabled(),
        detected: false,
        shouldBlock: false,
        score: 0,
        reason: 'clean',
        findings: [],
      };
    }

    return this.analyzeText(bodyBuffer.toString('utf8'), {
      effectiveMode,
    });
  }
}

module.exports = {
  HallucinationTripwire,
};
