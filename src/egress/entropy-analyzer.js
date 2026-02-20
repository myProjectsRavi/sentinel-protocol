const crypto = require('crypto');
const { clampPositiveInt, normalizeMode } = require('../utils/primitives');

function clampProbability(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 1) {
    return fallback;
  }
  return parsed;
}

function clampEntropy(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 8) {
    return fallback;
  }
  return parsed;
}

function shannonEntropy(text) {
  if (!text || text.length === 0) {
    return 0;
  }
  const counts = new Map();
  for (const ch of text) {
    counts.set(ch, (counts.get(ch) || 0) + 1);
  }
  let result = 0;
  for (const count of counts.values()) {
    const p = count / text.length;
    result -= p * Math.log2(p);
  }
  return result;
}

function maskTokenHash(value) {
  return crypto.createHash('sha256').update(String(value || ''), 'utf8').digest('hex').slice(0, 16);
}

function uniqueCharacterRatio(value) {
  if (!value) {
    return 0;
  }
  return new Set(value).size / value.length;
}

function normalizeConfig(config = {}) {
  return {
    enabled: config.enabled === true,
    mode: normalizeMode(config.mode, 'monitor', ['monitor', 'block']),
    threshold: clampEntropy(config.threshold, 4.5),
    minTokenLength: clampPositiveInt(config.min_token_length, 24, 8, 8192),
    maxScanBytes: clampPositiveInt(config.max_scan_bytes, 65536, 256, 4 * 1024 * 1024),
    maxFindings: clampPositiveInt(config.max_findings, 8, 1, 128),
    minUniqueRatio: clampProbability(config.min_unique_ratio, 0.3),
    detectBase64: config.detect_base64 !== false,
    detectHex: config.detect_hex !== false,
    detectGeneric: config.detect_generic !== false,
    redactReplacement: String(config.redact_replacement || '[REDACTED_HIGH_ENTROPY]'),
  };
}

function budgetText(input, maxScanBytes) {
  const text = String(input || '');
  const bytes = Buffer.byteLength(text, 'utf8');
  if (bytes <= maxScanBytes) {
    return {
      text,
      truncated: false,
    };
  }
  return {
    text: Buffer.from(text, 'utf8').subarray(0, maxScanBytes).toString('utf8'),
    truncated: true,
  };
}

function collectCandidates(text, config) {
  const candidates = [];
  const occupied = [];
  const markRange = (start, end) => occupied.push([start, end]);
  const intersects = (start, end) =>
    occupied.some(([a, b]) => {
      return start < b && end > a;
    });

  if (config.detectBase64) {
    const pattern = /(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;
    let match;
    while ((match = pattern.exec(text)) !== null) {
      const value = match[0];
      const start = match.index;
      const end = start + value.length;
      if (value.length < config.minTokenLength) {
        continue;
      }
      const usefulLength = value.replace(/=+$/, '').length;
      if (usefulLength < config.minTokenLength) {
        continue;
      }
      candidates.push({
        kind: 'base64',
        value,
        start,
        end,
      });
      markRange(start, end);
      if (candidates.length >= config.maxFindings * 4) {
        break;
      }
    }
  }

  if (config.detectHex) {
    const pattern = /\b(?:[A-Fa-f0-9]{2}){12,}\b/g;
    let match;
    while ((match = pattern.exec(text)) !== null) {
      const value = match[0];
      const start = match.index;
      const end = start + value.length;
      if (value.length < config.minTokenLength || intersects(start, end)) {
        continue;
      }
      candidates.push({
        kind: 'hex',
        value,
        start,
        end,
      });
      markRange(start, end);
      if (candidates.length >= config.maxFindings * 4) {
        break;
      }
    }
  }

  if (config.detectGeneric) {
    const tokenPattern = new RegExp(`[A-Za-z0-9_+\\/=:-]{${config.minTokenLength},}`, 'g');
    let match;
    while ((match = tokenPattern.exec(text)) !== null) {
      const value = match[0];
      const start = match.index;
      const end = start + value.length;
      if (intersects(start, end)) {
        continue;
      }
      if (uniqueCharacterRatio(value) < config.minUniqueRatio) {
        continue;
      }
      candidates.push({
        kind: 'generic',
        value,
        start,
        end,
      });
      if (candidates.length >= config.maxFindings * 5) {
        break;
      }
    }
  }

  return candidates;
}

function analyzeEntropyText(input, rawConfig = {}) {
  const config = normalizeConfig(rawConfig);
  if (!config.enabled) {
    return {
      enabled: false,
      detected: false,
      findings: [],
      truncated: false,
      mode: config.mode,
      threshold: config.threshold,
    };
  }

  const budgeted = budgetText(input, config.maxScanBytes);
  const text = budgeted.text;
  if (!text) {
    return {
      enabled: true,
      detected: false,
      findings: [],
      truncated: budgeted.truncated,
      mode: config.mode,
      threshold: config.threshold,
    };
  }

  const findings = [];
  const candidates = collectCandidates(text, config);
  for (const candidate of candidates) {
    if (findings.length >= config.maxFindings) {
      break;
    }
    const entropy = shannonEntropy(candidate.value);
    if (entropy < config.threshold) {
      continue;
    }
    findings.push({
      kind: candidate.kind,
      entropy: Number(entropy.toFixed(4)),
      start: candidate.start,
      end: candidate.end,
      length: candidate.value.length,
      token_hash: maskTokenHash(candidate.value),
    });
  }

  return {
    enabled: true,
    detected: findings.length > 0,
    findings,
    truncated: budgeted.truncated,
    mode: config.mode,
    threshold: config.threshold,
    redactReplacement: config.redactReplacement,
  };
}

function redactEntropyFindings(text, findings, replacement = '[REDACTED_HIGH_ENTROPY]') {
  const input = String(text || '');
  if (!input || !Array.isArray(findings) || findings.length === 0) {
    return input;
  }
  const ordered = findings
    .filter((item) => Number.isInteger(item.start) && Number.isInteger(item.end) && item.end > item.start)
    .sort((a, b) => a.start - b.start);
  let out = '';
  let cursor = 0;
  for (const finding of ordered) {
    if (finding.start < cursor) {
      continue;
    }
    out += input.slice(cursor, finding.start);
    out += replacement;
    cursor = finding.end;
  }
  out += input.slice(cursor);
  return out;
}

module.exports = {
  analyzeEntropyText,
  redactEntropyFindings,
  normalizeEntropyConfig: normalizeConfig,
  shannonEntropy,
};
