const {
  clampPositiveInt,
  clampProbability,
  normalizeMode,
} = require('../utils/primitives');
const { isTextualContentType } = require('./response-scanner');

const ZERO_WIDTH_RE = /[\u200B-\u200F\uFEFF]/g;
const INVISIBLE_RE = /[\u0300-\u036F\uFE00-\uFE0F\u{E0001}\u{E0020}-\u{E007F}]/gu;
const WHITESPACE_SEGMENT_RE = /[ \t]{24,}/g;
const EMOJI_ZWJ_RE = /(?:\p{Emoji}(?:\u200D\p{Emoji}){2,})/gu;

function shannonEntropy(input = '') {
  const text = String(input || '');
  if (!text) {
    return 0;
  }
  const counts = new Map();
  for (const ch of text) {
    counts.set(ch, (counts.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const value of counts.values()) {
    const p = value / text.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function countMatches(regex, text, maxMatches) {
  regex.lastIndex = 0;
  const matches = [];
  let match;
  while ((match = regex.exec(text)) !== null) {
    matches.push(match);
    if (matches.length >= maxMatches) {
      break;
    }
    if (match[0] === '') {
      regex.lastIndex += 1;
    }
  }
  return matches;
}

class StegoExfilDetector {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.maxScanChars = clampPositiveInt(config.max_scan_chars, 16384, 128, 1048576);
    this.maxFindings = clampPositiveInt(config.max_findings, 16, 1, 256);
    this.zeroWidthDensityThreshold = clampProbability(config.zero_width_density_threshold, 0.02);
    this.invisibleDensityThreshold = clampProbability(config.invisible_density_threshold, 0.03);
    this.whitespaceBitsThreshold = clampPositiveInt(config.whitespace_bits_threshold, 128, 8, 1048576);
    this.segmentEntropyThreshold = Number.isFinite(Number(config.segment_entropy_threshold))
      ? Number(config.segment_entropy_threshold)
      : 3.2;
    this.emojiCompoundThreshold = clampPositiveInt(config.emoji_compound_threshold, 3, 1, 1024);
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
        reason: 'clean',
        findings: [],
      };
    }

    const findings = [];
    const textLength = bounded.length;

    const zeroWidthMatches = countMatches(ZERO_WIDTH_RE, bounded, this.maxFindings);
    const zeroWidthDensity = textLength > 0 ? zeroWidthMatches.length / textLength : 0;
    if (zeroWidthDensity >= this.zeroWidthDensityThreshold) {
      findings.push({
        code: 'stego_zero_width_density',
        density: Number(zeroWidthDensity.toFixed(6)),
        count: zeroWidthMatches.length,
        blockEligible: this.blockOnDetect,
      });
    }

    const invisibleMatches = countMatches(INVISIBLE_RE, bounded, this.maxFindings);
    const invisibleDensity = textLength > 0 ? invisibleMatches.length / textLength : 0;
    if (invisibleDensity >= this.invisibleDensityThreshold) {
      findings.push({
        code: 'stego_invisible_unicode_density',
        density: Number(invisibleDensity.toFixed(6)),
        count: invisibleMatches.length,
        blockEligible: this.blockOnDetect,
      });
    }

    const whitespaceSegments = countMatches(WHITESPACE_SEGMENT_RE, bounded, this.maxFindings);
    let whitespaceBits = 0;
    for (const segmentMatch of whitespaceSegments) {
      const segment = String(segmentMatch[0] || '');
      const spaces = (segment.match(/ /g) || []).length;
      const tabs = (segment.match(/\t/g) || []).length;
      if (spaces > 0 && tabs > 0) {
        whitespaceBits += segment.length;
      }
    }
    if (whitespaceBits >= this.whitespaceBitsThreshold) {
      findings.push({
        code: 'stego_whitespace_binary_pattern',
        bits: whitespaceBits,
        segments: whitespaceSegments.length,
        blockEligible: this.blockOnDetect,
      });
    }

    for (const segmentMatch of whitespaceSegments) {
      if (findings.length >= this.maxFindings) {
        break;
      }
      const segment = String(segmentMatch[0] || '');
      const entropy = shannonEntropy(segment);
      if (entropy >= this.segmentEntropyThreshold) {
        findings.push({
          code: 'stego_blank_segment_entropy',
          entropy: Number(entropy.toFixed(4)),
          length: segment.length,
          blockEligible: this.blockOnDetect,
        });
      }
    }

    const emojiMatches = countMatches(EMOJI_ZWJ_RE, bounded, this.maxFindings);
    if (emojiMatches.length >= this.emojiCompoundThreshold) {
      findings.push({
        code: 'stego_emoji_compound_sequence',
        count: emojiMatches.length,
        blockEligible: this.blockOnDetect,
      });
    }

    const detected = findings.length > 0;
    const shouldBlock =
      detected &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce' &&
      findings.some((item) => item.blockEligible === true);

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      reason: detected ? String(findings[0].code || 'stego_exfil_detected') : 'clean',
      findings: findings.slice(0, this.maxFindings),
      stats: {
        zero_width_density: Number(zeroWidthDensity.toFixed(6)),
        invisible_density: Number(invisibleDensity.toFixed(6)),
        whitespace_bits: whitespaceBits,
        emoji_compounds: emojiMatches.length,
      },
    };
  }

  analyzeBuffer({
    bodyBuffer,
    contentType,
    effectiveMode = 'monitor',
  } = {}) {
    if (!Buffer.isBuffer(bodyBuffer) || bodyBuffer.length === 0) {
      return {
        enabled: this.isEnabled(),
        detected: false,
        shouldBlock: false,
        reason: 'clean',
        findings: [],
      };
    }
    if (!isTextualContentType(contentType)) {
      return {
        enabled: this.isEnabled(),
        detected: false,
        shouldBlock: false,
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
  StegoExfilDetector,
};
