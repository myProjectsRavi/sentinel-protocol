const {
  clampPositiveInt,
  clampProbability,
  normalizeMode,
} = require('../utils/primitives');
const { isTextualContentType } = require('./response-scanner');

const STEP_INJECTION_PATTERNS = [
  /\b(ignore\s+previous\s+instructions?)\b/i,
  /\b(bypass\s+policy|disable\s+guardrails?)\b/i,
  /\b(reveal\s+secrets?|dump\s+credentials?)\b/i,
  /\b(system\s+override|developer\s+message)\b/i,
];

function tokenize(text = '') {
  return String(text || '')
    .toLowerCase()
    .replace(/[^a-z0-9\s]+/g, ' ')
    .split(/\s+/)
    .filter(Boolean);
}

function jaccard(leftText, rightText) {
  const left = new Set(tokenize(leftText));
  const right = new Set(tokenize(rightText));
  if (left.size === 0 && right.size === 0) {
    return 1;
  }
  let intersection = 0;
  for (const token of left) {
    if (right.has(token)) {
      intersection += 1;
    }
  }
  const union = left.size + right.size - intersection;
  if (union <= 0) {
    return 0;
  }
  return intersection / union;
}

function stableStepHash(previousHash, stepText) {
  const crypto = require('crypto');
  const hasher = crypto.createHash('sha256');
  hasher.update(String(previousHash || ''), 'utf8');
  hasher.update('|', 'utf8');
  hasher.update(String(stepText || ''), 'utf8');
  return hasher.digest('hex');
}

class ReasoningTraceMonitor {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.maxScanChars = clampPositiveInt(config.max_scan_chars, 16384, 256, 1048576);
    this.maxSteps = clampPositiveInt(config.max_steps, 64, 2, 1024);
    this.minStepChars = clampPositiveInt(config.min_step_chars, 12, 4, 512);
    this.coherenceThreshold = clampProbability(config.coherence_threshold, 0.1);
    this.blockOnInjection = config.block_on_injection === true;
    this.blockOnIncoherence = config.block_on_incoherence === true;
    this.blockOnConclusionMismatch = config.block_on_conclusion_mismatch === true;
    this.observability = config.observability !== false;
  }

  isEnabled() {
    return this.enabled === true;
  }

  extractSteps(text) {
    const bounded = String(text || '').slice(0, this.maxScanChars);
    const steps = [];

    const thinkBlocks = [];
    const blockRegex = /<(think|reasoning)[^>]*>([\s\S]*?)<\/\1>/gi;
    let blockMatch;
    while ((blockMatch = blockRegex.exec(bounded)) !== null) {
      thinkBlocks.push(String(blockMatch[2] || ''));
      if (thinkBlocks.length >= this.maxSteps) {
        break;
      }
      if (String(blockMatch[0] || '').length === 0) {
        blockRegex.lastIndex += 1;
      }
    }

    const source = thinkBlocks.length > 0 ? thinkBlocks.join('\n') : bounded;
    const numbered = source
      .split(/\r?\n/)
      .map((line) => String(line || '').trim())
      .filter(Boolean)
      .filter((line) => /^\d+[\).:\-\s]/.test(line));

    if (numbered.length > 0) {
      for (const line of numbered.slice(0, this.maxSteps)) {
        const normalized = line.replace(/^\d+[\).:\-\s]+/, '').trim();
        if (normalized.length >= this.minStepChars) {
          steps.push(normalized);
        }
      }
      return steps;
    }

    const paragraphs = source
      .split(/(?:\r?\n){2,}|(?<=[.!?])\s+(?=[A-Z0-9])/)
      .map((line) => String(line || '').trim())
      .filter(Boolean);
    for (const paragraph of paragraphs.slice(0, this.maxSteps)) {
      if (paragraph.length >= this.minStepChars) {
        steps.push(paragraph);
      }
    }
    return steps;
  }

  analyzeText(text, { effectiveMode = 'monitor' } = {}) {
    const enabled = this.isEnabled();
    if (!enabled) {
      return {
        enabled: false,
        detected: false,
        shouldBlock: false,
        reason: 'clean',
        findings: [],
      };
    }

    const steps = this.extractSteps(text);
    if (steps.length < 2) {
      return {
        enabled: true,
        mode: this.mode,
        detected: false,
        shouldBlock: false,
        reason: 'clean',
        findings: [],
        steps,
      };
    }

    const findings = [];
    let chainHash = '';

    for (let index = 0; index < steps.length; index += 1) {
      const step = steps[index];
      chainHash = stableStepHash(chainHash, step);
      for (const pattern of STEP_INJECTION_PATTERNS) {
        if (!pattern.test(step)) {
          continue;
        }
        findings.push({
          code: 'reasoning_trace_injection_signal',
          step_index: index,
          blockEligible: this.blockOnInjection,
        });
        break;
      }
      if (findings.length >= this.maxSteps) {
        break;
      }
    }

    for (let index = 1; index < steps.length; index += 1) {
      const score = jaccard(steps[index - 1], steps[index]);
      if (score < this.coherenceThreshold) {
        findings.push({
          code: 'reasoning_trace_incoherent_shift',
          step_index: index,
          coherence: Number(score.toFixed(4)),
          blockEligible: this.blockOnIncoherence,
        });
      }
      if (findings.length >= this.maxSteps) {
        break;
      }
    }

    const joined = steps.join(' ').toLowerCase();
    const last = steps[steps.length - 1].toLowerCase();
    if (
      /\b(approve|allow|proceed|execute|grant)\b/.test(last) &&
      /\b(reject|deny|block|unsafe|high risk)\b/.test(joined)
    ) {
      findings.push({
        code: 'reasoning_trace_conclusion_mismatch',
        blockEligible: this.blockOnConclusionMismatch,
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
      reason: detected ? String(findings[0].code || 'reasoning_trace_violation') : 'clean',
      findings,
      steps,
      chain_hash_prefix: chainHash.slice(0, 16),
    };
  }

  analyzeBuffer({ bodyBuffer, contentType, effectiveMode = 'monitor' } = {}) {
    if (!Buffer.isBuffer(bodyBuffer) || bodyBuffer.length === 0 || !isTextualContentType(contentType)) {
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
  ReasoningTraceMonitor,
};
