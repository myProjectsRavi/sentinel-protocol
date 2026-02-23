const { isTextualContentType } = require('./response-scanner');
const {
  clampPositiveInt,
  clampProbability,
  normalizeMode,
} = require('../utils/primitives');

const CATEGORY_NAMES = [
  'toxicity',
  'code_execution',
  'hallucination',
  'unauthorized_disclosure',
];

const DEFAULT_CATEGORY_THRESHOLDS = {
  toxicity: { warn: 0.45, block: 0.8 },
  code_execution: { warn: 0.4, block: 0.75 },
  hallucination: { warn: 0.5, block: 0.85 },
  unauthorized_disclosure: { warn: 0.4, block: 0.7 },
};

const CATEGORY_PATTERNS = {
  toxicity: [
    { id: 'self_harm_directive', weight: 0.6, pattern: /\bkill\s+yourself\b/i },
    { id: 'violent_threat', weight: 0.45, pattern: /\b(i\s+will|we\s+will)\s+(attack|shoot|harm|hurt)\b/i },
    { id: 'hate_speech', weight: 0.35, pattern: /\b(hate|subhuman|exterminate)\b/i },
    { id: 'abusive_insult', weight: 0.25, pattern: /\b(idiot|moron|worthless)\b/i },
    { id: 'genocide_reference', weight: 0.75, pattern: /\bgenocide\b/i },
  ],
  code_execution: [
    { id: 'dangerous_shell', weight: 0.85, pattern: /\brm\s+-rf\b/i },
    { id: 'dangerous_eval', weight: 0.75, pattern: /\b(eval|exec)\s*\(/i },
    { id: 'python_exec', weight: 0.7, pattern: /\b(os\.system|subprocess\.popen)\b/i },
    { id: 'sql_drop', weight: 0.75, pattern: /\b(drop\s+table|delete\s+from\s+\w+)\b/i },
    { id: 'remote_shell', weight: 0.45, pattern: /\b(curl|wget)\s+https?:\/\//i },
    { id: 'permission_abuse', weight: 0.45, pattern: /\bchmod\s+777\b/i },
  ],
  hallucination: [
    {
      id: 'fabricated_api',
      weight: 0.45,
      pattern: /\b(non[- ]existent|imaginary|fabricated)\s+(api|endpoint|reference|citation)\b/i,
    },
    {
      id: 'suspicious_source_host',
      weight: 0.5,
      pattern: /https?:\/\/(?:[\w-]+\.)*(?:example|invalid|localhost|internal|local)(?:\/|\b)/i,
    },
    {
      id: 'fake_certainty',
      weight: 0.4,
      pattern: /\b(guaranteed factual|100% accurate|absolutely verified)\b/i,
    },
    {
      id: 'unknown_doi',
      weight: 0.5,
      pattern: /\bdoi\s*:\s*(unknown|n\/?a|none)\b/i,
    },
    {
      id: 'phantom_standard',
      weight: 0.45,
      pattern: /\b(rfc\s*\d{2,4}\s*\(draft\)|iso\s*99999)\b/i,
    },
  ],
  unauthorized_disclosure: [
    { id: 'system_prompt_marker', weight: 0.65, pattern: /\b(system\s+prompt|developer\s+message)\b/i },
    { id: 'internal_policy_marker', weight: 0.55, pattern: /\b(internal\s+policy|private\s+policy\s+rules?)\b/i },
    { id: 'header_leak', weight: 0.45, pattern: /\bx-sentinel-[a-z0-9_-]+\b/i },
    {
      id: 'explicit_prompt_dump',
      weight: 0.8,
      pattern: /\b(begin|start)\s+system\s+prompt\b|\b<system>.*<\/system>\b/si,
    },
    { id: 'canary_disclosure', weight: 0.65, pattern: /\b(canary\s+token|honeypot\s+token)\b/i },
    { id: 'key_material', weight: 0.5, pattern: /\b(api\s+key|private\s+key|secret\s+token)\b/i },
  ],
};

function normalizeCategoryConfig(name, raw = {}) {
  const defaults = DEFAULT_CATEGORY_THRESHOLDS[name] || { warn: 0.5, block: 0.8 };
  const warn = clampProbability(raw.warn_threshold, defaults.warn);
  const block = clampProbability(raw.block_threshold, Math.max(defaults.block, warn));
  return {
    enabled: raw.enabled !== false,
    warnThreshold: warn,
    blockThreshold: Math.max(warn, block),
  };
}

function normalizeConfig(input = {}) {
  const config = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
  const categoriesInput =
    config.categories && typeof config.categories === 'object' && !Array.isArray(config.categories)
      ? config.categories
      : {};

  const categories = {};
  for (const name of CATEGORY_NAMES) {
    categories[name] = normalizeCategoryConfig(name, categoriesInput[name]);
  }

  return {
    enabled: config.enabled === true,
    mode: normalizeMode(config.mode, 'monitor', ['monitor', 'block']),
    maxScanChars: clampPositiveInt(config.max_scan_chars, 8192, 256, 262144),
    categories,
  };
}

function scoreCategory(name, text) {
  const rules = CATEGORY_PATTERNS[name] || [];
  let score = 0;
  const matches = [];
  for (const rule of rules) {
    if (rule.pattern.test(text)) {
      score += Number(rule.weight || 0);
      matches.push(rule.id);
    }
  }
  return {
    score: Math.min(1, Number(score.toFixed(4))),
    matches,
  };
}

class OutputClassifier {
  constructor(config = {}) {
    this.config = normalizeConfig(config);
  }

  isEnabled() {
    return this.config.enabled === true;
  }

  classifyText(text, options = {}) {
    const effectiveMode = String(options.effectiveMode || 'monitor').toLowerCase();
    const enabled = this.isEnabled();
    const boundedText = String(text || '').slice(0, this.config.maxScanChars);

    if (!enabled || !boundedText) {
      return {
        enabled,
        shouldWarn: false,
        shouldBlock: false,
        blockedBy: [],
        warnedBy: [],
        categories: {},
        reasons: [],
      };
    }

    const categories = {};
    const warnedBy = [];
    const blockedBy = [];
    const reasons = [];

    for (const name of CATEGORY_NAMES) {
      const categoryConfig = this.config.categories[name];
      if (!categoryConfig.enabled) {
        categories[name] = {
          enabled: false,
          score: 0,
          warn: false,
          block: false,
          matches: [],
        };
        continue;
      }

      const scored = scoreCategory(name, boundedText);
      const warn = scored.score >= categoryConfig.warnThreshold;
      const block =
        scored.score >= categoryConfig.blockThreshold &&
        this.config.mode === 'block' &&
        effectiveMode === 'enforce';

      categories[name] = {
        enabled: true,
        score: scored.score,
        warn,
        block,
        matches: scored.matches,
      };

      if (warn) {
        warnedBy.push(name);
      }
      if (block) {
        blockedBy.push(name);
      }
      if (warn) {
        reasons.push(`output_classifier:${name}`);
      }
    }

    return {
      enabled: true,
      shouldWarn: warnedBy.length > 0,
      shouldBlock: blockedBy.length > 0,
      warnedBy,
      blockedBy,
      categories,
      reasons,
    };
  }

  classifyBuffer(input = {}) {
    const bodyBuffer = input.bodyBuffer;
    const contentType = String(input.contentType || '').toLowerCase();
    const effectiveMode = input.effectiveMode;

    if (!Buffer.isBuffer(bodyBuffer) || bodyBuffer.length === 0 || !isTextualContentType(contentType)) {
      return {
        enabled: this.isEnabled(),
        shouldWarn: false,
        shouldBlock: false,
        blockedBy: [],
        warnedBy: [],
        categories: {},
        reasons: [],
      };
    }

    return this.classifyText(bodyBuffer.toString('utf8'), {
      effectiveMode,
    });
  }
}

module.exports = {
  CATEGORY_NAMES,
  CATEGORY_PATTERNS,
  OutputClassifier,
  normalizeOutputClassifierConfig: normalizeConfig,
};
