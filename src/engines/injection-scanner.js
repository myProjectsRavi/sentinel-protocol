const HIGH_RISK_PATTERNS = [
  {
    id: 'ignore_previous_instructions',
    weight: 0.55,
    regex: /\b(ignore|disregard|forget)\b[\s\S]{0,80}\b(previous|prior|above)\b[\s\S]{0,50}\b(instruction|prompt|rule)s?\b/gi,
  },
  {
    id: 'system_override',
    weight: 0.5,
    regex: /\b(system|policy|guardrail)\b[\s\S]{0,30}\b(override|bypass|disable|ignore)\b/gi,
  },
  {
    id: 'dan_jailbreak',
    weight: 0.65,
    regex: /\b(you are now dan|do anything now|jailbreak mode|developer mode)\b/gi,
  },
  {
    id: 'safety_bypass',
    weight: 0.45,
    regex: /\b(do not follow|ignore|bypass)\b[\s\S]{0,40}\b(safety|security|policy|guardrail)s?\b/gi,
  },
  {
    id: 'secret_exfiltration',
    weight: 0.45,
    regex: /\b(exfiltrate|leak|steal|dump)\b[\s\S]{0,40}\b(secret|credential|api\s*key|token|password|private\s*key)s?\b/gi,
  },
];

const MEDIUM_RISK_PATTERNS = [
  {
    id: 'system_delimiter',
    weight: 0.2,
    regex: /(<<\s*sys\s*>>|<\s*system\s*>|\[system\]|\{\{system\}\})/gi,
  },
  {
    id: 'prompt_boundary_markers',
    weight: 0.18,
    regex: /\b(begin|end)\s+(system|prompt|instruction)s?\b/gi,
  },
  {
    id: 'delimiter_override',
    weight: 0.15,
    regex: /(^|\n)\s*(###|---|===)\s*(system|instructions?|override)\b/gi,
  },
  {
    id: 'fenced_system_prompt',
    weight: 0.15,
    regex: /```(?:\s*(system|prompt|policy|instructions?))?/gi,
  },
];

function countMatches(regex, text) {
  regex.lastIndex = 0;
  let count = 0;
  while (regex.exec(text) !== null) {
    count += 1;
    if (count >= 5) {
      break;
    }
  }
  return count;
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

class InjectionScanner {
  constructor(options = {}) {
    this.maxScanBytes = Number(options.maxScanBytes ?? 131072);
    this.highRiskPatterns = HIGH_RISK_PATTERNS.map((entry) => ({
      ...entry,
      regex: new RegExp(entry.regex.source, 'gi'),
    }));
    this.mediumRiskPatterns = MEDIUM_RISK_PATTERNS.map((entry) => ({
      ...entry,
      regex: new RegExp(entry.regex.source, 'gi'),
    }));
  }

  scan(input, options = {}) {
    if (typeof input !== 'string' || input.length === 0) {
      return {
        score: 0,
        matchedSignals: [],
        scanTruncated: false,
      };
    }

    const maxBytes = Number(options.maxScanBytes ?? this.maxScanBytes);
    const inputBytes = Buffer.byteLength(input, 'utf8');
    const scanTruncated = inputBytes > maxBytes;
    const text = scanTruncated ? Buffer.from(input).subarray(0, maxBytes).toString('utf8') : input;

    const matchedSignals = [];
    let score = 0;

    for (const pattern of this.highRiskPatterns) {
      const count = countMatches(pattern.regex, text);
      if (count > 0) {
        const contribution = clamp(pattern.weight + (count - 1) * 0.05, pattern.weight, pattern.weight + 0.2);
        score += contribution;
        matchedSignals.push({
          id: pattern.id,
          category: 'high',
          count,
          contribution,
        });
      }
    }

    for (const pattern of this.mediumRiskPatterns) {
      const count = countMatches(pattern.regex, text);
      if (count > 0) {
        const contribution = clamp(pattern.weight + (count - 1) * 0.03, pattern.weight, pattern.weight + 0.12);
        score += contribution;
        matchedSignals.push({
          id: pattern.id,
          category: 'medium',
          count,
          contribution,
        });
      }
    }

    return {
      score: clamp(Number(score.toFixed(3)), 0, 1),
      matchedSignals,
      scanTruncated,
    };
  }
}

module.exports = {
  InjectionScanner,
};
