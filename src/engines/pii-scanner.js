const { PATTERN_DEFINITIONS } = require('./pii-patterns');

const SEVERITY_RANK = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function entropy(value) {
  const map = new Map();
  for (const char of value) {
    map.set(char, (map.get(char) || 0) + 1);
  }

  let result = 0;
  const len = value.length;
  for (const count of map.values()) {
    const p = count / len;
    result -= p * Math.log2(p);
  }

  return result;
}

function luhnValid(value) {
  const digits = value.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) {
    return false;
  }

  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let n = Number.parseInt(digits[i], 10);
    if (double) {
      n *= 2;
      if (n > 9) {
        n -= 9;
      }
    }
    sum += n;
    double = !double;
  }

  return sum % 10 === 0;
}

function sinValid(value) {
  const digits = value.replace(/\D/g, '');
  if (digits.length !== 9) {
    return false;
  }
  return luhnValid(digits);
}

function npiValid(value) {
  const digits = value.replace(/\D/g, '');
  if (digits.length !== 10) {
    return false;
  }

  const prefixed = `80840${digits.slice(0, 9)}`;
  const check = Number.parseInt(digits[9], 10);
  return luhnValid(`${prefixed}${check}`);
}

function nhsValid(value) {
  const digits = value.replace(/\D/g, '');
  if (digits.length !== 10) {
    return false;
  }

  const base = digits.slice(0, 9).split('').map(Number);
  const check = Number(digits[9]);
  const sum = base.reduce((acc, digit, idx) => acc + digit * (10 - idx), 0);
  const remainder = 11 - (sum % 11);
  const expected = remainder === 11 ? 0 : remainder;
  if (remainder === 10) {
    return false;
  }
  return check === expected;
}

function validatorValid(validator, value) {
  if (!validator) {
    return true;
  }

  if (validator === 'luhn') {
    return luhnValid(value);
  }
  if (validator === 'sin') {
    return sinValid(value);
  }
  if (validator === 'npi') {
    return npiValid(value);
  }
  if (validator === 'nhs') {
    return nhsValid(value);
  }
  if (validator === 'highEntropy') {
    return entropy(value) >= 4.2;
  }
  return true;
}

function toRegex(value) {
  if (value instanceof RegExp) {
    return value;
  }
  return new RegExp(value, 'g');
}

class PIIScanner {
  constructor(options = {}) {
    this.maxScanBytes = options.maxScanBytes ?? 262144;
    this.patterns = PATTERN_DEFINITIONS.map((item) => ({
      ...item,
      regex: toRegex(item.regex),
      replacement: `[REDACTED_${item.id.toUpperCase()}]`,
    }));
  }

  scan(input, options = {}) {
    if (typeof input !== 'string') {
      return {
        findings: [],
        redactedText: input,
        highestSeverity: null,
        scanTruncated: false,
      };
    }

    const maxBytes = options.maxScanBytes ?? this.maxScanBytes;
    const inputBytes = Buffer.byteLength(input, 'utf8');
    const scanTruncated = inputBytes > maxBytes;
    const text = scanTruncated ? Buffer.from(input).subarray(0, maxBytes).toString('utf8') : input;
    const lowered = text.toLowerCase();

    let redactedText = text;
    const findings = [];

    for (const pattern of this.patterns) {
      if (Array.isArray(pattern.keywords) && pattern.keywords.length > 0) {
        const matchesKeyword = pattern.keywords.some((keyword) => lowered.includes(keyword.toLowerCase()));
        if (!matchesKeyword) {
          continue;
        }
      }

      pattern.regex.lastIndex = 0;
      let match;
      while ((match = pattern.regex.exec(text)) !== null) {
        const rawValue = match[0];
        if (!validatorValid(pattern.validator, rawValue)) {
          continue;
        }

        findings.push({
          id: pattern.id,
          severity: pattern.severity,
          value: rawValue,
        });

        redactedText = redactedText.replace(rawValue, pattern.replacement);
      }
    }

    const highestSeverity = findings.reduce((current, finding) => {
      if (!current) {
        return finding.severity;
      }
      return SEVERITY_RANK[finding.severity] > SEVERITY_RANK[current] ? finding.severity : current;
    }, null);

    return {
      findings,
      redactedText,
      highestSeverity,
      scanTruncated,
    };
  }
}

module.exports = {
  PIIScanner,
  SEVERITY_RANK,
};
