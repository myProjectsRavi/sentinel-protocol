const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { InjectionScanner } = require('../engines/injection-scanner');

const DEFAULT_FIXTURE_PATH = path.resolve(__dirname, '../../test/fixtures/adversarial-attack-fixtures.json');
const REQUIRED_FAMILIES = new Set([
  'homoglyph',
  'token_smuggling',
  'instruction_hierarchy_bypass',
  'multi_turn_escalation',
]);
const MAX_ROBUSTNESS_CASES = 5000;
const DEFAULT_INJECTION_THRESHOLD = 0.22;
const DEFAULT_MIN_DETECTION_RATE = 0.8;
const DEFAULT_MAX_SCAN_BYTES = 131072;
const KEYWORD_SIGNAL_PATTERNS = Object.freeze([
  /\b(ignore|disregard|forget)\b/i,
  /\b(previous|prior|above)\b/i,
  /\b(instruction|prompt|policy|guardrail)\b/i,
  /\b(bypass|override|disable)\b/i,
  /\b(reveal|leak|dump|exfiltrate)\b/i,
  /\b(secret|credential|api key|token|private key)\b/i,
]);
const REQUIRED_DIVERSITY_SIGNALS = Object.freeze([
  'base64_payload',
  'markdown_js_link',
  'multilingual_script',
  'recursive_reference',
  'fake_assistant_turn',
]);
const FAMILY_EXPECTED_SIGNALS = Object.freeze({
  homoglyph: Object.freeze(['homoglyph_script_mix', 'zero_width_chars', 'bidi_control']),
  token_smuggling: Object.freeze(['token_boundary_split', 'base64_payload', 'markdown_js_link']),
  instruction_hierarchy_bypass: Object.freeze(['role_swap_payload', 'fake_assistant_turn', 'tool_call_forgery']),
  multi_turn_escalation: Object.freeze(['multi_turn_structure', 'recursive_reference', 'yaml_or_json_swap']),
});

const HOMOGLYPH_NORMALIZATION_MAP = {
  а: 'a',
  е: 'e',
  і: 'i',
  о: 'o',
  с: 'c',
  р: 'p',
  у: 'y',
  А: 'a',
  Е: 'e',
  О: 'o',
  С: 'c',
  Р: 'p',
  У: 'y',
};

function clampNumber(value, min, max, fallback) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return fallback;
  }
  if (numeric < min) {
    return min;
  }
  if (numeric > max) {
    return max;
  }
  return numeric;
}

function normalizeBoolean(value, fallback = false) {
  if (value === true) {
    return true;
  }
  if (value === false) {
    return false;
  }
  return fallback;
}

function normalizeInteger(value, fallback, min, max) {
  const numeric = Number(value);
  if (!Number.isInteger(numeric)) {
    return fallback;
  }
  if (numeric < min || numeric > max) {
    return fallback;
  }
  return numeric;
}

function stableCaseId(prompt, vector, fallbackIndex = 0) {
  const payload = `${String(vector || 'adversarial')}::${String(prompt || '')}`;
  const digest = crypto.createHash('sha256').update(payload, 'utf8').digest('hex').slice(0, 16);
  return `adv-${String(fallbackIndex + 1).padStart(4, '0')}-${digest}`;
}

function canonicalizeAttackIntent(input) {
  const text = String(input || '')
    .normalize('NFKC')
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .split('')
    .map((char) => HOMOGLYPH_NORMALIZATION_MAP[char] || char)
    .join('')
    .toLowerCase();
  return text.replace(/\s+/g, ' ').trim();
}

function detectTokenBoundarySmuggling(input) {
  const raw = String(input || '');
  if (!raw) {
    return false;
  }
  const compact = canonicalizeAttackIntent(raw).replace(/[^a-z0-9]/g, '');
  const suspicious = [
    'ignorepreviousinstructions',
    'bypassguardrails',
    'revealsystemprompt',
    'returnallsecrets',
    'exfiltratecredentials',
  ];
  const hasKeyword = suspicious.some((keyword) => compact.includes(keyword));
  if (!hasKeyword) {
    return false;
  }
  return /(\w\s+){8,}\w/.test(raw) || /[\u200B-\u200D\uFEFF]/.test(raw);
}

function detectDiversitySignals(input) {
  const raw = String(input || '');
  if (!raw) {
    return {
      base64_payload: false,
      markdown_js_link: false,
      html_comment: false,
      multilingual_script: false,
      recursive_reference: false,
      fake_assistant_turn: false,
      role_swap_payload: false,
      yaml_or_json_swap: false,
      zero_width_chars: false,
      bidi_control: false,
      token_boundary_split: false,
      tool_call_forgery: false,
      homoglyph_script_mix: false,
      multi_turn_structure: false,
    };
  }
  return {
    base64_payload: /\b(?:[A-Za-z0-9+/]{20,}={0,2})\b/.test(raw),
    markdown_js_link: /\[[^\]]+\]\(\s*javascript:/i.test(raw),
    html_comment: /<!--[\s\S]{0,800}?-->/.test(raw),
    multilingual_script: /[\u0600-\u06FF\u0900-\u097F\u4E00-\u9FFF]/.test(raw),
    recursive_reference: /\b(repeat|restate|echo)\b[\s\S]{0,64}\b(previous|last)\b[\s\S]{0,64}\b(token|message|response)s?\b/i.test(raw),
    fake_assistant_turn: /\buser\s*:/i.test(raw) && /\bassistant\s*:/i.test(raw),
    role_swap_payload: /("role"\s*:\s*"system"|role:\s*system|\[system\]|<system>)/i.test(raw),
    yaml_or_json_swap: /(\n\s*role:\s*system\b|\{[\s\S]{0,200}"role"\s*:\s*"system")/i.test(raw),
    zero_width_chars: /[\u200B-\u200D\uFEFF]/.test(raw),
    bidi_control: /[\u202A-\u202E\u2066-\u2069]/.test(raw),
    token_boundary_split: /(\b\w\b[\s._-]*){8,}/.test(raw),
    tool_call_forgery: /\b(tool_call|function_call|execute_shell|x-mcp-tool|tool schema)\b/i.test(raw),
    homoglyph_script_mix: /[А-Яа-я]/.test(raw),
    multi_turn_structure: /\b(step\s*\d+|turn\s*\d+)\b/i.test(raw),
  };
}

function countKeywordSignals(input) {
  const text = String(input || '');
  if (!text) {
    return 0;
  }
  let hits = 0;
  for (const pattern of KEYWORD_SIGNAL_PATTERNS) {
    if (pattern.test(text)) {
      hits += 1;
    }
  }
  return hits;
}

function toSortedObject(counts) {
  return Object.fromEntries(
    Object.entries(counts || {}).sort((left, right) => String(left[0]).localeCompare(String(right[0])))
  );
}

function normalizeFixtureEntry(entry, index) {
  if (!entry || typeof entry !== 'object') {
    return null;
  }
  const prompt = String(entry.prompt || '').trim();
  if (!prompt) {
    return null;
  }
  const vector = String(entry.vector || 'adversarial').trim().toLowerCase() || 'adversarial';
  const family = String(entry.family || vector || 'unknown').trim().toLowerCase() || 'unknown';
  const id = String(entry.id || '').trim() || stableCaseId(prompt, vector, index);
  return {
    id,
    prompt,
    vector,
    family,
    canonical_intent: canonicalizeAttackIntent(prompt),
    token_smuggling_detected: detectTokenBoundarySmuggling(prompt),
  };
}

function loadAdversarialFixturePack(options = {}) {
  const fixturePath = options.fixturePath
    ? path.resolve(String(options.fixturePath))
    : DEFAULT_FIXTURE_PATH;
  if (!fs.existsSync(fixturePath)) {
    return [];
  }
  const text = fs.readFileSync(fixturePath, 'utf8');
  const parsed = JSON.parse(text);
  if (!Array.isArray(parsed)) {
    return [];
  }
  return parsed
    .map((item, index) => normalizeFixtureEntry(item, index))
    .filter(Boolean)
    .sort((a, b) => String(a.id).localeCompare(String(b.id)));
}

function requiredFamilySummary(cases = []) {
  const familyCounts = {};
  for (const item of cases) {
    const family = String(item?.family || 'unknown').toLowerCase();
    familyCounts[family] = (familyCounts[family] || 0) + 1;
  }
  const missing = Array.from(REQUIRED_FAMILIES).filter((family) => !familyCounts[family]);
  return {
    counts: familyCounts,
    missing,
    ok: missing.length === 0,
  };
}

function evaluateAdversarialCase(entry, options = {}) {
  const normalizedEntry = normalizeFixtureEntry(entry, Number(options.index || 0));
  if (!normalizedEntry) {
    return null;
  }

  const scanner = options.scanner || new InjectionScanner({
    maxScanBytes: normalizeInteger(options.maxScanBytes, DEFAULT_MAX_SCAN_BYTES, 1024, 2 * 1024 * 1024),
  });
  const injectionThreshold = clampNumber(
    options.injectionThreshold,
    0.05,
    1,
    DEFAULT_INJECTION_THRESHOLD
  );
  const keywordThreshold = normalizeInteger(options.keywordThreshold, 2, 1, 32);
  const allowExpectedSignalPass = normalizeBoolean(options.allowExpectedSignalPass, true);

  const injection = scanner.scan(normalizedEntry.prompt, {
    maxScanBytes: normalizeInteger(options.maxScanBytes, DEFAULT_MAX_SCAN_BYTES, 1024, 2 * 1024 * 1024),
  });
  const diversitySignals = detectDiversitySignals(normalizedEntry.prompt);
  const keywordSignals = countKeywordSignals(normalizedEntry.canonical_intent);
  const expectedSignals = FAMILY_EXPECTED_SIGNALS[normalizedEntry.family] || [];
  const expectedSignalHits = expectedSignals.filter((name) => diversitySignals[name] === true);

  const matchedSignals = Array.isArray(injection.matchedSignals)
    ? injection.matchedSignals.map((item) => String(item.id || '')).filter(Boolean)
    : [];
  const detectedBy = [];
  if (Number(injection.score || 0) >= injectionThreshold) {
    detectedBy.push('injection_score');
  }
  if (matchedSignals.length > 0) {
    detectedBy.push('injection_signals');
  }
  if (normalizedEntry.token_smuggling_detected) {
    detectedBy.push('token_smuggling');
  }
  if (keywordSignals >= keywordThreshold) {
    detectedBy.push('keyword_signals');
  }
  if (allowExpectedSignalPass && expectedSignalHits.length > 0) {
    detectedBy.push('expected_family_signal');
  }

  const detected = detectedBy.length > 0;
  return {
    id: normalizedEntry.id,
    family: normalizedEntry.family,
    vector: normalizedEntry.vector,
    detected,
    pass: detected,
    score: Number(Number(injection.score || 0).toFixed(4)),
    matched_signals: matchedSignals,
    token_smuggling_detected: normalizedEntry.token_smuggling_detected,
    keyword_signal_count: keywordSignals,
    expected_signal_hits: expectedSignalHits.sort((a, b) => a.localeCompare(b)),
    diversity_signals: diversitySignals,
    detected_by: detectedBy,
  };
}

function runAdversarialRobustnessSuite(cases = loadAdversarialFixturePack(), options = {}) {
  const normalizedCases = (Array.isArray(cases) ? cases : [])
    .map((item, index) => normalizeFixtureEntry(item, index))
    .filter(Boolean)
    .sort((a, b) => String(a.id).localeCompare(String(b.id)));
  const maxCases = normalizeInteger(
    options.maxCases,
    normalizedCases.length,
    1,
    MAX_ROBUSTNESS_CASES
  );
  const selected = normalizedCases.slice(0, maxCases);
  const scanner = options.scanner || new InjectionScanner({
    maxScanBytes: normalizeInteger(options.maxScanBytes, DEFAULT_MAX_SCAN_BYTES, 1024, 2 * 1024 * 1024),
  });
  const minDetectionRate = clampNumber(
    options.minDetectionRate,
    0,
    1,
    DEFAULT_MIN_DETECTION_RATE
  );

  const familyCoverage = {};
  const vectorCoverage = {};
  const diversitySignalCoverage = {};
  const canonicalIntents = new Set();
  let detectedCases = 0;

  const results = selected
    .map((item, index) =>
      evaluateAdversarialCase(item, {
        index,
        scanner,
        maxScanBytes: options.maxScanBytes,
        injectionThreshold: options.injectionThreshold,
        keywordThreshold: options.keywordThreshold,
        allowExpectedSignalPass: options.allowExpectedSignalPass,
      })
    )
    .filter(Boolean)
    .map((result, idx) => {
      const source = selected[idx];
      canonicalIntents.add(source.canonical_intent);
      familyCoverage[source.family] = familyCoverage[source.family] || { total: 0, detected: 0 };
      familyCoverage[source.family].total += 1;
      if (result.detected) {
        familyCoverage[source.family].detected += 1;
        detectedCases += 1;
      }
      vectorCoverage[source.vector] = (vectorCoverage[source.vector] || 0) + 1;
      for (const [signalName, signalDetected] of Object.entries(result.diversity_signals || {})) {
        if (signalDetected === true) {
          diversitySignalCoverage[signalName] = (diversitySignalCoverage[signalName] || 0) + 1;
        }
      }
      return result;
    });

  const totalCases = results.length;
  const detectionRate = totalCases > 0 ? detectedCases / totalCases : 0;
  const families = Object.fromEntries(
    Object.entries(familyCoverage)
      .sort((left, right) => String(left[0]).localeCompare(String(right[0])))
      .map(([family, stats]) => {
        const total = Number(stats.total || 0);
        const detected = Number(stats.detected || 0);
        const missed = Math.max(0, total - detected);
        const detectionRatePercent = total > 0 ? Number(((detected / total) * 100).toFixed(2)) : 0;
        return [
          family,
          {
            total,
            detected,
            missed,
            detection_rate_percent: detectionRatePercent,
          },
        ];
      })
  );
  const requiredFamily = requiredFamilySummary(selected);
  const missingSignals = REQUIRED_DIVERSITY_SIGNALS.filter((name) => Number(diversitySignalCoverage[name] || 0) === 0);

  return {
    total_cases: totalCases,
    detected_cases: detectedCases,
    missed_cases: Math.max(0, totalCases - detectedCases),
    detection_rate_percent: Number((detectionRate * 100).toFixed(2)),
    min_detection_rate_percent: Number((minDetectionRate * 100).toFixed(2)),
    status:
      totalCases > 0 &&
      detectionRate >= minDetectionRate &&
      requiredFamily.ok &&
      missingSignals.length === 0
        ? 'pass'
        : 'fail',
    family_coverage: families,
    required_families: requiredFamily,
    vector_coverage: toSortedObject(vectorCoverage),
    diversity_signals: toSortedObject(diversitySignalCoverage),
    required_diversity: {
      required: [...REQUIRED_DIVERSITY_SIGNALS],
      missing: missingSignals,
      ok: missingSignals.length === 0,
    },
    unique_canonical_intents: canonicalIntents.size,
    cases: results,
  };
}

module.exports = {
  REQUIRED_FAMILIES,
  DEFAULT_FIXTURE_PATH,
  canonicalizeAttackIntent,
  detectTokenBoundarySmuggling,
  detectDiversitySignals,
  evaluateAdversarialCase,
  loadAdversarialFixturePack,
  requiredFamilySummary,
  runAdversarialRobustnessSuite,
};
