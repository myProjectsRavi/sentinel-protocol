const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DEFAULT_FIXTURE_PATH = path.resolve(__dirname, '../../test/fixtures/adversarial-attack-fixtures.json');
const REQUIRED_FAMILIES = new Set([
  'homoglyph',
  'token_smuggling',
  'instruction_hierarchy_bypass',
  'multi_turn_escalation',
]);

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

module.exports = {
  REQUIRED_FAMILIES,
  DEFAULT_FIXTURE_PATH,
  canonicalizeAttackIntent,
  detectTokenBoundarySmuggling,
  loadAdversarialFixturePack,
  requiredFamilySummary,
};
