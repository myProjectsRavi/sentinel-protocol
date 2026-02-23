const crypto = require('crypto');
const {
  clampPositiveInt,
} = require('../utils/primitives');

function sha256(input = '') {
  return crypto.createHash('sha256').update(String(input || ''), 'utf8').digest('hex');
}

function redactSensitive(input = '') {
  return String(input || '')
    .replace(/\b(sk-[A-Za-z0-9_-]{8,})\b/g, '[REDACTED_API_KEY]')
    .replace(/\b([A-Fa-f0-9]{32,})\b/g, '[REDACTED_HEX]')
    .replace(/\b(\d{12,19})\b/g, '[REDACTED_NUMERIC]')
    .replace(/\bx-sentinel-[a-z0-9_-]+\b/gi, 'x-sentinel-[REDACTED]');
}

function classifyFamily(text = '') {
  const lower = String(text || '').toLowerCase();
  if (/[а-яё]/i.test(lower) || /[\u4e00-\u9fff]/.test(lower)) {
    return 'cross_script';
  }
  if (/base64|[A-Za-z0-9+/]{16,}={0,2}/.test(lower)) {
    return 'encoded_payload';
  }
  if (/ignore previous|override|bypass/.test(lower)) {
    return 'instruction_override';
  }
  if (/system prompt|developer message|internal policy/.test(lower)) {
    return 'prompt_exfiltration';
  }
  return 'generic';
}

class AttackCorpusEvolver {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.maxCandidates = clampPositiveInt(config.max_candidates, 10000, 32, 1_000_000);
    this.maxPromptChars = clampPositiveInt(config.max_prompt_chars, 2048, 64, 32768);
    this.maxFamilies = clampPositiveInt(config.max_families, 256, 4, 4096);
    this.includeMonitorDecisions = config.include_monitor_decisions === true;
    this.observability = config.observability !== false;
    this.candidates = new Map();
  }

  isEnabled() {
    return this.enabled === true;
  }

  ingestAuditEvent(event = {}) {
    if (!this.isEnabled()) {
      return null;
    }
    const decision = String(event.decision || '');
    if (!decision.startsWith('blocked') && !this.includeMonitorDecisions) {
      return null;
    }
    const promptRaw = String(event.prompt || event.request_body || event.body || event.reasons?.join(' ') || '');
    if (!promptRaw.trim()) {
      return null;
    }
    const sanitized = redactSensitive(promptRaw).slice(0, this.maxPromptChars);
    const canonical = sanitized.toLowerCase().replace(/\s+/g, ' ').trim();
    const fingerprint = sha256(canonical);
    if (this.candidates.has(fingerprint)) {
      const existing = this.candidates.get(fingerprint);
      existing.count += 1;
      existing.last_seen = new Date().toISOString();
      this.candidates.set(fingerprint, existing);
      return existing;
    }
    const family = classifyFamily(canonical);
    const candidate = {
      id: `evolved_${fingerprint.slice(0, 12)}`,
      family,
      fingerprint,
      prompt: sanitized,
      count: 1,
      created_at: new Date().toISOString(),
      last_seen: new Date().toISOString(),
    };
    this.candidates.set(fingerprint, candidate);
    while (this.candidates.size > this.maxCandidates) {
      const first = this.candidates.keys().next().value;
      if (!first) {
        break;
      }
      this.candidates.delete(first);
    }
    return candidate;
  }

  exportFixturePack() {
    const entries = Array.from(this.candidates.values())
      .sort((a, b) => String(a.id).localeCompare(String(b.id)));
    const families = {};
    for (const entry of entries) {
      families[entry.family] = (families[entry.family] || 0) + 1;
    }
    const familyEntries = Object.entries(families)
      .sort((a, b) => b[1] - a[1])
      .slice(0, this.maxFamilies);
    return {
      generated_at: new Date().toISOString(),
      total: entries.length,
      families: Object.fromEntries(familyEntries),
      prompts: entries.map((entry) => ({
        id: entry.id,
        family: entry.family,
        fingerprint: entry.fingerprint,
        prompt: entry.prompt,
        count: entry.count,
      })),
    };
  }
}

module.exports = {
  AttackCorpusEvolver,
  redactSensitive,
  classifyFamily,
};
