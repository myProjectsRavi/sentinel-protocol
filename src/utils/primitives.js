const crypto = require('crypto');

function toObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return value;
}

function clampPositiveInt(value, fallback, min = 1, max = Number.MAX_SAFE_INTEGER) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  const normalized = Math.floor(parsed);
  if (normalized < min || normalized > max) {
    return fallback;
  }
  return normalized;
}

function clampProbability(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 1) {
    return fallback;
  }
  return parsed;
}

function normalizeMode(value, fallback = 'monitor', allowed = ['monitor', 'warn', 'enforce']) {
  const normalized = String(value ?? fallback)
    .toLowerCase()
    .trim();
  return allowed.includes(normalized) ? normalized : fallback;
}

function normalizeSessionValue(value, maxLength = 256) {
  const out = String(value || '').trim();
  if (!out) {
    return '';
  }
  return out.length > maxLength ? out.slice(0, maxLength) : out;
}

function mapHeaderValue(headers = {}, name) {
  const wanted = String(name || '').toLowerCase();
  for (const [key, value] of Object.entries(headers || {})) {
    if (String(key).toLowerCase() === wanted) {
      return value;
    }
  }
  return undefined;
}

function cosineSimilarity(a = [], b = []) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length === 0 || b.length === 0) {
    return 0;
  }
  const len = Math.min(a.length, b.length);
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < len; i += 1) {
    const av = Number(a[i] || 0);
    const bv = Number(b[i] || 0);
    dot += av * bv;
    normA += av * av;
    normB += bv * bv;
  }
  if (normA <= 0 || normB <= 0) {
    return 0;
  }
  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}

function snippetHash(text, length = 16) {
  const digest = crypto.createHash('sha256').update(String(text || '')).digest('hex');
  const size = clampPositiveInt(length, 16, 6, 64);
  return digest.slice(0, size);
}

module.exports = {
  toObject,
  clampPositiveInt,
  clampProbability,
  normalizeMode,
  normalizeSessionValue,
  mapHeaderValue,
  cosineSimilarity,
  snippetHash,
};
