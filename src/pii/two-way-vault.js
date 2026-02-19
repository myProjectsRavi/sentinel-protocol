const crypto = require('crypto');
const { Transform } = require('stream');
const { StringDecoder } = require('string_decoder');

function toObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return value;
}

function clampPositiveInt(value, fallback, min = 1, max = 86400000) {
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

function normalizeMode(value, fallback = 'monitor') {
  const normalized = String(value || fallback).toLowerCase();
  return normalized === 'active' ? 'active' : 'monitor';
}

function maskHash(input, salt = '') {
  return crypto.createHash('sha256').update(String(salt)).update('::').update(String(input)).digest('hex');
}

function hashDigits(input, count, salt = '') {
  const hex = maskHash(input, salt);
  let out = '';
  let idx = 0;
  while (out.length < count) {
    const code = Number.parseInt(hex[idx % hex.length], 16);
    out += String(code % 10);
    idx += 1;
  }
  return out;
}

function hashLetters(input, count, salt = '') {
  const hex = maskHash(input, salt);
  const alphabet = 'abcdefghijklmnopqrstuvwxyz';
  let out = '';
  let idx = 0;
  while (out.length < count) {
    const code = Number.parseInt(hex[idx % hex.length], 16);
    out += alphabet[code % alphabet.length];
    idx += 1;
  }
  return out;
}

function escapeRegExp(value) {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function mapHeaderValue(headers = {}, name) {
  const target = String(name || '').toLowerCase();
  for (const [key, value] of Object.entries(headers || {})) {
    if (String(key).toLowerCase() === target) {
      return value;
    }
  }
  return undefined;
}

function normalizeSessionValue(value) {
  const raw = String(value || '').trim();
  if (!raw) {
    return '';
  }
  return raw.length > 256 ? raw.slice(0, 256) : raw;
}

function looksTextualContentType(contentType = '') {
  const value = String(contentType || '').toLowerCase();
  if (!value) {
    return false;
  }
  return value.includes('application/json')
    || value.includes('application/problem+json')
    || value.includes('text/')
    || value.includes('application/xml')
    || value.includes('application/javascript')
    || value.includes('text/event-stream');
}

function replaceAllByMap(text, mappingEntries) {
  let out = String(text || '');
  let replacements = 0;
  for (const item of mappingEntries) {
    const from = String(item.from || '');
    const to = String(item.to || '');
    if (!from || from === to) {
      continue;
    }
    const re = new RegExp(escapeRegExp(from), 'g');
    const before = out;
    out = out.replace(re, to);
    if (before !== out) {
      const count = (before.match(re) || []).length;
      replacements += count;
    }
  }
  return {
    text: out,
    replacements,
  };
}

class VaultRewriteTransform extends Transform {
  constructor(options = {}) {
    super();
    this.entries = Array.isArray(options.entries) ? options.entries : [];
    this.maxTokenLength = this.entries.reduce((max, item) => Math.max(max, String(item.from || '').length), 0);
    // Keep a larger tail so replacement tokens cannot straddle the emission boundary.
    // This avoids missing matches when token boundaries are split across chunks.
    this.tailCarryLength = this.maxTokenLength > 1 ? (this.maxTokenLength - 1) * 2 : 0;
    this.decoder = new StringDecoder('utf8');
    this.pending = '';
    this.replacements = 0;
    this.onMetrics = typeof options.onMetrics === 'function' ? options.onMetrics : null;
  }

  _transform(chunk, encoding, callback) {
    try {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
      const decoded = this.decoder.write(buffer);
      if (!decoded) {
        callback();
        return;
      }
      const joined = `${this.pending}${decoded}`;
      const carryLength = Math.max(0, this.tailCarryLength);
      const safeLength = Math.max(0, joined.length - carryLength);
      const safeText = joined.slice(0, safeLength);
      this.pending = joined.slice(safeLength);
      const rewritten = replaceAllByMap(safeText, this.entries);
      this.replacements += rewritten.replacements;
      this.push(rewritten.text);
      callback();
    } catch (error) {
      callback(error);
    }
  }

  _flush(callback) {
    try {
      const tail = this.decoder.end();
      const joined = `${this.pending}${tail || ''}`;
      const rewritten = replaceAllByMap(joined, this.entries);
      this.replacements += rewritten.replacements;
      this.push(rewritten.text);
      if (this.onMetrics) {
        this.onMetrics({
          replacements: this.replacements,
        });
      }
      callback();
    } catch (error) {
      callback(error);
    }
  }
}

class TwoWayPIIVault {
  constructor(config = {}, deps = {}) {
    const normalized = toObject(config);
    this.enabled = normalized.enabled === true;
    this.mode = normalizeMode(normalized.mode, 'monitor');
    this.salt = String(normalized.salt || process.env.SENTINEL_PII_VAULT_SALT || '');
    this.sessionHeader = String(normalized.session_header || 'x-sentinel-session-id').toLowerCase();
    this.fallbackHeaders = Array.isArray(normalized.fallback_headers)
      ? normalized.fallback_headers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
      : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
    this.ttlMs = clampPositiveInt(normalized.ttl_ms, 3600000, 1000, 7 * 24 * 3600000);
    this.maxSessions = clampPositiveInt(normalized.max_sessions, 5000, 1, 500000);
    this.maxMappingsPerSession = clampPositiveInt(normalized.max_mappings_per_session, 1000, 1, 50000);
    this.tokenDomain = String(normalized.token_domain || 'sentinel.local');
    this.tokenPrefix = String(normalized.token_prefix || 'sentinel_');
    this.targetTypes = new Set(
      Array.isArray(normalized.target_types)
        ? normalized.target_types.map((item) => String(item || '').toLowerCase()).filter(Boolean)
        : ['email_address', 'phone_us', 'phone_e164', 'ssn_us']
    );
    this.observability = normalized.observability !== false;
    this.now = typeof deps.now === 'function' ? deps.now : Date.now;
    this.sessions = new Map();
    this.nextCleanupAt = 0;
  }

  isEnabled() {
    return this.enabled === true;
  }

  isActive() {
    return this.isEnabled() && this.mode === 'active';
  }

  deriveSessionKey(headers = {}, correlationId = '') {
    const primary = normalizeSessionValue(mapHeaderValue(headers, this.sessionHeader));
    if (primary) {
      return `hdr:${this.sessionHeader}:${primary}`;
    }
    for (const headerName of this.fallbackHeaders) {
      const value = normalizeSessionValue(mapHeaderValue(headers, headerName));
      if (value) {
        return `hdr:${headerName}:${value}`;
      }
    }
    const fallbackCorrelation = normalizeSessionValue(correlationId);
    if (fallbackCorrelation) {
      return `corr:${fallbackCorrelation}`;
    }
    return 'session:anonymous';
  }

  cleanup(nowMs = Number(this.now())) {
    if (nowMs < this.nextCleanupAt && this.sessions.size <= this.maxSessions) {
      return;
    }
    for (const [sessionKey, session] of this.sessions.entries()) {
      if (!session || Number(session.expiresAt || 0) <= nowMs) {
        this.sessions.delete(sessionKey);
      }
    }
    while (this.sessions.size > this.maxSessions) {
      const oldest = this.sessions.keys().next().value;
      if (!oldest) {
        break;
      }
      this.sessions.delete(oldest);
    }
    this.nextCleanupAt = nowMs + Math.min(this.ttlMs, 5000);
  }

  getSession(sessionKey, createIfMissing = false) {
    const nowMs = Number(this.now());
    this.cleanup(nowMs);
    const key = String(sessionKey || '');
    let session = this.sessions.get(key);
    if (!session && createIfMissing) {
      session = {
        createdAt: nowMs,
        lastSeenAt: nowMs,
        expiresAt: nowMs + this.ttlMs,
        tokenToEntry: new Map(),
        valueKeyToToken: new Map(),
      };
      this.sessions.set(key, session);
    }
    if (!session) {
      return null;
    }
    session.lastSeenAt = nowMs;
    session.expiresAt = nowMs + this.ttlMs;
    return session;
  }

  buildToken(piiType, value, sessionKey) {
    const type = String(piiType || 'generic').toLowerCase();
    const seed = `${sessionKey}:${type}:${value}`;
    if (type === 'email_address') {
      const user = hashLetters(seed, 8, this.salt);
      return `user_${user}@${this.tokenDomain}`;
    }
    if (type === 'phone_us' || type === 'phone_e164') {
      const digits = hashDigits(seed, 10, this.salt);
      return `+1${digits}`;
    }
    if (type === 'ssn_us') {
      const digits = hashDigits(seed, 9, this.salt);
      return `${digits.slice(0, 3)}-${digits.slice(3, 5)}-${digits.slice(5, 9)}`;
    }
    const suffix = maskHash(seed, this.salt).slice(0, 12);
    return `${this.tokenPrefix}${suffix}`;
  }

  getOrCreateToken(session, sessionKey, piiType, realValue) {
    const valueKey = `${String(piiType || '').toLowerCase()}:${String(realValue || '')}`;
    const existing = session.valueKeyToToken.get(valueKey);
    if (existing) {
      return existing;
    }
    if (session.tokenToEntry.size >= this.maxMappingsPerSession) {
      return null;
    }
    let token = this.buildToken(piiType, realValue, sessionKey);
    let attempts = 0;
    while (session.tokenToEntry.has(token) && session.tokenToEntry.get(token)?.value !== realValue && attempts < 5) {
      attempts += 1;
      token = this.buildToken(piiType, `${realValue}:${attempts}`, sessionKey);
    }
    session.valueKeyToToken.set(valueKey, token);
    session.tokenToEntry.set(token, {
      piiType: String(piiType || '').toLowerCase(),
      value: String(realValue || ''),
      token,
      createdAt: Number(this.now()),
    });
    return token;
  }

  applyIngress({ text, findings, sessionKey }) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        detected: false,
        applied: false,
        monitorOnly: false,
        text,
        mappings: [],
      };
    }

    const input = String(text || '');
    const eligible = [];
    const seenValues = new Set();
    for (const finding of findings || []) {
      const piiType = String(finding?.id || '').toLowerCase();
      const value = String(finding?.value || '');
      if (!value || value.length < 3) {
        continue;
      }
      if (!this.targetTypes.has(piiType)) {
        continue;
      }
      const key = `${piiType}:${value}`;
      if (seenValues.has(key)) {
        continue;
      }
      seenValues.add(key);
      eligible.push({
        piiType,
        value,
      });
    }
    if (eligible.length === 0) {
      return {
        enabled: true,
        detected: false,
        applied: false,
        monitorOnly: this.mode === 'monitor',
        text: input,
        mappings: [],
      };
    }
    if (!this.isActive()) {
      return {
        enabled: true,
        detected: true,
        applied: false,
        monitorOnly: true,
        text: input,
        mappings: eligible.map((item) => ({
          pii_type: item.piiType,
          value_hash: maskHash(item.value, this.salt).slice(0, 16),
        })),
      };
    }

    const session = this.getSession(sessionKey, true);
    const mappings = [];
    const replaceEntries = [];
    for (const item of eligible) {
      const token = this.getOrCreateToken(session, sessionKey, item.piiType, item.value);
      if (!token) {
        continue;
      }
      mappings.push({
        pii_type: item.piiType,
        token,
        value_hash: maskHash(item.value, this.salt).slice(0, 16),
      });
      replaceEntries.push({
        from: item.value,
        to: token,
      });
    }
    replaceEntries.sort((a, b) => String(b.from).length - String(a.from).length);
    const rewritten = replaceAllByMap(input, replaceEntries);

    return {
      enabled: true,
      detected: true,
      applied: rewritten.replacements > 0,
      monitorOnly: false,
      text: rewritten.text,
      replacements: rewritten.replacements,
      mappings,
      sessionKey,
    };
  }

  getReverseEntries(sessionKey) {
    const session = this.getSession(sessionKey, false);
    if (!session) {
      return [];
    }
    const entries = [];
    for (const [token, entry] of session.tokenToEntry.entries()) {
      entries.push({
        from: token,
        to: entry.value,
        pii_type: entry.piiType,
      });
    }
    entries.sort((a, b) => String(b.from).length - String(a.from).length);
    return entries;
  }

  applyEgressBuffer({ bodyBuffer, contentType, sessionKey }) {
    if (!this.isActive()) {
      return {
        changed: false,
        bodyBuffer,
        replacements: 0,
        mappedTypes: [],
      };
    }
    if (!Buffer.isBuffer(bodyBuffer) || bodyBuffer.length === 0 || !looksTextualContentType(contentType)) {
      return {
        changed: false,
        bodyBuffer,
        replacements: 0,
        mappedTypes: [],
      };
    }
    const entries = this.getReverseEntries(sessionKey);
    if (entries.length === 0) {
      return {
        changed: false,
        bodyBuffer,
        replacements: 0,
        mappedTypes: [],
      };
    }
    const input = bodyBuffer.toString('utf8');
    const rewritten = replaceAllByMap(input, entries);
    return {
      changed: rewritten.replacements > 0,
      bodyBuffer: rewritten.replacements > 0 ? Buffer.from(rewritten.text, 'utf8') : bodyBuffer,
      replacements: rewritten.replacements,
      mappedTypes: Array.from(new Set(entries.map((item) => item.pii_type))).sort(),
    };
  }

  createEgressStreamTransform({ sessionKey, contentType, onMetrics }) {
    if (!this.isActive()) {
      return null;
    }
    if (!looksTextualContentType(contentType)) {
      return null;
    }
    const entries = this.getReverseEntries(sessionKey);
    if (entries.length === 0) {
      return null;
    }
    return new VaultRewriteTransform({
      entries,
      onMetrics,
    });
  }
}

module.exports = {
  TwoWayPIIVault,
  VaultRewriteTransform,
  replaceAllByMap,
  looksTextualContentType,
};
