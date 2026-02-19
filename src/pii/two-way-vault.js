const crypto = require('crypto');
const { Transform } = require('stream');
const { StringDecoder } = require('string_decoder');
const {
  toObject,
  clampPositiveInt,
  normalizeMode,
  mapHeaderValue,
  normalizeSessionValue,
} = require('../utils/primitives');

function utf8Bytes(value) {
  return Buffer.byteLength(String(value || ''), 'utf8');
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
  return replaceAllByMapWithCap(text, mappingEntries, Number.POSITIVE_INFINITY);
}

function replaceAllByMapWithCap(text, mappingEntries, maxReplacements) {
  let out = String(text || '');
  let replacements = 0;
  const cap = Number.isFinite(Number(maxReplacements)) ? Math.max(0, Number(maxReplacements)) : Number.POSITIVE_INFINITY;
  for (const item of mappingEntries) {
    if (replacements >= cap) {
      break;
    }
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
      if (replacements >= cap) {
        replacements = cap;
        break;
      }
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
    this.maxReplacements = Number.isFinite(Number(options.maxReplacements))
      ? Math.max(0, Number(options.maxReplacements))
      : Number.POSITIVE_INFINITY;
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
      const rewritten = replaceAllByMapWithCap(safeText, this.entries, this.maxReplacements - this.replacements);
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
      const rewritten = replaceAllByMapWithCap(joined, this.entries, this.maxReplacements - this.replacements);
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
    this.mode = normalizeMode(normalized.mode, 'monitor', ['monitor', 'active']);
    this.salt = String(normalized.salt || process.env.SENTINEL_PII_VAULT_SALT || '');
    this.sessionHeader = String(normalized.session_header || 'x-sentinel-session-id').toLowerCase();
    this.fallbackHeaders = Array.isArray(normalized.fallback_headers)
      ? normalized.fallback_headers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
      : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
    this.ttlMs = clampPositiveInt(normalized.ttl_ms, 3600000, 1000, 7 * 24 * 3600000);
    this.maxSessions = clampPositiveInt(normalized.max_sessions, 5000, 1, 500000);
    this.maxMappingsPerSession = clampPositiveInt(normalized.max_mappings_per_session, 1000, 1, 50000);
    this.maxEgressRewriteEntries = clampPositiveInt(normalized.max_egress_rewrite_entries, 256, 1, 10000);
    this.maxPayloadBytes = clampPositiveInt(normalized.max_payload_bytes, 512 * 1024, 64, 20 * 1024 * 1024);
    this.maxReplacementsPerPass = clampPositiveInt(normalized.max_replacements_per_pass, 1000, 1, 1000000);
    this.maxMemoryBytes = clampPositiveInt(normalized.max_memory_bytes, 64 * 1024 * 1024, 1024, 1024 * 1024 * 1024);
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
    this.totalApproxBytes = 0;
    this.nextCleanupAt = 0;
    this.metrics = {
      sessionsCreated: 0,
      entriesCreated: 0,
      sessionEvictionsTtl: 0,
      sessionEvictionsLru: 0,
      sessionEvictionsMemory: 0,
      entryEvictionsLru: 0,
      memoryPressureDrops: 0,
      lastEvictionReason: null,
      lastEvictionAt: null,
      peakApproxBytes: 0,
    };
  }

  isEnabled() {
    return this.enabled === true;
  }

  isActive() {
    return this.isEnabled() && this.mode === 'active';
  }

  updatePeakMemory() {
    if (this.totalApproxBytes > this.metrics.peakApproxBytes) {
      this.metrics.peakApproxBytes = this.totalApproxBytes;
    }
  }

  estimateSessionBaseBytes(sessionKey = '') {
    return 192 + utf8Bytes(sessionKey);
  }

  estimateEntryBytes({ token, value, piiType }) {
    return 128 + utf8Bytes(token) + utf8Bytes(value) + utf8Bytes(piiType);
  }

  touchSession(sessionKey, session) {
    if (!this.sessions.has(sessionKey)) {
      return;
    }
    this.sessions.delete(sessionKey);
    this.sessions.set(sessionKey, session);
  }

  touchEntry(session, token) {
    if (!session || !session.tokenToEntry || !session.tokenToEntry.has(token)) {
      return;
    }
    const entry = session.tokenToEntry.get(token);
    session.tokenToEntry.delete(token);
    session.tokenToEntry.set(token, entry);
  }

  evictOldestEntryInSession(session) {
    if (!session || !session.tokenToEntry || session.tokenToEntry.size === 0) {
      return false;
    }
    const oldestToken = session.tokenToEntry.keys().next().value;
    if (!oldestToken) {
      return false;
    }
    const oldest = session.tokenToEntry.get(oldestToken);
    session.tokenToEntry.delete(oldestToken);
    if (oldest && oldest.valueKey) {
      session.valueKeyToToken.delete(oldest.valueKey);
    }
    const reclaimed = Number(oldest?.byteSize || 0);
    if (reclaimed > 0) {
      session.approxBytes = Math.max(0, Number(session.approxBytes || 0) - reclaimed);
      this.totalApproxBytes = Math.max(0, this.totalApproxBytes - reclaimed);
    }
    this.metrics.entryEvictionsLru += 1;
    this.updatePeakMemory();
    return true;
  }

  evictSession(sessionKey, reason = 'lru', nowMs = Number(this.now())) {
    const key = String(sessionKey || '');
    const session = this.sessions.get(key);
    if (!session) {
      return false;
    }
    this.sessions.delete(key);
    const reclaimed = Number(session.approxBytes || 0);
    if (reclaimed > 0) {
      this.totalApproxBytes = Math.max(0, this.totalApproxBytes - reclaimed);
    }
    if (reason === 'ttl') {
      this.metrics.sessionEvictionsTtl += 1;
    } else if (reason === 'memory') {
      this.metrics.sessionEvictionsMemory += 1;
    } else {
      this.metrics.sessionEvictionsLru += 1;
    }
    this.metrics.lastEvictionReason = reason;
    this.metrics.lastEvictionAt = nowMs;
    return true;
  }

  oldestSessionKeyExcluding(protectedSessionKey = '') {
    for (const key of this.sessions.keys()) {
      if (!protectedSessionKey || key !== protectedSessionKey) {
        return key;
      }
    }
    return null;
  }

  ensureHeadroom(requiredBytes = 0, protectedSessionKey = '', nowMs = Number(this.now())) {
    const need = Math.max(0, Number(requiredBytes || 0));
    this.cleanup(nowMs);
    while (this.totalApproxBytes + need > this.maxMemoryBytes) {
      const candidate = this.oldestSessionKeyExcluding(protectedSessionKey);
      if (!candidate) {
        return false;
      }
      this.evictSession(candidate, 'memory', nowMs);
    }
    return true;
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
    if (
      nowMs < this.nextCleanupAt
      && this.sessions.size <= this.maxSessions
      && this.totalApproxBytes <= this.maxMemoryBytes
    ) {
      return;
    }
    for (const [sessionKey, session] of this.sessions.entries()) {
      if (!session || Number(session.expiresAt || 0) <= nowMs) {
        this.evictSession(sessionKey, 'ttl', nowMs);
      }
    }
    while (this.sessions.size > this.maxSessions) {
      const oldest = this.sessions.keys().next().value;
      if (!oldest) {
        break;
      }
      this.evictSession(oldest, 'lru', nowMs);
    }
    while (this.totalApproxBytes > this.maxMemoryBytes) {
      const oldest = this.sessions.keys().next().value;
      if (!oldest) {
        break;
      }
      this.evictSession(oldest, 'memory', nowMs);
    }
    this.nextCleanupAt = nowMs + Math.min(this.ttlMs, 5000);
    this.updatePeakMemory();
  }

  getSession(sessionKey, createIfMissing = false) {
    const nowMs = Number(this.now());
    this.cleanup(nowMs);
    const key = String(sessionKey || '');
    let session = this.sessions.get(key);
    if (!session && createIfMissing) {
      const sessionBaseBytes = this.estimateSessionBaseBytes(key);
      if (!this.ensureHeadroom(sessionBaseBytes, key, nowMs)) {
        this.metrics.memoryPressureDrops += 1;
        return null;
      }
      session = {
        createdAt: nowMs,
        lastSeenAt: nowMs,
        expiresAt: nowMs + this.ttlMs,
        tokenToEntry: new Map(),
        valueKeyToToken: new Map(),
        approxBytes: sessionBaseBytes,
      };
      this.sessions.set(key, session);
      this.totalApproxBytes += sessionBaseBytes;
      this.metrics.sessionsCreated += 1;
      this.updatePeakMemory();
    }
    if (!session) {
      return null;
    }
    session.lastSeenAt = nowMs;
    session.expiresAt = nowMs + this.ttlMs;
    this.touchSession(key, session);
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
      this.touchEntry(session, existing);
      return existing;
    }
    if (session.tokenToEntry.size >= this.maxMappingsPerSession) {
      this.evictOldestEntryInSession(session);
    }
    let token = this.buildToken(piiType, realValue, sessionKey);
    let attempts = 0;
    while (session.tokenToEntry.has(token) && session.tokenToEntry.get(token)?.value !== realValue && attempts < 5) {
      attempts += 1;
      token = this.buildToken(piiType, `${realValue}:${attempts}`, sessionKey);
    }
    const entryBytes = this.estimateEntryBytes({
      token,
      value: realValue,
      piiType,
    });
    if (!this.ensureHeadroom(entryBytes, sessionKey, Number(this.now()))) {
      this.metrics.memoryPressureDrops += 1;
      return null;
    }
    session.valueKeyToToken.set(valueKey, token);
    session.tokenToEntry.set(token, {
      piiType: String(piiType || '').toLowerCase(),
      value: String(realValue || ''),
      token,
      valueKey,
      byteSize: entryBytes,
      createdAt: Number(this.now()),
    });
    session.approxBytes = Number(session.approxBytes || 0) + entryBytes;
    this.totalApproxBytes += entryBytes;
    this.metrics.entriesCreated += 1;
    this.updatePeakMemory();
    this.touchEntry(session, token);
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
    if (Buffer.byteLength(input, 'utf8') > this.maxPayloadBytes) {
      return {
        enabled: true,
        detected: false,
        applied: false,
        monitorOnly: this.mode === 'monitor',
        skipped: 'payload_too_large',
        text: input,
        mappings: [],
      };
    }
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
    if (!session) {
      return {
        enabled: true,
        detected: true,
        applied: false,
        monitorOnly: true,
        skipped: 'memory_pressure',
        text: input,
        mappings: [],
      };
    }
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
    const rewritten = replaceAllByMapWithCap(input, replaceEntries, this.maxReplacementsPerPass);

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
    const touchedTokens = [];
    for (const [token, entry] of session.tokenToEntry.entries()) {
      entries.push({
        from: token,
        to: entry.value,
        pii_type: entry.piiType,
      });
      touchedTokens.push(token);
      if (entries.length >= this.maxEgressRewriteEntries) {
        break;
      }
    }
    for (const token of touchedTokens) {
      this.touchEntry(session, token);
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
    if (bodyBuffer.length > this.maxPayloadBytes) {
      return {
        changed: false,
        bodyBuffer,
        replacements: 0,
        mappedTypes: [],
        skipped: 'payload_too_large',
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
    const rewritten = replaceAllByMapWithCap(input, entries, this.maxReplacementsPerPass);
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
      maxReplacements: this.maxReplacementsPerPass,
      onMetrics,
    });
  }

  getStats() {
    return {
      sessions: this.sessions.size,
      approx_bytes: this.totalApproxBytes,
      max_memory_bytes: this.maxMemoryBytes,
      peak_approx_bytes: this.metrics.peakApproxBytes,
      sessions_created: this.metrics.sessionsCreated,
      entries_created: this.metrics.entriesCreated,
      session_evictions_ttl: this.metrics.sessionEvictionsTtl,
      session_evictions_lru: this.metrics.sessionEvictionsLru,
      session_evictions_memory: this.metrics.sessionEvictionsMemory,
      entry_evictions_lru: this.metrics.entryEvictionsLru,
      memory_pressure_drops: this.metrics.memoryPressureDrops,
      last_eviction_reason: this.metrics.lastEvictionReason,
      last_eviction_at: this.metrics.lastEvictionAt,
    };
  }
}

module.exports = {
  TwoWayPIIVault,
  VaultRewriteTransform,
  replaceAllByMap,
  replaceAllByMapWithCap,
  looksTextualContentType,
};
