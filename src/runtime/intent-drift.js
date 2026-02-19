const crypto = require('crypto');

function toObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return value;
}

function clampPositiveInt(value, fallback, min = 1, max = 1000000) {
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

function normalizeMode(value, fallback = 'monitor') {
  const normalized = String(value || fallback).toLowerCase();
  return normalized === 'block' ? 'block' : 'monitor';
}

function mapHeaderValue(headers = {}, headerName) {
  const wanted = String(headerName || '').toLowerCase();
  for (const [key, value] of Object.entries(headers || {})) {
    if (String(key).toLowerCase() === wanted) {
      return value;
    }
  }
  return undefined;
}

function normalizeSessionPart(value) {
  const out = String(value || '').trim();
  if (!out) {
    return '';
  }
  return out.length > 256 ? out.slice(0, 256) : out;
}

function extractMessageText(message) {
  if (!message || typeof message !== 'object') {
    return '';
  }
  if (typeof message.content === 'string') {
    return message.content;
  }
  if (Array.isArray(message.content)) {
    return message.content
      .map((item) => {
        if (!item || typeof item !== 'object') {
          return '';
        }
        if (typeof item.text === 'string') {
          return item.text;
        }
        if (item.type === 'text' && typeof item.value === 'string') {
          return item.value;
        }
        return '';
      })
      .filter(Boolean)
      .join('\n');
  }
  return '';
}

function normalizeTextForEmbedding(text, stripVolatileTokens = true) {
  let out = String(text || '');
  if (!out) {
    return '';
  }
  out = out.normalize('NFKC');
  out = out.replace(/[\u200B-\u200D\uFEFF]/g, '');
  if (stripVolatileTokens) {
    out = out
      .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi, ' [uuid] ')
      .replace(
        /\b\d{4}-\d{2}-\d{2}t\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:z|[+-]\d{2}:\d{2})\b/gi,
        ' [timestamp] '
      )
      .replace(/\btrace[_-]?id\s*[:=]\s*[a-z0-9-]{8,}\b/gi, ' trace_id:[id] ')
      .replace(/\bspan[_-]?id\s*[:=]\s*[a-z0-9-]{8,}\b/gi, ' span_id:[id] ')
      .replace(/\breq(?:uest)?[_-]?id\s*[:=]\s*[a-z0-9-]{8,}\b/gi, ' request_id:[id] ')
      .replace(/\b[0-9a-f]{24,}\b/gi, ' [hexid] ');
  }
  out = out.replace(/\s+/g, ' ').trim();
  return out;
}

function countKeywordHits(text, keywords = []) {
  const haystack = String(text || '').toLowerCase();
  if (!haystack) {
    return 0;
  }
  let hits = 0;
  for (const raw of keywords) {
    const token = String(raw || '').trim().toLowerCase();
    if (!token) {
      continue;
    }
    if (haystack.includes(token)) {
      hits += 1;
    }
  }
  return hits;
}

function cosineSimilarity(a = [], b = []) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length === 0 || b.length === 0) {
    return 0;
  }
  const len = Math.min(a.length, b.length);
  let dot = 0;
  let aNorm = 0;
  let bNorm = 0;
  for (let i = 0; i < len; i += 1) {
    const av = Number(a[i] || 0);
    const bv = Number(b[i] || 0);
    dot += av * bv;
    aNorm += av * av;
    bNorm += bv * bv;
  }
  if (aNorm <= 0 || bNorm <= 0) {
    return 0;
  }
  return dot / (Math.sqrt(aNorm) * Math.sqrt(bNorm));
}

class IntentDriftDetector {
  constructor(config = {}, deps = {}) {
    const normalized = toObject(config);
    this.enabled = normalized.enabled === true;
    this.mode = normalizeMode(normalized.mode, 'monitor');
    this.keyHeader = String(normalized.key_header || 'x-sentinel-session-id').toLowerCase();
    this.fallbackHeaders = Array.isArray(normalized.fallback_key_headers)
      ? normalized.fallback_key_headers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
      : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
    this.sampleEveryTurns = clampPositiveInt(normalized.sample_every_turns, 10, 1, 1000);
    this.minTurns = clampPositiveInt(normalized.min_turns, 10, 1, 10000);
    this.threshold = clampProbability(normalized.threshold, 0.35);
    this.maxSessions = clampPositiveInt(normalized.max_sessions, 5000, 1, 100000);
    this.contextWindowMessages = clampPositiveInt(normalized.context_window_messages, 8, 1, 100);
    this.modelId = String(normalized.model_id || 'Xenova/all-MiniLM-L6-v2');
    this.cacheDir = String(normalized.cache_dir || '~/.sentinel/models');
    this.maxPromptChars = clampPositiveInt(normalized.max_prompt_chars, 4000, 128, 20000);
    this.cooldownMs = clampPositiveInt(normalized.cooldown_ms, 60000, 1000, 3600000);
    this.targetRoles = new Set(
      Array.isArray(normalized.target_roles)
        ? normalized.target_roles.map((item) => String(item || '').toLowerCase()).filter(Boolean)
        : ['system', 'user', 'assistant']
    );
    this.stripVolatileTokens = normalized.strip_volatile_tokens !== false;
    this.riskKeywords = Array.isArray(normalized.risk_keywords)
      ? normalized.risk_keywords.map((item) => String(item || '').trim().toLowerCase()).filter(Boolean)
      : [
          'password',
          'credential',
          'api key',
          'token',
          'secret',
          'id_rsa',
          'ssh key',
          'bypass',
          'ignore previous instructions',
          'override safety',
        ];
    this.riskBoost = clampProbability(normalized.risk_boost, 0.12);
    this.observability = normalized.observability !== false;

    this.now = typeof deps.now === 'function' ? deps.now : Date.now;
    this.embedText = typeof deps.embedText === 'function' ? deps.embedText : null;
    this.sessions = new Map();
    this.nextCleanupAt = 0;
  }

  isEnabled() {
    return this.enabled === true;
  }

  deriveSessionKey(headers = {}, correlationId = '') {
    const primary = normalizeSessionPart(mapHeaderValue(headers, this.keyHeader));
    if (primary) {
      return `hdr:${this.keyHeader}:${primary}`;
    }
    for (const header of this.fallbackHeaders) {
      const value = normalizeSessionPart(mapHeaderValue(headers, header));
      if (value) {
        return `hdr:${header}:${value}`;
      }
    }
    const fallback = normalizeSessionPart(correlationId);
    if (fallback) {
      return `corr:${fallback}`;
    }
    return 'session:anonymous';
  }

  cleanup(nowMs = Number(this.now())) {
    if (nowMs < this.nextCleanupAt && this.sessions.size <= this.maxSessions) {
      return;
    }
    for (const [key, state] of this.sessions.entries()) {
      if (!state || Number(state.expiresAt || 0) <= nowMs) {
        this.sessions.delete(key);
      }
    }
    while (this.sessions.size > this.maxSessions) {
      const oldest = this.sessions.keys().next().value;
      if (!oldest) {
        break;
      }
      this.sessions.delete(oldest);
    }
    this.nextCleanupAt = nowMs + Math.min(this.cooldownMs, 5000);
  }

  getOrCreateState(sessionKey) {
    const nowMs = Number(this.now());
    this.cleanup(nowMs);
    let state = this.sessions.get(sessionKey);
    if (!state) {
      state = {
        createdAt: nowMs,
        expiresAt: nowMs + this.cooldownMs * 4,
        turnCount: 0,
        anchorVector: null,
        anchorHash: null,
        blockedUntil: 0,
        lastDistance: null,
      };
      this.sessions.set(sessionKey, state);
    }
    state.expiresAt = nowMs + this.cooldownMs * 4;
    return state;
  }

  buildAnchorText(messages = []) {
    let systemText = '';
    let userText = '';
    for (const msg of messages) {
      const role = String(msg?.role || '').toLowerCase();
      if (!systemText && role === 'system') {
        systemText = normalizeTextForEmbedding(extractMessageText(msg), this.stripVolatileTokens);
      }
      if (!userText && role === 'user') {
        userText = normalizeTextForEmbedding(extractMessageText(msg), this.stripVolatileTokens);
      }
      if (systemText && userText) {
        break;
      }
    }
    return [systemText, userText].filter(Boolean).join('\n').slice(0, this.maxPromptChars);
  }

  buildCurrentText(messages = []) {
    const tail = messages.slice(Math.max(0, messages.length - this.contextWindowMessages));
    return tail
      .filter((message) => {
        if (this.targetRoles.size === 0) {
          return true;
        }
        return this.targetRoles.has(String(message?.role || '').toLowerCase());
      })
      .map((message) => {
        const role = String(message?.role || 'unknown').toLowerCase();
        const normalized = normalizeTextForEmbedding(extractMessageText(message), this.stripVolatileTokens);
        return `${role}: ${normalized}`;
      })
      .join('\n')
      .slice(0, this.maxPromptChars);
  }

  async evaluate({ headers = {}, bodyJson, correlationId, effectiveMode = 'monitor', embedText }) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        evaluated: false,
        drifted: false,
        reason: 'disabled',
      };
    }
    if (!bodyJson || typeof bodyJson !== 'object' || !Array.isArray(bodyJson.messages)) {
      return {
        enabled: true,
        evaluated: false,
        drifted: false,
        reason: 'unsupported_payload',
      };
    }
    const embed = typeof embedText === 'function' ? embedText : this.embedText;
    if (typeof embed !== 'function') {
      return {
        enabled: true,
        evaluated: false,
        drifted: false,
        reason: 'embedder_unavailable',
      };
    }

    const sessionKey = this.deriveSessionKey(headers, correlationId);
    const state = this.getOrCreateState(sessionKey);
    state.turnCount += 1;
    const nowMs = Number(this.now());

    const anchorText = this.buildAnchorText(bodyJson.messages);
    if (!anchorText) {
      return {
        enabled: true,
        evaluated: false,
        drifted: false,
        reason: 'anchor_text_empty',
        sessionKey,
        turnCount: state.turnCount,
      };
    }

    if (!state.anchorVector) {
      const anchorVector = await embed(anchorText, {
        modelId: this.modelId,
        cacheDir: this.cacheDir,
        maxPromptChars: this.maxPromptChars,
      });
      if (!Array.isArray(anchorVector) || anchorVector.length === 0) {
        return {
          enabled: true,
          evaluated: false,
          drifted: false,
          reason: 'anchor_embedding_failed',
          sessionKey,
          turnCount: state.turnCount,
        };
      }
      state.anchorVector = anchorVector;
      state.anchorText = anchorText;
      state.anchorRisk = countKeywordHits(anchorText, this.riskKeywords);
      state.anchorHash = crypto.createHash('sha256').update(anchorText, 'utf8').digest('hex').slice(0, 16);
      return {
        enabled: true,
        evaluated: false,
        drifted: false,
        reason: 'initialized',
        sessionKey,
        turnCount: state.turnCount,
        anchorHash: state.anchorHash,
      };
    }

    if (state.turnCount < this.minTurns) {
      return {
        enabled: true,
        evaluated: false,
        drifted: false,
        reason: 'min_turns_not_reached',
        sessionKey,
        turnCount: state.turnCount,
        minTurns: this.minTurns,
      };
    }

    if (state.turnCount % this.sampleEveryTurns !== 0) {
      return {
        enabled: true,
        evaluated: false,
        drifted: false,
        reason: 'sample_window',
        sessionKey,
        turnCount: state.turnCount,
      };
    }

    const currentText = this.buildCurrentText(bodyJson.messages);
    if (!currentText) {
      return {
        enabled: true,
        evaluated: false,
        drifted: false,
        reason: 'current_text_empty',
        sessionKey,
        turnCount: state.turnCount,
      };
    }

    const currentVector = await embed(currentText, {
      modelId: this.modelId,
      cacheDir: this.cacheDir,
      maxPromptChars: this.maxPromptChars,
    });
    if (!Array.isArray(currentVector) || currentVector.length === 0) {
      return {
        enabled: true,
        evaluated: false,
        drifted: false,
        reason: 'current_embedding_failed',
        sessionKey,
        turnCount: state.turnCount,
      };
    }

    const similarity = cosineSimilarity(state.anchorVector, currentVector);
    const distance = 1 - similarity;
    const currentRisk = countKeywordHits(currentText, this.riskKeywords);
    const anchorRisk = Number(state.anchorRisk || 0);
    const riskDelta = Math.max(0, currentRisk - anchorRisk);
    const adjustedDistance = Math.min(1, distance + (riskDelta * this.riskBoost));
    state.lastDistance = adjustedDistance;
    const drifted = adjustedDistance >= this.threshold;
    if (drifted && nowMs > state.blockedUntil) {
      state.blockedUntil = nowMs + this.cooldownMs;
    }

    const shouldBlock = drifted && this.mode === 'block' && effectiveMode === 'enforce';
    return {
      enabled: true,
      evaluated: true,
      drifted,
      shouldBlock,
      sessionKey,
      turnCount: state.turnCount,
      similarity: Number(similarity.toFixed(6)),
      distance: Number(distance.toFixed(6)),
      adjustedDistance: Number(adjustedDistance.toFixed(6)),
      riskDelta,
      threshold: this.threshold,
      blockedUntil: state.blockedUntil,
      anchorHash: state.anchorHash,
      reason: drifted ? 'drift_threshold_exceeded' : 'within_threshold',
    };
  }
}

module.exports = {
  IntentDriftDetector,
  cosineSimilarity,
};
