const crypto = require('crypto');

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

function clampProbability(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  if (parsed < 0 || parsed > 1) {
    return fallback;
  }
  return parsed;
}

function normalizeMode(value, fallback = 'monitor') {
  const normalized = String(value || fallback).toLowerCase();
  return normalized === 'block' ? 'block' : 'monitor';
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

function extractMessageText(message) {
  if (!message || typeof message !== 'object') {
    return '';
  }
  const content = message.content;
  if (typeof content === 'string') {
    return content;
  }
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (typeof part === 'string') {
          return part;
        }
        if (part && typeof part === 'object' && typeof part.text === 'string') {
          return part.text;
        }
        return '';
      })
      .join('\n');
  }
  return '';
}

function normalizeText(text) {
  return String(text || '')
    .normalize('NFKC')
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function cosineSimilarity(a = [], b = []) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length === 0 || b.length === 0 || a.length !== b.length) {
    return 0;
  }
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i += 1) {
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

class EpistemicAnchor {
  constructor(config = {}, deps = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor');
    this.requiredAcknowledgement = String(
      config.required_acknowledgement || 'I_UNDERSTAND_EPISTEMIC_ANCHOR_IS_EXPERIMENTAL'
    );
    this.acknowledgement = String(config.acknowledgement || '');
    this.keyHeader = String(config.key_header || 'x-sentinel-session-id').toLowerCase();
    this.fallbackKeyHeaders = Array.isArray(config.fallback_key_headers)
      ? config.fallback_key_headers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
      : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
    this.sampleEveryTurns = clampPositiveInt(config.sample_every_turns, 5, 1, 1000);
    this.minTurns = clampPositiveInt(config.min_turns, 6, 1, 10000);
    this.threshold = clampProbability(config.threshold, 0.8);
    this.cooldownMs = clampPositiveInt(config.cooldown_ms, 60000, 1000, 3600000);
    this.maxSessions = clampPositiveInt(config.max_sessions, 5000, 1, 500000);
    this.contextWindowMessages = clampPositiveInt(config.context_window_messages, 8, 1, 128);
    this.modelId = String(config.model_id || 'Xenova/all-MiniLM-L6-v2');
    this.cacheDir = String(config.cache_dir || '~/.sentinel/models');
    this.maxPromptChars = clampPositiveInt(config.max_prompt_chars, 4000, 128, 20000);
    this.observability = config.observability !== false;

    this.now = typeof deps.now === 'function' ? deps.now : Date.now;
    this.embedText = typeof deps.embedText === 'function' ? deps.embedText : null;
    this.sessions = new Map();
    this.nextCleanupAt = 0;
  }

  isEnabled() {
    return this.enabled === true && this.acknowledgement === this.requiredAcknowledgement;
  }

  deriveSessionKey(headers = {}, correlationId = '') {
    const primary = normalizeSessionValue(mapHeaderValue(headers, this.keyHeader));
    if (primary) {
      return `hdr:${this.keyHeader}:${primary}`;
    }
    for (const fallback of this.fallbackKeyHeaders) {
      const value = normalizeSessionValue(mapHeaderValue(headers, fallback));
      if (value) {
        return `hdr:${fallback}:${value}`;
      }
    }
    const corr = normalizeSessionValue(correlationId);
    if (corr) {
      return `corr:${corr}`;
    }
    return 'epistemic:anonymous';
  }

  cleanup(nowMs = Number(this.now())) {
    if (nowMs < this.nextCleanupAt && this.sessions.size <= this.maxSessions) {
      return;
    }
    for (const [key, session] of this.sessions.entries()) {
      if (!session || Number(session.expiresAt || 0) <= nowMs) {
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
    this.nextCleanupAt = nowMs + 5000;
  }

  getSession(sessionKey, createIfMissing = false) {
    const nowMs = Number(this.now());
    this.cleanup(nowMs);
    const key = String(sessionKey || '');
    let session = this.sessions.get(key);
    if (!session && createIfMissing) {
      session = {
        turnCount: 0,
        anchorVector: null,
        anchorHash: null,
        expiresAt: nowMs + 24 * 3600000,
        blockedUntil: 0,
      };
      this.sessions.set(key, session);
    }
    if (!session) {
      return null;
    }
    session.expiresAt = nowMs + 24 * 3600000;
    this.sessions.delete(key);
    this.sessions.set(key, session);
    return session;
  }

  buildAnchorText(messages = []) {
    let systemText = '';
    let userText = '';
    for (const msg of messages) {
      const role = String(msg?.role || '').toLowerCase();
      if (!systemText && role === 'system') {
        systemText = normalizeText(extractMessageText(msg));
      }
      if (!userText && role === 'user') {
        userText = normalizeText(extractMessageText(msg));
      }
      if (systemText && userText) {
        break;
      }
    }
    return `${systemText}\n${userText}`.trim().slice(0, this.maxPromptChars);
  }

  buildCurrentText(messages = []) {
    const tail = messages.slice(Math.max(0, messages.length - this.contextWindowMessages));
    return tail
      .map((message) => `${String(message?.role || 'unknown').toLowerCase()}: ${normalizeText(extractMessageText(message))}`)
      .join('\n')
      .slice(0, this.maxPromptChars);
  }

  async embed(text) {
    if (!this.embedText) {
      throw new Error('embedder_unavailable');
    }
    return this.embedText(String(text || ''), {
      modelId: this.modelId,
      cacheDir: this.cacheDir,
      maxPromptChars: this.maxPromptChars,
    });
  }

  async evaluate({ headers = {}, bodyJson, correlationId, effectiveMode = 'monitor' } = {}) {
    if (this.enabled !== true) {
      return {
        enabled: false,
        evaluated: false,
        drifted: false,
        shouldBlock: false,
        reason: 'disabled',
      };
    }
    if (this.acknowledgement !== this.requiredAcknowledgement) {
      return {
        enabled: true,
        evaluated: false,
        drifted: false,
        shouldBlock: false,
        reason: 'ack_missing',
      };
    }
    const messages = Array.isArray(bodyJson?.messages) ? bodyJson.messages : [];
    if (messages.length === 0) {
      return {
        enabled: true,
        evaluated: false,
        drifted: false,
        shouldBlock: false,
        reason: 'no_messages',
      };
    }
    const sessionKey = this.deriveSessionKey(headers, correlationId);
    const session = this.getSession(sessionKey, true);
    if (!session) {
      return {
        enabled: true,
        evaluated: false,
        drifted: false,
        shouldBlock: false,
        reason: 'session_unavailable',
      };
    }
    session.turnCount += 1;
    if (session.turnCount < this.minTurns || (session.turnCount % this.sampleEveryTurns !== 0)) {
      return {
        enabled: true,
        evaluated: false,
        drifted: false,
        shouldBlock: false,
        reason: session.turnCount < this.minTurns ? 'min_turns_not_reached' : 'sampling_skip',
        turnCount: session.turnCount,
      };
    }

    const anchorText = this.buildAnchorText(messages);
    if (!anchorText) {
      return {
        enabled: true,
        evaluated: false,
        drifted: false,
        shouldBlock: false,
        reason: 'anchor_text_empty',
      };
    }

    if (!session.anchorVector) {
      const anchorVector = await this.embed(anchorText);
      if (!Array.isArray(anchorVector) || anchorVector.length === 0) {
        return {
          enabled: true,
          evaluated: true,
          drifted: false,
          shouldBlock: false,
          reason: 'anchor_embedding_failed',
        };
      }
      session.anchorVector = anchorVector;
      session.anchorHash = crypto.createHash('sha256').update(anchorText, 'utf8').digest('hex').slice(0, 16);
      return {
        enabled: true,
        evaluated: true,
        drifted: false,
        shouldBlock: false,
        reason: 'anchor_initialized',
        turnCount: session.turnCount,
        anchorHash: session.anchorHash,
      };
    }

    const currentText = this.buildCurrentText(messages);
    if (!currentText) {
      return {
        enabled: true,
        evaluated: false,
        drifted: false,
        shouldBlock: false,
        reason: 'current_text_empty',
      };
    }
    const currentVector = await this.embed(currentText);
    if (!Array.isArray(currentVector) || currentVector.length === 0) {
      return {
        enabled: true,
        evaluated: true,
        drifted: false,
        shouldBlock: false,
        reason: 'current_embedding_failed',
      };
    }

    const similarity = cosineSimilarity(session.anchorVector, currentVector);
    const distance = 1 - similarity;
    const drifted = distance >= this.threshold;
    const nowMs = Number(this.now());
    if (drifted && nowMs > Number(session.blockedUntil || 0)) {
      session.blockedUntil = nowMs + this.cooldownMs;
    }
    const shouldBlock = drifted && this.mode === 'block' && String(effectiveMode || '') === 'enforce';

    return {
      enabled: true,
      evaluated: true,
      drifted,
      shouldBlock,
      reason: drifted ? 'anchor_divergence' : 'within_threshold',
      similarity: Number(similarity.toFixed(6)),
      distance: Number(distance.toFixed(6)),
      threshold: this.threshold,
      turnCount: session.turnCount,
      blockedUntil: Number(session.blockedUntil || 0),
      anchorHash: session.anchorHash,
    };
  }
}

module.exports = {
  EpistemicAnchor,
  cosineSimilarity,
};
