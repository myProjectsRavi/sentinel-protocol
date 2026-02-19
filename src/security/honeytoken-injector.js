const crypto = require('crypto');

function clampProbability(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 1) {
    return fallback;
  }
  return parsed;
}

function clampPositiveInt(value, fallback, min = 1, max = 1000) {
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

function sanitizePrefix(value, fallback = 'SNTL') {
  const raw = String(value || '').trim();
  if (!raw) {
    return fallback;
  }
  const sanitized = raw.replace(/[^a-zA-Z0-9_-]/g, '');
  return sanitized || fallback;
}

function encodeInvisibleToken(token) {
  const bytes = Buffer.from(String(token || ''), 'utf8');
  const parts = [];
  for (const byte of bytes) {
    for (let bit = 7; bit >= 0; bit -= 1) {
      const isOne = ((byte >> bit) & 1) === 1;
      parts.push(isOne ? '\u200C' : '\u200B');
    }
  }
  return `\u2063${parts.join('')}\u2063`;
}

function cloneJson(input) {
  return JSON.parse(JSON.stringify(input));
}

function pickCandidates(messages, targetRoles) {
  const candidates = [];
  for (let idx = 0; idx < messages.length; idx += 1) {
    const message = messages[idx];
    if (!message || typeof message !== 'object') {
      continue;
    }
    const role = String(message.role || '').toLowerCase();
    if (!targetRoles.has(role)) {
      continue;
    }
    if (typeof message.content === 'string' && message.content.length > 0) {
      candidates.push({
        messageIndex: idx,
        contentType: 'string',
      });
      continue;
    }
    if (Array.isArray(message.content)) {
      for (let partIndex = 0; partIndex < message.content.length; partIndex += 1) {
        const part = message.content[partIndex];
        if (!part || typeof part !== 'object') {
          continue;
        }
        if (String(part.type || '').toLowerCase() !== 'text') {
          continue;
        }
        if (typeof part.text === 'string' && part.text.length > 0) {
          candidates.push({
            messageIndex: idx,
            contentType: 'text_part',
            partIndex,
          });
        }
      }
    }
  }
  return candidates;
}

class HoneytokenInjector {
  constructor(config = {}, options = {}) {
    this.enabled = config.enabled === true;
    this.mode = String(config.mode || 'zero_width').toLowerCase() === 'uuid_suffix' ? 'uuid_suffix' : 'zero_width';
    this.injectionRate = clampProbability(config.injection_rate, 0.05);
    this.maxInsertionsPerRequest = clampPositiveInt(config.max_insertions_per_request, 1, 1, 10);
    this.targetRoles = new Set(
      Array.isArray(config.target_roles)
        ? config.target_roles.map((item) => String(item || '').toLowerCase()).filter(Boolean)
        : ['user']
    );
    this.tokenPrefix = sanitizePrefix(config.token_prefix || 'SNTL');
    this.random = typeof options.random === 'function' ? options.random : Math.random;
  }

  isEnabled() {
    return this.enabled === true;
  }

  shouldInject() {
    return this.isEnabled() && this.random() < this.injectionRate;
  }

  generateToken() {
    return `${this.tokenPrefix}-${crypto.randomUUID()}`;
  }

  createMarker(token) {
    if (this.mode === 'uuid_suffix') {
      return ` ${token}`;
    }
    return encodeInvisibleToken(token);
  }

  applyMarkerToMessage(message, candidate, marker) {
    if (candidate.contentType === 'string') {
      message.content = `${message.content}${marker}`;
      return;
    }
    if (candidate.contentType === 'text_part') {
      const part = message.content[candidate.partIndex];
      part.text = `${part.text}${marker}`;
    }
  }

  inject(input = {}) {
    if (!this.isEnabled()) {
      return {
        applied: false,
        reason: 'disabled',
      };
    }
    if (!this.shouldInject()) {
      return {
        applied: false,
        reason: 'sampled_out',
      };
    }

    const bodyJson = input.bodyJson && typeof input.bodyJson === 'object' ? cloneJson(input.bodyJson) : null;
    if (!bodyJson || !Array.isArray(bodyJson.messages)) {
      return {
        applied: false,
        reason: 'unsupported_payload',
      };
    }

    const candidates = pickCandidates(bodyJson.messages, this.targetRoles);
    if (candidates.length === 0) {
      return {
        applied: false,
        reason: 'no_target_messages',
      };
    }

    const token = this.generateToken();
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const marker = this.createMarker(token);
    let appliedCount = 0;
    const usedIndices = new Set();
    const locations = [];
    while (appliedCount < this.maxInsertionsPerRequest && usedIndices.size < candidates.length) {
      const idx = Math.floor(this.random() * candidates.length);
      if (usedIndices.has(idx)) {
        continue;
      }
      usedIndices.add(idx);
      const candidate = candidates[idx];
      const message = bodyJson.messages[candidate.messageIndex];
      this.applyMarkerToMessage(message, candidate, marker);
      locations.push({
        message_index: candidate.messageIndex,
        content_type: candidate.contentType,
        part_index: candidate.partIndex,
      });
      appliedCount += 1;
    }

    return {
      applied: appliedCount > 0,
      bodyJson,
      bodyText: JSON.stringify(bodyJson),
      meta: {
        mode: this.mode,
        token_hash: tokenHash,
        insertions: appliedCount,
        locations,
      },
    };
  }
}

module.exports = {
  HoneytokenInjector,
  encodeInvisibleToken,
};
