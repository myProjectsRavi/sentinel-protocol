const crypto = require('crypto');

function clampPositiveInteger(value, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
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

function normalizeAction(value, fallback = 'block') {
  const normalized = String(value || fallback).toLowerCase();
  return normalized === 'warn' ? 'warn' : 'block';
}

function toCanonicalObject(value) {
  if (value === null || value === undefined) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => toCanonicalObject(item));
  }
  if (typeof value !== 'object') {
    return value;
  }
  const out = {};
  for (const key of Object.keys(value).sort()) {
    out[key] = toCanonicalObject(value[key]);
  }
  return out;
}

function normalizeText(value) {
  return String(value || '')
    .replace(/\s+/g, ' ')
    .trim();
}

function isVolatileKey(key) {
  const normalized = String(key || '').toLowerCase();
  return normalized === 'metadata'
    || normalized === 'id'
    || normalized === 'trace_id'
    || normalized === 'traceid'
    || normalized === 'timestamp'
    || normalized === 'request_id'
    || normalized === 'requestid'
    || normalized === 'run_id'
    || normalized === 'span_id'
    || normalized === 'session_id'
    || normalized === 'nonce'
    || normalized === 'uuid'
    || normalized === 'created_at'
    || normalized === 'updated_at';
}

function normalizeStructuredValue(value) {
  if (value === null || value === undefined) {
    return value;
  }
  if (typeof value === 'string') {
    return normalizeText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalizeStructuredValue(item));
  }
  if (typeof value !== 'object') {
    return value;
  }

  const out = {};
  for (const key of Object.keys(value).sort()) {
    if (isVolatileKey(key)) {
      continue;
    }
    out[key] = normalizeStructuredValue(value[key]);
  }
  return out;
}

function normalizeMessages(messages) {
  if (!Array.isArray(messages)) {
    return null;
  }

  return messages.map((message) => {
    if (typeof message === 'string') {
      return normalizeText(message);
    }
    if (!message || typeof message !== 'object') {
      return message;
    }

    const normalized = {};
    if (message.role !== undefined) {
      normalized.role = normalizeText(message.role);
    }
    if (message.name !== undefined) {
      normalized.name = normalizeText(message.name);
    }
    if (message.content !== undefined) {
      normalized.content = normalizeStructuredValue(message.content);
    }
    if (message.function_call && typeof message.function_call === 'object') {
      normalized.function_call = {
        name: normalizeText(message.function_call.name || ''),
        arguments: normalizeStructuredValue(message.function_call.arguments),
      };
    }
    if (Array.isArray(message.tool_calls)) {
      normalized.tool_calls = message.tool_calls.map((toolCall) => {
        if (!toolCall || typeof toolCall !== 'object') {
          return normalizeStructuredValue(toolCall);
        }
        const out = {};
        if (toolCall.type !== undefined) {
          out.type = normalizeText(toolCall.type);
        }
        if (toolCall.function && typeof toolCall.function === 'object') {
          out.function = {
            name: normalizeText(toolCall.function.name || ''),
            arguments: normalizeStructuredValue(toolCall.function.arguments),
          };
        }
        return out;
      });
    }

    return normalized;
  });
}

function normalizeConversationState(bodyJson) {
  if (!bodyJson || typeof bodyJson !== 'object') {
    return null;
  }

  const conversation = {};

  if (Array.isArray(bodyJson.messages)) {
    conversation.messages = normalizeMessages(bodyJson.messages);
  }
  if (bodyJson.input !== undefined) {
    conversation.input = normalizeStructuredValue(bodyJson.input);
  }
  if (bodyJson.prompt !== undefined) {
    conversation.prompt = normalizeStructuredValue(bodyJson.prompt);
  }
  if (bodyJson.model !== undefined) {
    conversation.model = normalizeText(bodyJson.model);
  }
  if (Array.isArray(bodyJson.tools)) {
    conversation.tools = bodyJson.tools.map((tool) => {
      if (!tool || typeof tool !== 'object') {
        return normalizeStructuredValue(tool);
      }
      const out = {};
      if (tool.type !== undefined) {
        out.type = normalizeText(tool.type);
      }
      if (tool.function && typeof tool.function === 'object') {
        out.function = {
          name: normalizeText(tool.function.name || ''),
          description: normalizeStructuredValue(tool.function.description),
          parameters: normalizeStructuredValue(tool.function.parameters),
        };
      }
      return out;
    });
  }

  if (Object.keys(conversation).length === 0) {
    return null;
  }
  return JSON.stringify(toCanonicalObject(conversation));
}

function normalizeBody(bodyText, bodyJson) {
  if (bodyJson && typeof bodyJson === 'object') {
    const conversationState = normalizeConversationState(bodyJson);
    if (conversationState) {
      return conversationState;
    }
    try {
      return JSON.stringify(toCanonicalObject(normalizeStructuredValue(bodyJson)));
    } catch {
      // fall through to text normalization
    }
  }
  return normalizeText(bodyText);
}

function extractAgentId(headers = {}, keyHeader = 'x-sentinel-agent-id') {
  if (headers[keyHeader]) {
    return String(headers[keyHeader]);
  }
  if (headers['x-forwarded-for']) {
    return String(headers['x-forwarded-for']).split(',')[0].trim();
  }
  if (headers['user-agent']) {
    return String(headers['user-agent']);
  }
  return 'anonymous';
}

function sha256(text) {
  return crypto.createHash('sha256').update(String(text)).digest('hex');
}

class LoopBreaker {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.action = normalizeAction(config.action, 'block');
    this.windowMs = clampPositiveInteger(config.window_ms, 30000, { min: 1000, max: 600000 });
    this.repeatThreshold = clampPositiveInteger(config.repeat_threshold, 4, { min: 2, max: 20 });
    this.maxRecent = clampPositiveInteger(config.max_recent, 5, { min: this.repeatThreshold, max: 100 });
    this.maxKeys = clampPositiveInteger(config.max_keys, 2048, { min: 64, max: 500000 });
    this.keyHeader = String(config.key_header || 'x-sentinel-agent-id').toLowerCase();
    this.state = new Map();
  }

  touch(key) {
    const entry = this.state.get(key);
    if (!entry) {
      return;
    }
    this.state.delete(key);
    this.state.set(key, entry);
  }

  ensureCapacity() {
    while (this.state.size > this.maxKeys) {
      const oldestKey = this.state.keys().next().value;
      if (!oldestKey) {
        break;
      }
      this.state.delete(oldestKey);
    }
  }

  pruneRecords(records, now) {
    const minTime = now - this.windowMs;
    const filtered = records.filter((item) => item.ts >= minTime);
    if (filtered.length <= this.maxRecent) {
      return filtered;
    }
    return filtered.slice(filtered.length - this.maxRecent);
  }

  detectRecentLoop(records, hash, now) {
    if (records.length < this.repeatThreshold) {
      return {
        detected: false,
        streak: 1,
      };
    }

    let streak = 0;
    for (let idx = records.length - 1; idx >= 0; idx -= 1) {
      if (records[idx].hash !== hash) {
        break;
      }
      streak += 1;
    }

    if (streak < this.repeatThreshold) {
      return {
        detected: false,
        streak,
      };
    }

    const thresholdIndex = records.length - this.repeatThreshold;
    const thresholdRecord = records[thresholdIndex];
    const withinWindow = thresholdRecord && now - thresholdRecord.ts <= this.windowMs;

    return {
      detected: Boolean(withinWindow),
      streak,
    };
  }

  evaluate(input = {}) {
    if (!this.enabled) {
      return {
        enabled: false,
        detected: false,
        shouldBlock: false,
      };
    }

    const now = Number(input.now || Date.now());
    const normalizedBody = normalizeBody(input.bodyText, input.bodyJson);
    if (!normalizedBody) {
      return {
        enabled: true,
        detected: false,
        shouldBlock: false,
        reason: 'empty_body',
      };
    }

    const agentId = extractAgentId(input.headers || {}, this.keyHeader);
    const provider = String(input.provider || 'unknown').toLowerCase();
    const path = String(input.path || '/');
    const method = String(input.method || 'POST').toUpperCase();
    const identityKey = `${provider}|${path}|${method}|${agentId}`;
    const hash = sha256(normalizedBody);

    const existing = this.state.get(identityKey) || [];
    existing.push({ hash, ts: now });
    const records = this.pruneRecords(existing, now);
    this.state.set(identityKey, records);
    this.touch(identityKey);
    this.ensureCapacity();

    const detection = this.detectRecentLoop(records, hash, now);
    return {
      enabled: true,
      detected: detection.detected,
      shouldBlock: detection.detected && this.action === 'block',
      action: this.action,
      streak: detection.streak,
      repeatThreshold: this.repeatThreshold,
      key: identityKey,
      hash_prefix: hash.slice(0, 12),
      within_ms: this.windowMs,
    };
  }
}

module.exports = {
  LoopBreaker,
  normalizeBody,
  extractAgentId,
};
