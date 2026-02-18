const os = require('os');
const path = require('path');
const crypto = require('crypto');

const { cosineSimilarity, resolveUserPath } = require('../engines/neural-injection-classifier');

function sha256Hex(input) {
  return crypto.createHash('sha256').update(String(input)).digest('hex');
}

function sanitizeResponseHeaders(headers = {}) {
  const allowed = new Set(['content-type', 'cache-control']);
  const out = {};
  for (const [key, value] of Object.entries(headers || {})) {
    const lowered = String(key).toLowerCase();
    if (!allowed.has(lowered)) {
      continue;
    }
    out[lowered] = String(value);
  }
  return out;
}

function stableStringify(value) {
  if (value === null || value === undefined) {
    return 'null';
  }
  if (typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  const pairs = keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`);
  return `{${pairs.join(',')}}`;
}

function normalizeCacheMode(config = {}) {
  const enabled = config.enabled === true;
  return {
    enabled,
    modelId: config.model_id || 'Xenova/all-MiniLM-L6-v2',
    cacheDir: resolveUserPath(config.cache_dir) || path.join(os.homedir(), '.sentinel', 'models'),
    similarityThreshold: Number(config.similarity_threshold ?? 0.95),
    maxEntries: Number(config.max_entries ?? 2000),
    ttlMs: Number(config.ttl_ms ?? 3600000),
    maxPromptChars: Number(config.max_prompt_chars ?? 2000),
    maxEntryBytes: Number(config.max_entry_bytes ?? 262144),
    maxRamMb: Number(config.max_ram_mb ?? 64),
  };
}

function extractPromptText(bodyJson, fallbackBodyText = '') {
  if (bodyJson && Array.isArray(bodyJson.messages)) {
    const userMessages = bodyJson.messages.filter((msg) => String(msg?.role).toLowerCase() === 'user');
    if (userMessages.length > 0) {
      return userMessages.map((msg) => String(msg.content || '')).join('\n').trim();
    }
  }
  return String(fallbackBodyText || '').trim();
}

function extractContextKey(input = {}) {
  const {
    provider,
    pathWithQuery,
    bodyJson,
    model,
    temperature,
    topP,
    systemPrompt,
    tools,
    responseFormat,
  } = input;
  const payload = {
    provider: String(provider || 'unknown'),
    path: String(pathWithQuery || '/'),
    model: model == null ? null : String(model),
    temperature: temperature == null ? null : Number(temperature),
    top_p: topP == null ? null : Number(topP),
    system_prompt: systemPrompt == null ? null : String(systemPrompt),
    tools_hash: sha256Hex(stableStringify(tools ?? bodyJson?.tools ?? null)),
    response_format_hash: sha256Hex(stableStringify(responseFormat ?? bodyJson?.response_format ?? null)),
  };
  return sha256Hex(stableStringify(payload));
}

function headersBytes(headers = {}) {
  let total = 0;
  for (const [key, value] of Object.entries(headers)) {
    total += Buffer.byteLength(String(key), 'utf8');
    total += Buffer.byteLength(String(value), 'utf8');
  }
  return total;
}

class SemanticCache {
  constructor(config = {}, deps = {}) {
    const normalized = normalizeCacheMode(config);
    this.enabled = normalized.enabled;
    this.modelId = normalized.modelId;
    this.cacheDir = normalized.cacheDir;
    this.similarityThreshold = Math.max(0, Math.min(1, normalized.similarityThreshold));
    this.maxEntries = Math.max(1, Math.floor(normalized.maxEntries));
    this.ttlMs = Math.max(0, Math.floor(normalized.ttlMs));
    this.maxPromptChars = Math.max(64, Math.floor(normalized.maxPromptChars));
    this.maxEntryBytes = Math.max(1, Math.floor(normalized.maxEntryBytes));
    this.maxRamBytes = Math.max(this.maxEntryBytes, Math.floor(normalized.maxRamMb * 1024 * 1024));
    this.scanWorkerPool = deps.scanWorkerPool || null;

    this.nextEntryId = 1;
    this.entries = new Map();
    this.byContext = new Map();
    this.order = new Map();
    this.currentBytes = 0;
  }

  isEnabled() {
    return this.enabled === true && this.scanWorkerPool?.enabled === true;
  }

  isEligibleRequest(input = {}) {
    if (!this.enabled) {
      return { eligible: false, reason: 'disabled' };
    }
    if (!this.scanWorkerPool || this.scanWorkerPool.enabled !== true) {
      return { eligible: false, reason: 'worker_pool_unavailable' };
    }
    if (String(input.method || '').toUpperCase() !== 'POST') {
      return { eligible: false, reason: 'method' };
    }
    if (input.wantsStream === true) {
      return { eligible: false, reason: 'stream' };
    }
    const prompt = extractPromptText(input.bodyJson, input.bodyText);
    if (!prompt || prompt.length < 4) {
      return { eligible: false, reason: 'prompt_empty' };
    }
    return {
      eligible: true,
      prompt,
      contextKey: extractContextKey({
        provider: input.provider,
        pathWithQuery: input.pathWithQuery,
        bodyJson: input.bodyJson,
        model: input.bodyJson?.model,
        temperature: input.bodyJson?.temperature,
        topP: input.bodyJson?.top_p,
        systemPrompt: Array.isArray(input.bodyJson?.messages)
          ? input.bodyJson.messages
              .filter((msg) => String(msg?.role).toLowerCase() === 'system')
              .map((msg) => String(msg.content || ''))
              .join('\n')
          : '',
        tools: input.bodyJson?.tools,
        responseFormat: input.bodyJson?.response_format,
      }),
    };
  }

  async embedPrompt(promptText) {
    const prompt = String(promptText || '').slice(0, this.maxPromptChars);
    if (!prompt) {
      return [];
    }
    const result = await this.scanWorkerPool.embed({
      text: prompt,
      modelId: this.modelId,
      cacheDir: this.cacheDir,
      maxPromptChars: this.maxPromptChars,
    });
    if (!Array.isArray(result?.vector)) {
      return [];
    }
    return result.vector;
  }

  isExpired(entry, now) {
    if (this.ttlMs <= 0) {
      return false;
    }
    return now - entry.createdAt > this.ttlMs;
  }

  estimateEntryBytes(entry) {
    const vectorBytes = Array.isArray(entry.vector) ? entry.vector.length * 8 : 0;
    const responseBytes = Buffer.isBuffer(entry.response?.bodyBuffer) ? entry.response.bodyBuffer.length : 0;
    const headerBytes = headersBytes(entry.response?.headers || {});
    const keyBytes = Buffer.byteLength(String(entry.contextKey || ''), 'utf8');
    // Add modest fixed overhead for object metadata.
    return responseBytes + vectorBytes + headerBytes + keyBytes + 256;
  }

  touchEntry(entryId) {
    if (!this.order.has(entryId)) {
      return;
    }
    this.order.delete(entryId);
    this.order.set(entryId, true);
  }

  removeEntry(entryId) {
    const existing = this.entries.get(entryId);
    if (!existing) {
      return;
    }
    this.entries.delete(entryId);
    this.currentBytes = Math.max(0, this.currentBytes - Number(existing.sizeBytes || 0));
    this.order.delete(entryId);
    const bucket = this.byContext.get(existing.contextKey);
    if (bucket) {
      const idx = bucket.indexOf(entryId);
      if (idx >= 0) {
        bucket.splice(idx, 1);
      }
      if (bucket.length === 0) {
        this.byContext.delete(existing.contextKey);
      }
    }
  }

  evictIfNeeded() {
    while ((this.entries.size > this.maxEntries || this.currentBytes > this.maxRamBytes) && this.order.size > 0) {
      const oldest = this.order.keys().next().value;
      if (oldest === undefined) {
        break;
      }
      this.removeEntry(oldest);
    }
  }

  async lookup(input = {}) {
    const eligibility = this.isEligibleRequest(input);
    if (!eligibility.eligible) {
      return { hit: false, reason: eligibility.reason || 'ineligible' };
    }

    const ids = this.byContext.get(eligibility.contextKey);
    if (!ids || ids.length === 0) {
      return { hit: false, reason: 'miss' };
    }

    const vector = await this.embedPrompt(eligibility.prompt);
    if (!Array.isArray(vector) || vector.length === 0) {
      return { hit: false, reason: 'embed_error' };
    }

    const now = Date.now();
    let best = null;
    for (const id of [...ids]) {
      const entry = this.entries.get(id);
      if (!entry) {
        continue;
      }
      if (this.isExpired(entry, now)) {
        this.removeEntry(id);
        continue;
      }
      const similarity = cosineSimilarity(vector, entry.vector);
      if (!best || similarity > best.similarity) {
        best = { similarity, entry };
      }
    }

    if (!best || best.similarity < this.similarityThreshold) {
      return { hit: false, reason: 'miss' };
    }

    this.touchEntry(best.entry.id);
    return {
      hit: true,
      similarity: Number(best.similarity.toFixed(4)),
      response: {
        status: best.entry.response.status,
        headers: best.entry.response.headers,
        bodyBuffer: Buffer.from(best.entry.response.bodyBuffer),
      },
    };
  }

  async store(input = {}) {
    const eligibility = this.isEligibleRequest(input);
    if (!eligibility.eligible) {
      return { stored: false, reason: eligibility.reason || 'ineligible' };
    }
    if (!Buffer.isBuffer(input.responseBodyBuffer) || input.responseBodyBuffer.length === 0) {
      return { stored: false, reason: 'response_empty' };
    }
    if (input.responseBodyBuffer.length > this.maxEntryBytes) {
      return { stored: false, reason: 'entry_too_large' };
    }
    const status = Number(input.responseStatus || 0);
    if (status < 200 || status >= 300) {
      return { stored: false, reason: 'status' };
    }

    const vector = await this.embedPrompt(eligibility.prompt);
    if (!Array.isArray(vector) || vector.length === 0) {
      return { stored: false, reason: 'embed_error' };
    }

    const id = this.nextEntryId++;
    const entry = {
      id,
      createdAt: Date.now(),
      contextKey: eligibility.contextKey,
      vector,
      response: {
        status,
        headers: sanitizeResponseHeaders(input.responseHeaders || {}),
        bodyBuffer: Buffer.from(input.responseBodyBuffer),
      },
    };
    entry.sizeBytes = this.estimateEntryBytes(entry);
    this.entries.set(id, entry);
    this.currentBytes += entry.sizeBytes;
    if (!this.byContext.has(eligibility.contextKey)) {
      this.byContext.set(eligibility.contextKey, []);
    }
    this.byContext.get(eligibility.contextKey).push(id);
    this.order.set(id, true);
    this.evictIfNeeded();
    return { stored: true };
  }
}

module.exports = {
  SemanticCache,
  normalizeCacheMode,
  extractPromptText,
  extractContextKey,
  stableStringify,
};
