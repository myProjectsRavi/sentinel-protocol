const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const { cosineSimilarity, flattenToVector, resolveUserPath } = require('../engines/neural-injection-classifier');

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

class SemanticCache {
  constructor(config = {}) {
    const normalized = normalizeCacheMode(config);
    this.enabled = normalized.enabled;
    this.modelId = normalized.modelId;
    this.cacheDir = normalized.cacheDir;
    this.similarityThreshold = Math.max(0, Math.min(1, normalized.similarityThreshold));
    this.maxEntries = Math.max(1, Math.floor(normalized.maxEntries));
    this.ttlMs = Math.max(0, Math.floor(normalized.ttlMs));
    this.maxPromptChars = Math.max(64, Math.floor(normalized.maxPromptChars));

    this.embedFn = null;
    this.embedderPromise = null;
    this.nextEntryId = 1;
    this.entries = new Map();
    this.byContext = new Map();
    this.order = [];
  }

  isEnabled() {
    return this.enabled === true;
  }

  isEligibleRequest(input = {}) {
    if (!this.isEnabled()) {
      return { eligible: false, reason: 'disabled' };
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

  async loadEmbedder() {
    if (!this.isEnabled()) {
      return null;
    }
    if (this.embedFn) {
      return this.embedFn;
    }
    if (this.embedderPromise) {
      return this.embedderPromise;
    }

    this.embedderPromise = (async () => {
      fs.mkdirSync(this.cacheDir, { recursive: true });
      const mod = await import('@xenova/transformers');
      const { pipeline, env } = mod;
      if (env) {
        env.allowRemoteModels = true;
        env.allowLocalModels = true;
        env.cacheDir = this.cacheDir;
        env.localModelPath = this.cacheDir;
      }
      const extractor = await pipeline('feature-extraction', this.modelId, {
        quantized: true,
      });
      this.embedFn = async (text) => {
        const output = await extractor(text, {
          pooling: 'mean',
          normalize: true,
        });
        return flattenToVector(output);
      };
      return this.embedFn;
    })();

    try {
      return await this.embedderPromise;
    } catch (error) {
      this.embedderPromise = null;
      throw error;
    }
  }

  async embedPrompt(promptText) {
    const prompt = String(promptText || '').slice(0, this.maxPromptChars);
    const embed = await this.loadEmbedder();
    if (!embed) {
      return [];
    }
    return embed(prompt);
  }

  isExpired(entry, now) {
    if (this.ttlMs <= 0) {
      return false;
    }
    return now - entry.createdAt > this.ttlMs;
  }

  removeEntry(entryId) {
    const existing = this.entries.get(entryId);
    if (!existing) {
      return;
    }
    this.entries.delete(entryId);
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
    while (this.entries.size > this.maxEntries && this.order.length > 0) {
      const id = this.order.shift();
      this.removeEntry(id);
    }
  }

  async lookup(input = {}) {
    if (!this.isEnabled()) {
      return { hit: false, reason: 'disabled' };
    }
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

    return {
      hit: true,
      similarity: Number(best.similarity.toFixed(4)),
      response: {
        status: best.entry.response.status,
        headers: best.entry.response.headers,
        bodyBuffer: Buffer.from(best.entry.response.bodyBase64, 'base64'),
      },
    };
  }

  async store(input = {}) {
    if (!this.isEnabled()) {
      return { stored: false, reason: 'disabled' };
    }
    const eligibility = this.isEligibleRequest(input);
    if (!eligibility.eligible) {
      return { stored: false, reason: eligibility.reason || 'ineligible' };
    }
    if (!Buffer.isBuffer(input.responseBodyBuffer) || input.responseBodyBuffer.length === 0) {
      return { stored: false, reason: 'response_empty' };
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
        bodyBase64: input.responseBodyBuffer.toString('base64'),
      },
    };
    this.entries.set(id, entry);
    if (!this.byContext.has(eligibility.contextKey)) {
      this.byContext.set(eligibility.contextKey, []);
    }
    this.byContext.get(eligibility.contextKey).push(id);
    this.order.push(id);
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
