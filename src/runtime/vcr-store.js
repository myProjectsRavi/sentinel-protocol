const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

const { SENTINEL_HOME } = require('../utils/paths');
const { normalizeMode } = require('../utils/primitives');

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function sanitizeResponseHeaders(headers = {}) {
  const allowed = new Set([
    'content-type',
    'cache-control',
    'retry-after',
    'x-request-id',
    'x-ratelimit-limit',
    'x-ratelimit-remaining',
    'x-ratelimit-reset',
  ]);
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

function normalizeTapePath(rawPath) {
  if (!rawPath || typeof rawPath !== 'string') {
    return path.join(SENTINEL_HOME, 'vcr-tape.jsonl');
  }
  if (rawPath.startsWith('~/')) {
    return path.join(process.env.HOME || SENTINEL_HOME, rawPath.slice(2));
  }
  return rawPath;
}

function buildSignature(input = {}) {
  const payload = {
    provider: String(input.provider || 'unknown'),
    method: String(input.method || 'GET').toUpperCase(),
    path_with_query: String(input.pathWithQuery || '/'),
    body_sha256: sha256Hex(Buffer.isBuffer(input.bodyBuffer) ? input.bodyBuffer : Buffer.alloc(0)),
    content_type: String(input.contentType || '').toLowerCase(),
    wants_stream: Boolean(input.wantsStream),
  };
  return sha256Hex(JSON.stringify(payload));
}

function safeParseLine(line) {
  try {
    return JSON.parse(line);
  } catch {
    return null;
  }
}

class VCRStore {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'off', ['off', 'record', 'replay']);
    this.strictReplay = config.strict_replay === true;
    this.maxEntries = Number(config.max_entries || 2000);
    this.tapePath = normalizeTapePath(config.tape_file);
    this.entryCount = 0;
    this.replayIndex = new Map();
    this.writeTail = Promise.resolve();
    this.loaded = false;
    this.loadPromise = null;
  }

  isActive() {
    return this.enabled && this.mode !== 'off';
  }

  async loadTape() {
    if (!fs.existsSync(this.tapePath)) {
      this.loaded = true;
      return;
    }

    const stream = fs.createReadStream(this.tapePath, {
      encoding: 'utf8',
      highWaterMark: 64 * 1024,
    });
    const rl = readline.createInterface({
      input: stream,
      crlfDelay: Infinity,
    });

    try {
      for await (const line of rl) {
        if (!line) {
          continue;
        }
        const entry = safeParseLine(line);
        if (!entry || typeof entry.signature !== 'string' || !entry.response) {
          continue;
        }
        if (!this.replayIndex.has(entry.signature)) {
          this.replayIndex.set(entry.signature, entry);
        }
        this.entryCount += 1;
        if (this.entryCount >= this.maxEntries) {
          rl.close();
          stream.destroy();
          break;
        }
      }
      this.loaded = true;
    } finally {
      rl.close();
      stream.destroy();
    }
  }

  async ensureLoaded() {
    if (this.loaded) {
      return;
    }
    if (!this.loadPromise) {
      this.loadPromise = this.loadTape().finally(() => {
        this.loadPromise = null;
      });
    }
    await this.loadPromise;
  }

  async lookup(requestMeta = {}) {
    if (!this.enabled || this.mode !== 'replay') {
      return {
        hit: false,
        strictReplay: false,
      };
    }

    await this.ensureLoaded();

    const signature = buildSignature(requestMeta);
    const entry = this.replayIndex.get(signature);
    if (!entry) {
      return {
        hit: false,
        strictReplay: this.strictReplay,
      };
    }

    return {
      hit: true,
      strictReplay: this.strictReplay,
      signature,
      response: {
        status: Number(entry.response.status || 200),
        headers: sanitizeResponseHeaders(entry.response.headers || {}),
        bodyBuffer: Buffer.from(String(entry.response.body_base64 || ''), 'base64'),
      },
    };
  }

  record(requestMeta = {}, responseMeta = {}) {
    if (!this.enabled || this.mode !== 'record') {
      return;
    }

    if (this.entryCount >= this.maxEntries) {
      return;
    }

    if (!Buffer.isBuffer(responseMeta.bodyBuffer)) {
      return;
    }

    const signature = buildSignature(requestMeta);
    const entry = {
      version: 1,
      signature,
      recorded_at: new Date().toISOString(),
      request: {
        provider: String(requestMeta.provider || 'unknown'),
        method: String(requestMeta.method || 'GET').toUpperCase(),
        path_with_query: String(requestMeta.pathWithQuery || '/'),
        body_sha256: sha256Hex(Buffer.isBuffer(requestMeta.bodyBuffer) ? requestMeta.bodyBuffer : Buffer.alloc(0)),
        content_type: String(requestMeta.contentType || '').toLowerCase(),
        wants_stream: Boolean(requestMeta.wantsStream),
      },
      response: {
        status: Number(responseMeta.status || 200),
        headers: sanitizeResponseHeaders(responseMeta.headers || {}),
        body_base64: responseMeta.bodyBuffer.toString('base64'),
      },
    };

    const line = `${JSON.stringify(entry)}\n`;
    this.entryCount += 1;

    this.writeTail = this.writeTail
      .then(async () => {
        await fs.promises.mkdir(path.dirname(this.tapePath), { recursive: true });
        await fs.promises.appendFile(this.tapePath, line, 'utf8');
      })
      .catch(() => {});
  }

  async flush() {
    await this.writeTail;
  }
}

module.exports = {
  VCRStore,
  buildSignature,
  normalizeMode,
  normalizeTapePath,
  sanitizeResponseHeaders,
};
