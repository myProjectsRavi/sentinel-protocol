const { parentPort } = require('worker_threads');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { PIIScanner } = require('../engines/pii-scanner');
const { InjectionScanner } = require('../engines/injection-scanner');
const { flattenToVector } = require('../engines/neural-injection-classifier');

const piiScannerCache = new Map();
const injectionScannerCache = new Map();
const embedderCache = new Map();

function positiveIntOr(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}

function getPIIScanner(options = {}) {
  const maxScanBytes = positiveIntOr(options.maxScanBytes, 262144);
  const regexSafetyCapBytes = positiveIntOr(options.regexSafetyCapBytes, 51200);
  const redactionMode = String(options.redactionMode || 'placeholder').toLowerCase();
  const redactionSalt = String(options.redactionSalt || '');
  const key = `${maxScanBytes}:${regexSafetyCapBytes}:${redactionMode}:${redactionSalt}`;
  if (!piiScannerCache.has(key)) {
    piiScannerCache.set(
      key,
      new PIIScanner({
        maxScanBytes,
        regexSafetyCapBytes,
        redactionMode,
        redactionSalt,
      })
    );
  }
  return piiScannerCache.get(key);
}

function getInjectionScanner(options = {}) {
  const maxScanBytes = positiveIntOr(options.maxScanBytes, 131072);
  const key = `${maxScanBytes}`;
  if (!injectionScannerCache.has(key)) {
    injectionScannerCache.set(
      key,
      new InjectionScanner({
        maxScanBytes,
      })
    );
  }
  return injectionScannerCache.get(key);
}

function resolveUserPath(rawPath) {
  if (typeof rawPath !== 'string' || rawPath.length === 0) {
    return rawPath;
  }
  if (rawPath === '~') {
    return os.homedir();
  }
  if (rawPath.startsWith('~/') || rawPath.startsWith('~\\')) {
    return path.join(os.homedir(), rawPath.slice(2));
  }
  return rawPath;
}

async function getEmbedder(options = {}) {
  const modelId = String(options.modelId || 'Xenova/all-MiniLM-L6-v2');
  const cacheDir = resolveUserPath(String(options.cacheDir || path.join(os.homedir(), '.sentinel', 'models')));
  const key = `${modelId}|${cacheDir}`;
  if (embedderCache.has(key)) {
    return embedderCache.get(key);
  }

  const loading = (async () => {
    fs.mkdirSync(cacheDir, { recursive: true });
    const mod = await import('@xenova/transformers');
    const { pipeline, env } = mod;
    if (env) {
      env.allowRemoteModels = true;
      env.allowLocalModels = true;
      env.cacheDir = cacheDir;
      env.localModelPath = cacheDir;
    }
    const extractor = await pipeline('feature-extraction', modelId, {
      quantized: true,
    });
    return async (text) => {
      const output = await extractor(text, {
        pooling: 'mean',
        normalize: true,
      });
      return flattenToVector(output);
    };
  })();

  embedderCache.set(key, loading);
  try {
    return await loading;
  } catch (error) {
    embedderCache.delete(key);
    throw error;
  }
}

function scanPayload(payload = {}) {
  const text = typeof payload.text === 'string' ? payload.text : '';
  const piiScanner = getPIIScanner(payload.pii || {});
  const injectionEnabled = payload.injection?.enabled !== false;
  const injectionScanner = getInjectionScanner(payload.injection || {});

  const piiResult = piiScanner.scan(text, {
    maxScanBytes: payload.pii?.maxScanBytes,
    regexSafetyCapBytes: payload.pii?.regexSafetyCapBytes,
    redactionMode: payload.pii?.redactionMode,
    redactionSalt: payload.pii?.redactionSalt,
  });
  const injectionResult = injectionEnabled
    ? injectionScanner.scan(text, {
        maxScanBytes: payload.injection?.maxScanBytes,
      })
    : { score: 0, matchedSignals: [], scanTruncated: false };

  return {
    piiResult,
    injectionResult,
  };
}

async function embedPayload(payload = {}) {
  const text = typeof payload.text === 'string' ? payload.text : '';
  if (text.length === 0) {
    return {
      vector: [],
    };
  }

  const maxChars = positiveIntOr(payload.maxPromptChars, 2000);
  const truncatedText = text.length > maxChars ? text.slice(0, maxChars) : text;
  const embed = await getEmbedder({
    modelId: payload.modelId,
    cacheDir: payload.cacheDir,
  });
  const vector = await embed(truncatedText);
  return {
    vector,
    truncated: truncatedText.length !== text.length,
  };
}

parentPort.on('message', async (message) => {
  const id = message?.id;
  const kind = message?.kind || 'scan';
  try {
    let result;
    if (kind === 'embed') {
      result = await embedPayload(message?.payload || {});
    } else {
      result = scanPayload(message?.payload || {});
    }
    parentPort.postMessage({
      id,
      ok: true,
      result,
    });
  } catch (error) {
    parentPort.postMessage({
      id,
      ok: false,
      error: error.message,
    });
  }
});
