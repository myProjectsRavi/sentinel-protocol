const { parentPort } = require('worker_threads');

const { PIIScanner } = require('../engines/pii-scanner');
const { InjectionScanner } = require('../engines/injection-scanner');

const piiScannerCache = new Map();
const injectionScannerCache = new Map();

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

parentPort.on('message', (message) => {
  const id = message?.id;
  try {
    const result = scanPayload(message?.payload || {});
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
