const fs = require('fs');
const os = require('os');
const path = require('path');

function maxSeverity(a, b) {
  const rank = { low: 1, medium: 2, high: 3, critical: 4 };
  if (!a) return b;
  if (!b) return a;
  return rank[b] > rank[a] ? b : a;
}

function toEntityType(raw) {
  const value = String(raw || '').toUpperCase();
  if (value.includes('PER') || value.includes('PERSON')) return 'person';
  if (value.includes('ORG')) return 'org';
  if (value.includes('LOC') || value.includes('GPE')) return 'location';
  return null;
}

function redactRanges(text, ranges) {
  if (!Array.isArray(ranges) || ranges.length === 0) {
    return text;
  }

  const sorted = [...ranges].sort((a, b) => a.start - b.start);
  const merged = [];
  for (const range of sorted) {
    if (merged.length === 0) {
      merged.push({ ...range });
      continue;
    }
    const last = merged[merged.length - 1];
    if (range.start <= last.end) {
      last.end = Math.max(last.end, range.end);
      last.label = range.label;
    } else {
      merged.push({ ...range });
    }
  }

  let out = '';
  let cursor = 0;
  for (const range of merged) {
    out += text.slice(cursor, range.start);
    out += `[REDACTED_SEMANTIC_${String(range.label || 'ENTITY').toUpperCase()}]`;
    cursor = range.end;
  }
  out += text.slice(cursor);
  return out;
}

class SemanticScanner {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.modelId = config.model_id || 'Xenova/bert-base-NER';
    this.scoreThreshold = Number(config.score_threshold ?? 0.6);
    this.maxScanBytes = Number(config.max_scan_bytes ?? 32768);
    this.cacheDir = config.cache_dir || path.join(os.homedir(), '.sentinel', 'models');
    this.pipelinePromise = null;
    this.loadError = null;
  }

  async loadPipeline() {
    if (!this.enabled) {
      return null;
    }

    if (this.pipelinePromise) {
      return this.pipelinePromise;
    }

    this.pipelinePromise = (async () => {
      fs.mkdirSync(this.cacheDir, { recursive: true });
      const mod = await import('@xenova/transformers');
      const { pipeline, env } = mod;

      if (env) {
        env.allowRemoteModels = true;
        env.allowLocalModels = true;
        env.cacheDir = this.cacheDir;
        env.localModelPath = this.cacheDir;
      }

      return pipeline('token-classification', this.modelId, {
        quantized: true,
      });
    })();

    try {
      return await this.pipelinePromise;
    } catch (error) {
      this.loadError = error;
      this.pipelinePromise = null;
      throw error;
    }
  }

  async scan(input, options = {}) {
    if (!this.enabled || typeof input !== 'string' || input.length === 0) {
      return {
        findings: [],
        redactedText: input,
        highestSeverity: null,
        scanTruncated: false,
        enabled: this.enabled,
      };
    }

    const maxBytes = Number(options.maxScanBytes ?? this.maxScanBytes);
    const inputBytes = Buffer.byteLength(input, 'utf8');
    const scanTruncated = inputBytes > maxBytes;
    const text = scanTruncated ? Buffer.from(input).subarray(0, maxBytes).toString('utf8') : input;

    let ner;
    try {
      ner = await this.loadPipeline();
    } catch (error) {
      return {
        findings: [],
        redactedText: text,
        highestSeverity: null,
        scanTruncated,
        enabled: true,
        error: error.message,
      };
    }

    const entities = await ner(text, {
      aggregation_strategy: 'simple',
    });

    const findings = [];
    const ranges = [];
    let highest = null;

    for (const entity of entities || []) {
      const type = toEntityType(entity.entity_group || entity.entity);
      if (!type) {
        continue;
      }
      if (Number(entity.score || 0) < this.scoreThreshold) {
        continue;
      }

      const value = String(entity.word || '').trim();
      if (!value) {
        continue;
      }

      findings.push({
        id: `semantic_${type}`,
        severity: 'medium',
        value,
      });
      highest = maxSeverity(highest, 'medium');

      if (Number.isInteger(entity.start) && Number.isInteger(entity.end) && entity.end > entity.start) {
        ranges.push({
          start: entity.start,
          end: entity.end,
          label: type,
        });
      }
    }

    const redactedText = redactRanges(text, ranges);
    return {
      findings,
      redactedText,
      highestSeverity: highest,
      scanTruncated,
      enabled: true,
      modelId: this.modelId,
    };
  }
}

module.exports = {
  SemanticScanner,
};
