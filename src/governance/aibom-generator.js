const { clampPositiveInt, mapHeaderValue, snippetHash } = require('../utils/primitives');

const SCHEMA_VERSION = 'sentinel.aibom.v1';
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_MAX_ENTRIES = 256;
const DEFAULT_MAX_BODY_BYTES = 128 * 1024;
const DEFAULT_MAX_TRAVERSAL_DEPTH = 8;
const DEFAULT_MAX_TRAVERSAL_NODES = 512;
const DEFAULT_MAX_TOOLS_PER_RECORD = 64;
const DEFAULT_MAX_DATASETS_PER_RECORD = 64;
const DEFAULT_MAX_DATASET_VALUE_CHARS = 512;
const DEFAULT_PRUNE_INTERVAL = 32;
const DEFAULT_EXPORT_CACHE_TTL_MS = 5000;
const DATASET_HEADER_KEYS = [
  'x-sentinel-dataset-id',
  'x-dataset-id',
  'x-dataset-name',
  'x-training-corpus',
  'x-knowledge-base-id',
];
const DATASET_KEY_RE = /(dataset|corpus|training|knowledge|index|collection|source|file|document|retriev)/i;

function normalizeId(value, options = {}) {
  const maxLength = clampPositiveInt(options.maxLength, 128, 8, 1024);
  const lowerCase = options.lowerCase !== false;
  const cleaned = String(value || '')
    .trim()
    .replace(/\s+/g, ' ');
  if (!cleaned) {
    return '';
  }
  const limited = cleaned.length > maxLength ? cleaned.slice(0, maxLength) : cleaned;
  return lowerCase ? limited.toLowerCase() : limited;
}

function toIsoTime(ms) {
  if (!Number.isFinite(Number(ms)) || Number(ms) <= 0) {
    return null;
  }
  return new Date(Number(ms)).toISOString();
}

function extractToolNamesFromValue(value, options = {}) {
  const maxDepth = clampPositiveInt(options.maxDepth, DEFAULT_MAX_TRAVERSAL_DEPTH, 1, 64);
  const maxNodes = clampPositiveInt(options.maxNodes, DEFAULT_MAX_TRAVERSAL_NODES, 16, 100000);
  const maxTools = clampPositiveInt(options.maxTools, DEFAULT_MAX_TOOLS_PER_RECORD, 1, 1024);
  const toolNames = new Set();
  const visited = new WeakSet();
  const stack = [{ node: value, depth: 0 }];
  let visitedNodes = 0;

  while (stack.length > 0 && visitedNodes < maxNodes && toolNames.size < maxTools) {
    const current = stack.pop();
    const node = current?.node;
    const depth = Number(current?.depth || 0);
    if (!node || typeof node !== 'object' || depth > maxDepth) {
      continue;
    }
    if (visited.has(node)) {
      continue;
    }
    visited.add(node);
    visitedNodes += 1;

    const maybeName = node?.function?.name || node?.name || '';
    const normalized = normalizeId(maybeName, { lowerCase: true, maxLength: 128 });
    if (normalized) {
      toolNames.add(normalized);
      if (toolNames.size >= maxTools) {
        break;
      }
    }

    if (depth >= maxDepth) {
      continue;
    }

    if (Array.isArray(node)) {
      for (let i = node.length - 1; i >= 0; i -= 1) {
        const item = node[i];
        if (item && typeof item === 'object') {
          stack.push({ node: item, depth: depth + 1 });
        }
      }
      continue;
    }

    for (const nested of Object.values(node)) {
      if (nested && typeof nested === 'object') {
        stack.push({ node: nested, depth: depth + 1 });
      }
    }
  }

  return Array.from(toolNames);
}

function parseBufferAsJson(bodyBuffer, maxBytes) {
  if (!Buffer.isBuffer(bodyBuffer) || bodyBuffer.length === 0) {
    return null;
  }
  const safeMaxBytes = clampPositiveInt(maxBytes, DEFAULT_MAX_BODY_BYTES, 1024, 2 * 1024 * 1024);
  const limited = bodyBuffer.length > safeMaxBytes ? bodyBuffer.subarray(0, safeMaxBytes) : bodyBuffer;
  try {
    return JSON.parse(limited.toString('utf8'));
  } catch {
    return null;
  }
}

function serializeDatasetValue(value, maxChars) {
  const safeMax = clampPositiveInt(maxChars, DEFAULT_MAX_DATASET_VALUE_CHARS, 32, 8192);
  if (value === null || value === undefined) {
    return '';
  }
  if (typeof value === 'string') {
    return value.slice(0, safeMax);
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  try {
    const serialized = JSON.stringify(value);
    return String(serialized || '').slice(0, safeMax);
  } catch {
    return String(value).slice(0, safeMax);
  }
}

function collectDatasetFingerprintsFromValue(value, options = {}) {
  const maxDepth = clampPositiveInt(options.maxDepth, DEFAULT_MAX_TRAVERSAL_DEPTH, 1, 64);
  const maxNodes = clampPositiveInt(options.maxNodes, DEFAULT_MAX_TRAVERSAL_NODES, 16, 100000);
  const maxFingerprints = clampPositiveInt(options.maxFingerprints, DEFAULT_MAX_DATASETS_PER_RECORD, 1, 2048);
  const maxValueChars = clampPositiveInt(options.maxValueChars, DEFAULT_MAX_DATASET_VALUE_CHARS, 32, 8192);

  const fingerprints = new Set();
  const visited = new WeakSet();
  const stack = [{ node: value, depth: 0 }];
  let visitedNodes = 0;

  while (stack.length > 0 && visitedNodes < maxNodes && fingerprints.size < maxFingerprints) {
    const current = stack.pop();
    const node = current?.node;
    const depth = Number(current?.depth || 0);
    if (!node || typeof node !== 'object' || depth > maxDepth) {
      continue;
    }
    if (visited.has(node)) {
      continue;
    }
    visited.add(node);
    visitedNodes += 1;

    if (Array.isArray(node)) {
      for (let i = node.length - 1; i >= 0; i -= 1) {
        const item = node[i];
        if (item && typeof item === 'object') {
          stack.push({ node: item, depth: depth + 1 });
        }
      }
      continue;
    }

    for (const [key, child] of Object.entries(node)) {
      const keyName = String(key || '');
      if (DATASET_KEY_RE.test(keyName)) {
        const serialized = serializeDatasetValue(child, maxValueChars);
        if (serialized) {
          const safeKey = normalizeId(keyName, { lowerCase: true, maxLength: 64 }) || 'dataset';
          fingerprints.add(`body:${safeKey}:${snippetHash(serialized, 24)}`);
          if (fingerprints.size >= maxFingerprints) {
            break;
          }
        }
      }
      if (child && typeof child === 'object' && depth < maxDepth) {
        stack.push({ node: child, depth: depth + 1 });
      }
    }
  }

  return Array.from(fingerprints);
}

function extractModelFromHeaders(headers = {}) {
  const modelHeaders = [
    'x-openai-model',
    'openai-model',
    'x-anthropic-model',
    'anthropic-model',
    'x-vertex-model',
    'x-goog-model',
    'x-model',
    'model',
  ];
  for (const name of modelHeaders) {
    const value = mapHeaderValue(headers, name);
    const normalized = normalizeId(value, { lowerCase: false, maxLength: 160 });
    if (normalized) {
      return normalized;
    }
  }
  return '';
}

class AIBOMGenerator {
  constructor(options = {}) {
    this.ttlMs = clampPositiveInt(options.ttlMs, DEFAULT_TTL_MS, 60 * 1000, 14 * 24 * 60 * 60 * 1000);
    this.maxEntriesPerCategory = clampPositiveInt(options.maxEntriesPerCategory, DEFAULT_MAX_ENTRIES, 16, 100000);
    this.maxBodyBytes = clampPositiveInt(options.maxBodyBytes, DEFAULT_MAX_BODY_BYTES, 1024, 2 * 1024 * 1024);
    this.maxTraversalDepth = clampPositiveInt(
      options.maxTraversalDepth,
      DEFAULT_MAX_TRAVERSAL_DEPTH,
      1,
      64
    );
    this.maxTraversalNodes = clampPositiveInt(
      options.maxTraversalNodes,
      DEFAULT_MAX_TRAVERSAL_NODES,
      16,
      100000
    );
    this.maxToolsPerRecord = clampPositiveInt(
      options.maxToolsPerRecord,
      DEFAULT_MAX_TOOLS_PER_RECORD,
      1,
      1024
    );
    this.maxDatasetsPerRecord = clampPositiveInt(
      options.maxDatasetsPerRecord,
      DEFAULT_MAX_DATASETS_PER_RECORD,
      1,
      2048
    );
    this.maxDatasetValueChars = clampPositiveInt(
      options.maxDatasetValueChars,
      DEFAULT_MAX_DATASET_VALUE_CHARS,
      32,
      8192
    );
    this.pruneInterval = clampPositiveInt(options.pruneInterval, DEFAULT_PRUNE_INTERVAL, 1, 10000);
    this.exportCacheTtlMs = clampPositiveInt(
      options.exportCacheTtlMs,
      DEFAULT_EXPORT_CACHE_TTL_MS,
      100,
      60000
    );
    this.clock = typeof options.clock === 'function' ? options.clock : () => Date.now();

    this.providers = new Map();
    this.models = new Map();
    this.tools = new Map();
    this.agents = new Map();
    this.datasets = new Map();
    this.operationCount = 0;
    this.dirty = true;
    this.cachedExport = null;
    this.cachedAtMs = 0;
  }

  pruneMap(map, nowMs) {
    const safeNow = Number(nowMs || this.clock());
    for (const [id, item] of map.entries()) {
      if (!item || safeNow - Number(item.lastSeenMs || 0) > this.ttlMs) {
        map.delete(id);
      }
    }
    if (map.size <= this.maxEntriesPerCategory) {
      return;
    }
    const sortedOldestFirst = Array.from(map.entries()).sort((left, right) => {
      const leftSeen = Number(left[1]?.lastSeenMs || 0);
      const rightSeen = Number(right[1]?.lastSeenMs || 0);
      if (leftSeen !== rightSeen) {
        return leftSeen - rightSeen;
      }
      return String(left[0]).localeCompare(String(right[0]));
    });
    const overflow = map.size - this.maxEntriesPerCategory;
    for (let i = 0; i < overflow; i += 1) {
      map.delete(sortedOldestFirst[i][0]);
    }
  }

  pruneAll(nowMs) {
    this.pruneMap(this.providers, nowMs);
    this.pruneMap(this.models, nowMs);
    this.pruneMap(this.tools, nowMs);
    this.pruneMap(this.agents, nowMs);
    this.pruneMap(this.datasets, nowMs);
  }

  touchMutation() {
    this.operationCount += 1;
    this.dirty = true;
    if (this.operationCount % this.pruneInterval === 0) {
      this.pruneAll();
    }
  }

  upsert(map, id, options = {}) {
    const normalizedId = normalizeId(id, {
      lowerCase: options.lowerCase !== false,
      maxLength: options.maxLength || 160,
    });
    if (!normalizedId) {
      return;
    }
    const nowMs = Number(this.clock());
    const existing = map.get(normalizedId);
    if (!existing) {
      map.set(normalizedId, {
        id: normalizedId,
        firstSeenMs: nowMs,
        lastSeenMs: nowMs,
        requestCount: options.count !== false ? 1 : 0,
        sources: new Set(options.source ? [String(options.source)] : []),
      });
      this.touchMutation();
      return;
    }
    let changed = false;
    existing.lastSeenMs = nowMs;
    changed = true;
    if (options.count !== false) {
      existing.requestCount += 1;
      changed = true;
    }
    if (options.source && !existing.sources.has(String(options.source))) {
      existing.sources.add(String(options.source));
      changed = true;
    }
    if (changed) {
      this.touchMutation();
    }
  }

  recordRoute({ provider, routePlan } = {}) {
    this.upsert(this.providers, provider, {
      source: routePlan?.routeSource || 'route',
      lowerCase: true,
      count: true,
    });
    if (routePlan?.requestedTarget) {
      this.upsert(this.providers, routePlan.requestedTarget, {
        source: 'requested_target',
        lowerCase: true,
        count: false,
      });
    }
  }

  recordRequest({ provider, headers = {}, body } = {}) {
    if (provider) {
      this.upsert(this.providers, provider, {
        source: 'request_provider',
        lowerCase: true,
        count: false,
      });
    }

    const bodyModel = normalizeId(body?.model, { lowerCase: false, maxLength: 160 });
    if (bodyModel) {
      this.upsert(this.models, bodyModel, {
        source: 'request_body',
        lowerCase: false,
      });
    }

    const toolNames = extractToolNamesFromValue(body?.tools || body?.tool_calls || [], {
      maxDepth: this.maxTraversalDepth,
      maxNodes: this.maxTraversalNodes,
      maxTools: this.maxToolsPerRecord,
    });
    for (const tool of toolNames) {
      this.upsert(this.tools, tool, {
        source: 'request_body',
        lowerCase: true,
      });
    }

    const datasetFingerprints = collectDatasetFingerprintsFromValue(body, {
      maxDepth: this.maxTraversalDepth,
      maxNodes: this.maxTraversalNodes,
      maxFingerprints: this.maxDatasetsPerRecord,
      maxValueChars: this.maxDatasetValueChars,
    });
    for (const fingerprint of datasetFingerprints) {
      this.upsert(this.datasets, fingerprint, {
        source: 'request_body_dataset',
        lowerCase: false,
      });
    }
    for (const headerName of DATASET_HEADER_KEYS) {
      const headerValue = mapHeaderValue(headers, headerName);
      const normalized = normalizeId(headerValue, {
        lowerCase: false,
        maxLength: this.maxDatasetValueChars,
      });
      if (normalized) {
        this.upsert(this.datasets, `header:${headerName}:${snippetHash(normalized, 24)}`, {
          source: 'request_header_dataset',
          lowerCase: false,
          count: false,
        });
      }
    }

    const explicitAgent = normalizeId(
      mapHeaderValue(headers, 'x-sentinel-agent-id') ||
        mapHeaderValue(headers, 'x-agent-id') ||
        mapHeaderValue(headers, 'x-sentinel-session-id') ||
        body?.agent_id ||
        body?.agent,
      { lowerCase: false, maxLength: 160 }
    );
    if (explicitAgent) {
      this.upsert(this.agents, explicitAgent, {
        source: 'request_identity',
        lowerCase: false,
      });
    } else {
      const userAgent = normalizeId(mapHeaderValue(headers, 'user-agent'), {
        lowerCase: false,
        maxLength: 512,
      });
      if (userAgent) {
        this.upsert(this.agents, `ua:${snippetHash(userAgent, 20)}`, {
          source: 'request_user_agent_hash',
          lowerCase: false,
        });
      }
    }

  }

  recordResponse({ provider, headers = {}, body, bodyBuffer } = {}) {
    if (provider) {
      this.upsert(this.providers, provider, {
        source: 'response_provider',
        lowerCase: true,
        count: false,
      });
    }

    const headerModel = extractModelFromHeaders(headers);
    if (headerModel) {
      this.upsert(this.models, headerModel, {
        source: 'response_header',
        lowerCase: false,
      });
    }
    for (const headerName of DATASET_HEADER_KEYS) {
      const headerValue = mapHeaderValue(headers, headerName);
      const normalized = normalizeId(headerValue, {
        lowerCase: false,
        maxLength: this.maxDatasetValueChars,
      });
      if (normalized) {
        this.upsert(this.datasets, `header:${headerName}:${snippetHash(normalized, 24)}`, {
          source: 'response_header_dataset',
          lowerCase: false,
          count: false,
        });
      }
    }

    const parsedBody =
      body && typeof body === 'object' && !Array.isArray(body)
        ? body
        : parseBufferAsJson(bodyBuffer, this.maxBodyBytes);
    if (parsedBody && typeof parsedBody === 'object') {
      const modelFromBody = normalizeId(parsedBody.model, {
        lowerCase: false,
        maxLength: 160,
      });
      if (modelFromBody) {
        this.upsert(this.models, modelFromBody, {
          source: 'response_body',
          lowerCase: false,
        });
      }
      const toolNames = extractToolNamesFromValue(parsedBody.tool_calls || parsedBody.choices || [], {
        maxDepth: this.maxTraversalDepth,
        maxNodes: this.maxTraversalNodes,
        maxTools: this.maxToolsPerRecord,
      });
      for (const tool of toolNames) {
        this.upsert(this.tools, tool, {
          source: 'response_body',
          lowerCase: true,
        });
      }

      const datasetFingerprints = collectDatasetFingerprintsFromValue(parsedBody, {
        maxDepth: this.maxTraversalDepth,
        maxNodes: this.maxTraversalNodes,
        maxFingerprints: this.maxDatasetsPerRecord,
        maxValueChars: this.maxDatasetValueChars,
      });
      for (const fingerprint of datasetFingerprints) {
        this.upsert(this.datasets, fingerprint, {
          source: 'response_body_dataset',
          lowerCase: false,
        });
      }
    }
  }

  toSortedArray(map) {
    return Array.from(map.values())
      .map((item) => ({
        id: item.id,
        request_count: Number(item.requestCount || 0),
        first_seen_at: toIsoTime(item.firstSeenMs),
        last_seen_at: toIsoTime(item.lastSeenMs),
        sources: Array.from(item.sources || []).sort((a, b) => a.localeCompare(b)),
      }))
      .sort((left, right) => String(left.id).localeCompare(String(right.id)));
  }

  exportArtifact() {
    const nowMs = Number(this.clock());
    const cacheFresh = nowMs - Number(this.cachedAtMs || 0) <= this.exportCacheTtlMs;
    if (!this.dirty && this.cachedExport && cacheFresh) {
      return this.cachedExport;
    }
    this.pruneAll();
    const providers = this.toSortedArray(this.providers);
    const models = this.toSortedArray(this.models);
    const tools = this.toSortedArray(this.tools);
    const agents = this.toSortedArray(this.agents);
    const datasets = this.toSortedArray(this.datasets);
    this.cachedExport = {
      schema_version: SCHEMA_VERSION,
      ttl_ms: this.ttlMs,
      max_entries_per_category: this.maxEntriesPerCategory,
      providers,
      models,
      tools,
      agents,
      datasets,
      totals: {
        providers: providers.length,
        models: models.length,
        tools: tools.length,
        agents: agents.length,
        datasets: datasets.length,
      },
    };
    this.dirty = false;
    this.cachedAtMs = nowMs;
    return this.cachedExport;
  }
}

module.exports = {
  SCHEMA_VERSION,
  AIBOMGenerator,
  extractToolNamesFromValue,
  extractModelFromHeaders,
  collectDatasetFingerprintsFromValue,
};
