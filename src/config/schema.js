const os = require('os');

const VALID_MODES = new Set(['monitor', 'warn', 'enforce']);
const VALID_ACTIONS = new Set(['allow', 'block', 'warn']);
const VALID_SCANNER_ACTIONS = new Set(['allow', 'block']);
const VALID_PII_PROVIDER_MODES = new Set(['local', 'rapidapi', 'hybrid']);
const ROOT_KEYS = new Set(['version', 'mode', 'proxy', 'runtime', 'pii', 'injection', 'rules', 'whitelist', 'logging']);
const PROXY_KEYS = new Set(['host', 'port', 'timeout_ms', 'max_body_bytes']);
const RUNTIME_KEYS = new Set(['fail_open', 'scanner_error_action', 'telemetry', 'upstream', 'worker_pool', 'vcr', 'semantic_cache', 'dashboard']);
const TELEMETRY_KEYS = new Set(['enabled']);
const UPSTREAM_KEYS = new Set(['retry', 'circuit_breaker', 'custom_targets']);
const WORKER_POOL_KEYS = new Set(['enabled', 'size', 'queue_limit', 'task_timeout_ms']);
const VCR_KEYS = new Set(['enabled', 'mode', 'tape_file', 'max_entries', 'strict_replay']);
const VCR_MODES = new Set(['off', 'record', 'replay']);
const SEMANTIC_CACHE_KEYS = new Set([
  'enabled',
  'model_id',
  'cache_dir',
  'similarity_threshold',
  'max_entries',
  'ttl_ms',
  'max_prompt_chars',
  'max_entry_bytes',
  'max_ram_mb',
]);
const DASHBOARD_KEYS = new Set(['enabled', 'host', 'port', 'auth_token', 'allow_remote']);
const RETRY_KEYS = new Set(['enabled', 'max_attempts', 'allow_post_with_idempotency_key']);
const CIRCUIT_BREAKER_KEYS = new Set([
  'enabled',
  'window_size',
  'min_failures_to_evaluate',
  'failure_rate_threshold',
  'consecutive_timeout_threshold',
  'open_seconds',
  'half_open_success_threshold',
]);
const CUSTOM_TARGET_KEYS = new Set(['enabled', 'allowlist', 'block_private_networks']);
const PII_KEYS = new Set([
  'enabled',
  'provider_mode',
  'max_scan_bytes',
  'regex_safety_cap_bytes',
  'redaction',
  'severity_actions',
  'rapidapi',
  'semantic',
  'egress',
]);
const PII_REDACTION_KEYS = new Set(['mode', 'salt']);
const PII_REDACTION_MODES = new Set(['placeholder', 'format_preserving']);
const PII_SEVERITY_KEYS = new Set(['critical', 'high', 'medium', 'low']);
const PII_SEMANTIC_KEYS = new Set(['enabled', 'model_id', 'cache_dir', 'score_threshold', 'max_scan_bytes']);
const PII_EGRESS_KEYS = new Set(['enabled', 'max_scan_bytes', 'stream_enabled', 'sse_line_max_bytes', 'stream_block_mode']);
const INJECTION_KEYS = new Set(['enabled', 'threshold', 'max_scan_bytes', 'action', 'neural']);
const INJECTION_ACTIONS = new Set(['allow', 'block', 'warn']);
const INJECTION_NEURAL_KEYS = new Set(['enabled', 'model_id', 'cache_dir', 'max_scan_bytes', 'timeout_ms', 'weight', 'mode']);
const INJECTION_NEURAL_MODES = new Set(['max', 'blend']);
const RAPIDAPI_KEYS = new Set([
  'endpoint',
  'host',
  'timeout_ms',
  'request_body_field',
  'fallback_to_local',
  'allow_non_rapidapi_host',
  'api_key',
  'extra_body',
  'cache_max_entries',
  'cache_ttl_ms',
  'max_timeout_ms',
]);
const RULE_KEYS = new Set(['name', 'match', 'action', 'message']);
const RULE_MATCH_KEYS = new Set([
  'method',
  'domain',
  'path_contains',
  'body_contains',
  'tool_name',
  'body_size_mb',
  'injection_threshold',
  'requests_per_minute',
]);
const WHITELIST_KEYS = new Set(['domains']);
const LOGGING_KEYS = new Set(['level', 'audit_file', 'audit_stdout']);

class ConfigValidationError extends Error {
  constructor(message, details = []) {
    super(message);
    this.name = 'ConfigValidationError';
    this.details = details;
  }
}

function assertType(condition, message, details) {
  if (!condition) {
    details.push(message);
  }
}

function assertNoUnknownKeys(object, allowedKeys, pathLabel, details) {
  if (!object || typeof object !== 'object' || Array.isArray(object)) {
    return;
  }
  for (const key of Object.keys(object)) {
    if (!allowedKeys.has(key)) {
      details.push(`Unknown key: ${pathLabel}.${key}`);
    }
  }
}

function validateRequiredKeys(config, details) {
  const required = ['version', 'mode', 'proxy', 'runtime', 'pii', 'rules', 'whitelist', 'logging'];
  for (const key of required) {
    assertType(Object.prototype.hasOwnProperty.call(config, key), `Missing required key: ${key}`, details);
  }
}

function validateRules(rules, details) {
  assertType(Array.isArray(rules), '`rules` must be an array', details);
  if (!Array.isArray(rules)) {
    return;
  }

  rules.forEach((rule, idx) => {
    const prefix = `rules[${idx}]`;
    assertType(rule && typeof rule === 'object', `${prefix} must be an object`, details);
    if (!rule || typeof rule !== 'object') {
      return;
    }
    assertNoUnknownKeys(rule, RULE_KEYS, prefix, details);

    assertType(typeof rule.name === 'string' && rule.name.length > 0, `${prefix}.name must be a non-empty string`, details);
    assertType(rule.match && typeof rule.match === 'object', `${prefix}.match must be an object`, details);
    assertType(typeof rule.action === 'string' && VALID_ACTIONS.has(rule.action), `${prefix}.action must be one of: allow, block, warn`, details);
    assertNoUnknownKeys(rule.match, RULE_MATCH_KEYS, `${prefix}.match`, details);
    if (rule.match?.injection_threshold !== undefined) {
      const threshold = Number(rule.match.injection_threshold);
      assertType(
        Number.isFinite(threshold) && threshold >= 0 && threshold <= 1,
        `${prefix}.match.injection_threshold must be between 0 and 1`,
        details
      );
    }
  });
}

function applyDefaults(config) {
  const normalized = JSON.parse(JSON.stringify(config));
  normalized.proxy = normalized.proxy || {};
  normalized.proxy.host = normalized.proxy.host || '127.0.0.1';
  normalized.proxy.port = Number(normalized.proxy.port || 8787);
  normalized.proxy.timeout_ms = Number(normalized.proxy.timeout_ms || 30000);
  normalized.proxy.max_body_bytes = Number(normalized.proxy.max_body_bytes ?? 1048576);

  normalized.runtime = normalized.runtime || {};
  normalized.runtime.fail_open = Boolean(normalized.runtime.fail_open);
  normalized.runtime.scanner_error_action = normalized.runtime.scanner_error_action || 'allow';
  normalized.runtime.telemetry = normalized.runtime.telemetry || {};
  normalized.runtime.telemetry.enabled = normalized.runtime.telemetry.enabled !== false;
  normalized.runtime.upstream = normalized.runtime.upstream || {};
  normalized.runtime.upstream.retry = normalized.runtime.upstream.retry || {};
  normalized.runtime.upstream.retry.enabled = normalized.runtime.upstream.retry.enabled !== false;
  normalized.runtime.upstream.retry.max_attempts = Number(normalized.runtime.upstream.retry.max_attempts ?? 1);
  normalized.runtime.upstream.retry.allow_post_with_idempotency_key = Boolean(
    normalized.runtime.upstream.retry.allow_post_with_idempotency_key
  );

  normalized.runtime.upstream.circuit_breaker = normalized.runtime.upstream.circuit_breaker || {};
  const cb = normalized.runtime.upstream.circuit_breaker;
  cb.enabled = cb.enabled !== false;
  cb.window_size = Number(cb.window_size ?? 20);
  cb.min_failures_to_evaluate = Number(cb.min_failures_to_evaluate ?? 8);
  cb.failure_rate_threshold = Number(cb.failure_rate_threshold ?? 0.5);
  cb.consecutive_timeout_threshold = Number(cb.consecutive_timeout_threshold ?? 5);
  cb.open_seconds = Number(cb.open_seconds ?? 20);
  cb.half_open_success_threshold = Number(cb.half_open_success_threshold ?? 3);

  normalized.runtime.upstream.custom_targets = normalized.runtime.upstream.custom_targets || {};
  const customTargets = normalized.runtime.upstream.custom_targets;
  customTargets.enabled = customTargets.enabled === true;
  customTargets.allowlist = Array.isArray(customTargets.allowlist) ? customTargets.allowlist : [];
  customTargets.block_private_networks = customTargets.block_private_networks !== false;

  normalized.runtime.worker_pool = normalized.runtime.worker_pool || {};
  const workerPool = normalized.runtime.worker_pool;
  workerPool.enabled = workerPool.enabled !== false;
  workerPool.size = Number(
    workerPool.size ?? Math.max(1, Math.min(4, (os.cpus()?.length || 2) - 1))
  );
  workerPool.queue_limit = Number(workerPool.queue_limit ?? 1024);
  workerPool.task_timeout_ms = Number(workerPool.task_timeout_ms ?? 2000);

  normalized.runtime.vcr = normalized.runtime.vcr || {};
  const vcr = normalized.runtime.vcr;
  vcr.enabled = vcr.enabled === true;
  vcr.mode = VCR_MODES.has(String(vcr.mode || '').toLowerCase()) ? String(vcr.mode).toLowerCase() : 'off';
  vcr.tape_file = vcr.tape_file || '~/.sentinel/vcr-tape.jsonl';
  vcr.max_entries = Number(vcr.max_entries ?? 2000);
  vcr.strict_replay = vcr.strict_replay === true;

  normalized.runtime.semantic_cache = normalized.runtime.semantic_cache || {};
  const semanticCache = normalized.runtime.semantic_cache;
  semanticCache.enabled = semanticCache.enabled === true;
  semanticCache.model_id = semanticCache.model_id || 'Xenova/all-MiniLM-L6-v2';
  semanticCache.cache_dir = semanticCache.cache_dir || '~/.sentinel/models';
  semanticCache.similarity_threshold = Number(semanticCache.similarity_threshold ?? 0.95);
  semanticCache.max_entries = Number(semanticCache.max_entries ?? 2000);
  semanticCache.ttl_ms = Number(semanticCache.ttl_ms ?? 3600000);
  semanticCache.max_prompt_chars = Number(semanticCache.max_prompt_chars ?? 2000);
  semanticCache.max_entry_bytes = Number(semanticCache.max_entry_bytes ?? 262144);
  semanticCache.max_ram_mb = Number(semanticCache.max_ram_mb ?? 64);

  normalized.runtime.dashboard = normalized.runtime.dashboard || {};
  const dashboard = normalized.runtime.dashboard;
  dashboard.enabled = dashboard.enabled === true;
  dashboard.host = dashboard.host || '127.0.0.1';
  dashboard.port = Number(dashboard.port ?? 8788);
  dashboard.auth_token = String(dashboard.auth_token || process.env.SENTINEL_DASHBOARD_TOKEN || '');
  dashboard.allow_remote = dashboard.allow_remote === true;

  normalized.pii = normalized.pii || {};
  normalized.pii.enabled = normalized.pii.enabled !== false;
  normalized.pii.provider_mode = String(normalized.pii.provider_mode || 'local').toLowerCase();
  normalized.pii.max_scan_bytes = Number(normalized.pii.max_scan_bytes ?? 262144);
  normalized.pii.regex_safety_cap_bytes = Number(normalized.pii.regex_safety_cap_bytes ?? 51200);
  normalized.pii.redaction = normalized.pii.redaction || {};
  normalized.pii.redaction.mode = PII_REDACTION_MODES.has(String(normalized.pii.redaction.mode || '').toLowerCase())
    ? String(normalized.pii.redaction.mode).toLowerCase()
    : 'placeholder';
  normalized.pii.redaction.salt = String(
    normalized.pii.redaction.salt || process.env.SENTINEL_MASKING_SALT || 'sentinel-mask-salt'
  );
  normalized.pii.severity_actions = normalized.pii.severity_actions || {};
  normalized.pii.severity_actions.critical = normalized.pii.severity_actions.critical || 'block';
  normalized.pii.severity_actions.high = normalized.pii.severity_actions.high || 'block';
  normalized.pii.severity_actions.medium = normalized.pii.severity_actions.medium || 'redact';
  normalized.pii.severity_actions.low = normalized.pii.severity_actions.low || 'log';
  normalized.pii.rapidapi = normalized.pii.rapidapi || {};
  normalized.pii.rapidapi.endpoint =
    normalized.pii.rapidapi.endpoint || process.env.SENTINEL_RAPIDAPI_ENDPOINT || 'https://pii-firewall-edge.p.rapidapi.com/redact';
  normalized.pii.rapidapi.host = normalized.pii.rapidapi.host || process.env.SENTINEL_RAPIDAPI_HOST || '';
  normalized.pii.rapidapi.timeout_ms = Number(normalized.pii.rapidapi.timeout_ms ?? 4000);
  normalized.pii.rapidapi.request_body_field = normalized.pii.rapidapi.request_body_field || 'text';
  normalized.pii.rapidapi.fallback_to_local = normalized.pii.rapidapi.fallback_to_local !== false;
  normalized.pii.rapidapi.allow_non_rapidapi_host = normalized.pii.rapidapi.allow_non_rapidapi_host === true;
  normalized.pii.rapidapi.api_key = normalized.pii.rapidapi.api_key || '';
  normalized.pii.rapidapi.cache_max_entries = Number(normalized.pii.rapidapi.cache_max_entries ?? 1024);
  normalized.pii.rapidapi.cache_ttl_ms = Number(normalized.pii.rapidapi.cache_ttl_ms ?? 300000);
  normalized.pii.rapidapi.max_timeout_ms = Number(normalized.pii.rapidapi.max_timeout_ms ?? 1500);
  normalized.pii.rapidapi.extra_body =
    normalized.pii.rapidapi.extra_body && typeof normalized.pii.rapidapi.extra_body === 'object'
      ? normalized.pii.rapidapi.extra_body
      : {};
  normalized.pii.semantic = normalized.pii.semantic || {};
  normalized.pii.semantic.enabled = normalized.pii.semantic.enabled === true;
  normalized.pii.semantic.model_id = normalized.pii.semantic.model_id || 'Xenova/bert-base-NER';
  normalized.pii.semantic.cache_dir = normalized.pii.semantic.cache_dir || '~/.sentinel/models';
  normalized.pii.semantic.score_threshold = Number(normalized.pii.semantic.score_threshold ?? 0.6);
  normalized.pii.semantic.max_scan_bytes = Number(normalized.pii.semantic.max_scan_bytes ?? 32768);
  normalized.pii.egress = normalized.pii.egress || {};
  normalized.pii.egress.enabled = normalized.pii.egress.enabled !== false;
  normalized.pii.egress.max_scan_bytes = Number(normalized.pii.egress.max_scan_bytes ?? 65536);
  normalized.pii.egress.stream_enabled = normalized.pii.egress.stream_enabled !== false;
  normalized.pii.egress.sse_line_max_bytes = Number(normalized.pii.egress.sse_line_max_bytes ?? 16384);
  normalized.pii.egress.stream_block_mode = normalized.pii.egress.stream_block_mode === 'terminate' ? 'terminate' : 'redact';

  normalized.injection = normalized.injection || {};
  normalized.injection.enabled = normalized.injection.enabled !== false;
  normalized.injection.threshold = Number(normalized.injection.threshold ?? 0.8);
  normalized.injection.max_scan_bytes = Number(normalized.injection.max_scan_bytes ?? 131072);
  normalized.injection.action = normalized.injection.action || 'block';
  normalized.injection.neural = normalized.injection.neural || {};
  normalized.injection.neural.enabled = normalized.injection.neural.enabled === true;
  normalized.injection.neural.model_id = normalized.injection.neural.model_id || 'Xenova/all-MiniLM-L6-v2';
  normalized.injection.neural.cache_dir = normalized.injection.neural.cache_dir || '~/.sentinel/models';
  normalized.injection.neural.max_scan_bytes = Number(normalized.injection.neural.max_scan_bytes ?? 32768);
  normalized.injection.neural.timeout_ms = Number(normalized.injection.neural.timeout_ms ?? 1200);
  normalized.injection.neural.weight = Number(normalized.injection.neural.weight ?? 1);
  normalized.injection.neural.mode = INJECTION_NEURAL_MODES.has(String(normalized.injection.neural.mode || '').toLowerCase())
    ? String(normalized.injection.neural.mode || '').toLowerCase()
    : 'max';

  normalized.whitelist = normalized.whitelist || {};
  normalized.whitelist.domains = Array.isArray(normalized.whitelist.domains) ? normalized.whitelist.domains : [];

  normalized.logging = normalized.logging || {};
  normalized.logging.level = normalized.logging.level || 'info';
  normalized.logging.audit_stdout =
    normalized.logging.audit_stdout !== undefined
      ? Boolean(normalized.logging.audit_stdout)
      : ['true', '1', 'yes', 'on'].includes(String(process.env.SENTINEL_AUDIT_STDOUT || '').toLowerCase());

  return normalized;
}

function validateConfigShape(config) {
  const details = [];

  assertType(config && typeof config === 'object', 'Config must be an object', details);
  if (!config || typeof config !== 'object') {
    throw new ConfigValidationError('Invalid config', details);
  }

  validateRequiredKeys(config, details);
  assertNoUnknownKeys(config, ROOT_KEYS, 'config', details);

  assertType(Number.isInteger(config.version), '`version` must be an integer', details);
  assertType(VALID_MODES.has(config.mode), '`mode` must be one of: monitor, warn, enforce', details);

  const proxy = config.proxy || {};
  assertNoUnknownKeys(proxy, PROXY_KEYS, 'proxy', details);
  assertType(typeof proxy.host === 'string' && proxy.host.length > 0, '`proxy.host` must be a non-empty string', details);
  assertType(Number.isInteger(proxy.port) && proxy.port > 0, '`proxy.port` must be integer > 0', details);
  assertType(Number.isInteger(proxy.timeout_ms) && proxy.timeout_ms > 0, '`proxy.timeout_ms` must be integer > 0', details);
  assertType(
    proxy.max_body_bytes === undefined || (Number.isInteger(proxy.max_body_bytes) && proxy.max_body_bytes > 0),
    '`proxy.max_body_bytes` must be integer > 0',
    details
  );

  const runtime = config.runtime || {};
  assertNoUnknownKeys(runtime, RUNTIME_KEYS, 'runtime', details);
  assertType(typeof runtime.fail_open === 'boolean', '`runtime.fail_open` must be boolean', details);
  const telemetry = runtime.telemetry || {};
  if (runtime.telemetry !== undefined) {
    assertNoUnknownKeys(telemetry, TELEMETRY_KEYS, 'runtime.telemetry', details);
    assertType(typeof telemetry.enabled === 'boolean', '`runtime.telemetry.enabled` must be boolean', details);
  }
  assertType(
    VALID_SCANNER_ACTIONS.has(runtime.scanner_error_action),
    '`runtime.scanner_error_action` must be allow|block',
    details
  );
  const workerPool = runtime.worker_pool || {};
  if (runtime.worker_pool !== undefined) {
    assertNoUnknownKeys(workerPool, WORKER_POOL_KEYS, 'runtime.worker_pool', details);
    assertType(typeof workerPool.enabled === 'boolean', '`runtime.worker_pool.enabled` must be boolean', details);
    assertType(
      Number.isInteger(workerPool.size) && workerPool.size > 0 && workerPool.size <= 32,
      '`runtime.worker_pool.size` must be integer between 1 and 32',
      details
    );
    assertType(
      Number.isInteger(workerPool.queue_limit) && workerPool.queue_limit > 0,
      '`runtime.worker_pool.queue_limit` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(workerPool.task_timeout_ms) && workerPool.task_timeout_ms > 0,
      '`runtime.worker_pool.task_timeout_ms` must be integer > 0',
      details
    );
  }
  const vcr = runtime.vcr || {};
  if (runtime.vcr !== undefined) {
    assertNoUnknownKeys(vcr, VCR_KEYS, 'runtime.vcr', details);
    assertType(typeof vcr.enabled === 'boolean', '`runtime.vcr.enabled` must be boolean', details);
    assertType(VCR_MODES.has(String(vcr.mode)), '`runtime.vcr.mode` must be one of: off, record, replay', details);
    assertType(typeof vcr.tape_file === 'string' && vcr.tape_file.length > 0, '`runtime.vcr.tape_file` must be string', details);
    assertType(
      Number.isInteger(vcr.max_entries) && vcr.max_entries > 0,
      '`runtime.vcr.max_entries` must be integer > 0',
      details
    );
    assertType(typeof vcr.strict_replay === 'boolean', '`runtime.vcr.strict_replay` must be boolean', details);
  }
  const semanticCache = runtime.semantic_cache || {};
  if (runtime.semantic_cache !== undefined) {
    assertNoUnknownKeys(semanticCache, SEMANTIC_CACHE_KEYS, 'runtime.semantic_cache', details);
    assertType(typeof semanticCache.enabled === 'boolean', '`runtime.semantic_cache.enabled` must be boolean', details);
    assertType(typeof semanticCache.model_id === 'string', '`runtime.semantic_cache.model_id` must be string', details);
    assertType(typeof semanticCache.cache_dir === 'string', '`runtime.semantic_cache.cache_dir` must be string', details);
    assertType(
      Number.isFinite(Number(semanticCache.similarity_threshold)) &&
        Number(semanticCache.similarity_threshold) >= 0 &&
        Number(semanticCache.similarity_threshold) <= 1,
      '`runtime.semantic_cache.similarity_threshold` must be between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(semanticCache.max_entries) && semanticCache.max_entries > 0,
      '`runtime.semantic_cache.max_entries` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(semanticCache.ttl_ms) && semanticCache.ttl_ms >= 0,
      '`runtime.semantic_cache.ttl_ms` must be integer >= 0',
      details
    );
    assertType(
      Number.isInteger(semanticCache.max_prompt_chars) && semanticCache.max_prompt_chars > 0,
      '`runtime.semantic_cache.max_prompt_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(semanticCache.max_entry_bytes) && semanticCache.max_entry_bytes > 0,
      '`runtime.semantic_cache.max_entry_bytes` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(semanticCache.max_ram_mb)) && Number(semanticCache.max_ram_mb) > 0,
      '`runtime.semantic_cache.max_ram_mb` must be number > 0',
      details
    );
  }
  const dashboard = runtime.dashboard || {};
  if (runtime.dashboard !== undefined) {
    assertNoUnknownKeys(dashboard, DASHBOARD_KEYS, 'runtime.dashboard', details);
    assertType(typeof dashboard.enabled === 'boolean', '`runtime.dashboard.enabled` must be boolean', details);
    assertType(typeof dashboard.host === 'string' && dashboard.host.length > 0, '`runtime.dashboard.host` must be string', details);
    assertType(
      Number.isInteger(dashboard.port) && dashboard.port > 0 && dashboard.port <= 65535,
      '`runtime.dashboard.port` must be integer between 1 and 65535',
      details
    );
    assertType(typeof dashboard.auth_token === 'string', '`runtime.dashboard.auth_token` must be string', details);
    assertType(typeof dashboard.allow_remote === 'boolean', '`runtime.dashboard.allow_remote` must be boolean', details);
    if (dashboard.allow_remote === true && String(dashboard.auth_token || '').length === 0) {
      details.push('`runtime.dashboard.auth_token` must be non-empty when `runtime.dashboard.allow_remote=true`');
    }
  }

  const retry = runtime.upstream?.retry || {};
  const upstream = runtime.upstream || {};
  assertNoUnknownKeys(upstream, UPSTREAM_KEYS, 'runtime.upstream', details);
  assertNoUnknownKeys(retry, RETRY_KEYS, 'runtime.upstream.retry', details);
  assertType(typeof retry.enabled === 'boolean', '`runtime.upstream.retry.enabled` must be boolean', details);
  assertType(Number.isInteger(retry.max_attempts) && retry.max_attempts >= 0, '`runtime.upstream.retry.max_attempts` must be integer >= 0', details);

  const cb = runtime.upstream?.circuit_breaker || {};
  assertNoUnknownKeys(cb, CIRCUIT_BREAKER_KEYS, 'runtime.upstream.circuit_breaker', details);
  assertType(typeof cb.enabled === 'boolean', '`runtime.upstream.circuit_breaker.enabled` must be boolean', details);
  assertType(Number.isInteger(cb.open_seconds) && cb.open_seconds > 0, '`runtime.upstream.circuit_breaker.open_seconds` must be integer > 0', details);

  const customTargets = runtime.upstream?.custom_targets;
  if (customTargets !== undefined) {
    assertNoUnknownKeys(customTargets, CUSTOM_TARGET_KEYS, 'runtime.upstream.custom_targets', details);
    assertType(typeof customTargets.enabled === 'boolean', '`runtime.upstream.custom_targets.enabled` must be boolean', details);
    assertType(Array.isArray(customTargets.allowlist), '`runtime.upstream.custom_targets.allowlist` must be an array', details);
    assertType(
      typeof customTargets.block_private_networks === 'boolean',
      '`runtime.upstream.custom_targets.block_private_networks` must be boolean',
      details
    );
    if (customTargets.enabled && Array.isArray(customTargets.allowlist) && customTargets.allowlist.length === 0) {
      details.push('`runtime.upstream.custom_targets.allowlist` must not be empty when custom targets are enabled');
    }
  }

  validateRules(config.rules, details);

  const pii = config.pii || {};
  if (pii !== undefined) {
    assertNoUnknownKeys(pii, PII_KEYS, 'pii', details);
    assertType(typeof pii.enabled === 'boolean', '`pii.enabled` must be boolean', details);
    assertType(typeof pii.provider_mode === 'string', '`pii.provider_mode` must be string', details);
    if (typeof pii.provider_mode === 'string' && !VALID_PII_PROVIDER_MODES.has(String(pii.provider_mode).toLowerCase())) {
      details.push('`pii.provider_mode` must be one of: local, rapidapi, hybrid');
    }
    assertType(
      Number.isFinite(Number(pii.max_scan_bytes)) && Number(pii.max_scan_bytes) > 0,
      '`pii.max_scan_bytes` must be > 0',
      details
    );
    assertType(
      pii.regex_safety_cap_bytes === undefined ||
        (Number.isFinite(Number(pii.regex_safety_cap_bytes)) && Number(pii.regex_safety_cap_bytes) > 0),
      '`pii.regex_safety_cap_bytes` must be > 0',
      details
    );
    if (pii.redaction !== undefined) {
      const redaction = pii.redaction || {};
      assertNoUnknownKeys(redaction, PII_REDACTION_KEYS, 'pii.redaction', details);
      assertType(
        PII_REDACTION_MODES.has(String(redaction.mode)),
        '`pii.redaction.mode` must be placeholder|format_preserving',
        details
      );
      assertType(
        typeof redaction.salt === 'string' && redaction.salt.length > 0,
        '`pii.redaction.salt` must be non-empty string',
        details
      );
    }
    assertNoUnknownKeys(pii.severity_actions, PII_SEVERITY_KEYS, 'pii.severity_actions', details);

    const rapidapi = pii.rapidapi || {};
    const semantic = pii.semantic || {};
    if (pii.rapidapi !== undefined) {
      assertNoUnknownKeys(rapidapi, RAPIDAPI_KEYS, 'pii.rapidapi', details);
      assertType(rapidapi.endpoint === undefined || typeof rapidapi.endpoint === 'string', '`pii.rapidapi.endpoint` must be string', details);
      assertType(rapidapi.host === undefined || typeof rapidapi.host === 'string', '`pii.rapidapi.host` must be string', details);
      assertType(
        rapidapi.timeout_ms === undefined || (Number.isInteger(rapidapi.timeout_ms) && rapidapi.timeout_ms > 0),
        '`pii.rapidapi.timeout_ms` must be integer > 0',
        details
      );
      assertType(
        rapidapi.request_body_field === undefined || typeof rapidapi.request_body_field === 'string',
        '`pii.rapidapi.request_body_field` must be string',
        details
      );
      assertType(
        rapidapi.fallback_to_local === undefined || typeof rapidapi.fallback_to_local === 'boolean',
        '`pii.rapidapi.fallback_to_local` must be boolean',
        details
      );
      assertType(
        rapidapi.allow_non_rapidapi_host === undefined || typeof rapidapi.allow_non_rapidapi_host === 'boolean',
        '`pii.rapidapi.allow_non_rapidapi_host` must be boolean',
        details
      );
      assertType(rapidapi.api_key === undefined || typeof rapidapi.api_key === 'string', '`pii.rapidapi.api_key` must be string', details);
      assertType(
        rapidapi.cache_max_entries === undefined ||
          (Number.isInteger(rapidapi.cache_max_entries) && rapidapi.cache_max_entries > 0),
        '`pii.rapidapi.cache_max_entries` must be integer > 0',
        details
      );
      assertType(
        rapidapi.cache_ttl_ms === undefined ||
          (Number.isInteger(rapidapi.cache_ttl_ms) && rapidapi.cache_ttl_ms >= 0),
        '`pii.rapidapi.cache_ttl_ms` must be integer >= 0',
        details
      );
      assertType(
        rapidapi.max_timeout_ms === undefined ||
          (Number.isInteger(rapidapi.max_timeout_ms) && rapidapi.max_timeout_ms > 0),
        '`pii.rapidapi.max_timeout_ms` must be integer > 0',
        details
      );
      assertType(
        rapidapi.extra_body === undefined ||
          (rapidapi.extra_body && typeof rapidapi.extra_body === 'object' && !Array.isArray(rapidapi.extra_body)),
        '`pii.rapidapi.extra_body` must be object',
        details
      );
    }
    if (pii.semantic !== undefined) {
      assertNoUnknownKeys(semantic, PII_SEMANTIC_KEYS, 'pii.semantic', details);
      assertType(typeof semantic.enabled === 'boolean', '`pii.semantic.enabled` must be boolean', details);
      assertType(typeof semantic.model_id === 'string', '`pii.semantic.model_id` must be string', details);
      assertType(typeof semantic.cache_dir === 'string', '`pii.semantic.cache_dir` must be string', details);
      assertType(
        Number.isFinite(Number(semantic.score_threshold)) &&
          Number(semantic.score_threshold) >= 0 &&
          Number(semantic.score_threshold) <= 1,
        '`pii.semantic.score_threshold` must be between 0 and 1',
        details
      );
      assertType(
        Number.isInteger(semantic.max_scan_bytes) && semantic.max_scan_bytes > 0,
        '`pii.semantic.max_scan_bytes` must be integer > 0',
        details
      );
    }
    if (pii.egress !== undefined) {
      const egress = pii.egress || {};
      assertNoUnknownKeys(egress, PII_EGRESS_KEYS, 'pii.egress', details);
      assertType(typeof egress.enabled === 'boolean', '`pii.egress.enabled` must be boolean', details);
      assertType(
        Number.isInteger(egress.max_scan_bytes) && egress.max_scan_bytes > 0,
        '`pii.egress.max_scan_bytes` must be integer > 0',
        details
      );
      assertType(typeof egress.stream_enabled === 'boolean', '`pii.egress.stream_enabled` must be boolean', details);
      assertType(
        Number.isInteger(egress.sse_line_max_bytes) && egress.sse_line_max_bytes > 0,
        '`pii.egress.sse_line_max_bytes` must be integer > 0',
        details
      );
      assertType(
        egress.stream_block_mode === undefined || ['redact', 'terminate'].includes(String(egress.stream_block_mode)),
        '`pii.egress.stream_block_mode` must be redact|terminate',
        details
      );
    }
  }

  const injection = config.injection || {};
  if (config.injection !== undefined) {
    assertNoUnknownKeys(injection, INJECTION_KEYS, 'injection', details);
    assertType(typeof injection.enabled === 'boolean', '`injection.enabled` must be boolean', details);
    assertType(
      Number.isFinite(Number(injection.threshold)) &&
        Number(injection.threshold) >= 0 &&
        Number(injection.threshold) <= 1,
      '`injection.threshold` must be between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(injection.max_scan_bytes) && injection.max_scan_bytes > 0,
      '`injection.max_scan_bytes` must be integer > 0',
      details
    );
    assertType(
      INJECTION_ACTIONS.has(String(injection.action)),
      '`injection.action` must be one of: allow, block, warn',
      details
    );
    if (injection.neural !== undefined) {
      const neural = injection.neural || {};
      assertNoUnknownKeys(neural, INJECTION_NEURAL_KEYS, 'injection.neural', details);
      assertType(typeof neural.enabled === 'boolean', '`injection.neural.enabled` must be boolean', details);
      assertType(typeof neural.model_id === 'string', '`injection.neural.model_id` must be string', details);
      assertType(typeof neural.cache_dir === 'string', '`injection.neural.cache_dir` must be string', details);
      assertType(
        Number.isInteger(neural.max_scan_bytes) && neural.max_scan_bytes > 0,
        '`injection.neural.max_scan_bytes` must be integer > 0',
        details
      );
      assertType(
        Number.isInteger(neural.timeout_ms) && neural.timeout_ms > 0,
        '`injection.neural.timeout_ms` must be integer > 0',
        details
      );
      assertType(
        Number.isFinite(Number(neural.weight)) && Number(neural.weight) >= 0 && Number(neural.weight) <= 2,
        '`injection.neural.weight` must be between 0 and 2',
        details
      );
      assertType(
        INJECTION_NEURAL_MODES.has(String(neural.mode)),
        '`injection.neural.mode` must be max|blend',
        details
      );
    }
  }

  assertType(Array.isArray(config.whitelist?.domains), '`whitelist.domains` must be an array', details);
  assertNoUnknownKeys(config.whitelist, WHITELIST_KEYS, 'whitelist', details);
  assertNoUnknownKeys(config.logging, LOGGING_KEYS, 'logging', details);
  if (config.logging?.audit_stdout !== undefined) {
    assertType(typeof config.logging.audit_stdout === 'boolean', '`logging.audit_stdout` must be boolean', details);
  }

  if (details.length > 0) {
    throw new ConfigValidationError('Configuration validation failed', details);
  }

  return applyDefaults(config);
}

module.exports = {
  ConfigValidationError,
  validateConfigShape,
  applyDefaults,
};
