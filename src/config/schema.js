const VALID_MODES = new Set(['monitor', 'warn', 'enforce']);
const VALID_ACTIONS = new Set(['allow', 'block', 'warn']);
const VALID_SCANNER_ACTIONS = new Set(['allow', 'block']);
const VALID_PII_PROVIDER_MODES = new Set(['local', 'rapidapi', 'hybrid']);

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

    assertType(typeof rule.name === 'string' && rule.name.length > 0, `${prefix}.name must be a non-empty string`, details);
    assertType(rule.match && typeof rule.match === 'object', `${prefix}.match must be an object`, details);
    assertType(typeof rule.action === 'string' && VALID_ACTIONS.has(rule.action), `${prefix}.action must be one of: allow, block, warn`, details);
  });
}

function applyDefaults(config) {
  const normalized = JSON.parse(JSON.stringify(config));
  normalized.proxy = normalized.proxy || {};
  normalized.proxy.host = normalized.proxy.host || '127.0.0.1';
  normalized.proxy.port = Number(normalized.proxy.port || 8787);
  normalized.proxy.timeout_ms = Number(normalized.proxy.timeout_ms || 30000);

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

  normalized.pii = normalized.pii || {};
  normalized.pii.enabled = normalized.pii.enabled !== false;
  normalized.pii.provider_mode = String(normalized.pii.provider_mode || 'local').toLowerCase();
  normalized.pii.max_scan_bytes = Number(normalized.pii.max_scan_bytes ?? 262144);
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
  normalized.pii.rapidapi.extra_body =
    normalized.pii.rapidapi.extra_body && typeof normalized.pii.rapidapi.extra_body === 'object'
      ? normalized.pii.rapidapi.extra_body
      : {};

  normalized.whitelist = normalized.whitelist || {};
  normalized.whitelist.domains = Array.isArray(normalized.whitelist.domains) ? normalized.whitelist.domains : [];

  normalized.logging = normalized.logging || {};
  normalized.logging.level = normalized.logging.level || 'info';

  return normalized;
}

function validateConfigShape(config) {
  const details = [];

  assertType(config && typeof config === 'object', 'Config must be an object', details);
  if (!config || typeof config !== 'object') {
    throw new ConfigValidationError('Invalid config', details);
  }

  validateRequiredKeys(config, details);

  assertType(Number.isInteger(config.version), '`version` must be an integer', details);
  assertType(VALID_MODES.has(config.mode), '`mode` must be one of: monitor, warn, enforce', details);

  const runtime = config.runtime || {};
  assertType(typeof runtime.fail_open === 'boolean', '`runtime.fail_open` must be boolean', details);
  const telemetry = runtime.telemetry || {};
  if (runtime.telemetry !== undefined) {
    assertType(typeof telemetry.enabled === 'boolean', '`runtime.telemetry.enabled` must be boolean', details);
  }
  assertType(
    VALID_SCANNER_ACTIONS.has(runtime.scanner_error_action),
    '`runtime.scanner_error_action` must be allow|block',
    details
  );

  const retry = runtime.upstream?.retry || {};
  assertType(typeof retry.enabled === 'boolean', '`runtime.upstream.retry.enabled` must be boolean', details);
  assertType(Number.isInteger(retry.max_attempts) && retry.max_attempts >= 0, '`runtime.upstream.retry.max_attempts` must be integer >= 0', details);

  const cb = runtime.upstream?.circuit_breaker || {};
  assertType(typeof cb.enabled === 'boolean', '`runtime.upstream.circuit_breaker.enabled` must be boolean', details);
  assertType(Number.isInteger(cb.open_seconds) && cb.open_seconds > 0, '`runtime.upstream.circuit_breaker.open_seconds` must be integer > 0', details);

  const customTargets = runtime.upstream?.custom_targets;
  if (customTargets !== undefined) {
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

    const rapidapi = pii.rapidapi || {};
    if (pii.rapidapi !== undefined) {
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
        rapidapi.extra_body === undefined ||
          (rapidapi.extra_body && typeof rapidapi.extra_body === 'object' && !Array.isArray(rapidapi.extra_body)),
        '`pii.rapidapi.extra_body` must be object',
        details
      );
    }
  }

  assertType(Array.isArray(config.whitelist?.domains), '`whitelist.domains` must be an array', details);

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
