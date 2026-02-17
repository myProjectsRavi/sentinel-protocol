const VALID_MODES = new Set(['monitor', 'warn', 'enforce']);
const VALID_ACTIONS = new Set(['allow', 'block', 'warn']);
const VALID_SCANNER_ACTIONS = new Set(['allow', 'block']);

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

  normalized.pii = normalized.pii || {};
  normalized.pii.enabled = normalized.pii.enabled !== false;
  normalized.pii.max_scan_bytes = Number(normalized.pii.max_scan_bytes ?? 262144);
  normalized.pii.severity_actions = normalized.pii.severity_actions || {};
  normalized.pii.severity_actions.critical = normalized.pii.severity_actions.critical || 'block';
  normalized.pii.severity_actions.high = normalized.pii.severity_actions.high || 'block';
  normalized.pii.severity_actions.medium = normalized.pii.severity_actions.medium || 'redact';
  normalized.pii.severity_actions.low = normalized.pii.severity_actions.low || 'log';

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

  validateRules(config.rules, details);

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
