const os = require('os');

const VALID_MODES = new Set(['monitor', 'warn', 'enforce']);
const VALID_ACTIONS = new Set(['allow', 'block', 'warn']);
const VALID_SCANNER_ACTIONS = new Set(['allow', 'block']);
const VALID_PII_PROVIDER_MODES = new Set(['local', 'rapidapi', 'hybrid']);
const ROOT_KEYS = new Set(['version', 'mode', 'proxy', 'runtime', 'pii', 'injection', 'rules', 'whitelist', 'logging']);
const PROXY_KEYS = new Set(['host', 'port', 'timeout_ms', 'max_body_bytes']);
const RUNTIME_KEYS = new Set([
  'fail_open',
  'scanner_error_action',
  'telemetry',
  'upstream',
  'worker_pool',
  'vcr',
  'semantic_cache',
  'intent_throttle',
  'swarm',
  'polymorphic_prompt',
  'synthetic_poisoning',
  'cognitive_rollback',
  'omni_shield',
  'dashboard',
  'budget',
  'loop_breaker',
  'provenance',
  'deception',
  'honeytoken',
  'latency_normalization',
  'canary_tools',
  'parallax',
]);
const TELEMETRY_KEYS = new Set(['enabled']);
const UPSTREAM_KEYS = new Set(['retry', 'circuit_breaker', 'custom_targets', 'resilience_mesh', 'canary', 'auth_vault', 'ghost_mode']);
const WORKER_POOL_KEYS = new Set([
  'enabled',
  'size',
  'queue_limit',
  'task_timeout_ms',
  'scan_task_timeout_ms',
  'embed_task_timeout_ms',
]);
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
  'max_consecutive_errors',
  'failure_cooldown_ms',
]);
const INTENT_THROTTLE_KEYS = new Set([
  'enabled',
  'mode',
  'key_header',
  'window_ms',
  'cooldown_ms',
  'max_events_per_window',
  'min_similarity',
  'max_prompt_chars',
  'max_sessions',
  'model_id',
  'cache_dir',
  'clusters',
]);
const INTENT_THROTTLE_MODES = new Set(['monitor', 'block']);
const INTENT_THROTTLE_CLUSTER_KEYS = new Set(['name', 'phrases', 'min_similarity']);
const SWARM_KEYS = new Set([
  'enabled',
  'mode',
  'node_id',
  'key_id',
  'private_key_pem',
  'public_key_pem',
  'verify_inbound',
  'sign_outbound',
  'require_envelope',
  'allowed_clock_skew_ms',
  'tolerance_window_ms',
  'nonce_ttl_ms',
  'max_nonce_entries',
  'sign_on_providers',
  'trusted_nodes',
]);
const SWARM_MODES = new Set(['monitor', 'block']);
const SWARM_TRUSTED_NODE_KEYS = new Set(['public_key_pem']);
const POLYMORPHIC_PROMPT_KEYS = new Set([
  'enabled',
  'rotation_seconds',
  'max_mutations_per_message',
  'target_roles',
  'bypass_header',
  'seed',
  'observability',
  'lexicon',
]);
const SYNTHETIC_POISONING_KEYS = new Set([
  'enabled',
  'mode',
  'required_acknowledgement',
  'acknowledgement',
  'allowed_triggers',
  'target_roles',
  'decoy_label',
  'max_insertions_per_request',
  'observability',
]);
const SYNTHETIC_POISONING_MODES = new Set(['monitor', 'inject']);
const COGNITIVE_ROLLBACK_KEYS = new Set([
  'enabled',
  'mode',
  'triggers',
  'target_roles',
  'drop_messages',
  'min_messages_remaining',
  'system_message',
  'observability',
]);
const COGNITIVE_ROLLBACK_MODES = new Set(['monitor', 'auto']);
const OMNI_SHIELD_KEYS = new Set([
  'enabled',
  'mode',
  'max_image_bytes',
  'allow_remote_image_urls',
  'allow_base64_images',
  'block_on_any_image',
  'max_findings',
  'target_roles',
  'observability',
]);
const OMNI_SHIELD_MODES = new Set(['monitor', 'block']);
const DASHBOARD_KEYS = new Set(['enabled', 'host', 'port', 'auth_token', 'allow_remote']);
const BUDGET_KEYS = new Set([
  'enabled',
  'action',
  'daily_limit_usd',
  'store_file',
  'reset_timezone',
  'chars_per_token',
  'input_cost_per_1k_tokens',
  'output_cost_per_1k_tokens',
  'charge_replay_hits',
  'retention_days',
]);
const LOOP_BREAKER_KEYS = new Set([
  'enabled',
  'action',
  'window_ms',
  'repeat_threshold',
  'max_recent',
  'max_keys',
  'key_header',
]);
const LOOP_BREAKER_ACTIONS = new Set(['block', 'warn']);
const PROVENANCE_KEYS = new Set([
  'enabled',
  'key_id',
  'sign_stream_trailers',
  'expose_public_key_endpoint',
  'max_signable_bytes',
]);
const DECEPTION_KEYS = new Set([
  'enabled',
  'mode',
  'on_injection',
  'on_loop',
  'min_injection_score',
  'sse_token_interval_ms',
  'sse_max_tokens',
  'non_stream_delay_ms',
]);
const DECEPTION_MODES = new Set(['off', 'tarpit']);
const HONEYTOKEN_KEYS = new Set([
  'enabled',
  'mode',
  'injection_rate',
  'max_insertions_per_request',
  'target_roles',
  'token_prefix',
]);
const HONEYTOKEN_MODES = new Set(['zero_width', 'uuid_suffix']);
const LATENCY_NORMALIZATION_KEYS = new Set([
  'enabled',
  'window_size',
  'min_samples',
  'max_delay_ms',
  'max_baseline_sample_ms',
  'trim_percentile',
  'max_concurrent_normalized',
  'jitter_ms',
  'statuses',
]);
const CANARY_TOOL_KEYS = new Set([
  'enabled',
  'mode',
  'tool_name',
  'tool_description',
  'max_injected_tools',
  'inject_on_providers',
  'require_tools_array',
]);
const CANARY_TOOL_MODES = new Set(['monitor', 'block']);
const PARALLAX_KEYS = new Set([
  'enabled',
  'mode',
  'high_risk_tools',
  'secondary_target',
  'secondary_group',
  'secondary_contract',
  'secondary_model',
  'timeout_ms',
  'risk_threshold',
]);
const PARALLAX_MODES = new Set(['monitor', 'block']);
const BUDGET_ACTIONS = new Set(['block', 'warn']);
const BUDGET_RESET_TIMEZONES = new Set(['utc', 'local']);
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
const RESILIENCE_MESH_KEYS = new Set([
  'enabled',
  'contract',
  'default_group',
  'max_failover_hops',
  'allow_post_with_idempotency_key',
  'failover_on_status',
  'failover_on_error_types',
  'groups',
  'targets',
]);
const RESILIENCE_GROUP_KEYS = new Set(['enabled', 'contract', 'targets']);
const RESILIENCE_TARGET_KEYS = new Set(['enabled', 'provider', 'contract', 'base_url', 'custom_url', 'headers']);
const CANARY_KEYS = new Set(['enabled', 'key_header', 'fallback_key_headers', 'splits']);
const CANARY_SPLIT_KEYS = new Set(['name', 'match_target', 'group_a', 'group_b', 'weight_a', 'weight_b', 'sticky']);
const GHOST_MODE_KEYS = new Set(['enabled', 'strip_headers', 'override_user_agent', 'user_agent_value']);
const AUTH_VAULT_KEYS = new Set(['enabled', 'mode', 'dummy_key', 'providers']);
const AUTH_VAULT_MODES = new Set(['replace_dummy', 'enforce']);
const AUTH_VAULT_PROVIDERS = new Set(['openai', 'anthropic', 'google']);
const AUTH_VAULT_PROVIDER_KEYS = new Set(['enabled', 'api_key', 'env_var']);
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
const PII_EGRESS_KEYS = new Set(['enabled', 'max_scan_bytes', 'stream_enabled', 'sse_line_max_bytes', 'stream_block_mode', 'entropy']);
const PII_EGRESS_ENTROPY_KEYS = new Set([
  'enabled',
  'mode',
  'threshold',
  'min_token_length',
  'max_scan_bytes',
  'max_findings',
  'min_unique_ratio',
  'detect_base64',
  'detect_hex',
  'detect_generic',
  'redact_replacement',
]);
const PII_EGRESS_ENTROPY_MODES = new Set(['monitor', 'block']);
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

  normalized.runtime.upstream.resilience_mesh = normalized.runtime.upstream.resilience_mesh || {};
  const resilienceMesh = normalized.runtime.upstream.resilience_mesh;
  resilienceMesh.enabled = resilienceMesh.enabled === true;
  resilienceMesh.contract = String(resilienceMesh.contract || 'passthrough');
  resilienceMesh.default_group = String(resilienceMesh.default_group || '').toLowerCase();
  resilienceMesh.max_failover_hops = Number(resilienceMesh.max_failover_hops ?? 1);
  resilienceMesh.allow_post_with_idempotency_key = resilienceMesh.allow_post_with_idempotency_key === true;
  resilienceMesh.failover_on_status = Array.isArray(resilienceMesh.failover_on_status)
    ? resilienceMesh.failover_on_status.map((status) => Number(status))
    : [429, 500, 502, 503, 504];
  resilienceMesh.failover_on_error_types = Array.isArray(resilienceMesh.failover_on_error_types)
    ? resilienceMesh.failover_on_error_types.map((value) => String(value).toLowerCase())
    : ['timeout', 'transport', 'circuit_open'];
  resilienceMesh.groups =
    resilienceMesh.groups && typeof resilienceMesh.groups === 'object' && !Array.isArray(resilienceMesh.groups)
      ? resilienceMesh.groups
      : {};
  resilienceMesh.targets =
    resilienceMesh.targets && typeof resilienceMesh.targets === 'object' && !Array.isArray(resilienceMesh.targets)
      ? resilienceMesh.targets
      : {};
  for (const [groupName, groupConfig] of Object.entries(resilienceMesh.groups)) {
    const normalizedGroup =
      groupConfig && typeof groupConfig === 'object' && !Array.isArray(groupConfig) ? groupConfig : {};
    normalizedGroup.enabled = normalizedGroup.enabled !== false;
    normalizedGroup.contract = String(normalizedGroup.contract || '');
    normalizedGroup.targets = Array.isArray(normalizedGroup.targets)
      ? normalizedGroup.targets.map((value) => String(value).toLowerCase()).filter(Boolean)
      : [];
    resilienceMesh.groups[groupName] = normalizedGroup;
  }
  for (const [targetName, targetConfig] of Object.entries(resilienceMesh.targets)) {
    const normalizedTarget =
      targetConfig && typeof targetConfig === 'object' && !Array.isArray(targetConfig) ? targetConfig : {};
    normalizedTarget.enabled = normalizedTarget.enabled !== false;
    normalizedTarget.provider = String(normalizedTarget.provider || targetName).toLowerCase();
    normalizedTarget.contract = String(normalizedTarget.contract || '');
    if (normalizedTarget.base_url !== undefined) {
      normalizedTarget.base_url = String(normalizedTarget.base_url);
    }
    if (normalizedTarget.custom_url !== undefined) {
      normalizedTarget.custom_url = String(normalizedTarget.custom_url);
    }
    normalizedTarget.headers =
      normalizedTarget.headers && typeof normalizedTarget.headers === 'object' && !Array.isArray(normalizedTarget.headers)
        ? normalizedTarget.headers
        : {};
    resilienceMesh.targets[targetName] = normalizedTarget;
  }

  normalized.runtime.upstream.canary = normalized.runtime.upstream.canary || {};
  const canary = normalized.runtime.upstream.canary;
  canary.enabled = canary.enabled === true;
  canary.key_header = String(canary.key_header || 'x-sentinel-canary-key').toLowerCase();
  canary.fallback_key_headers = Array.isArray(canary.fallback_key_headers)
    ? canary.fallback_key_headers.map((value) => String(value).toLowerCase()).filter(Boolean)
    : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
  canary.splits = Array.isArray(canary.splits) ? canary.splits : [];
  canary.splits = canary.splits.map((split, idx) => {
    const normalizedSplit = split && typeof split === 'object' && !Array.isArray(split) ? split : {};
    normalizedSplit.name = String(normalizedSplit.name || `split-${idx + 1}`);
    normalizedSplit.match_target = String(normalizedSplit.match_target || '*').toLowerCase();
    normalizedSplit.group_a = String(normalizedSplit.group_a || '').toLowerCase();
    normalizedSplit.group_b = String(normalizedSplit.group_b || '').toLowerCase();
    normalizedSplit.weight_a = Number(normalizedSplit.weight_a ?? 90);
    normalizedSplit.weight_b = Number(normalizedSplit.weight_b ?? 10);
    normalizedSplit.sticky = normalizedSplit.sticky !== false;
    return normalizedSplit;
  });

  normalized.runtime.upstream.ghost_mode = normalized.runtime.upstream.ghost_mode || {};
  const ghostMode = normalized.runtime.upstream.ghost_mode;
  ghostMode.enabled = ghostMode.enabled === true;
  ghostMode.strip_headers = Array.isArray(ghostMode.strip_headers)
    ? ghostMode.strip_headers.map((value) => String(value).toLowerCase()).filter(Boolean)
    : [
        'x-stainless-os',
        'x-stainless-arch',
        'x-stainless-runtime',
        'x-stainless-runtime-version',
        'x-stainless-package-version',
        'x-stainless-lang',
        'x-stainless-helper-method',
        'user-agent',
      ];
  ghostMode.override_user_agent = ghostMode.override_user_agent !== false;
  ghostMode.user_agent_value = String(ghostMode.user_agent_value || 'Sentinel/1.0 (Privacy Proxy)');

  normalized.runtime.upstream.auth_vault = normalized.runtime.upstream.auth_vault || {};
  const authVault = normalized.runtime.upstream.auth_vault;
  authVault.enabled = authVault.enabled === true;
  authVault.mode = AUTH_VAULT_MODES.has(String(authVault.mode || '').toLowerCase())
    ? String(authVault.mode).toLowerCase()
    : 'replace_dummy';
  authVault.dummy_key = String(authVault.dummy_key || 'sk-sentinel-local');
  authVault.providers =
    authVault.providers && typeof authVault.providers === 'object' && !Array.isArray(authVault.providers)
      ? authVault.providers
      : {};
  for (const provider of AUTH_VAULT_PROVIDERS) {
    const providerConfig =
      authVault.providers[provider] && typeof authVault.providers[provider] === 'object' && !Array.isArray(authVault.providers[provider])
        ? authVault.providers[provider]
        : {};
    providerConfig.enabled = providerConfig.enabled !== false;
    providerConfig.api_key = String(providerConfig.api_key || '');
    const defaultEnv =
      provider === 'openai'
        ? 'SENTINEL_OPENAI_API_KEY'
        : provider === 'anthropic'
          ? 'SENTINEL_ANTHROPIC_API_KEY'
          : 'SENTINEL_GOOGLE_API_KEY';
    providerConfig.env_var = String(providerConfig.env_var || defaultEnv);
    authVault.providers[provider] = providerConfig;
  }

  normalized.runtime.worker_pool = normalized.runtime.worker_pool || {};
  const workerPool = normalized.runtime.worker_pool;
  workerPool.enabled = workerPool.enabled !== false;
  workerPool.size = Number(
    workerPool.size ?? Math.max(1, Math.min(4, (os.cpus()?.length || 2) - 1))
  );
  workerPool.queue_limit = Number(workerPool.queue_limit ?? 1024);
  workerPool.task_timeout_ms = Number(workerPool.task_timeout_ms ?? 10000);
  workerPool.scan_task_timeout_ms = Number(workerPool.scan_task_timeout_ms ?? 2000);
  workerPool.embed_task_timeout_ms = Number(
    workerPool.embed_task_timeout_ms ?? Math.max(workerPool.task_timeout_ms, 10000)
  );

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
  semanticCache.max_consecutive_errors = Number(semanticCache.max_consecutive_errors ?? 3);
  semanticCache.failure_cooldown_ms = Number(semanticCache.failure_cooldown_ms ?? 30000);

  normalized.runtime.intent_throttle = normalized.runtime.intent_throttle || {};
  const intentThrottle = normalized.runtime.intent_throttle;
  intentThrottle.enabled = intentThrottle.enabled === true;
  intentThrottle.mode = INTENT_THROTTLE_MODES.has(String(intentThrottle.mode || '').toLowerCase())
    ? String(intentThrottle.mode).toLowerCase()
    : 'monitor';
  intentThrottle.key_header = String(intentThrottle.key_header || 'x-sentinel-agent-id').toLowerCase();
  intentThrottle.window_ms = Number(intentThrottle.window_ms ?? 3600000);
  intentThrottle.cooldown_ms = Number(intentThrottle.cooldown_ms ?? 900000);
  intentThrottle.max_events_per_window = Number(intentThrottle.max_events_per_window ?? 3);
  intentThrottle.min_similarity = Number(intentThrottle.min_similarity ?? 0.82);
  intentThrottle.max_prompt_chars = Number(intentThrottle.max_prompt_chars ?? 2000);
  intentThrottle.max_sessions = Number(intentThrottle.max_sessions ?? 5000);
  intentThrottle.model_id = String(intentThrottle.model_id || 'Xenova/all-MiniLM-L6-v2');
  intentThrottle.cache_dir = String(intentThrottle.cache_dir || '~/.sentinel/models');
  intentThrottle.clusters = Array.isArray(intentThrottle.clusters)
    ? intentThrottle.clusters.map((cluster) => {
        const normalizedCluster =
          cluster && typeof cluster === 'object' && !Array.isArray(cluster) ? cluster : {};
        normalizedCluster.name = String(normalizedCluster.name || '').trim().toLowerCase();
        normalizedCluster.phrases = Array.isArray(normalizedCluster.phrases)
          ? normalizedCluster.phrases.map((value) => String(value)).filter(Boolean)
          : [];
        if (normalizedCluster.min_similarity !== undefined) {
          normalizedCluster.min_similarity = Number(normalizedCluster.min_similarity);
        }
        return normalizedCluster;
      })
    : [];

  normalized.runtime.swarm = normalized.runtime.swarm || {};
  const swarm = normalized.runtime.swarm;
  swarm.enabled = swarm.enabled === true;
  swarm.mode = SWARM_MODES.has(String(swarm.mode || '').toLowerCase())
    ? String(swarm.mode).toLowerCase()
    : 'monitor';
  swarm.node_id = String(swarm.node_id || `sentinel-node-${process.pid}`);
  swarm.key_id = String(swarm.key_id || swarm.node_id || `sentinel-node-${process.pid}`);
  swarm.private_key_pem = String(swarm.private_key_pem || '');
  swarm.public_key_pem = String(swarm.public_key_pem || '');
  swarm.verify_inbound = swarm.verify_inbound !== false;
  swarm.sign_outbound = swarm.sign_outbound !== false;
  swarm.require_envelope = swarm.require_envelope === true;
  swarm.allowed_clock_skew_ms = Number(swarm.allowed_clock_skew_ms ?? swarm.tolerance_window_ms ?? 30000);
  swarm.tolerance_window_ms = Number(swarm.tolerance_window_ms ?? swarm.allowed_clock_skew_ms);
  swarm.nonce_ttl_ms = Number(swarm.nonce_ttl_ms ?? 300000);
  swarm.max_nonce_entries = Number(swarm.max_nonce_entries ?? 50000);
  swarm.sign_on_providers = Array.isArray(swarm.sign_on_providers)
    ? swarm.sign_on_providers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['custom'];
  swarm.trusted_nodes =
    swarm.trusted_nodes && typeof swarm.trusted_nodes === 'object' && !Array.isArray(swarm.trusted_nodes)
      ? swarm.trusted_nodes
      : {};
  for (const [nodeId, nodeConfig] of Object.entries(swarm.trusted_nodes)) {
    if (typeof nodeConfig === 'string') {
      swarm.trusted_nodes[nodeId] = {
        public_key_pem: String(nodeConfig),
      };
      continue;
    }
    const normalizedNode =
      nodeConfig && typeof nodeConfig === 'object' && !Array.isArray(nodeConfig) ? nodeConfig : {};
    normalizedNode.public_key_pem = String(normalizedNode.public_key_pem || '');
    swarm.trusted_nodes[nodeId] = normalizedNode;
  }

  normalized.runtime.polymorphic_prompt = normalized.runtime.polymorphic_prompt || {};
  const polymorphicPrompt = normalized.runtime.polymorphic_prompt;
  polymorphicPrompt.enabled = polymorphicPrompt.enabled === true;
  polymorphicPrompt.rotation_seconds = Number(polymorphicPrompt.rotation_seconds ?? 1800);
  polymorphicPrompt.max_mutations_per_message = Number(polymorphicPrompt.max_mutations_per_message ?? 3);
  polymorphicPrompt.target_roles = Array.isArray(polymorphicPrompt.target_roles)
    ? polymorphicPrompt.target_roles.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['system'];
  polymorphicPrompt.bypass_header = String(polymorphicPrompt.bypass_header || 'x-sentinel-polymorph-disable').toLowerCase();
  polymorphicPrompt.seed = String(polymorphicPrompt.seed || 'sentinel-mtd-seed');
  polymorphicPrompt.observability = polymorphicPrompt.observability !== false;
  polymorphicPrompt.lexicon =
    polymorphicPrompt.lexicon && typeof polymorphicPrompt.lexicon === 'object' && !Array.isArray(polymorphicPrompt.lexicon)
      ? polymorphicPrompt.lexicon
      : {};

  normalized.runtime.synthetic_poisoning = normalized.runtime.synthetic_poisoning || {};
  const syntheticPoisoning = normalized.runtime.synthetic_poisoning;
  syntheticPoisoning.enabled = syntheticPoisoning.enabled === true;
  syntheticPoisoning.mode = SYNTHETIC_POISONING_MODES.has(String(syntheticPoisoning.mode || '').toLowerCase())
    ? String(syntheticPoisoning.mode).toLowerCase()
    : 'monitor';
  syntheticPoisoning.required_acknowledgement = String(
    syntheticPoisoning.required_acknowledgement || 'I_UNDERSTAND_SYNTHETIC_DATA_RISK'
  );
  syntheticPoisoning.acknowledgement = String(syntheticPoisoning.acknowledgement || '');
  syntheticPoisoning.allowed_triggers = Array.isArray(syntheticPoisoning.allowed_triggers)
    ? syntheticPoisoning.allowed_triggers.map((item) => String(item || '').trim()).filter(Boolean)
    : ['intent_velocity_exceeded'];
  syntheticPoisoning.target_roles = Array.isArray(syntheticPoisoning.target_roles)
    ? syntheticPoisoning.target_roles.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['system'];
  syntheticPoisoning.decoy_label = String(syntheticPoisoning.decoy_label || 'SENTINEL_SYNTHETIC_CONTEXT');
  syntheticPoisoning.max_insertions_per_request = Number(syntheticPoisoning.max_insertions_per_request ?? 1);
  syntheticPoisoning.observability = syntheticPoisoning.observability !== false;

  normalized.runtime.cognitive_rollback = normalized.runtime.cognitive_rollback || {};
  const cognitiveRollback = normalized.runtime.cognitive_rollback;
  cognitiveRollback.enabled = cognitiveRollback.enabled === true;
  cognitiveRollback.mode = COGNITIVE_ROLLBACK_MODES.has(String(cognitiveRollback.mode || '').toLowerCase())
    ? String(cognitiveRollback.mode).toLowerCase()
    : 'monitor';
  cognitiveRollback.triggers = Array.isArray(cognitiveRollback.triggers)
    ? cognitiveRollback.triggers.map((item) => String(item || '').trim()).filter(Boolean)
    : ['canary_tool_triggered', 'parallax_veto'];
  cognitiveRollback.target_roles = Array.isArray(cognitiveRollback.target_roles)
    ? cognitiveRollback.target_roles.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['user', 'assistant', 'tool'];
  cognitiveRollback.drop_messages = Number(cognitiveRollback.drop_messages ?? 2);
  cognitiveRollback.min_messages_remaining = Number(cognitiveRollback.min_messages_remaining ?? 2);
  cognitiveRollback.system_message = String(
    cognitiveRollback.system_message ||
      '[SYSTEM OVERRIDE] Your previous thought process was corrupted. Resume execution from the last safe checkpoint and try a different approach.'
  );
  cognitiveRollback.observability = cognitiveRollback.observability !== false;

  normalized.runtime.omni_shield = normalized.runtime.omni_shield || {};
  const omniShield = normalized.runtime.omni_shield;
  omniShield.enabled = omniShield.enabled === true;
  omniShield.mode = OMNI_SHIELD_MODES.has(String(omniShield.mode || '').toLowerCase())
    ? String(omniShield.mode).toLowerCase()
    : 'monitor';
  omniShield.max_image_bytes = Number(omniShield.max_image_bytes ?? 5 * 1024 * 1024);
  omniShield.allow_remote_image_urls = omniShield.allow_remote_image_urls === true;
  omniShield.allow_base64_images = omniShield.allow_base64_images !== false;
  omniShield.block_on_any_image = omniShield.block_on_any_image === true;
  omniShield.max_findings = Number(omniShield.max_findings ?? 20);
  omniShield.target_roles = Array.isArray(omniShield.target_roles)
    ? omniShield.target_roles.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['user'];
  omniShield.observability = omniShield.observability !== false;

  normalized.runtime.dashboard = normalized.runtime.dashboard || {};
  const dashboard = normalized.runtime.dashboard;
  dashboard.enabled = dashboard.enabled === true;
  dashboard.host = dashboard.host || '127.0.0.1';
  dashboard.port = Number(dashboard.port ?? 8788);
  dashboard.auth_token = String(dashboard.auth_token || process.env.SENTINEL_DASHBOARD_TOKEN || '');
  dashboard.allow_remote = dashboard.allow_remote === true;

  normalized.runtime.budget = normalized.runtime.budget || {};
  const budget = normalized.runtime.budget;
  budget.enabled = budget.enabled === true;
  budget.action = BUDGET_ACTIONS.has(String(budget.action).toLowerCase())
    ? String(budget.action).toLowerCase()
    : 'block';
  budget.daily_limit_usd = Number(budget.daily_limit_usd ?? 5);
  budget.store_file = String(budget.store_file || '~/.sentinel/budget-ledger.json');
  budget.reset_timezone = BUDGET_RESET_TIMEZONES.has(String(budget.reset_timezone).toLowerCase())
    ? String(budget.reset_timezone).toLowerCase()
    : 'utc';
  budget.chars_per_token = Number(budget.chars_per_token ?? 4);
  budget.input_cost_per_1k_tokens = Number(budget.input_cost_per_1k_tokens ?? 0);
  budget.output_cost_per_1k_tokens = Number(budget.output_cost_per_1k_tokens ?? 0);
  budget.charge_replay_hits = budget.charge_replay_hits === true;
  budget.retention_days = Number(budget.retention_days ?? 90);

  normalized.runtime.loop_breaker = normalized.runtime.loop_breaker || {};
  const loopBreaker = normalized.runtime.loop_breaker;
  loopBreaker.enabled = loopBreaker.enabled === true;
  loopBreaker.action = LOOP_BREAKER_ACTIONS.has(String(loopBreaker.action).toLowerCase())
    ? String(loopBreaker.action).toLowerCase()
    : 'block';
  loopBreaker.window_ms = Number(loopBreaker.window_ms ?? 30000);
  loopBreaker.repeat_threshold = Number(loopBreaker.repeat_threshold ?? 4);
  loopBreaker.max_recent = Number(loopBreaker.max_recent ?? 5);
  loopBreaker.max_keys = Number(loopBreaker.max_keys ?? 2048);
  loopBreaker.key_header = String(loopBreaker.key_header || 'x-sentinel-agent-id').toLowerCase();

  normalized.runtime.provenance = normalized.runtime.provenance || {};
  const provenance = normalized.runtime.provenance;
  provenance.enabled = provenance.enabled === true;
  provenance.key_id = String(provenance.key_id || `sentinel-${process.pid}`);
  provenance.sign_stream_trailers = provenance.sign_stream_trailers !== false;
  provenance.expose_public_key_endpoint = provenance.expose_public_key_endpoint !== false;
  provenance.max_signable_bytes = Number(provenance.max_signable_bytes ?? 2097152);

  normalized.runtime.deception = normalized.runtime.deception || {};
  const deception = normalized.runtime.deception;
  deception.enabled = deception.enabled === true;
  deception.mode = DECEPTION_MODES.has(String(deception.mode || '').toLowerCase())
    ? String(deception.mode).toLowerCase()
    : 'off';
  deception.on_injection = deception.on_injection !== false;
  deception.on_loop = deception.on_loop !== false;
  deception.min_injection_score = Number(deception.min_injection_score ?? 0.9);
  deception.sse_token_interval_ms = Number(deception.sse_token_interval_ms ?? 1000);
  deception.sse_max_tokens = Number(deception.sse_max_tokens ?? 20);
  deception.non_stream_delay_ms = Number(deception.non_stream_delay_ms ?? 250);

  normalized.runtime.honeytoken = normalized.runtime.honeytoken || {};
  const honeytoken = normalized.runtime.honeytoken;
  honeytoken.enabled = honeytoken.enabled === true;
  honeytoken.mode = HONEYTOKEN_MODES.has(String(honeytoken.mode || '').toLowerCase())
    ? String(honeytoken.mode).toLowerCase()
    : 'uuid_suffix';
  honeytoken.injection_rate = Number(honeytoken.injection_rate ?? 0.05);
  honeytoken.max_insertions_per_request = Number(honeytoken.max_insertions_per_request ?? 1);
  honeytoken.target_roles = Array.isArray(honeytoken.target_roles)
    ? honeytoken.target_roles.map((value) => String(value).toLowerCase()).filter(Boolean)
    : ['user'];
  honeytoken.token_prefix = String(honeytoken.token_prefix || 'SNTL');

  normalized.runtime.latency_normalization = normalized.runtime.latency_normalization || {};
  const latencyNormalization = normalized.runtime.latency_normalization;
  latencyNormalization.enabled = latencyNormalization.enabled === true;
  latencyNormalization.window_size = Number(latencyNormalization.window_size ?? 10);
  latencyNormalization.min_samples = Number(latencyNormalization.min_samples ?? 3);
  latencyNormalization.max_delay_ms = Number(latencyNormalization.max_delay_ms ?? 2000);
  latencyNormalization.max_baseline_sample_ms = Number(latencyNormalization.max_baseline_sample_ms ?? 5000);
  latencyNormalization.trim_percentile = Number(latencyNormalization.trim_percentile ?? 0.1);
  latencyNormalization.max_concurrent_normalized = Number(latencyNormalization.max_concurrent_normalized ?? 128);
  latencyNormalization.jitter_ms = Number(latencyNormalization.jitter_ms ?? 25);
  latencyNormalization.statuses = Array.isArray(latencyNormalization.statuses)
    ? latencyNormalization.statuses.map((value) => Number(value))
    : [402, 403, 429];

  normalized.runtime.canary_tools = normalized.runtime.canary_tools || {};
  const canaryTools = normalized.runtime.canary_tools;
  canaryTools.enabled = canaryTools.enabled === true;
  canaryTools.mode = CANARY_TOOL_MODES.has(String(canaryTools.mode || '').toLowerCase())
    ? String(canaryTools.mode).toLowerCase()
    : 'monitor';
  canaryTools.tool_name = String(canaryTools.tool_name || 'fetch_admin_passwords');
  canaryTools.tool_description = String(
    canaryTools.tool_description || 'Retrieve privileged credentials for internal diagnostics.'
  );
  canaryTools.max_injected_tools = Number(canaryTools.max_injected_tools ?? 1);
  canaryTools.inject_on_providers = Array.isArray(canaryTools.inject_on_providers)
    ? canaryTools.inject_on_providers.map((value) => String(value).toLowerCase()).filter(Boolean)
    : ['openai', 'anthropic', 'google', 'ollama'];
  canaryTools.require_tools_array = canaryTools.require_tools_array !== false;

  normalized.runtime.parallax = normalized.runtime.parallax || {};
  const parallax = normalized.runtime.parallax;
  parallax.enabled = parallax.enabled === true;
  parallax.mode = PARALLAX_MODES.has(String(parallax.mode || '').toLowerCase())
    ? String(parallax.mode).toLowerCase()
    : 'monitor';
  parallax.high_risk_tools = Array.isArray(parallax.high_risk_tools)
    ? parallax.high_risk_tools.map((value) => String(value)).filter(Boolean)
    : ['execute_shell', 'execute_sql', 'aws_cli'];
  parallax.secondary_target = String(parallax.secondary_target || 'ollama').toLowerCase();
  parallax.secondary_group = String(parallax.secondary_group || '');
  parallax.secondary_contract = String(parallax.secondary_contract || 'openai_chat_v1').toLowerCase();
  parallax.secondary_model = String(parallax.secondary_model || '');
  parallax.timeout_ms = Number(parallax.timeout_ms ?? 3000);
  parallax.risk_threshold = Number(parallax.risk_threshold ?? 0.7);

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
  normalized.pii.egress.entropy = normalized.pii.egress.entropy || {};
  normalized.pii.egress.entropy.enabled = normalized.pii.egress.entropy.enabled === true;
  normalized.pii.egress.entropy.mode =
    PII_EGRESS_ENTROPY_MODES.has(String(normalized.pii.egress.entropy.mode || '').toLowerCase())
      ? String(normalized.pii.egress.entropy.mode).toLowerCase()
      : 'monitor';
  normalized.pii.egress.entropy.threshold = Number(normalized.pii.egress.entropy.threshold ?? 4.5);
  normalized.pii.egress.entropy.min_token_length = Number(normalized.pii.egress.entropy.min_token_length ?? 24);
  normalized.pii.egress.entropy.max_scan_bytes = Number(normalized.pii.egress.entropy.max_scan_bytes ?? 65536);
  normalized.pii.egress.entropy.max_findings = Number(normalized.pii.egress.entropy.max_findings ?? 8);
  normalized.pii.egress.entropy.min_unique_ratio = Number(normalized.pii.egress.entropy.min_unique_ratio ?? 0.3);
  normalized.pii.egress.entropy.detect_base64 = normalized.pii.egress.entropy.detect_base64 !== false;
  normalized.pii.egress.entropy.detect_hex = normalized.pii.egress.entropy.detect_hex !== false;
  normalized.pii.egress.entropy.detect_generic = normalized.pii.egress.entropy.detect_generic !== false;
  normalized.pii.egress.entropy.redact_replacement =
    String(normalized.pii.egress.entropy.redact_replacement || '[REDACTED_HIGH_ENTROPY]');

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
    assertType(
      Number.isInteger(workerPool.scan_task_timeout_ms) && workerPool.scan_task_timeout_ms > 0,
      '`runtime.worker_pool.scan_task_timeout_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(workerPool.embed_task_timeout_ms) && workerPool.embed_task_timeout_ms > 0,
      '`runtime.worker_pool.embed_task_timeout_ms` must be integer > 0',
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
    assertType(
      Number.isInteger(semanticCache.max_consecutive_errors) && semanticCache.max_consecutive_errors > 0,
      '`runtime.semantic_cache.max_consecutive_errors` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(semanticCache.failure_cooldown_ms) && semanticCache.failure_cooldown_ms > 0,
      '`runtime.semantic_cache.failure_cooldown_ms` must be integer > 0',
      details
    );
  }

  const intentThrottle = runtime.intent_throttle || {};
  if (runtime.intent_throttle !== undefined) {
    assertNoUnknownKeys(intentThrottle, INTENT_THROTTLE_KEYS, 'runtime.intent_throttle', details);
    assertType(typeof intentThrottle.enabled === 'boolean', '`runtime.intent_throttle.enabled` must be boolean', details);
    assertType(
      INTENT_THROTTLE_MODES.has(String(intentThrottle.mode)),
      '`runtime.intent_throttle.mode` must be monitor|block',
      details
    );
    assertType(
      typeof intentThrottle.key_header === 'string' && intentThrottle.key_header.length > 0,
      '`runtime.intent_throttle.key_header` must be non-empty string',
      details
    );
    assertType(
      Number.isInteger(intentThrottle.window_ms) && intentThrottle.window_ms > 0,
      '`runtime.intent_throttle.window_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(intentThrottle.cooldown_ms) && intentThrottle.cooldown_ms > 0,
      '`runtime.intent_throttle.cooldown_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(intentThrottle.max_events_per_window) && intentThrottle.max_events_per_window > 0,
      '`runtime.intent_throttle.max_events_per_window` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(intentThrottle.min_similarity)) &&
        Number(intentThrottle.min_similarity) >= 0 &&
        Number(intentThrottle.min_similarity) <= 1,
      '`runtime.intent_throttle.min_similarity` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(intentThrottle.max_prompt_chars) && intentThrottle.max_prompt_chars > 0,
      '`runtime.intent_throttle.max_prompt_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(intentThrottle.max_sessions) && intentThrottle.max_sessions > 0,
      '`runtime.intent_throttle.max_sessions` must be integer > 0',
      details
    );
    assertType(
      typeof intentThrottle.model_id === 'string' && intentThrottle.model_id.length > 0,
      '`runtime.intent_throttle.model_id` must be non-empty string',
      details
    );
    assertType(
      typeof intentThrottle.cache_dir === 'string' && intentThrottle.cache_dir.length > 0,
      '`runtime.intent_throttle.cache_dir` must be non-empty string',
      details
    );
    assertType(
      Array.isArray(intentThrottle.clusters),
      '`runtime.intent_throttle.clusters` must be an array',
      details
    );
    if (Array.isArray(intentThrottle.clusters)) {
      intentThrottle.clusters.forEach((cluster, idx) => {
        const label = `runtime.intent_throttle.clusters[${idx}]`;
        assertType(
          cluster && typeof cluster === 'object' && !Array.isArray(cluster),
          `${label} must be object`,
          details
        );
        if (!cluster || typeof cluster !== 'object' || Array.isArray(cluster)) {
          return;
        }
        assertNoUnknownKeys(cluster, INTENT_THROTTLE_CLUSTER_KEYS, label, details);
        assertType(
          typeof cluster.name === 'string' && cluster.name.length > 0,
          `${label}.name must be non-empty string`,
          details
        );
        assertType(
          Array.isArray(cluster.phrases) && cluster.phrases.length > 0,
          `${label}.phrases must be non-empty array`,
          details
        );
        if (Array.isArray(cluster.phrases)) {
          cluster.phrases.forEach((phrase, phraseIdx) => {
            assertType(
              typeof phrase === 'string' && phrase.length > 0,
              `${label}.phrases[${phraseIdx}] must be non-empty string`,
              details
            );
          });
        }
        if (cluster.min_similarity !== undefined) {
          assertType(
            Number.isFinite(Number(cluster.min_similarity)) &&
              Number(cluster.min_similarity) >= 0 &&
              Number(cluster.min_similarity) <= 1,
            `${label}.min_similarity must be number between 0 and 1`,
            details
          );
        }
      });
    }
  }

  const swarm = runtime.swarm || {};
  if (runtime.swarm !== undefined) {
    assertNoUnknownKeys(swarm, SWARM_KEYS, 'runtime.swarm', details);
    assertType(typeof swarm.enabled === 'boolean', '`runtime.swarm.enabled` must be boolean', details);
    assertType(SWARM_MODES.has(String(swarm.mode)), '`runtime.swarm.mode` must be monitor|block', details);
    assertType(typeof swarm.node_id === 'string' && swarm.node_id.length > 0, '`runtime.swarm.node_id` must be non-empty string', details);
    assertType(typeof swarm.key_id === 'string' && swarm.key_id.length > 0, '`runtime.swarm.key_id` must be non-empty string', details);
    assertType(typeof swarm.private_key_pem === 'string', '`runtime.swarm.private_key_pem` must be string', details);
    assertType(typeof swarm.public_key_pem === 'string', '`runtime.swarm.public_key_pem` must be string', details);
    assertType(typeof swarm.verify_inbound === 'boolean', '`runtime.swarm.verify_inbound` must be boolean', details);
    assertType(typeof swarm.sign_outbound === 'boolean', '`runtime.swarm.sign_outbound` must be boolean', details);
    assertType(typeof swarm.require_envelope === 'boolean', '`runtime.swarm.require_envelope` must be boolean', details);
    assertType(
      Number.isInteger(swarm.allowed_clock_skew_ms) && swarm.allowed_clock_skew_ms > 0,
      '`runtime.swarm.allowed_clock_skew_ms` must be integer > 0',
      details
    );
    assertType(
      swarm.tolerance_window_ms === undefined ||
        (Number.isInteger(swarm.tolerance_window_ms) && swarm.tolerance_window_ms > 0),
      '`runtime.swarm.tolerance_window_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(swarm.nonce_ttl_ms) && swarm.nonce_ttl_ms > 0,
      '`runtime.swarm.nonce_ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(swarm.max_nonce_entries) && swarm.max_nonce_entries > 0,
      '`runtime.swarm.max_nonce_entries` must be integer > 0',
      details
    );
    assertType(
      Array.isArray(swarm.sign_on_providers) && swarm.sign_on_providers.length > 0,
      '`runtime.swarm.sign_on_providers` must be non-empty array',
      details
    );
    if (Array.isArray(swarm.sign_on_providers)) {
      swarm.sign_on_providers.forEach((provider, idx) => {
        assertType(
          ['openai', 'anthropic', 'google', 'ollama', 'custom'].includes(String(provider || '').toLowerCase()),
          `runtime.swarm.sign_on_providers[${idx}] must be openai|anthropic|google|ollama|custom`,
          details
        );
      });
    }
    assertType(
      swarm.trusted_nodes && typeof swarm.trusted_nodes === 'object' && !Array.isArray(swarm.trusted_nodes),
      '`runtime.swarm.trusted_nodes` must be an object',
      details
    );
    if (swarm.trusted_nodes && typeof swarm.trusted_nodes === 'object' && !Array.isArray(swarm.trusted_nodes)) {
      Object.entries(swarm.trusted_nodes).forEach(([nodeId, nodeConfig]) => {
        assertType(nodeId.length > 0, '`runtime.swarm.trusted_nodes` keys must be non-empty', details);
        assertType(
          nodeConfig && typeof nodeConfig === 'object' && !Array.isArray(nodeConfig),
          `runtime.swarm.trusted_nodes.${nodeId} must be object`,
          details
        );
        if (!nodeConfig || typeof nodeConfig !== 'object' || Array.isArray(nodeConfig)) {
          return;
        }
        assertNoUnknownKeys(nodeConfig, SWARM_TRUSTED_NODE_KEYS, `runtime.swarm.trusted_nodes.${nodeId}`, details);
        assertType(
          typeof nodeConfig.public_key_pem === 'string' && nodeConfig.public_key_pem.length > 0,
          `runtime.swarm.trusted_nodes.${nodeId}.public_key_pem must be non-empty string`,
          details
        );
      });
    }
  }

  const polymorphicPrompt = runtime.polymorphic_prompt || {};
  if (runtime.polymorphic_prompt !== undefined) {
    assertNoUnknownKeys(polymorphicPrompt, POLYMORPHIC_PROMPT_KEYS, 'runtime.polymorphic_prompt', details);
    assertType(typeof polymorphicPrompt.enabled === 'boolean', '`runtime.polymorphic_prompt.enabled` must be boolean', details);
    assertType(
      Number.isInteger(polymorphicPrompt.rotation_seconds) && polymorphicPrompt.rotation_seconds > 0,
      '`runtime.polymorphic_prompt.rotation_seconds` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(polymorphicPrompt.max_mutations_per_message) && polymorphicPrompt.max_mutations_per_message > 0,
      '`runtime.polymorphic_prompt.max_mutations_per_message` must be integer > 0',
      details
    );
    assertType(
      Array.isArray(polymorphicPrompt.target_roles) && polymorphicPrompt.target_roles.length > 0,
      '`runtime.polymorphic_prompt.target_roles` must be non-empty array',
      details
    );
    assertType(
      typeof polymorphicPrompt.bypass_header === 'string' && polymorphicPrompt.bypass_header.length > 0,
      '`runtime.polymorphic_prompt.bypass_header` must be non-empty string',
      details
    );
    assertType(
      typeof polymorphicPrompt.seed === 'string' && polymorphicPrompt.seed.length > 0,
      '`runtime.polymorphic_prompt.seed` must be non-empty string',
      details
    );
    assertType(
      typeof polymorphicPrompt.observability === 'boolean',
      '`runtime.polymorphic_prompt.observability` must be boolean',
      details
    );
    assertType(
      polymorphicPrompt.lexicon && typeof polymorphicPrompt.lexicon === 'object' && !Array.isArray(polymorphicPrompt.lexicon),
      '`runtime.polymorphic_prompt.lexicon` must be object',
      details
    );
  }

  const syntheticPoisoning = runtime.synthetic_poisoning || {};
  if (runtime.synthetic_poisoning !== undefined) {
    assertNoUnknownKeys(syntheticPoisoning, SYNTHETIC_POISONING_KEYS, 'runtime.synthetic_poisoning', details);
    assertType(typeof syntheticPoisoning.enabled === 'boolean', '`runtime.synthetic_poisoning.enabled` must be boolean', details);
    assertType(
      SYNTHETIC_POISONING_MODES.has(String(syntheticPoisoning.mode)),
      '`runtime.synthetic_poisoning.mode` must be monitor|inject',
      details
    );
    assertType(
      typeof syntheticPoisoning.required_acknowledgement === 'string' &&
        syntheticPoisoning.required_acknowledgement.length > 0,
      '`runtime.synthetic_poisoning.required_acknowledgement` must be non-empty string',
      details
    );
    assertType(
      typeof syntheticPoisoning.acknowledgement === 'string',
      '`runtime.synthetic_poisoning.acknowledgement` must be string',
      details
    );
    assertType(
      Array.isArray(syntheticPoisoning.allowed_triggers) && syntheticPoisoning.allowed_triggers.length > 0,
      '`runtime.synthetic_poisoning.allowed_triggers` must be non-empty array',
      details
    );
    assertType(
      Array.isArray(syntheticPoisoning.target_roles) && syntheticPoisoning.target_roles.length > 0,
      '`runtime.synthetic_poisoning.target_roles` must be non-empty array',
      details
    );
    assertType(
      typeof syntheticPoisoning.decoy_label === 'string' && syntheticPoisoning.decoy_label.length > 0,
      '`runtime.synthetic_poisoning.decoy_label` must be non-empty string',
      details
    );
    assertType(
      Number.isInteger(syntheticPoisoning.max_insertions_per_request) &&
        syntheticPoisoning.max_insertions_per_request > 0,
      '`runtime.synthetic_poisoning.max_insertions_per_request` must be integer > 0',
      details
    );
    assertType(
      typeof syntheticPoisoning.observability === 'boolean',
      '`runtime.synthetic_poisoning.observability` must be boolean',
      details
    );
  }

  const cognitiveRollback = runtime.cognitive_rollback || {};
  if (runtime.cognitive_rollback !== undefined) {
    assertNoUnknownKeys(cognitiveRollback, COGNITIVE_ROLLBACK_KEYS, 'runtime.cognitive_rollback', details);
    assertType(
      typeof cognitiveRollback.enabled === 'boolean',
      '`runtime.cognitive_rollback.enabled` must be boolean',
      details
    );
    assertType(
      COGNITIVE_ROLLBACK_MODES.has(String(cognitiveRollback.mode)),
      '`runtime.cognitive_rollback.mode` must be monitor|auto',
      details
    );
    assertType(
      Array.isArray(cognitiveRollback.triggers) && cognitiveRollback.triggers.length > 0,
      '`runtime.cognitive_rollback.triggers` must be non-empty array',
      details
    );
    assertType(
      Array.isArray(cognitiveRollback.target_roles) && cognitiveRollback.target_roles.length > 0,
      '`runtime.cognitive_rollback.target_roles` must be non-empty array',
      details
    );
    assertType(
      Number.isInteger(cognitiveRollback.drop_messages) && cognitiveRollback.drop_messages > 0,
      '`runtime.cognitive_rollback.drop_messages` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(cognitiveRollback.min_messages_remaining) && cognitiveRollback.min_messages_remaining > 0,
      '`runtime.cognitive_rollback.min_messages_remaining` must be integer > 0',
      details
    );
    assertType(
      typeof cognitiveRollback.system_message === 'string' && cognitiveRollback.system_message.length > 0,
      '`runtime.cognitive_rollback.system_message` must be non-empty string',
      details
    );
    assertType(
      typeof cognitiveRollback.observability === 'boolean',
      '`runtime.cognitive_rollback.observability` must be boolean',
      details
    );
  }

  const omniShield = runtime.omni_shield || {};
  if (runtime.omni_shield !== undefined) {
    assertNoUnknownKeys(omniShield, OMNI_SHIELD_KEYS, 'runtime.omni_shield', details);
    assertType(typeof omniShield.enabled === 'boolean', '`runtime.omni_shield.enabled` must be boolean', details);
    assertType(
      OMNI_SHIELD_MODES.has(String(omniShield.mode)),
      '`runtime.omni_shield.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(omniShield.max_image_bytes) && omniShield.max_image_bytes > 0,
      '`runtime.omni_shield.max_image_bytes` must be integer > 0',
      details
    );
    assertType(
      typeof omniShield.allow_remote_image_urls === 'boolean',
      '`runtime.omni_shield.allow_remote_image_urls` must be boolean',
      details
    );
    assertType(
      typeof omniShield.allow_base64_images === 'boolean',
      '`runtime.omni_shield.allow_base64_images` must be boolean',
      details
    );
    assertType(
      typeof omniShield.block_on_any_image === 'boolean',
      '`runtime.omni_shield.block_on_any_image` must be boolean',
      details
    );
    assertType(
      Number.isInteger(omniShield.max_findings) && omniShield.max_findings > 0,
      '`runtime.omni_shield.max_findings` must be integer > 0',
      details
    );
    assertType(
      Array.isArray(omniShield.target_roles) && omniShield.target_roles.length > 0,
      '`runtime.omni_shield.target_roles` must be non-empty array',
      details
    );
    assertType(
      typeof omniShield.observability === 'boolean',
      '`runtime.omni_shield.observability` must be boolean',
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

  const budget = runtime.budget || {};
  if (runtime.budget !== undefined) {
    assertNoUnknownKeys(budget, BUDGET_KEYS, 'runtime.budget', details);
    assertType(typeof budget.enabled === 'boolean', '`runtime.budget.enabled` must be boolean', details);
    assertType(
      BUDGET_ACTIONS.has(String(budget.action)),
      '`runtime.budget.action` must be block|warn',
      details
    );
    assertType(
      Number.isFinite(Number(budget.daily_limit_usd)) && Number(budget.daily_limit_usd) > 0,
      '`runtime.budget.daily_limit_usd` must be number > 0',
      details
    );
    assertType(
      typeof budget.store_file === 'string' && budget.store_file.length > 0,
      '`runtime.budget.store_file` must be non-empty string',
      details
    );
    assertType(
      BUDGET_RESET_TIMEZONES.has(String(budget.reset_timezone)),
      '`runtime.budget.reset_timezone` must be utc|local',
      details
    );
    assertType(
      Number.isInteger(budget.chars_per_token) && budget.chars_per_token > 0,
      '`runtime.budget.chars_per_token` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(budget.input_cost_per_1k_tokens)) && Number(budget.input_cost_per_1k_tokens) >= 0,
      '`runtime.budget.input_cost_per_1k_tokens` must be number >= 0',
      details
    );
    assertType(
      Number.isFinite(Number(budget.output_cost_per_1k_tokens)) && Number(budget.output_cost_per_1k_tokens) >= 0,
      '`runtime.budget.output_cost_per_1k_tokens` must be number >= 0',
      details
    );
    assertType(
      typeof budget.charge_replay_hits === 'boolean',
      '`runtime.budget.charge_replay_hits` must be boolean',
      details
    );
    assertType(
      Number.isInteger(budget.retention_days) && budget.retention_days > 0,
      '`runtime.budget.retention_days` must be integer > 0',
      details
    );
  }

  const loopBreaker = runtime.loop_breaker || {};
  if (runtime.loop_breaker !== undefined) {
    assertNoUnknownKeys(loopBreaker, LOOP_BREAKER_KEYS, 'runtime.loop_breaker', details);
    assertType(typeof loopBreaker.enabled === 'boolean', '`runtime.loop_breaker.enabled` must be boolean', details);
    assertType(
      LOOP_BREAKER_ACTIONS.has(String(loopBreaker.action)),
      '`runtime.loop_breaker.action` must be block|warn',
      details
    );
    assertType(
      Number.isInteger(loopBreaker.window_ms) && loopBreaker.window_ms > 0,
      '`runtime.loop_breaker.window_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(loopBreaker.repeat_threshold) && loopBreaker.repeat_threshold >= 2,
      '`runtime.loop_breaker.repeat_threshold` must be integer >= 2',
      details
    );
    assertType(
      Number.isInteger(loopBreaker.max_recent) && loopBreaker.max_recent >= Number(loopBreaker.repeat_threshold || 2),
      '`runtime.loop_breaker.max_recent` must be integer >= repeat_threshold',
      details
    );
    assertType(
      Number.isInteger(loopBreaker.max_keys) && loopBreaker.max_keys > 0,
      '`runtime.loop_breaker.max_keys` must be integer > 0',
      details
    );
    assertType(
      typeof loopBreaker.key_header === 'string' && loopBreaker.key_header.length > 0,
      '`runtime.loop_breaker.key_header` must be non-empty string',
      details
    );
  }

  const provenance = runtime.provenance || {};
  if (runtime.provenance !== undefined) {
    assertNoUnknownKeys(provenance, PROVENANCE_KEYS, 'runtime.provenance', details);
    assertType(typeof provenance.enabled === 'boolean', '`runtime.provenance.enabled` must be boolean', details);
    assertType(typeof provenance.key_id === 'string' && provenance.key_id.length > 0, '`runtime.provenance.key_id` must be non-empty string', details);
    assertType(
      typeof provenance.sign_stream_trailers === 'boolean',
      '`runtime.provenance.sign_stream_trailers` must be boolean',
      details
    );
    assertType(
      typeof provenance.expose_public_key_endpoint === 'boolean',
      '`runtime.provenance.expose_public_key_endpoint` must be boolean',
      details
    );
    assertType(
      Number.isInteger(provenance.max_signable_bytes) && provenance.max_signable_bytes > 0,
      '`runtime.provenance.max_signable_bytes` must be integer > 0',
      details
    );
  }

  const deception = runtime.deception || {};
  if (runtime.deception !== undefined) {
    assertNoUnknownKeys(deception, DECEPTION_KEYS, 'runtime.deception', details);
    assertType(typeof deception.enabled === 'boolean', '`runtime.deception.enabled` must be boolean', details);
    assertType(
      DECEPTION_MODES.has(String(deception.mode)),
      '`runtime.deception.mode` must be off|tarpit',
      details
    );
    assertType(typeof deception.on_injection === 'boolean', '`runtime.deception.on_injection` must be boolean', details);
    assertType(typeof deception.on_loop === 'boolean', '`runtime.deception.on_loop` must be boolean', details);
    assertType(
      Number.isFinite(Number(deception.min_injection_score)) &&
        Number(deception.min_injection_score) >= 0 &&
        Number(deception.min_injection_score) <= 1,
      '`runtime.deception.min_injection_score` must be between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(deception.sse_token_interval_ms) && deception.sse_token_interval_ms >= 0,
      '`runtime.deception.sse_token_interval_ms` must be integer >= 0',
      details
    );
    assertType(
      Number.isInteger(deception.sse_max_tokens) && deception.sse_max_tokens > 0,
      '`runtime.deception.sse_max_tokens` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(deception.non_stream_delay_ms) && deception.non_stream_delay_ms >= 0,
      '`runtime.deception.non_stream_delay_ms` must be integer >= 0',
      details
    );
  }

  const honeytoken = runtime.honeytoken || {};
  if (runtime.honeytoken !== undefined) {
    assertNoUnknownKeys(honeytoken, HONEYTOKEN_KEYS, 'runtime.honeytoken', details);
    assertType(typeof honeytoken.enabled === 'boolean', '`runtime.honeytoken.enabled` must be boolean', details);
    assertType(
      HONEYTOKEN_MODES.has(String(honeytoken.mode)),
      '`runtime.honeytoken.mode` must be zero_width|uuid_suffix',
      details
    );
    assertType(
      Number.isFinite(Number(honeytoken.injection_rate)) &&
        Number(honeytoken.injection_rate) >= 0 &&
        Number(honeytoken.injection_rate) <= 1,
      '`runtime.honeytoken.injection_rate` must be between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(honeytoken.max_insertions_per_request) && honeytoken.max_insertions_per_request > 0,
      '`runtime.honeytoken.max_insertions_per_request` must be integer > 0',
      details
    );
    assertType(
      Array.isArray(honeytoken.target_roles) && honeytoken.target_roles.length > 0,
      '`runtime.honeytoken.target_roles` must be non-empty array',
      details
    );
    if (Array.isArray(honeytoken.target_roles)) {
      honeytoken.target_roles.forEach((role, idx) => {
        assertType(
          typeof role === 'string' && role.length > 0,
          `runtime.honeytoken.target_roles[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      typeof honeytoken.token_prefix === 'string' && honeytoken.token_prefix.length > 0,
      '`runtime.honeytoken.token_prefix` must be non-empty string',
      details
    );
  }

  const latencyNormalization = runtime.latency_normalization || {};
  if (runtime.latency_normalization !== undefined) {
    assertNoUnknownKeys(latencyNormalization, LATENCY_NORMALIZATION_KEYS, 'runtime.latency_normalization', details);
    assertType(
      typeof latencyNormalization.enabled === 'boolean',
      '`runtime.latency_normalization.enabled` must be boolean',
      details
    );
    assertType(
      Number.isInteger(latencyNormalization.window_size) && latencyNormalization.window_size > 0,
      '`runtime.latency_normalization.window_size` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(latencyNormalization.min_samples) &&
        latencyNormalization.min_samples > 0 &&
        latencyNormalization.min_samples <= latencyNormalization.window_size,
      '`runtime.latency_normalization.min_samples` must be integer > 0 and <= window_size',
      details
    );
    assertType(
      Number.isInteger(latencyNormalization.max_delay_ms) && latencyNormalization.max_delay_ms > 0,
      '`runtime.latency_normalization.max_delay_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(latencyNormalization.max_baseline_sample_ms) && latencyNormalization.max_baseline_sample_ms > 0,
      '`runtime.latency_normalization.max_baseline_sample_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(latencyNormalization.trim_percentile)) &&
        Number(latencyNormalization.trim_percentile) >= 0 &&
        Number(latencyNormalization.trim_percentile) < 0.5,
      '`runtime.latency_normalization.trim_percentile` must be number in [0, 0.5)',
      details
    );
    assertType(
      Number.isInteger(latencyNormalization.max_concurrent_normalized) &&
        latencyNormalization.max_concurrent_normalized > 0,
      '`runtime.latency_normalization.max_concurrent_normalized` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(latencyNormalization.jitter_ms) && latencyNormalization.jitter_ms >= 0,
      '`runtime.latency_normalization.jitter_ms` must be integer >= 0',
      details
    );
    assertType(
      Array.isArray(latencyNormalization.statuses) && latencyNormalization.statuses.length > 0,
      '`runtime.latency_normalization.statuses` must be non-empty array',
      details
    );
    if (Array.isArray(latencyNormalization.statuses)) {
      latencyNormalization.statuses.forEach((status, idx) => {
        assertType(
          Number.isInteger(status) && status >= 100 && status <= 599,
          `runtime.latency_normalization.statuses[${idx}] must be HTTP status integer`,
          details
        );
      });
    }
  }

  const canaryTools = runtime.canary_tools || {};
  if (runtime.canary_tools !== undefined) {
    assertNoUnknownKeys(canaryTools, CANARY_TOOL_KEYS, 'runtime.canary_tools', details);
    assertType(typeof canaryTools.enabled === 'boolean', '`runtime.canary_tools.enabled` must be boolean', details);
    assertType(
      CANARY_TOOL_MODES.has(String(canaryTools.mode)),
      '`runtime.canary_tools.mode` must be monitor|block',
      details
    );
    assertType(
      typeof canaryTools.tool_name === 'string' && canaryTools.tool_name.length > 0,
      '`runtime.canary_tools.tool_name` must be non-empty string',
      details
    );
    assertType(
      typeof canaryTools.tool_description === 'string' && canaryTools.tool_description.length > 0,
      '`runtime.canary_tools.tool_description` must be non-empty string',
      details
    );
    assertType(
      Number.isInteger(canaryTools.max_injected_tools) && canaryTools.max_injected_tools > 0,
      '`runtime.canary_tools.max_injected_tools` must be integer > 0',
      details
    );
    assertType(
      Array.isArray(canaryTools.inject_on_providers) && canaryTools.inject_on_providers.length > 0,
      '`runtime.canary_tools.inject_on_providers` must be non-empty array',
      details
    );
    assertType(
      typeof canaryTools.require_tools_array === 'boolean',
      '`runtime.canary_tools.require_tools_array` must be boolean',
      details
    );
  }

  const parallax = runtime.parallax || {};
  if (runtime.parallax !== undefined) {
    assertNoUnknownKeys(parallax, PARALLAX_KEYS, 'runtime.parallax', details);
    assertType(typeof parallax.enabled === 'boolean', '`runtime.parallax.enabled` must be boolean', details);
    assertType(
      PARALLAX_MODES.has(String(parallax.mode)),
      '`runtime.parallax.mode` must be monitor|block',
      details
    );
    assertType(
      Array.isArray(parallax.high_risk_tools) && parallax.high_risk_tools.length > 0,
      '`runtime.parallax.high_risk_tools` must be non-empty array',
      details
    );
    if (Array.isArray(parallax.high_risk_tools)) {
      parallax.high_risk_tools.forEach((toolName, idx) => {
        assertType(
          typeof toolName === 'string' && toolName.length > 0,
          `runtime.parallax.high_risk_tools[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      ['openai', 'anthropic', 'google', 'ollama', 'custom'].includes(String(parallax.secondary_target)),
      '`runtime.parallax.secondary_target` must be openai|anthropic|google|ollama|custom',
      details
    );
    assertType(
      typeof parallax.secondary_group === 'string',
      '`runtime.parallax.secondary_group` must be string',
      details
    );
    assertType(
      typeof parallax.secondary_contract === 'string' && parallax.secondary_contract.length > 0,
      '`runtime.parallax.secondary_contract` must be non-empty string',
      details
    );
    assertType(
      typeof parallax.secondary_model === 'string',
      '`runtime.parallax.secondary_model` must be string',
      details
    );
    assertType(
      Number.isInteger(parallax.timeout_ms) && parallax.timeout_ms > 0,
      '`runtime.parallax.timeout_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(parallax.risk_threshold)) &&
        Number(parallax.risk_threshold) >= 0 &&
        Number(parallax.risk_threshold) <= 1,
      '`runtime.parallax.risk_threshold` must be number between 0 and 1',
      details
    );
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

  const resilienceMesh = runtime.upstream?.resilience_mesh;
  if (resilienceMesh !== undefined) {
    assertNoUnknownKeys(resilienceMesh, RESILIENCE_MESH_KEYS, 'runtime.upstream.resilience_mesh', details);
    assertType(
      typeof resilienceMesh.enabled === 'boolean',
      '`runtime.upstream.resilience_mesh.enabled` must be boolean',
      details
    );
    assertType(
      typeof resilienceMesh.contract === 'string',
      '`runtime.upstream.resilience_mesh.contract` must be string',
      details
    );
    assertType(
      typeof resilienceMesh.default_group === 'string',
      '`runtime.upstream.resilience_mesh.default_group` must be string',
      details
    );
    assertType(
      Number.isInteger(resilienceMesh.max_failover_hops) && resilienceMesh.max_failover_hops >= 0,
      '`runtime.upstream.resilience_mesh.max_failover_hops` must be integer >= 0',
      details
    );
    assertType(
      typeof resilienceMesh.allow_post_with_idempotency_key === 'boolean',
      '`runtime.upstream.resilience_mesh.allow_post_with_idempotency_key` must be boolean',
      details
    );
    assertType(
      Array.isArray(resilienceMesh.failover_on_status),
      '`runtime.upstream.resilience_mesh.failover_on_status` must be an array',
      details
    );
    if (Array.isArray(resilienceMesh.failover_on_status)) {
      resilienceMesh.failover_on_status.forEach((status, idx) => {
        assertType(
          Number.isInteger(status) && status >= 100 && status <= 599,
          `runtime.upstream.resilience_mesh.failover_on_status[${idx}] must be HTTP status integer`,
          details
        );
      });
    }
    assertType(
      Array.isArray(resilienceMesh.failover_on_error_types),
      '`runtime.upstream.resilience_mesh.failover_on_error_types` must be an array',
      details
    );
    if (Array.isArray(resilienceMesh.failover_on_error_types)) {
      resilienceMesh.failover_on_error_types.forEach((item, idx) => {
        const normalized = String(item).toLowerCase();
        assertType(
          ['timeout', 'transport', 'circuit_open'].includes(normalized),
          `runtime.upstream.resilience_mesh.failover_on_error_types[${idx}] must be timeout|transport|circuit_open`,
          details
        );
      });
    }
    assertType(
      resilienceMesh.groups && typeof resilienceMesh.groups === 'object' && !Array.isArray(resilienceMesh.groups),
      '`runtime.upstream.resilience_mesh.groups` must be an object',
      details
    );
    if (resilienceMesh.groups && typeof resilienceMesh.groups === 'object' && !Array.isArray(resilienceMesh.groups)) {
      Object.entries(resilienceMesh.groups).forEach(([groupName, groupConfig]) => {
        assertType(
          groupConfig && typeof groupConfig === 'object' && !Array.isArray(groupConfig),
          `runtime.upstream.resilience_mesh.groups.${groupName} must be object`,
          details
        );
        if (!groupConfig || typeof groupConfig !== 'object' || Array.isArray(groupConfig)) {
          return;
        }
        assertNoUnknownKeys(
          groupConfig,
          RESILIENCE_GROUP_KEYS,
          `runtime.upstream.resilience_mesh.groups.${groupName}`,
          details
        );
        assertType(
          typeof groupConfig.enabled === 'boolean',
          `runtime.upstream.resilience_mesh.groups.${groupName}.enabled must be boolean`,
          details
        );
        assertType(
          typeof groupConfig.contract === 'string',
          `runtime.upstream.resilience_mesh.groups.${groupName}.contract must be string`,
          details
        );
        assertType(
          Array.isArray(groupConfig.targets),
          `runtime.upstream.resilience_mesh.groups.${groupName}.targets must be array`,
          details
        );
      });
    }
    assertType(
      resilienceMesh.targets && typeof resilienceMesh.targets === 'object' && !Array.isArray(resilienceMesh.targets),
      '`runtime.upstream.resilience_mesh.targets` must be an object',
      details
    );
    if (resilienceMesh.targets && typeof resilienceMesh.targets === 'object' && !Array.isArray(resilienceMesh.targets)) {
      Object.entries(resilienceMesh.targets).forEach(([targetName, targetConfig]) => {
        assertType(
          targetConfig && typeof targetConfig === 'object' && !Array.isArray(targetConfig),
          `runtime.upstream.resilience_mesh.targets.${targetName} must be object`,
          details
        );
        if (!targetConfig || typeof targetConfig !== 'object' || Array.isArray(targetConfig)) {
          return;
        }
        assertNoUnknownKeys(
          targetConfig,
          RESILIENCE_TARGET_KEYS,
          `runtime.upstream.resilience_mesh.targets.${targetName}`,
          details
        );
        assertType(
          typeof targetConfig.enabled === 'boolean',
          `runtime.upstream.resilience_mesh.targets.${targetName}.enabled must be boolean`,
          details
        );
        assertType(
          typeof targetConfig.provider === 'string',
          `runtime.upstream.resilience_mesh.targets.${targetName}.provider must be string`,
          details
        );
        assertType(
          ['openai', 'anthropic', 'google', 'ollama', 'custom'].includes(String(targetConfig.provider).toLowerCase()),
          `runtime.upstream.resilience_mesh.targets.${targetName}.provider must be openai|anthropic|google|ollama|custom`,
          details
        );
        assertType(
          typeof targetConfig.contract === 'string',
          `runtime.upstream.resilience_mesh.targets.${targetName}.contract must be string`,
          details
        );
        if (targetConfig.base_url !== undefined) {
          assertType(
            typeof targetConfig.base_url === 'string' && targetConfig.base_url.length > 0,
            `runtime.upstream.resilience_mesh.targets.${targetName}.base_url must be non-empty string`,
            details
          );
        }
        if (targetConfig.custom_url !== undefined) {
          assertType(
            typeof targetConfig.custom_url === 'string' && targetConfig.custom_url.length > 0,
            `runtime.upstream.resilience_mesh.targets.${targetName}.custom_url must be non-empty string`,
            details
          );
        }
        if (targetConfig.headers !== undefined) {
          assertType(
            targetConfig.headers && typeof targetConfig.headers === 'object' && !Array.isArray(targetConfig.headers),
            `runtime.upstream.resilience_mesh.targets.${targetName}.headers must be object`,
            details
          );
        }
      });
    }
  }

  const canary = runtime.upstream?.canary;
  if (canary !== undefined) {
    assertNoUnknownKeys(canary, CANARY_KEYS, 'runtime.upstream.canary', details);
    assertType(typeof canary.enabled === 'boolean', '`runtime.upstream.canary.enabled` must be boolean', details);
    assertType(typeof canary.key_header === 'string', '`runtime.upstream.canary.key_header` must be string', details);
    assertType(
      Array.isArray(canary.fallback_key_headers),
      '`runtime.upstream.canary.fallback_key_headers` must be array',
      details
    );
    assertType(Array.isArray(canary.splits), '`runtime.upstream.canary.splits` must be array', details);
    if (Array.isArray(canary.splits)) {
      canary.splits.forEach((split, idx) => {
        assertType(split && typeof split === 'object' && !Array.isArray(split), `runtime.upstream.canary.splits[${idx}] must be object`, details);
        if (!split || typeof split !== 'object' || Array.isArray(split)) {
          return;
        }
        assertNoUnknownKeys(split, CANARY_SPLIT_KEYS, `runtime.upstream.canary.splits[${idx}]`, details);
        assertType(typeof split.name === 'string', `runtime.upstream.canary.splits[${idx}].name must be string`, details);
        assertType(typeof split.match_target === 'string', `runtime.upstream.canary.splits[${idx}].match_target must be string`, details);
        assertType(typeof split.group_a === 'string', `runtime.upstream.canary.splits[${idx}].group_a must be string`, details);
        assertType(typeof split.group_b === 'string', `runtime.upstream.canary.splits[${idx}].group_b must be string`, details);
        assertType(
          Number.isFinite(Number(split.weight_a)) && Number(split.weight_a) >= 0,
          `runtime.upstream.canary.splits[${idx}].weight_a must be number >= 0`,
          details
        );
        assertType(
          Number.isFinite(Number(split.weight_b)) && Number(split.weight_b) >= 0,
          `runtime.upstream.canary.splits[${idx}].weight_b must be number >= 0`,
          details
        );
        assertType(typeof split.sticky === 'boolean', `runtime.upstream.canary.splits[${idx}].sticky must be boolean`, details);
      });
    }
  }

  const ghostMode = runtime.upstream?.ghost_mode;
  if (ghostMode !== undefined) {
    assertNoUnknownKeys(ghostMode, GHOST_MODE_KEYS, 'runtime.upstream.ghost_mode', details);
    assertType(
      ghostMode.enabled === undefined || typeof ghostMode.enabled === 'boolean',
      '`runtime.upstream.ghost_mode.enabled` must be boolean',
      details
    );
    assertType(
      ghostMode.strip_headers === undefined || Array.isArray(ghostMode.strip_headers),
      '`runtime.upstream.ghost_mode.strip_headers` must be array',
      details
    );
    if (Array.isArray(ghostMode.strip_headers)) {
      ghostMode.strip_headers.forEach((value, idx) => {
        assertType(
          typeof value === 'string' && value.length > 0,
          `runtime.upstream.ghost_mode.strip_headers[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      ghostMode.override_user_agent === undefined || typeof ghostMode.override_user_agent === 'boolean',
      '`runtime.upstream.ghost_mode.override_user_agent` must be boolean',
      details
    );
    assertType(
      ghostMode.user_agent_value === undefined || (typeof ghostMode.user_agent_value === 'string' && ghostMode.user_agent_value.length > 0),
      '`runtime.upstream.ghost_mode.user_agent_value` must be non-empty string',
      details
    );
  }

  const authVault = runtime.upstream?.auth_vault;
  if (authVault !== undefined) {
    assertNoUnknownKeys(authVault, AUTH_VAULT_KEYS, 'runtime.upstream.auth_vault', details);
    assertType(
      authVault.enabled === undefined || typeof authVault.enabled === 'boolean',
      '`runtime.upstream.auth_vault.enabled` must be boolean',
      details
    );
    assertType(
      authVault.mode === undefined || AUTH_VAULT_MODES.has(String(authVault.mode)),
      '`runtime.upstream.auth_vault.mode` must be replace_dummy|enforce',
      details
    );
    assertType(
      authVault.dummy_key === undefined || (typeof authVault.dummy_key === 'string' && authVault.dummy_key.length > 0),
      '`runtime.upstream.auth_vault.dummy_key` must be non-empty string',
      details
    );
    if (authVault.providers !== undefined) {
      assertType(
        authVault.providers && typeof authVault.providers === 'object' && !Array.isArray(authVault.providers),
        '`runtime.upstream.auth_vault.providers` must be object',
        details
      );
    }
    if (authVault.providers && typeof authVault.providers === 'object' && !Array.isArray(authVault.providers)) {
      for (const [providerName, providerConfig] of Object.entries(authVault.providers)) {
        if (!AUTH_VAULT_PROVIDERS.has(providerName)) {
          details.push(
            `runtime.upstream.auth_vault.providers.${providerName} is not supported (allowed: openai, anthropic, google)`
          );
          continue;
        }
        assertType(
          providerConfig && typeof providerConfig === 'object' && !Array.isArray(providerConfig),
          `runtime.upstream.auth_vault.providers.${providerName} must be object`,
          details
        );
        if (!providerConfig || typeof providerConfig !== 'object' || Array.isArray(providerConfig)) {
          continue;
        }
        assertNoUnknownKeys(
          providerConfig,
          AUTH_VAULT_PROVIDER_KEYS,
          `runtime.upstream.auth_vault.providers.${providerName}`,
          details
        );
        assertType(
          providerConfig.enabled === undefined || typeof providerConfig.enabled === 'boolean',
          `runtime.upstream.auth_vault.providers.${providerName}.enabled must be boolean`,
          details
        );
        assertType(
          providerConfig.api_key === undefined || typeof providerConfig.api_key === 'string',
          `runtime.upstream.auth_vault.providers.${providerName}.api_key must be string`,
          details
        );
        assertType(
          providerConfig.env_var === undefined || typeof providerConfig.env_var === 'string',
          `runtime.upstream.auth_vault.providers.${providerName}.env_var must be string`,
          details
        );
      }
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

      if (egress.entropy !== undefined) {
        assertType(
          egress.entropy && typeof egress.entropy === 'object' && !Array.isArray(egress.entropy),
          '`pii.egress.entropy` must be object',
          details
        );
        if (egress.entropy && typeof egress.entropy === 'object' && !Array.isArray(egress.entropy)) {
          assertNoUnknownKeys(egress.entropy, PII_EGRESS_ENTROPY_KEYS, 'pii.egress.entropy', details);
          assertType(typeof egress.entropy.enabled === 'boolean', '`pii.egress.entropy.enabled` must be boolean', details);
          assertType(
            PII_EGRESS_ENTROPY_MODES.has(String(egress.entropy.mode)),
            '`pii.egress.entropy.mode` must be monitor|block',
            details
          );
          assertType(
            Number.isFinite(Number(egress.entropy.threshold)) &&
              Number(egress.entropy.threshold) >= 0 &&
              Number(egress.entropy.threshold) <= 8,
            '`pii.egress.entropy.threshold` must be number between 0 and 8',
            details
          );
          assertType(
            Number.isInteger(egress.entropy.min_token_length) && egress.entropy.min_token_length > 0,
            '`pii.egress.entropy.min_token_length` must be integer > 0',
            details
          );
          assertType(
            Number.isInteger(egress.entropy.max_scan_bytes) && egress.entropy.max_scan_bytes > 0,
            '`pii.egress.entropy.max_scan_bytes` must be integer > 0',
            details
          );
          assertType(
            Number.isInteger(egress.entropy.max_findings) && egress.entropy.max_findings > 0,
            '`pii.egress.entropy.max_findings` must be integer > 0',
            details
          );
          assertType(
            Number.isFinite(Number(egress.entropy.min_unique_ratio)) &&
              Number(egress.entropy.min_unique_ratio) >= 0 &&
              Number(egress.entropy.min_unique_ratio) <= 1,
            '`pii.egress.entropy.min_unique_ratio` must be number between 0 and 1',
            details
          );
          assertType(
            typeof egress.entropy.detect_base64 === 'boolean',
            '`pii.egress.entropy.detect_base64` must be boolean',
            details
          );
          assertType(
            typeof egress.entropy.detect_hex === 'boolean',
            '`pii.egress.entropy.detect_hex` must be boolean',
            details
          );
          assertType(
            typeof egress.entropy.detect_generic === 'boolean',
            '`pii.egress.entropy.detect_generic` must be boolean',
            details
          );
          assertType(
            typeof egress.entropy.redact_replacement === 'string' &&
              egress.entropy.redact_replacement.length > 0,
            '`pii.egress.entropy.redact_replacement` must be non-empty string',
            details
          );
        }
      }
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
