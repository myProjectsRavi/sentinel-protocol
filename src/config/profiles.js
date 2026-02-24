const PROFILE_NAMES = new Set(['minimal', 'standard', 'paranoid']);

const NON_ENGINE_RUNTIME_KEYS = new Set([
  'telemetry',
  'upstream',
  'worker_pool',
  'dashboard',
  'vcr',
]);

const MINIMAL_RUNTIME_ENGINES = new Set([
  'rate_limiter',
  'loop_breaker',
  'prompt_rebuff',
  'output_classifier',
  'serialization_firewall',
  'context_integrity_guardian',
  'tool_schema_validator',
  'cost_efficiency_optimizer',
]);

const PARANOID_MODE_OVERRIDES = Object.freeze({
  pii_vault: 'active',
  synthetic_poisoning: 'inject',
  cognitive_rollback: 'auto',
  websocket: 'enforce',
  budget_autopilot: 'active',
  cost_efficiency_optimizer: 'active',
  evidence_vault: 'active',
});

function isObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function cloneConfig(config) {
  return JSON.parse(JSON.stringify(config || {}));
}

function listRuntimeToggleKeys(runtime = {}) {
  return Object.entries(runtime)
    .filter(([key, value]) => {
      if (NON_ENGINE_RUNTIME_KEYS.has(String(key || ''))) {
        return false;
      }
      return isObject(value) && Object.prototype.hasOwnProperty.call(value, 'enabled');
    })
    .map(([key]) => key);
}

function setRuntimeEnabled(runtime, key, enabled) {
  if (!isObject(runtime[key])) {
    return;
  }
  runtime[key].enabled = enabled === true;
}

function applyMinimalProfile(config) {
  const next = cloneConfig(config);
  next.mode = 'monitor';
  next.runtime = isObject(next.runtime) ? next.runtime : {};

  const runtimeKeys = listRuntimeToggleKeys(next.runtime);
  for (const key of runtimeKeys) {
    setRuntimeEnabled(next.runtime, key, false);
  }
  for (const key of MINIMAL_RUNTIME_ENGINES) {
    setRuntimeEnabled(next.runtime, key, true);
  }

  next.pii = isObject(next.pii) ? next.pii : {};
  next.injection = isObject(next.injection) ? next.injection : {};
  next.pii.enabled = true;
  next.injection.enabled = true;

  next.runtime.cost_efficiency_optimizer = isObject(next.runtime.cost_efficiency_optimizer)
    ? next.runtime.cost_efficiency_optimizer
    : {};
  next.runtime.cost_efficiency_optimizer.enabled = true;
  next.runtime.cost_efficiency_optimizer.mode = 'active';
  next.runtime.cost_efficiency_optimizer.memory_warn_bytes = 384 * 1024 * 1024;
  next.runtime.cost_efficiency_optimizer.memory_critical_bytes = 448 * 1024 * 1024;
  next.runtime.cost_efficiency_optimizer.memory_hard_cap_bytes = 512 * 1024 * 1024;
  next.runtime.cost_efficiency_optimizer.shed_on_memory_pressure = true;
  next.runtime.cost_efficiency_optimizer.max_shed_engines = 24;
  next.runtime.cost_efficiency_optimizer.shed_cooldown_ms = 15000;
  next.runtime.cost_efficiency_optimizer.shed_engine_order = [
    'anomaly_telemetry',
    'attack_corpus_evolver',
    'threat_graph',
    'evidence_vault',
    'forensic_debugger',
    'adversarial_eval_harness',
    'semantic_drift_canary',
    'output_schema_validator',
    'output_classifier',
    'agent_observability',
    'capability_introspection',
    'policy_gradient_analyzer',
  ];

  return next;
}

function applyParanoidProfile(config) {
  const next = cloneConfig(config);
  next.mode = 'enforce';
  next.runtime = isObject(next.runtime) ? next.runtime : {};

  const runtimeKeys = listRuntimeToggleKeys(next.runtime);
  for (const key of runtimeKeys) {
    setRuntimeEnabled(next.runtime, key, true);
    if (typeof next.runtime[key].mode === 'string') {
      const currentMode = String(next.runtime[key].mode || '').toLowerCase();
      if (currentMode === 'monitor' || currentMode === 'warn') {
        next.runtime[key].mode = PARANOID_MODE_OVERRIDES[key] || 'block';
      }
    }
  }

  next.pii = isObject(next.pii) ? next.pii : {};
  next.injection = isObject(next.injection) ? next.injection : {};
  next.pii.enabled = true;
  next.injection.enabled = true;
  next.injection.action = 'block';
  return next;
}

function applyStandardProfile(config) {
  return cloneConfig(config);
}

function applyConfigProfile(config, profileName = 'standard') {
  const normalizedProfile = String(profileName || 'standard').trim().toLowerCase();
  if (!PROFILE_NAMES.has(normalizedProfile)) {
    throw new Error(`Invalid profile "${profileName}". Use minimal|standard|paranoid.`);
  }

  let profiled;
  if (normalizedProfile === 'minimal') {
    profiled = applyMinimalProfile(config);
  } else if (normalizedProfile === 'paranoid') {
    profiled = applyParanoidProfile(config);
  } else {
    profiled = applyStandardProfile(config);
  }

  const runtime = isObject(profiled.runtime) ? profiled.runtime : {};
  const runtimeKeys = listRuntimeToggleKeys(runtime);
  const enabledRuntimeEngines = runtimeKeys.filter((key) => runtime[key]?.enabled === true).length;

  return {
    profile: normalizedProfile,
    config: profiled,
    enabledRuntimeEngines,
    totalRuntimeEngines: runtimeKeys.length,
  };
}

module.exports = {
  PROFILE_NAMES,
  applyConfigProfile,
  listRuntimeToggleKeys,
};
