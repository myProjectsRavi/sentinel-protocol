function validateRapidApiEndpoint(endpoint, allowNonRapidApiHost) {
  let parsed;
  try {
    parsed = new URL(String(endpoint));
  } catch {
    return {
      ok: false,
      message: 'RapidAPI endpoint is not a valid absolute URL.',
    };
  }

  if (parsed.protocol !== 'https:') {
    return {
      ok: false,
      message: 'RapidAPI endpoint must use https.',
    };
  }

  if (!allowNonRapidApiHost) {
    const hostname = parsed.hostname.toLowerCase();
    const allowed = hostname === 'rapidapi.com' || hostname.endsWith('.rapidapi.com');
    if (!allowed) {
      return {
        ok: false,
        message: 'RapidAPI endpoint host must be rapidapi.com or *.rapidapi.com.',
      };
    }
  }

  return {
    ok: true,
    message: `RapidAPI endpoint is valid (${parsed.hostname}).`,
  };
}

function detectRapidApiKeySource(rapidapiConfig = {}, env = process.env) {
  if (env.SENTINEL_RAPIDAPI_KEY) {
    return 'env';
  }
  if (rapidapiConfig.api_key) {
    return 'config';
  }
  return 'none';
}

function detectAuthVaultKeySource(providerConfig = {}, env = process.env) {
  const envVar = String(providerConfig.env_var || '');
  if (envVar && env[envVar]) {
    return 'env';
  }
  if (providerConfig.api_key) {
    return 'config';
  }
  return 'none';
}

function summarizeChecks(checks) {
  const summary = { pass: 0, warn: 0, fail: 0 };
  for (const check of checks) {
    if (check.status === 'fail') summary.fail += 1;
    else if (check.status === 'warn') summary.warn += 1;
    else summary.pass += 1;
  }
  return summary;
}

function runDoctorChecks(config, env = process.env) {
  const checks = [];
  const mode = String(config?.pii?.provider_mode || 'local').toLowerCase();
  const rapidapi = config?.pii?.rapidapi || {};
  const semantic = config?.pii?.semantic || {};
  const semanticCache = config?.runtime?.semantic_cache || {};
  const intentThrottle = config?.runtime?.intent_throttle || {};
  const intentDrift = config?.runtime?.intent_drift || {};
  const swarm = config?.runtime?.swarm || {};
  const piiVault = config?.runtime?.pii_vault || {};
  const polymorphicPrompt = config?.runtime?.polymorphic_prompt || {};
  const syntheticPoisoning = config?.runtime?.synthetic_poisoning || {};
  const cognitiveRollback = config?.runtime?.cognitive_rollback || {};
  const omniShield = config?.runtime?.omni_shield || {};
  const sandboxExperimental = config?.runtime?.sandbox_experimental || {};
  const shadowOs = config?.runtime?.shadow_os || {};
  const epistemicAnchor = config?.runtime?.epistemic_anchor || {};
  const dashboard = config?.runtime?.dashboard || {};
  const budget = config?.runtime?.budget || {};
  const upstream = config?.runtime?.upstream || {};
  const autoImmune = config?.runtime?.auto_immune || {};
  const mesh = upstream.resilience_mesh || {};
  const canary = upstream.canary || {};
  const authVault = upstream.auth_vault || {};
  const workerPool = config?.runtime?.worker_pool || {};
  const fallbackToLocal = rapidapi.fallback_to_local !== false;
  const nodeEnv = String(env.NODE_ENV || '').toLowerCase();

  checks.push({
    id: 'pii-provider-mode',
    status: 'pass',
    message: `PII provider mode is '${mode}'.`,
  });

  checks.push({
    id: 'node-env',
    status: nodeEnv === 'production' ? 'pass' : 'warn',
    message:
      nodeEnv === 'production'
        ? 'NODE_ENV is production.'
        : 'NODE_ENV is not set to production. Use NODE_ENV=production for safer and faster runtime behavior.',
  });

  if (mode === 'local') {
    checks.push({
      id: 'rapidapi-not-required',
      status: 'pass',
      message: 'RapidAPI checks skipped because provider mode is local.',
    });
  } else {
    const endpointCheck = validateRapidApiEndpoint(rapidapi.endpoint, Boolean(rapidapi.allow_non_rapidapi_host));
    checks.push({
      id: 'rapidapi-endpoint',
      status: endpointCheck.ok ? 'pass' : 'fail',
      message: endpointCheck.message,
    });

    const keySource = detectRapidApiKeySource(rapidapi, env);
    if (keySource === 'env') {
      checks.push({
        id: 'rapidapi-key-source',
        status: 'pass',
        message: 'RapidAPI key found via SENTINEL_RAPIDAPI_KEY.',
      });
    } else if (keySource === 'config') {
      checks.push({
        id: 'rapidapi-key-source',
        status: 'warn',
        message: 'RapidAPI key is stored in config. Prefer SENTINEL_RAPIDAPI_KEY for secure BYOK handling.',
      });
    } else {
      const status = mode === 'rapidapi' && !fallbackToLocal ? 'fail' : 'warn';
      checks.push({
        id: 'rapidapi-key-source',
        status,
        message:
          status === 'fail'
            ? 'No RapidAPI key found and fallback_to_local=false. Requests will fail with PII_PROVIDER_ERROR.'
            : 'No RapidAPI key found. Sentinel will rely on local scanner fallback.',
      });
    }

    if (mode === 'rapidapi') {
      checks.push({
        id: 'rapidapi-fallback',
        status: fallbackToLocal ? 'pass' : 'warn',
        message: fallbackToLocal
          ? 'fallback_to_local=true: Sentinel can degrade safely to local scanning.'
          : 'fallback_to_local=false: RapidAPI outages or auth failures will fail requests.',
      });
    } else {
      checks.push({
        id: 'hybrid-local-safety',
        status: 'pass',
        message: 'Hybrid mode keeps local scanner active even when RapidAPI is unavailable.',
      });
    }
  }

  if (semantic.enabled === true) {
    let hasDependency = true;
    try {
      require.resolve('@xenova/transformers');
    } catch {
      hasDependency = false;
    }

    checks.push({
      id: 'semantic-scanner-dependency',
      status: hasDependency ? 'pass' : 'fail',
      message: hasDependency
        ? 'Semantic scanner dependency (@xenova/transformers) is installed.'
        : 'Semantic scanner is enabled but @xenova/transformers is missing. Install it to use semantic NER.',
    });
  }

  if (semanticCache.enabled === true) {
    checks.push({
      id: 'semantic-cache-worker-pool',
      status: workerPool.enabled === false ? 'fail' : 'pass',
      message:
        workerPool.enabled === false
          ? 'Semantic cache requires runtime.worker_pool.enabled=true for off-main-thread embeddings.'
          : 'Worker pool enabled for semantic cache embedding tasks.',
    });

    let hasDependency = true;
    try {
      require.resolve('@xenova/transformers');
    } catch {
      hasDependency = false;
    }

    checks.push({
      id: 'semantic-cache-dependency',
      status: hasDependency ? 'pass' : 'fail',
      message: hasDependency
        ? 'Semantic cache dependency (@xenova/transformers) is installed.'
        : 'Semantic cache is enabled but @xenova/transformers is missing.',
    });

    const embedTimeoutMs = Number(workerPool.embed_task_timeout_ms ?? workerPool.task_timeout_ms ?? 0);
    checks.push({
      id: 'semantic-cache-embed-timeout',
      status: embedTimeoutMs >= 5000 ? 'pass' : 'warn',
      message:
        embedTimeoutMs >= 5000
          ? `Worker embed timeout is ${embedTimeoutMs}ms (cold-start resilient).`
          : `Worker embed timeout is ${embedTimeoutMs}ms. Increase runtime.worker_pool.embed_task_timeout_ms to >=5000ms (recommended 10000ms).`,
    });
  }

  if (intentThrottle.enabled === true) {
    checks.push({
      id: 'intent-throttle-worker-pool',
      status: workerPool.enabled === false ? 'fail' : 'pass',
      message:
        workerPool.enabled === false
          ? 'Intent throttle requires runtime.worker_pool.enabled=true for off-main-thread embeddings.'
          : 'Worker pool enabled for intent throttle embedding tasks.',
    });

    let hasDependency = true;
    try {
      require.resolve('@xenova/transformers');
    } catch {
      hasDependency = false;
    }
    checks.push({
      id: 'intent-throttle-dependency',
      status: hasDependency ? 'pass' : 'fail',
      message: hasDependency
        ? 'Intent throttle dependency (@xenova/transformers) is installed.'
        : 'Intent throttle is enabled but @xenova/transformers is missing.',
    });

    const embedTimeoutMs = Number(workerPool.embed_task_timeout_ms ?? workerPool.task_timeout_ms ?? 0);
    checks.push({
      id: 'intent-throttle-embed-timeout',
      status: embedTimeoutMs >= 5000 ? 'pass' : 'warn',
      message:
        embedTimeoutMs >= 5000
          ? `Intent throttle embed timeout is ${embedTimeoutMs}ms (cold-start resilient).`
          : `Intent throttle embed timeout is ${embedTimeoutMs}ms. Increase runtime.worker_pool.embed_task_timeout_ms to >=5000ms (recommended 10000ms).`,
    });
  }

  if (intentDrift.enabled === true) {
    checks.push({
      id: 'intent-drift-worker-pool',
      status: workerPool.enabled === false ? 'fail' : 'pass',
      message:
        workerPool.enabled === false
          ? 'Intent drift detection requires runtime.worker_pool.enabled=true for off-main-thread embeddings.'
          : 'Worker pool enabled for intent drift embedding tasks.',
    });

    let hasDependency = true;
    try {
      require.resolve('@xenova/transformers');
    } catch {
      hasDependency = false;
    }
    checks.push({
      id: 'intent-drift-dependency',
      status: hasDependency ? 'pass' : 'fail',
      message: hasDependency
        ? 'Intent drift dependency (@xenova/transformers) is installed.'
        : 'Intent drift is enabled but @xenova/transformers is missing.',
    });

    const embedTimeoutMs = Number(workerPool.embed_task_timeout_ms ?? workerPool.task_timeout_ms ?? 0);
    checks.push({
      id: 'intent-drift-embed-timeout',
      status: embedTimeoutMs >= 5000 ? 'pass' : 'warn',
      message:
        embedTimeoutMs >= 5000
          ? `Intent drift embed timeout is ${embedTimeoutMs}ms (cold-start resilient).`
          : `Intent drift embed timeout is ${embedTimeoutMs}ms. Increase runtime.worker_pool.embed_task_timeout_ms to >=5000ms (recommended 10000ms).`,
    });

    const threshold = Number(intentDrift.threshold ?? 0.35);
    checks.push({
      id: 'intent-drift-threshold',
      status: threshold >= 0.2 && threshold <= 0.7 ? 'pass' : 'warn',
      message:
        threshold >= 0.2 && threshold <= 0.7
          ? `Intent drift threshold=${threshold} is within recommended operating range (0.2-0.7).`
          : `Intent drift threshold=${threshold} is outside recommended range (0.2-0.7); expect either false positives or missed drift.`,
    });

    const riskBoost = Number(intentDrift.risk_boost ?? 0.12);
    checks.push({
      id: 'intent-drift-risk-boost',
      status: riskBoost >= 0 && riskBoost <= 0.4 ? 'pass' : 'warn',
      message:
        riskBoost >= 0 && riskBoost <= 0.4
          ? `Intent drift risk_boost=${riskBoost} is in recommended range (0-0.4).`
          : `Intent drift risk_boost=${riskBoost} is high; tune to reduce false positives.`,
    });
  }

  if (swarm.enabled === true) {
    const skewWindow = Number(swarm.allowed_clock_skew_ms ?? swarm.tolerance_window_ms ?? 30000);
    checks.push({
      id: 'swarm-node-id',
      status: String(swarm.node_id || '').length > 0 ? 'pass' : 'fail',
      message:
        String(swarm.node_id || '').length > 0
          ? `Swarm node_id configured (${swarm.node_id}).`
          : 'Swarm enabled but runtime.swarm.node_id is empty.',
    });
    checks.push({
      id: 'swarm-clock-skew-window',
      status: skewWindow >= 5000 ? 'pass' : 'warn',
      message:
        skewWindow >= 5000
          ? `Swarm clock skew window is ${skewWindow}ms (global-friendly).`
          : `Swarm clock skew window is ${skewWindow}ms. Values below 5000ms can cause legitimate cross-region requests to fail under NTP drift.`,
    });
    checks.push({
      id: 'swarm-trust-store',
      status:
        swarm.verify_inbound === true &&
        swarm.require_envelope === true &&
        Object.keys(swarm.trusted_nodes || {}).length === 0
          ? 'warn'
          : 'pass',
      message:
        swarm.verify_inbound === true &&
        swarm.require_envelope === true &&
        Object.keys(swarm.trusted_nodes || {}).length === 0
          ? 'Swarm verification is strict but trusted_nodes is empty. All inbound swarm envelopes will fail verification.'
          : `Swarm trust store loaded (${Object.keys(swarm.trusted_nodes || {}).length} trusted node(s)).`,
    });
  }

  if (piiVault.enabled === true) {
    checks.push({
      id: 'pii-vault-mode',
      status: ['monitor', 'active'].includes(String(piiVault.mode || '').toLowerCase()) ? 'pass' : 'fail',
      message:
        ['monitor', 'active'].includes(String(piiVault.mode || '').toLowerCase())
          ? `PII vault enabled in '${String(piiVault.mode || 'monitor')}' mode.`
          : `PII vault mode '${String(piiVault.mode || '')}' is invalid.`,
    });
    checks.push({
      id: 'pii-vault-target-types',
      status: Array.isArray(piiVault.target_types) && piiVault.target_types.length > 0 ? 'pass' : 'fail',
      message:
        Array.isArray(piiVault.target_types) && piiVault.target_types.length > 0
          ? `PII vault target types: ${piiVault.target_types.join(', ')}`
          : 'PII vault is enabled but target_types is empty.',
    });
    checks.push({
      id: 'pii-vault-session-header',
      status: String(piiVault.session_header || '').length > 0 ? 'pass' : 'fail',
      message:
        String(piiVault.session_header || '').length > 0
          ? `PII vault session header: ${piiVault.session_header}`
          : 'PII vault is enabled but session_header is empty.',
    });
    const vaultMemoryBytes = Number(piiVault.max_memory_bytes || 0);
    checks.push({
      id: 'pii-vault-memory-cap',
      status: vaultMemoryBytes >= 8 * 1024 * 1024 ? 'pass' : 'warn',
      message:
        vaultMemoryBytes >= 8 * 1024 * 1024
          ? `PII vault max_memory_bytes=${vaultMemoryBytes}.`
          : `PII vault max_memory_bytes=${vaultMemoryBytes}. Recommended >= 8388608 for stable active tokenization.`,
    });
  }

  if (polymorphicPrompt.enabled === true) {
    checks.push({
      id: 'polymorphic-rotation',
      status: Number(polymorphicPrompt.rotation_seconds) >= 300 ? 'pass' : 'warn',
      message:
        Number(polymorphicPrompt.rotation_seconds) >= 300
          ? `Polymorphic prompt rotation is ${Number(polymorphicPrompt.rotation_seconds)}s.`
          : `Polymorphic prompt rotation is ${Number(polymorphicPrompt.rotation_seconds)}s; values <300s can cause instability in deterministic tool workflows.`,
    });
    checks.push({
      id: 'polymorphic-target-roles',
      status: Array.isArray(polymorphicPrompt.target_roles) && polymorphicPrompt.target_roles.length > 0 ? 'pass' : 'fail',
      message:
        Array.isArray(polymorphicPrompt.target_roles) && polymorphicPrompt.target_roles.length > 0
          ? `Polymorphic prompt targets roles: ${polymorphicPrompt.target_roles.join(', ')}`
          : 'Polymorphic prompt enabled but target_roles is empty.',
    });
  }

  if (syntheticPoisoning.enabled === true) {
    const requiredAck = String(syntheticPoisoning.required_acknowledgement || 'I_UNDERSTAND_SYNTHETIC_DATA_RISK');
    const ack = String(syntheticPoisoning.acknowledgement || '');
    checks.push({
      id: 'synthetic-poisoning-ack',
      status: syntheticPoisoning.mode === 'inject' && ack !== requiredAck ? 'fail' : 'pass',
      message:
        syntheticPoisoning.mode === 'inject' && ack !== requiredAck
          ? 'Synthetic poisoning inject mode requires an explicit legal acknowledgement string before activation.'
          : `Synthetic poisoning mode '${String(syntheticPoisoning.mode || 'monitor')}' acknowledged.`,
    });
    checks.push({
      id: 'synthetic-poisoning-trigger-scope',
      status: Array.isArray(syntheticPoisoning.allowed_triggers) && syntheticPoisoning.allowed_triggers.length > 0 ? 'pass' : 'fail',
      message:
        Array.isArray(syntheticPoisoning.allowed_triggers) && syntheticPoisoning.allowed_triggers.length > 0
          ? `Synthetic poisoning triggers: ${syntheticPoisoning.allowed_triggers.join(', ')}`
          : 'Synthetic poisoning enabled but allowed_triggers is empty.',
    });
  }

  if (cognitiveRollback.enabled === true) {
    checks.push({
      id: 'cognitive-rollback-mode',
      status: ['monitor', 'auto'].includes(String(cognitiveRollback.mode || '').toLowerCase()) ? 'pass' : 'fail',
      message:
        ['monitor', 'auto'].includes(String(cognitiveRollback.mode || '').toLowerCase())
          ? `Cognitive rollback is enabled in '${String(cognitiveRollback.mode || 'monitor')}' mode.`
          : `Cognitive rollback mode '${String(cognitiveRollback.mode || '')}' is invalid.`,
    });
    checks.push({
      id: 'cognitive-rollback-triggers',
      status: Array.isArray(cognitiveRollback.triggers) && cognitiveRollback.triggers.length > 0 ? 'pass' : 'fail',
      message:
        Array.isArray(cognitiveRollback.triggers) && cognitiveRollback.triggers.length > 0
          ? `Cognitive rollback triggers: ${cognitiveRollback.triggers.join(', ')}`
          : 'Cognitive rollback enabled but triggers list is empty.',
    });
  }

  if (omniShield.enabled === true) {
    checks.push({
      id: 'omni-shield-mode',
      status: ['monitor', 'block'].includes(String(omniShield.mode || '').toLowerCase()) ? 'pass' : 'fail',
      message:
        ['monitor', 'block'].includes(String(omniShield.mode || '').toLowerCase())
          ? `Omni-Shield enabled in '${String(omniShield.mode || 'monitor')}' mode.`
          : `Omni-Shield mode '${String(omniShield.mode || '')}' is invalid.`,
    });
    checks.push({
      id: 'omni-shield-image-budget',
      status: Number(omniShield.max_image_bytes || 0) > 0 ? 'pass' : 'fail',
      message:
        Number(omniShield.max_image_bytes || 0) > 0
          ? `Omni-Shield max_image_bytes=${Number(omniShield.max_image_bytes)}`
          : 'Omni-Shield enabled but max_image_bytes is invalid.',
    });

    const plugin = omniShield.plugin || {};
    if (plugin.enabled === true) {
      const timeoutMs = Number(plugin.timeout_ms || 0);
      checks.push({
        id: 'omni-shield-plugin-timeout',
        status: timeoutMs >= 100 && timeoutMs <= 5000 ? 'pass' : 'warn',
        message:
          timeoutMs >= 100 && timeoutMs <= 5000
            ? `Omni-Shield plugin timeout=${timeoutMs}ms.`
            : `Omni-Shield plugin timeout=${timeoutMs}ms. Recommended range is 100-5000ms.`,
      });
      checks.push({
        id: 'omni-shield-plugin-fail-closed',
        status: plugin.fail_closed === true ? 'warn' : 'pass',
        message:
          plugin.fail_closed === true
            ? 'Omni-Shield plugin fail-closed is enabled. Verify chaos scenarios to avoid accidental hard-blocks.'
            : 'Omni-Shield plugin fail-closed is disabled (safer for initial rollout).',
      });
    }
  }

  if (sandboxExperimental.enabled === true) {
    const patternCount = Array.isArray(sandboxExperimental.disallowed_patterns)
      ? sandboxExperimental.disallowed_patterns.length
      : 0;
    checks.push({
      id: 'sandbox-experimental-patterns',
      status: patternCount > 0 ? 'pass' : 'fail',
      message:
        patternCount > 0
          ? `Sandbox experimental module enabled with ${patternCount} disallowed pattern(s).`
          : 'Sandbox experimental module is enabled but has no disallowed patterns.',
    });
    checks.push({
      id: 'sandbox-experimental-mode',
      status: String(sandboxExperimental.mode || '').toLowerCase() === 'block' ? 'warn' : 'pass',
      message:
        String(sandboxExperimental.mode || '').toLowerCase() === 'block'
          ? 'Sandbox experimental mode is block. Validate false positives before production rollout.'
          : `Sandbox experimental mode is '${String(sandboxExperimental.mode || 'monitor')}'.`,
    });
    checks.push({
      id: 'sandbox-evasion-normalization',
      status: sandboxExperimental.normalize_evasion === false ? 'warn' : 'pass',
      message:
        sandboxExperimental.normalize_evasion === false
          ? 'Sandbox evasion normalization is disabled. Escaped/obfuscated payloads may bypass detection.'
          : 'Sandbox evasion normalization is enabled.',
    });
    checks.push({
      id: 'sandbox-base64-decoding',
      status: sandboxExperimental.decode_base64 === false ? 'warn' : 'pass',
      message:
        sandboxExperimental.decode_base64 === false
          ? 'Sandbox base64 decoding is disabled. Encoded payloads may evade detection.'
          : `Sandbox base64 decoding enabled (max_decoded_bytes=${Number(sandboxExperimental.max_decoded_bytes || 0)}).`,
    });
  }

  if (shadowOs.enabled === true) {
    checks.push({
      id: 'shadow-os-mode',
      status: ['monitor', 'block'].includes(String(shadowOs.mode || '').toLowerCase()) ? 'pass' : 'fail',
      message:
        ['monitor', 'block'].includes(String(shadowOs.mode || '').toLowerCase())
          ? `Shadow OS enabled in '${String(shadowOs.mode || 'monitor')}' mode.`
          : `Shadow OS mode '${String(shadowOs.mode || '')}' is invalid.`,
    });
    checks.push({
      id: 'shadow-os-rules',
      status: Array.isArray(shadowOs.sequence_rules) && shadowOs.sequence_rules.length > 0 ? 'pass' : 'fail',
      message:
        Array.isArray(shadowOs.sequence_rules) && shadowOs.sequence_rules.length > 0
          ? `Shadow OS sequence rules loaded (${shadowOs.sequence_rules.length}).`
          : 'Shadow OS enabled but sequence_rules is empty.',
    });
  }

  if (epistemicAnchor.enabled === true) {
    const ackRequired = String(epistemicAnchor.required_acknowledgement || 'I_UNDERSTAND_EPISTEMIC_ANCHOR_IS_EXPERIMENTAL');
    const ackGiven = String(epistemicAnchor.acknowledgement || '');
    checks.push({
      id: 'epistemic-anchor-ack',
      status: ackGiven === ackRequired ? 'pass' : 'warn',
      message:
        ackGiven === ackRequired
          ? 'Epistemic anchor acknowledgement is present.'
          : 'Epistemic anchor is experimental. Set acknowledgement to required_acknowledgement before enabling enforce behavior.',
    });
    checks.push({
      id: 'epistemic-anchor-threshold',
      status: Number(epistemicAnchor.threshold || 0) >= 0.6 ? 'pass' : 'warn',
      message:
        Number(epistemicAnchor.threshold || 0) >= 0.6
          ? `Epistemic anchor threshold=${Number(epistemicAnchor.threshold)}`
          : `Epistemic anchor threshold=${Number(epistemicAnchor.threshold)} may be too sensitive.`,
    });
  }

  if (dashboard.enabled === true) {
    checks.push({
      id: 'dashboard-local-only',
      status: dashboard.allow_remote === true ? 'warn' : 'pass',
      message:
        dashboard.allow_remote === true
          ? 'Dashboard allow_remote=true. Prefer local-only mode unless protected by token and network ACL.'
          : 'Dashboard is local-only (allow_remote=false).',
    });
  }

  if (budget.enabled === true) {
    checks.push({
      id: 'budget-limit',
      status: Number(budget.daily_limit_usd) > 0 ? 'pass' : 'fail',
      message:
        Number(budget.daily_limit_usd) > 0
          ? `Daily budget limit configured: $${Number(budget.daily_limit_usd).toFixed(2)}`
          : 'Budget enabled but daily_limit_usd is invalid.',
    });
    checks.push({
      id: 'budget-cost-model',
      status:
        Number(budget.input_cost_per_1k_tokens) > 0 || Number(budget.output_cost_per_1k_tokens) > 0
          ? 'pass'
          : 'warn',
      message:
        Number(budget.input_cost_per_1k_tokens) > 0 || Number(budget.output_cost_per_1k_tokens) > 0
          ? 'Budget token pricing is configured.'
          : 'Budget enabled with zero token pricing. Accounting will track tokens but estimated spend will remain $0.',
    });
  }

  if (autoImmune.enabled === true) {
    checks.push({
      id: 'auto-immune-mode',
      status: ['monitor', 'block'].includes(String(autoImmune.mode || '').toLowerCase()) ? 'pass' : 'fail',
      message:
        ['monitor', 'block'].includes(String(autoImmune.mode || '').toLowerCase())
          ? `Auto-Immune enabled in '${String(autoImmune.mode || 'monitor')}' mode.`
          : `Auto-Immune mode '${String(autoImmune.mode || '')}' is invalid.`,
    });
    checks.push({
      id: 'auto-immune-confidence-threshold',
      status: Number(autoImmune.min_confidence_to_match || 0) >= 0.6 ? 'pass' : 'warn',
      message:
        Number(autoImmune.min_confidence_to_match || 0) >= 0.6
          ? `Auto-Immune min_confidence_to_match=${Number(autoImmune.min_confidence_to_match)}`
          : `Auto-Immune min_confidence_to_match=${Number(autoImmune.min_confidence_to_match)} may be too low and can increase false positives.`,
    });
    checks.push({
      id: 'auto-immune-decay-half-life',
      status: Number(autoImmune.decay_half_life_ms || 0) >= 300000 ? 'pass' : 'warn',
      message:
        Number(autoImmune.decay_half_life_ms || 0) >= 300000
          ? `Auto-Immune decay_half_life_ms=${Number(autoImmune.decay_half_life_ms)}.`
          : `Auto-Immune decay_half_life_ms=${Number(autoImmune.decay_half_life_ms)} is very short; learned antibodies may evaporate too quickly.`,
    });
  }

  if (mesh.enabled === true) {
    const groupCount = mesh.groups && typeof mesh.groups === 'object' ? Object.keys(mesh.groups).length : 0;
    checks.push({
      id: 'mesh-groups',
      status: groupCount > 0 ? 'pass' : 'fail',
      message:
        groupCount > 0
          ? `Resilience mesh enabled with ${groupCount} group(s).`
          : 'Resilience mesh enabled but no groups are defined.',
    });
    checks.push({
      id: 'mesh-failover-hops',
      status: Number(mesh.max_failover_hops) > 0 ? 'pass' : 'warn',
      message:
        Number(mesh.max_failover_hops) > 0
          ? `Failover hops configured: ${Number(mesh.max_failover_hops)}`
          : 'Mesh failover is effectively disabled because max_failover_hops=0.',
    });
  }

  if (canary.enabled === true) {
    checks.push({
      id: 'canary-mesh-dependency',
      status: mesh.enabled === true ? 'pass' : 'warn',
      message:
        mesh.enabled === true
          ? 'Canary routing has resilience mesh enabled.'
          : 'Canary is enabled but resilience mesh is disabled; canary splits will not route.',
    });
    const splitCount = Array.isArray(canary.splits) ? canary.splits.length : 0;
    checks.push({
      id: 'canary-splits',
      status: splitCount > 0 ? 'pass' : 'warn',
      message:
        splitCount > 0
          ? `Canary configured with ${splitCount} split rule(s).`
          : 'Canary enabled without splits; no traffic will be split.',
    });
  }

  if (authVault.enabled === true) {
    const mode = String(authVault.mode || 'replace_dummy').toLowerCase();
    const dummyKey = String(authVault.dummy_key || '');
    const providers =
      authVault.providers && typeof authVault.providers === 'object' && !Array.isArray(authVault.providers)
        ? authVault.providers
        : {};

    checks.push({
      id: 'auth-vault-mode',
      status: ['replace_dummy', 'enforce'].includes(mode) ? 'pass' : 'fail',
      message:
        ['replace_dummy', 'enforce'].includes(mode)
          ? `Auth vault enabled in '${mode}' mode.`
          : `Auth vault mode '${mode}' is invalid.`,
    });

    checks.push({
      id: 'auth-vault-dummy-key',
      status: dummyKey.length > 0 ? 'pass' : 'fail',
      message: dummyKey.length > 0
        ? 'Auth vault dummy key is configured.'
        : 'Auth vault dummy key is empty.',
    });

    for (const providerName of ['openai', 'anthropic', 'google']) {
      const providerConfig =
        providers[providerName] && typeof providers[providerName] === 'object' && !Array.isArray(providers[providerName])
          ? providers[providerName]
          : {};
      if (providerConfig.enabled === false) {
        checks.push({
          id: `auth-vault-key-${providerName}`,
          status: 'pass',
          message: `Auth vault provider '${providerName}' is disabled.`,
        });
        continue;
      }

      const source = detectAuthVaultKeySource(providerConfig, env);
      if (source === 'env') {
        checks.push({
          id: `auth-vault-key-${providerName}`,
          status: 'pass',
          message: `Auth vault key for '${providerName}' found via ${providerConfig.env_var || 'env var'}.`,
        });
      } else if (source === 'config') {
        checks.push({
          id: `auth-vault-key-${providerName}`,
          status: 'warn',
          message: `Auth vault key for '${providerName}' is stored in config. Prefer ${providerConfig.env_var || 'env var'}.`,
        });
      } else {
        checks.push({
          id: `auth-vault-key-${providerName}`,
          status: mode === 'enforce' ? 'fail' : 'warn',
          message:
            mode === 'enforce'
              ? `Auth vault enforce mode requires a key for '${providerName}'.`
              : `No vault key found for '${providerName}'. Dummy-key replacement for this provider will fail.`,
        });
      }
    }
  }

  const summary = summarizeChecks(checks);
  return {
    ok: summary.fail === 0,
    summary,
    checks,
  };
}

function formatDoctorReport(report, options = {}) {
  const includeSummary = options.includeSummary !== false;
  const includeWarnings = options.includeWarnings !== false;
  const includePasses = options.includePasses !== false;
  const lines = [];

  if (includeSummary) {
    lines.push(`Doctor summary: pass=${report.summary.pass} warn=${report.summary.warn} fail=${report.summary.fail}`);
  }

  for (const check of report.checks) {
    if (check.status === 'pass' && !includePasses) continue;
    if (check.status === 'warn' && !includeWarnings) continue;
    lines.push(`[${check.status.toUpperCase()}] ${check.id}: ${check.message}`);
  }

  return lines.join('\n');
}

module.exports = {
  runDoctorChecks,
  formatDoctorReport,
  detectRapidApiKeySource,
  detectAuthVaultKeySource,
  validateRapidApiEndpoint,
};
