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
  const dashboard = config?.runtime?.dashboard || {};
  const budget = config?.runtime?.budget || {};
  const upstream = config?.runtime?.upstream || {};
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
