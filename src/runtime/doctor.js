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
  validateRapidApiEndpoint,
};
