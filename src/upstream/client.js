const {
  parseRetryAfterMs,
  jitterBackoffMs,
  methodRetryEligible,
  shouldRetryResponse,
  shouldRetryError,
} = require('../resilience/retry');
const { Readable } = require('stream');
const dns = require('dns');
const net = require('net');
const { Agent } = require('undici');
const { selectUpstreamAdapter } = require('./adapters');

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'trailers',
  'transfer-encoding',
  'upgrade',
]);

const KNOWN_PROVIDER_AUTH_HEADERS = ['authorization', 'x-api-key', 'x-goog-api-key'];
const PROVIDER_AUTH_DEFAULTS = {
  openai: {
    headerName: 'authorization',
    scheme: 'bearer',
    envVar: 'SENTINEL_OPENAI_API_KEY',
  },
  anthropic: {
    headerName: 'x-api-key',
    scheme: 'raw',
    envVar: 'SENTINEL_ANTHROPIC_API_KEY',
  },
  google: {
    headerName: 'x-goog-api-key',
    scheme: 'raw',
    envVar: 'SENTINEL_GOOGLE_API_KEY',
  },
};
const DEFAULT_GHOST_STRIP_HEADERS = [
  'x-stainless-os',
  'x-stainless-arch',
  'x-stainless-runtime',
  'x-stainless-runtime-version',
  'x-stainless-package-version',
  'x-stainless-lang',
  'x-stainless-helper-method',
  'user-agent',
];

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function normalizeHeaderValue(value) {
  if (Array.isArray(value)) {
    return value.join(', ');
  }
  return value;
}

function findHeaderKey(headers, targetName) {
  const wanted = String(targetName || '').toLowerCase();
  for (const key of Object.keys(headers || {})) {
    if (String(key).toLowerCase() === wanted) {
      return key;
    }
  }
  return null;
}

function getHeader(headers, targetName) {
  const key = findHeaderKey(headers, targetName);
  if (!key) {
    return undefined;
  }
  return headers[key];
}

function setHeader(headers, targetName, value) {
  const existing = findHeaderKey(headers, targetName);
  if (existing) {
    headers[existing] = value;
    return;
  }
  headers[targetName] = value;
}

function deleteHeader(headers, targetName) {
  const existing = findHeaderKey(headers, targetName);
  if (existing) {
    delete headers[existing];
  }
}

function normalizeAuthVaultConfig(raw = {}) {
  const config = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const mode = String(config.mode || 'replace_dummy').toLowerCase();
  const providers = config.providers && typeof config.providers === 'object' && !Array.isArray(config.providers)
    ? config.providers
    : {};
  const normalizedProviders = {};

  for (const [provider, defaults] of Object.entries(PROVIDER_AUTH_DEFAULTS)) {
    const providerConfig = providers[provider] && typeof providers[provider] === 'object' && !Array.isArray(providers[provider])
      ? providers[provider]
      : {};
    normalizedProviders[provider] = {
      enabled: providerConfig.enabled !== false,
      apiKey: String(providerConfig.api_key || ''),
      envVar: String(providerConfig.env_var || defaults.envVar),
      headerName: defaults.headerName,
      scheme: defaults.scheme,
    };
  }

  return {
    enabled: config.enabled === true,
    mode: mode === 'enforce' ? 'enforce' : 'replace_dummy',
    dummyKey: String(config.dummy_key || 'sk-sentinel-local'),
    providers: normalizedProviders,
  };
}

function normalizeGhostModeConfig(raw = {}) {
  const config = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const stripHeaders = Array.isArray(config.strip_headers)
    ? config.strip_headers.map((value) => String(value).toLowerCase()).filter(Boolean)
    : DEFAULT_GHOST_STRIP_HEADERS;
  return {
    enabled: config.enabled === true,
    stripHeaders: Array.from(new Set(stripHeaders)),
    overrideUserAgent: config.override_user_agent !== false,
    userAgentValue: String(config.user_agent_value || 'Sentinel/1.0 (Privacy Proxy)'),
  };
}

function extractCredentialFromHeader(value, scheme) {
  if (value === undefined || value === null) {
    return '';
  }
  const text = String(value).trim();
  if (text.length === 0) {
    return '';
  }
  if (scheme === 'bearer') {
    const match = text.match(/^Bearer\s+(.+)$/i);
    if (match) {
      return String(match[1] || '').trim();
    }
  }
  return text;
}

function headerContainsDummy(value, dummyKey) {
  if (!value || !dummyKey) {
    return false;
  }
  const raw = String(value).trim();
  if (raw === dummyKey) {
    return true;
  }
  const bearerToken = extractCredentialFromHeader(raw, 'bearer');
  return bearerToken === dummyKey;
}

function containsDummyCredential(headers, dummyKey) {
  for (const headerName of KNOWN_PROVIDER_AUTH_HEADERS) {
    const value = getHeader(headers, headerName);
    if (headerContainsDummy(value, dummyKey)) {
      return true;
    }
  }
  return false;
}

function resolveProviderVaultKey(providerConfig) {
  if (!providerConfig) {
    return { key: '', source: 'none' };
  }
  const envVar = String(providerConfig.envVar || '');
  if (envVar && process.env[envVar]) {
    return { key: String(process.env[envVar]), source: 'env', envVar };
  }
  if (providerConfig.apiKey) {
    return { key: String(providerConfig.apiKey), source: 'config', envVar };
  }
  return { key: '', source: 'none', envVar };
}

function formatProviderAuthValue(key, scheme) {
  if (!key) {
    return '';
  }
  return scheme === 'bearer' ? `Bearer ${key}` : key;
}

function applyProviderAuthorization({ headers, provider, authVaultConfig }) {
  const providerName = String(provider || '').toLowerCase();
  const defaults = PROVIDER_AUTH_DEFAULTS[providerName];
  if (!defaults) {
    return {
      ok: true,
      headers,
      auth: {
        mode: 'passthrough',
        injected: false,
      },
    };
  }

  const outputHeaders = { ...(headers || {}) };
  const providerConfig = authVaultConfig.providers[providerName];
  const providerHeaderName = providerConfig?.headerName || defaults.headerName;
  const providerScheme = providerConfig?.scheme || defaults.scheme;
  const originalProviderValue = getHeader(outputHeaders, providerHeaderName);
  const dummyMatched = containsDummyCredential(outputHeaders, authVaultConfig.dummyKey);

  // Never forward non-target provider credentials to avoid cross-provider key leakage.
  for (const headerName of KNOWN_PROVIDER_AUTH_HEADERS) {
    deleteHeader(outputHeaders, headerName);
  }

  if (!authVaultConfig.enabled || providerConfig?.enabled !== true) {
    if (originalProviderValue !== undefined) {
      setHeader(outputHeaders, providerHeaderName, originalProviderValue);
    }
    return {
      ok: true,
      headers: outputHeaders,
      auth: {
        mode: 'passthrough',
        injected: false,
        dummyMatched,
      },
    };
  }

  const providerKey = resolveProviderVaultKey(providerConfig);
  if (authVaultConfig.mode === 'enforce') {
    if (!providerKey.key) {
      return {
        ok: false,
        errorCode: 'VAULT_PROVIDER_KEY_MISSING',
        message: `Auth vault enabled for provider ${providerName} but no key is configured. Set ${providerKey.envVar || 'provider env var'} or runtime.upstream.auth_vault.providers.${providerName}.api_key.`,
      };
    }
    setHeader(outputHeaders, providerHeaderName, formatProviderAuthValue(providerKey.key, providerScheme));
    return {
      ok: true,
      headers: outputHeaders,
      auth: {
        mode: 'enforce',
        injected: true,
        source: providerKey.source,
        dummyMatched,
      },
    };
  }

  const providerHeaderDummyMatched = headerContainsDummy(originalProviderValue, authVaultConfig.dummyKey);
  if (dummyMatched || providerHeaderDummyMatched) {
    if (!providerKey.key) {
      return {
        ok: false,
        errorCode: 'VAULT_PROVIDER_KEY_MISSING',
        message: `Dummy key detected for provider ${providerName}, but no vault key is configured. Set ${providerKey.envVar || 'provider env var'} or runtime.upstream.auth_vault.providers.${providerName}.api_key.`,
      };
    }
    setHeader(outputHeaders, providerHeaderName, formatProviderAuthValue(providerKey.key, providerScheme));
    return {
      ok: true,
      headers: outputHeaders,
      auth: {
        mode: 'replace_dummy',
        injected: true,
        source: providerKey.source,
        dummyMatched: true,
      },
    };
  }

  if (originalProviderValue !== undefined) {
    setHeader(outputHeaders, providerHeaderName, originalProviderValue);
  }
  return {
    ok: true,
    headers: outputHeaders,
    auth: {
      mode: 'replace_dummy',
      injected: false,
      dummyMatched: false,
    },
  };
}

function applyGhostMode(inputHeaders = {}, ghostModeConfig = {}) {
  const headers = { ...(inputHeaders || {}) };
  if (!ghostModeConfig.enabled) {
    return headers;
  }

  for (const headerName of ghostModeConfig.stripHeaders || []) {
    deleteHeader(headers, headerName);
  }

  if (ghostModeConfig.overrideUserAgent) {
    setHeader(headers, 'user-agent', ghostModeConfig.userAgentValue);
  }

  return headers;
}

function parseConnectionHeaderTokens(value) {
  if (!value) {
    return new Set();
  }
  const raw = String(value);
  return new Set(
    raw
      .split(',')
      .map((token) => token.trim().toLowerCase())
      .filter(Boolean)
  );
}

function buildForwardHeaders(originalHeaders, bodyLength, hostHeader) {
  const headers = { ...originalHeaders };
  const connectionTokens = parseConnectionHeaderTokens(headers.connection);
  delete headers.host;
  delete headers['content-length'];

  for (const key of Object.keys(headers)) {
    const lowered = key.toLowerCase();
    if (lowered.startsWith('x-sentinel-')) {
      delete headers[key];
      continue;
    }
    if (HOP_BY_HOP_HEADERS.has(lowered) || connectionTokens.has(lowered)) {
      delete headers[key];
    }
  }

  headers.host = hostHeader;
  if (bodyLength > 0) {
    headers['content-length'] = String(bodyLength);
  }

  for (const [key, value] of Object.entries(headers)) {
    headers[key] = normalizeHeaderValue(value);
  }

  return headers;
}

function classifyTransportError(error) {
  if (error && (error.name === 'TimeoutError' || error.name === 'AbortError')) {
    return 'timeout';
  }
  return 'transport';
}

function copyResponseHeaders(response) {
  const headers = {};
  response.headers.forEach((value, key) => {
    headers[key] = value;
  });
  return headers;
}

function sanitizeRoutePlan(input = {}) {
  const candidates = Array.isArray(input.candidates) ? input.candidates.filter(Boolean) : [];
  const failover = input.failover || {};
  return {
    desiredContract: String(input.desiredContract || 'passthrough').toLowerCase(),
    selectedGroup: input.selectedGroup || null,
    routeSource: input.routeSource || 'target',
    requestedTarget: input.requestedTarget || (candidates[0]?.targetName || 'openai'),
    canary: input.canary || null,
    candidates,
    failover: {
      enabled: failover.enabled === true,
      maxFailoverHops: Number.isInteger(failover.maxFailoverHops)
        ? Math.max(0, failover.maxFailoverHops)
        : 0,
      allowPostWithIdempotencyKey: failover.allowPostWithIdempotencyKey === true,
      onStatus: Array.isArray(failover.onStatus)
        ? failover.onStatus.map((status) => Number(status)).filter((status) => Number.isInteger(status))
        : [429, 500, 502, 503, 504],
      onErrorTypes: Array.isArray(failover.onErrorTypes)
        ? failover.onErrorTypes.map((item) => String(item).toLowerCase())
        : ['timeout', 'transport', 'circuit_open'],
    },
  };
}

function failoverMethodEligible(method, failoverConfig, headers) {
  if (!failoverConfig.enabled) {
    return false;
  }
  return methodRetryEligible(method, {
    allow_post_with_idempotency_key: failoverConfig.allowPostWithIdempotencyKey === true,
  }, headers || {});
}

function shouldFailoverResponseStatus(status, failoverConfig) {
  return failoverConfig.onStatus.includes(Number(status));
}

function shouldFailoverFailureType(failureType, failoverConfig) {
  return failoverConfig.onErrorTypes.includes(String(failureType || '').toLowerCase());
}

class UpstreamClient {
  constructor(options) {
    this.timeoutMs = options.timeoutMs;
    this.retryConfig = options.retryConfig;
    this.circuitBreakers = options.circuitBreakers;
    this.telemetry = options.telemetry;
    this.dispatchers = new Map();
    this.authVaultConfig = normalizeAuthVaultConfig(options.authVaultConfig || {});
    this.ghostModeConfig = normalizeGhostModeConfig(options.ghostModeConfig || {});
  }

  getPinnedDispatcher({ upstreamHostname, resolvedIp, resolvedFamily }) {
    if (!upstreamHostname || !resolvedIp) {
      return null;
    }

    const key = `${upstreamHostname}|${resolvedIp}|${resolvedFamily || net.isIP(resolvedIp) || 0}`;
    if (this.dispatchers.has(key)) {
      return this.dispatchers.get(key);
    }

    const family = Number(resolvedFamily || net.isIP(resolvedIp) || 0);
    const dispatcher = new Agent({
      connect: {
        lookup: (hostname, options, callback) => {
          if (hostname === upstreamHostname) {
            callback(null, resolvedIp, family || undefined);
            return;
          }
          dns.lookup(hostname, options, callback);
        },
        servername: upstreamHostname,
      },
    });

    this.dispatchers.set(key, dispatcher);
    return dispatcher;
  }

  buildSentinelFailure({
    status = 502,
    error = 'UPSTREAM_FAILURE',
    message = 'Upstream failure',
    failureType = 'transport',
    provider,
    targetName,
    breakerKey,
    breakerState,
    correlationId,
    retryCount = 0,
    responseHeaders = {},
    upstreamError = false,
  }) {
    return {
      ok: false,
      status,
      isStream: false,
      body: {
        error,
        message,
      },
      responseHeaders,
      failureType,
      targetName,
      provider,
      breakerKey,
      diagnostics: {
        errorSource: upstreamError ? 'upstream' : 'sentinel',
        upstreamError,
        provider,
        retryCount,
        circuitState: breakerState,
        correlationId,
      },
    };
  }

  async forwardRequest(params) {
    const {
      req,
      method,
      pathWithQuery,
      bodyBuffer,
      bodyJson,
      correlationId,
      wantsStream,
      forwardHeaders: providedForwardHeaders,
      routePlan: rawRoutePlan,
    } = params;

    const fallbackPlan = {
      desiredContract: 'passthrough',
      routeSource: 'target',
      requestedTarget: params.provider || 'openai',
      selectedGroup: null,
      canary: null,
      candidates: [
        {
          targetName: params.provider || 'openai',
          provider: params.provider || 'openai',
          baseUrl: params.baseUrl,
          upstreamHostname: params.upstreamHostname,
          upstreamHostHeader: params.upstreamHostHeader,
          resolvedIp: params.resolvedIp,
          resolvedFamily: params.resolvedFamily,
          contract: 'passthrough',
          staticHeaders: {},
          breakerKey: params.provider || 'openai',
        },
      ],
      failover: {
        enabled: false,
        maxFailoverHops: 0,
        allowPostWithIdempotencyKey: false,
        onStatus: [429, 500, 502, 503, 504],
        onErrorTypes: ['timeout', 'transport', 'circuit_open'],
      },
    };

    const routePlan = sanitizeRoutePlan(rawRoutePlan || fallbackPlan);
    const failoverAllowed = failoverMethodEligible(method, routePlan.failover, req.headers || {});
    const maxIndex = failoverAllowed
      ? Math.min(routePlan.candidates.length - 1, Math.max(0, routePlan.failover.maxFailoverHops))
      : 0;

    const failoverChain = [];
    let totalRetryCount = 0;
    let finalResult = null;

    for (let index = 0; index <= maxIndex; index += 1) {
      const candidate = routePlan.candidates[index];
      if (!candidate) {
        continue;
      }

      const attempt = await this.forwardCandidate({
        candidate,
        desiredContract: routePlan.desiredContract,
        req,
        method,
        pathWithQuery,
        bodyBuffer,
        bodyJson,
        correlationId,
        wantsStream,
        providedForwardHeaders,
      });

      totalRetryCount += Number(attempt.diagnostics?.retryCount || 0);
      failoverChain.push({
        target: candidate.targetName,
        provider: candidate.provider,
        status: attempt.status,
        ok: attempt.ok,
        failure_type: attempt.failureType || null,
      });

      finalResult = attempt;
      const hasMoreCandidates = index < maxIndex;

      if (attempt.ok) {
        const canFailoverStatus =
          hasMoreCandidates &&
          failoverAllowed &&
          attempt.status >= 400 &&
          shouldFailoverResponseStatus(attempt.status, routePlan.failover);

        if (canFailoverStatus) {
          continue;
        }
        break;
      }

      const canFailoverFailure =
        hasMoreCandidates &&
        failoverAllowed &&
        shouldFailoverFailureType(attempt.failureType, routePlan.failover);

      if (canFailoverFailure) {
        continue;
      }
      break;
    }

    if (!finalResult) {
      finalResult = this.buildSentinelFailure({
        status: 502,
        error: 'UPSTREAM_UNAVAILABLE',
        message: 'No upstream candidates available',
        failureType: 'transport',
        provider: routePlan.candidates[0]?.provider || 'unknown',
        targetName: routePlan.candidates[0]?.targetName || 'unknown',
        breakerKey: routePlan.candidates[0]?.breakerKey || routePlan.candidates[0]?.provider || 'unknown',
        breakerState: 'closed',
        correlationId,
        retryCount: 0,
        upstreamError: true,
      });
    }

    finalResult.route = {
      requestedTarget: routePlan.requestedTarget,
      selectedGroup: routePlan.selectedGroup,
      desiredContract: routePlan.desiredContract,
      routeSource: routePlan.routeSource,
      canary: routePlan.canary,
      failoverUsed: failoverChain.length > 1,
      failoverChain,
      selectedTarget: finalResult.targetName,
      selectedProvider: finalResult.provider,
      selectedBreakerKey: finalResult.breakerKey || null,
      totalRetryCount,
    };

    finalResult.diagnostics = {
      ...(finalResult.diagnostics || {}),
      retryCount: totalRetryCount,
    };

    return finalResult;
  }

  async forwardCandidate(params) {
    const {
      candidate,
      desiredContract,
      req,
      method,
      pathWithQuery,
      bodyBuffer,
      bodyJson,
      correlationId,
      wantsStream,
      providedForwardHeaders,
    } = params;

    const provider = candidate.provider;
    const targetName = candidate.targetName;
    const breakerKey = candidate.breakerKey || `${provider}:${targetName}`;

    const gate = this.circuitBreakers.canRequest(breakerKey);
    if (!gate.allowed) {
      this.telemetry?.addUpstreamError({
        provider,
        reason: 'circuit_open',
      });
      return this.buildSentinelFailure({
        status: 503,
        error: 'UPSTREAM_CIRCUIT_OPEN',
        message: `Provider ${provider} circuit is open`,
        failureType: 'circuit_open',
        provider,
        targetName,
        breakerKey,
        breakerState: gate.state,
        correlationId,
        retryCount: 0,
        responseHeaders: {
          'retry-after': String(gate.retryAfterSeconds || 1),
        },
        upstreamError: true,
      });
    }

    const adapterSelection = selectUpstreamAdapter({
      desiredContract,
      candidateContract: candidate.contract,
      provider,
      candidate,
    });
    if (!adapterSelection.ok) {
      return this.buildSentinelFailure({
        status: 502,
        error: 'ADAPTER_UNSUPPORTED',
        message: adapterSelection.reason,
        failureType: 'adapter_unsupported',
        provider,
        targetName,
        breakerKey,
        breakerState: this.circuitBreakers.getProviderState(breakerKey).state,
        correlationId,
        retryCount: 0,
        upstreamError: false,
      });
    }

    const adapter = adapterSelection.adapter;
    if (wantsStream && adapter.supportsStreaming !== true) {
      return this.buildSentinelFailure({
        status: 501,
        error: 'ADAPTER_STREAM_UNSUPPORTED',
        message: `Adapter ${adapter.name} does not support streaming requests`,
        failureType: 'adapter_stream_unsupported',
        provider,
        targetName,
        breakerKey,
        breakerState: this.circuitBreakers.getProviderState(breakerKey).state,
        correlationId,
        retryCount: 0,
        upstreamError: false,
      });
    }

    let prepared;
    try {
      prepared = adapter.prepareRequest({
        method,
        pathWithQuery,
        bodyBuffer,
        bodyJson,
        reqHeaders: req.headers || {},
        wantsStream,
        candidate,
      });
    } catch (error) {
      return this.buildSentinelFailure({
        status: 502,
        error: 'ADAPTER_PREPARE_FAILED',
        message: error.message,
        failureType: 'adapter_prepare_failed',
        provider,
        targetName,
        breakerKey,
        breakerState: this.circuitBreakers.getProviderState(breakerKey).state,
        correlationId,
        retryCount: 0,
        upstreamError: false,
      });
    }

    const forwardMethod = String(prepared.method || method).toUpperCase();
    const forwardBody = Buffer.isBuffer(prepared.bodyBuffer)
      ? prepared.bodyBuffer
      : Buffer.from(prepared.bodyBuffer || '', 'utf8');
    const forwardPathWithQuery = String(prepared.pathWithQuery || pathWithQuery || '/');

    const mergedHeaders = {
      ...(providedForwardHeaders || req.headers || {}),
      ...(candidate.staticHeaders || {}),
      ...(prepared.headerOverrides || {}),
    };

    const authResolution = applyProviderAuthorization({
      headers: mergedHeaders,
      provider,
      authVaultConfig: this.authVaultConfig,
    });
    if (!authResolution.ok) {
      return this.buildSentinelFailure({
        status: 502,
        error: authResolution.errorCode || 'VAULT_CONFIGURATION_ERROR',
        message: authResolution.message || 'Unable to resolve provider credentials from auth vault',
        failureType: 'vault_configuration_error',
        provider,
        targetName,
        breakerKey,
        breakerState: this.circuitBreakers.getProviderState(breakerKey).state,
        correlationId,
        retryCount: 0,
        upstreamError: false,
      });
    }

    const ghostHeaders = applyGhostMode(authResolution.headers, this.ghostModeConfig);
    const forwardHeaders = buildForwardHeaders(
      ghostHeaders,
      forwardBody.length,
      candidate.upstreamHostHeader
    );

    const dispatcher = this.getPinnedDispatcher({
      upstreamHostname: candidate.upstreamHostname,
      resolvedIp: candidate.resolvedIp,
      resolvedFamily: candidate.resolvedFamily,
    });

    const base = new URL(candidate.baseUrl);
    const url = new URL(forwardPathWithQuery, base).toString();
    const safeUpstreamUrl = `${base.origin}${new URL(url).pathname}`;

    const retryEnabled = this.retryConfig.enabled !== false;
    const maxAttempts = retryEnabled ? 1 + Number(this.retryConfig.max_attempts || 0) : 1;
    const eligibleMethod = methodRetryEligible(forwardMethod, this.retryConfig, req.headers);
    const forwardSpan = this.telemetry?.startSpan('sentinel.upstream.forward', {
      provider,
      target: targetName,
      method: forwardMethod,
      upstream_url: safeUpstreamUrl,
      wants_stream: Boolean(wantsStream),
      adapter: adapter.name,
    });

    let retryCount = 0;
    let lastErrorType = null;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      const attemptSpan = this.telemetry?.startSpan('sentinel.upstream.attempt', {
        provider,
        target: targetName,
        method: forwardMethod,
        attempt,
      });

      try {
        const controller = AbortSignal.timeout(this.timeoutMs);
        const response = await fetch(url, {
          method: forwardMethod,
          headers: forwardHeaders,
          body: forwardMethod === 'GET' || forwardMethod === 'HEAD' ? undefined : forwardBody,
          signal: controller,
          ...(dispatcher ? { dispatcher } : {}),
        });

        const status = response.status;
        const responseHeaders = copyResponseHeaders(response);
        const retryableStatus = shouldRetryResponse(status);
        const canRetry = retryEnabled && eligibleMethod && attempt < maxAttempts && retryableStatus;

        if (canRetry) {
          this.telemetry?.endSpan(attemptSpan, {
            provider,
            target: targetName,
            method: forwardMethod,
            status,
            retrying: true,
          });
          retryCount += 1;
          const delay = parseRetryAfterMs(response.headers.get('retry-after')) ?? jitterBackoffMs();
          await sleep(delay);
          continue;
        }

        if (status >= 500 || status === 429) {
          this.circuitBreakers.recordUpstreamFailure(breakerKey, 'status');
          this.telemetry?.addUpstreamError({
            provider,
            reason: `status_${status}`,
          });
        } else {
          this.circuitBreakers.recordUpstreamSuccess(breakerKey);
        }

        const contentType = String(response.headers.get('content-type') || '').toLowerCase();
        const streamEligible =
          Boolean(wantsStream) &&
          Boolean(response.body) &&
          status < 400 &&
          adapter.supportsStreaming === true;
        const isSSE = contentType.includes('text/event-stream');

        if (streamEligible && isSSE) {
          this.telemetry?.endSpan(attemptSpan, {
            provider,
            target: targetName,
            method: forwardMethod,
            status,
            streamed: true,
          });
          this.telemetry?.endSpan(forwardSpan, {
            provider,
            target: targetName,
            method: forwardMethod,
            status,
            streamed: true,
            retries: retryCount,
          });

          return {
            ok: true,
            status,
            isStream: true,
            bodyStream: Readable.fromWeb(response.body),
            responseHeaders,
            targetName,
            provider,
            breakerKey,
            diagnostics: {
              errorSource: 'upstream',
              upstreamError: false,
              provider,
              retryCount,
              circuitState: this.circuitBreakers.getProviderState(breakerKey).state,
              correlationId,
            },
          };
        }

        let responseBody = Buffer.from(await response.arrayBuffer());
        let transformedHeaders = responseHeaders;
        if (typeof adapter.transformBufferedResponse === 'function') {
          try {
            const transformed = adapter.transformBufferedResponse({
              status,
              bodyBuffer: responseBody,
              responseHeaders,
              candidate,
            });
            if (transformed && Buffer.isBuffer(transformed.bodyBuffer)) {
              responseBody = transformed.bodyBuffer;
            }
            if (transformed && transformed.responseHeaders) {
              transformedHeaders = transformed.responseHeaders;
            }
          } catch (error) {
            this.telemetry?.endSpan(attemptSpan, {
              provider,
              target: targetName,
              method: forwardMethod,
              status,
              adapter_error: true,
            }, error);
            this.telemetry?.endSpan(forwardSpan, {
              provider,
              target: targetName,
              method: forwardMethod,
              adapter_error: true,
              retries: retryCount,
            }, error);
            return this.buildSentinelFailure({
              status: 502,
              error: 'ADAPTER_TRANSFORM_FAILED',
              message: error.message,
              failureType: 'adapter_transform_failed',
              provider,
              targetName,
              breakerKey,
              breakerState: this.circuitBreakers.getProviderState(breakerKey).state,
              correlationId,
              retryCount,
              upstreamError: false,
            });
          }
        }

        this.telemetry?.endSpan(attemptSpan, {
          provider,
          target: targetName,
          method: forwardMethod,
          status,
          streamed: false,
        });
        this.telemetry?.endSpan(forwardSpan, {
          provider,
          target: targetName,
          method: forwardMethod,
          status,
          retries: retryCount,
        });

        return {
          ok: true,
          status,
          isStream: false,
          body: responseBody,
          responseHeaders: transformedHeaders,
          targetName,
          provider,
          breakerKey,
          diagnostics: {
            errorSource: 'upstream',
            upstreamError: status >= 400,
            provider,
            retryCount,
            circuitState: this.circuitBreakers.getProviderState(breakerKey).state,
            correlationId,
          },
        };
      } catch (error) {
        const errorType = classifyTransportError(error);
        lastErrorType = errorType;
        this.telemetry?.endSpan(attemptSpan, {
          provider,
          target: targetName,
          method: forwardMethod,
          error_type: errorType,
        }, error);

        const canRetry =
          retryEnabled &&
          eligibleMethod &&
          attempt < maxAttempts &&
          shouldRetryError(errorType);

        if (canRetry) {
          retryCount += 1;
          await sleep(jitterBackoffMs());
          continue;
        }

        this.circuitBreakers.recordUpstreamFailure(breakerKey, errorType);
        this.telemetry?.addUpstreamError({
          provider,
          reason: errorType,
        });
        this.telemetry?.endSpan(forwardSpan, {
          provider,
          target: targetName,
          method: forwardMethod,
          error_type: errorType,
          retries: retryCount,
        }, error);

        return this.buildSentinelFailure({
          status: errorType === 'timeout' ? 504 : 502,
          error: errorType === 'timeout' ? 'UPSTREAM_TIMEOUT' : 'UPSTREAM_TRANSPORT_ERROR',
          message: error.message,
          failureType: errorType,
          provider,
          targetName,
          breakerKey,
          breakerState: this.circuitBreakers.getProviderState(breakerKey).state,
          correlationId,
          retryCount,
          upstreamError: true,
        });
      }
    }

    this.circuitBreakers.recordUpstreamFailure(breakerKey, lastErrorType || 'transport');
    this.telemetry?.addUpstreamError({
      provider,
      reason: lastErrorType || 'transport',
    });
    this.telemetry?.endSpan(forwardSpan, {
      provider,
      target: targetName,
      method: method,
      error_type: lastErrorType || 'transport',
      retries: retryCount,
    }, new Error('UPSTREAM_UNAVAILABLE'));

    return this.buildSentinelFailure({
      status: 502,
      error: 'UPSTREAM_UNAVAILABLE',
      message: 'Upstream is unavailable',
      failureType: lastErrorType || 'transport',
      provider,
      targetName,
      breakerKey,
      breakerState: this.circuitBreakers.getProviderState(breakerKey).state,
      correlationId,
      retryCount,
      upstreamError: true,
    });
  }

  async close() {
    const closers = [];
    for (const dispatcher of this.dispatchers.values()) {
      if (dispatcher && typeof dispatcher.close === 'function') {
        closers.push(dispatcher.close().catch(() => {}));
      }
    }
    this.dispatchers.clear();
    await Promise.allSettled(closers);
  }
}

module.exports = {
  UpstreamClient,
};
