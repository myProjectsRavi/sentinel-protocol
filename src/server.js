const fs = require('fs');
const express = require('express');
const { v4: uuidv4 } = require('uuid');

const logger = require('./utils/logger');
const { PIIScanner } = require('./engines/pii-scanner');
const { PolicyEngine } = require('./engines/policy-engine');
const { InMemoryRateLimiter } = require('./engines/rate-limiter');
const { NeuralInjectionClassifier } = require('./engines/neural-injection-classifier');
const { mergeInjectionResults } = require('./engines/injection-merge');
const { resolveUpstreamPlan } = require('./upstream/router');
const { UpstreamClient } = require('./upstream/client');
const { RuntimeOverrideManager } = require('./runtime/override');
const { CircuitBreakerManager } = require('./resilience/circuit-breaker');
const { AuditLogger } = require('./logging/audit-logger');
const { StatusStore } = require('./status/store');
const { loadOptimizerPlugin } = require('./optimizer/loader');
const { createTelemetry } = require('./telemetry');
const { PIIProviderEngine } = require('./pii/provider-engine');
const { scanBufferedResponse } = require('./egress/response-scanner');
const { SSERedactionTransform } = require('./egress/sse-redaction-transform');
const { ScanWorkerPool } = require('./workers/scan-pool');
const { VCRStore } = require('./runtime/vcr-store');
const { SemanticCache } = require('./cache/semantic-cache');
const { BudgetStore } = require('./accounting/budget-store');
const { DashboardServer } = require('./monitor/dashboard-server');
const { LoopBreaker } = require('./engines/loop-breaker');
const { DeceptionEngine } = require('./engines/deception-engine');
const { ProvenanceSigner } = require('./security/provenance-signer');
const {
  PID_FILE_PATH,
  STATUS_FILE_PATH,
  OVERRIDE_FILE_PATH,
  AUDIT_LOG_PATH,
  ensureSentinelHome,
} = require('./utils/paths');

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

function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function tryParseJson(text) {
  try {
    return {
      ok: true,
      value: JSON.parse(text),
      error: null,
    };
  } catch (error) {
    return {
      ok: false,
      value: null,
      error,
    };
  }
}

function flattenFindings(findings) {
  return Array.from(new Set(findings.map((item) => item.id))).sort();
}

function highestSeverity(findings) {
  const rank = { low: 1, medium: 2, high: 3, critical: 4 };
  let current = null;
  for (const finding of findings) {
    if (!current || rank[finding.severity] > rank[current]) {
      current = finding.severity;
    }
  }
  return current;
}

function responseHeaderDiagnostics(res, diagnostics) {
  res.setHeader('x-sentinel-error-source', diagnostics.errorSource);
  res.setHeader('x-sentinel-upstream-error', String(Boolean(diagnostics.upstreamError)));
  res.setHeader('x-sentinel-provider', diagnostics.provider);
  res.setHeader('x-sentinel-retry-count', String(diagnostics.retryCount));
  res.setHeader('x-sentinel-circuit-state', diagnostics.circuitState);
  res.setHeader('x-sentinel-correlation-id', diagnostics.correlationId);
}

function formatBudgetUsd(value) {
  return Number(Number(value || 0).toFixed(6)).toString();
}

function setBudgetHeaders(res, budget) {
  if (!budget || budget.enabled !== true) {
    return;
  }
  res.setHeader('x-sentinel-budget-action', budget.action);
  res.setHeader('x-sentinel-budget-day', budget.dayKey);
  res.setHeader('x-sentinel-budget-limit-usd', formatBudgetUsd(budget.dailyLimitUsd));
  res.setHeader('x-sentinel-budget-spent-usd', formatBudgetUsd(budget.spentUsd));
  res.setHeader('x-sentinel-budget-remaining-usd', formatBudgetUsd(budget.remainingUsd));
}

function scrubForwardHeaders(inputHeaders = {}) {
  const headers = { ...inputHeaders };
  const connectionTokens = new Set(
    String(headers.connection || '')
      .split(',')
      .map((token) => token.trim().toLowerCase())
      .filter(Boolean)
  );

  for (const key of Object.keys(headers)) {
    const lowered = key.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lowered) || connectionTokens.has(lowered)) {
      delete headers[key];
    }
  }

  return headers;
}

function filterUpstreamResponseHeaders(responseHeaders = {}) {
  const connectionTokens = new Set(
    String(responseHeaders.connection || '')
      .split(',')
      .map((token) => token.trim().toLowerCase())
      .filter(Boolean)
  );
  const filtered = {};
  for (const [key, value] of Object.entries(responseHeaders)) {
    const lowered = String(key).toLowerCase();
    if (lowered === 'content-length') {
      continue;
    }
    if (HOP_BY_HOP_HEADERS.has(lowered) || connectionTokens.has(lowered)) {
      continue;
    }
    filtered[key] = value;
  }
  return filtered;
}

function positiveIntOr(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}

class SentinelServer {
  constructor(config, options = {}) {
    ensureSentinelHome();

    this.config = config;
    this.options = options;
    this.app = express();
    this.startedAt = Date.now();
    this.stats = {
      requests_total: 0,
      blocked_total: 0,
      policy_blocked: 0,
      pii_blocked: 0,
      injection_detected: 0,
      injection_blocked: 0,
      pii_provider_fallbacks: 0,
      rapidapi_error_count: 0,
      upstream_errors: 0,
      egress_detected: 0,
      egress_redacted: 0,
      egress_blocked: 0,
      egress_stream_redacted: 0,
      scan_worker_fallbacks: 0,
      warnings_total: 0,
      vcr_replay_hits: 0,
      vcr_replay_misses: 0,
      vcr_records: 0,
      semantic_cache_hits: 0,
      semantic_cache_misses: 0,
      semantic_cache_stores: 0,
      budget_blocked: 0,
      budget_limit_warnings: 0,
      budget_charged_usd: 0,
      failover_events: 0,
      canary_routed: 0,
      loop_detected: 0,
      loop_blocked: 0,
      deception_engaged: 0,
      deception_streamed: 0,
    };

    this.rateLimiter = new InMemoryRateLimiter();
    this.policyEngine = new PolicyEngine(config, this.rateLimiter);
    this.piiScanner = new PIIScanner({
      maxScanBytes: config.pii.max_scan_bytes,
      regexSafetyCapBytes: config.pii.regex_safety_cap_bytes,
      redactionMode: config.pii?.redaction?.mode,
      redactionSalt: config.pii?.redaction?.salt,
    });
    this.telemetry = createTelemetry({
      enabled: config.runtime?.telemetry?.enabled !== false,
      serviceVersion: '1.0.0',
    });
    this.piiProviderEngine = new PIIProviderEngine({
      piiConfig: config.pii,
      localScanner: this.piiScanner,
      telemetry: this.telemetry,
    });
    this.neuralInjectionClassifier = new NeuralInjectionClassifier(config.injection?.neural || {});
    this.circuitBreakers = new CircuitBreakerManager(config.runtime.upstream.circuit_breaker);
    this.upstreamClient = new UpstreamClient({
      timeoutMs: config.proxy.timeout_ms,
      retryConfig: config.runtime.upstream.retry,
      circuitBreakers: this.circuitBreakers,
      telemetry: this.telemetry,
      authVaultConfig: config.runtime?.upstream?.auth_vault || {},
      ghostModeConfig: config.runtime?.upstream?.ghost_mode || {},
    });
    this.scanWorkerPool = null;
    try {
      this.scanWorkerPool = new ScanWorkerPool(config.runtime?.worker_pool || {});
    } catch (error) {
      logger.warn('Scan worker pool unavailable; using main-thread scanners', { error: error.message });
      this.scanWorkerPool = null;
    }

    this.overrideManager = new RuntimeOverrideManager(OVERRIDE_FILE_PATH);
    this.auditLogger = new AuditLogger(AUDIT_LOG_PATH, {
      mirrorStdout: this.config.logging?.audit_stdout === true,
    });
    this.vcrStore = new VCRStore(this.config.runtime?.vcr || {});
    this.semanticCache = new SemanticCache(this.config.runtime?.semantic_cache || {}, {
      scanWorkerPool: this.scanWorkerPool,
    });
    this.budgetStore = new BudgetStore(this.config.runtime?.budget || {});
    this.loopBreaker = new LoopBreaker(this.config.runtime?.loop_breaker || {});
    this.deceptionEngine = new DeceptionEngine(this.config.runtime?.deception || {});
    this.provenanceSigner = new ProvenanceSigner(this.config.runtime?.provenance || {});
    if (this.config.runtime?.semantic_cache?.enabled === true && !this.semanticCache.isEnabled()) {
      logger.warn('Semantic cache disabled at runtime because worker pool is unavailable', {
        semantic_cache_enabled: true,
        worker_pool_enabled: this.scanWorkerPool?.enabled === true,
      });
    }
    this.statusStore = new StatusStore(STATUS_FILE_PATH);
    this.optimizerPlugin = loadOptimizerPlugin();
    this.dashboardServer = null;

    this.setupApp();
  }

  computeEffectiveMode() {
    if (this.options.dryRun) {
      return 'monitor';
    }

    if (this.options.failOpen || this.config.runtime.fail_open || this.overrideManager.getOverride().emergency_open) {
      return 'monitor';
    }

    return this.config.mode;
  }

  currentStatusPayload() {
    const budgetSnapshot = this.budgetStore.snapshot();
    return {
      service_status: this.server ? 'running' : 'stopped',
      configured_mode: this.config.mode,
      effective_mode: this.computeEffectiveMode(),
      emergency_open: this.overrideManager.getOverride().emergency_open,
      providers: this.circuitBreakers.snapshot(),
      pii_provider_mode: this.config.pii.provider_mode,
      pii_provider_fallbacks: this.stats.pii_provider_fallbacks,
      rapidapi_error_count: this.stats.rapidapi_error_count,
      loop_breaker_enabled: this.loopBreaker.enabled,
      deception_enabled: this.deceptionEngine.isEnabled(),
      provenance_enabled: this.provenanceSigner.isEnabled(),
      vcr_mode: this.config.runtime?.vcr?.mode || 'off',
      semantic_cache_enabled: this.semanticCache.isEnabled(),
      budget_enabled: budgetSnapshot.enabled,
      budget_action: budgetSnapshot.action,
      budget_day_key: budgetSnapshot.dayKey,
      budget_daily_limit_usd: budgetSnapshot.dailyLimitUsd,
      budget_spent_usd_today: budgetSnapshot.spentUsd,
      budget_remaining_usd_today: budgetSnapshot.remainingUsd,
      budget_requests_today: budgetSnapshot.requests,
      dashboard_enabled: this.config.runtime?.dashboard?.enabled === true,
      dashboard_host: this.config.runtime?.dashboard?.host || '127.0.0.1',
      dashboard_port: this.config.runtime?.dashboard?.port || 8788,
      uptime_seconds: Math.floor((Date.now() - this.startedAt) / 1000),
      version: this.config.version,
      counters: this.stats,
      pid: process.pid,
    };
  }

  writeStatus() {
    this.statusStore.write(this.currentStatusPayload());
  }

  getEgressConfig() {
    const egress = this.config?.pii?.egress || {};
    return {
      enabled: egress.enabled !== false,
      maxScanBytes: positiveIntOr(egress.max_scan_bytes, 65536),
      streamEnabled: egress.stream_enabled !== false,
      sseLineMaxBytes: positiveIntOr(egress.sse_line_max_bytes, 16384),
      streamBlockMode: egress.stream_block_mode === 'terminate' ? 'terminate' : 'redact',
    };
  }

  toResponseBodyBuffer(body) {
    if (Buffer.isBuffer(body)) {
      return body;
    }
    if (body === undefined || body === null) {
      return Buffer.alloc(0);
    }
    if (typeof body === 'string') {
      return Buffer.from(body, 'utf8');
    }
    if (typeof body === 'object') {
      return Buffer.from(JSON.stringify(body), 'utf8');
    }
    return Buffer.from(String(body), 'utf8');
  }

  applyBufferedProvenanceHeaders(res, { body, statusCode, provider, correlationId }) {
    if (!this.provenanceSigner.isEnabled() || res.headersSent) {
      return;
    }
    if (res.getHeader('x-sentinel-signature')) {
      return;
    }

    const proof = this.provenanceSigner.signBufferedResponse({
      bodyBuffer: this.toResponseBodyBuffer(body),
      statusCode,
      provider,
      correlationId,
    });
    if (!proof) {
      res.setHeader('x-sentinel-signature-status', 'skipped');
      return;
    }

    const proofHeaders = ProvenanceSigner.proofHeaders(proof);
    for (const [key, value] of Object.entries(proofHeaders)) {
      res.setHeader(key, value);
    }
    res.setHeader('x-sentinel-signature-status', 'signed');
  }

  async maybeServeDeceptionResponse({
    res,
    trigger,
    provider,
    effectiveMode,
    wantsStream,
    injectionScore,
    correlationId,
    requestStart,
    requestBytes,
    piiTypes,
    redactedCount,
    warnings,
    routePlan,
    finalizeRequestTelemetry,
  }) {
    const decision = this.deceptionEngine.shouldEngage({
      trigger,
      injectionScore,
      effectiveMode,
    });
    if (!decision.engage) {
      return false;
    }

    this.stats.deception_engaged += 1;
    const statusCode = 200;
    const diagnostics = {
      errorSource: 'sentinel',
      upstreamError: false,
      provider,
      retryCount: 0,
      circuitState: this.circuitBreakers.getProviderState(provider).state,
      correlationId,
    };
    responseHeaderDiagnostics(res, diagnostics);
    res.setHeader('x-sentinel-deception', 'tarpit');
    res.setHeader('x-sentinel-deception-trigger', trigger);

    if (wantsStream) {
      this.stats.deception_streamed += 1;
      res.status(statusCode);
      res.setHeader('content-type', 'text/event-stream; charset=utf-8');
      res.setHeader('cache-control', 'no-cache, no-transform');
      res.setHeader('connection', 'keep-alive');

      const streamProof = this.provenanceSigner.createStreamContext({
        statusCode,
        provider,
        correlationId,
      });
      const canAddTrailers =
        Boolean(streamProof) &&
        this.provenanceSigner.signStreamTrailers === true &&
        typeof res.addTrailers === 'function';
      if (canAddTrailers) {
        res.setHeader(
          'trailer',
          'x-sentinel-signature-v, x-sentinel-signature-alg, x-sentinel-signature-key-id, x-sentinel-signature-input, x-sentinel-payload-sha256, x-sentinel-signature'
        );
        res.setHeader('x-sentinel-signature-status', 'stream-trailer');
      } else if (this.provenanceSigner.isEnabled()) {
        res.setHeader('x-sentinel-signature-status', 'stream-unsigned');
      }

      let streamedBytes = 0;
      await this.deceptionEngine.streamToSSE(res, {
        trigger,
        onChunk: (chunk) => {
          streamedBytes += chunk.length;
          if (streamProof) {
            streamProof.update(chunk);
          }
        },
      });

      if (canAddTrailers) {
        const proof = streamProof.finalize();
        if (proof) {
          res.addTrailers(ProvenanceSigner.proofHeaders(proof));
        }
      }

      this.auditLogger.write({
        timestamp: new Date().toISOString(),
        correlation_id: correlationId,
        config_version: this.config.version,
        mode: effectiveMode,
        decision: 'deception_tarpit',
        reasons: [`deception_${trigger}`],
        pii_types: piiTypes,
        redactions: redactedCount,
        duration_ms: Date.now() - requestStart,
        request_bytes: requestBytes,
        response_status: statusCode,
        response_bytes: streamedBytes,
        provider,
        route_source: routePlan?.routeSource,
        route_group: routePlan?.selectedGroup || undefined,
        route_contract: routePlan?.desiredContract,
        requested_target: routePlan?.requestedTarget,
      });
      this.writeStatus();
      finalizeRequestTelemetry({
        decision: 'deception_tarpit',
        status: statusCode,
        providerName: provider,
      });
      return true;
    }

    if (this.deceptionEngine.nonStreamDelayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.deceptionEngine.nonStreamDelayMs));
    }
    const bodyBuffer = this.deceptionEngine.createBufferedPayload({
      trigger,
      provider,
    });
    this.applyBufferedProvenanceHeaders(res, {
      body: bodyBuffer,
      statusCode,
      provider,
      correlationId,
    });
    this.auditLogger.write({
      timestamp: new Date().toISOString(),
      correlation_id: correlationId,
      config_version: this.config.version,
      mode: effectiveMode,
      decision: 'deception_tarpit',
      reasons: [`deception_${trigger}`],
      pii_types: piiTypes,
      redactions: redactedCount,
      duration_ms: Date.now() - requestStart,
      request_bytes: requestBytes,
      response_status: statusCode,
      response_bytes: bodyBuffer.length,
      provider,
      route_source: routePlan?.routeSource,
      route_group: routePlan?.selectedGroup || undefined,
      route_contract: routePlan?.desiredContract,
      requested_target: routePlan?.requestedTarget,
    });
    this.writeStatus();
    finalizeRequestTelemetry({
      decision: 'deception_tarpit',
      status: statusCode,
      providerName: provider,
    });
    if (warnings.length > 0) {
      res.setHeader('x-sentinel-warning', warnings.join(','));
    }
    res.status(statusCode).send(bodyBuffer);
    return true;
  }

  setupApp() {
    this.app.use(
      express.raw({
        type: '*/*',
        limit: Number(this.config.proxy.max_body_bytes || 1048576),
      })
    );

    this.app.use((error, req, res, next) => {
      if (!error) {
        next();
        return;
      }

      if (error.type === 'entity.too.large') {
        res.status(413).json({
          error: 'REQUEST_BODY_TOO_LARGE',
          message: 'Request body exceeds proxy.max_body_bytes',
        });
        return;
      }

      next(error);
    });

    this.app.get('/_sentinel/health', (req, res) => {
      res.status(200).json({ status: 'ok' });
    });

    this.app.get('/_sentinel/provenance/public-key', (req, res) => {
      if (!this.provenanceSigner.isEnabled() || this.provenanceSigner.exposePublicKeyEndpoint !== true) {
        res.status(404).json({
          error: 'PROVENANCE_DISABLED',
        });
        return;
      }
      res.status(200).json(this.provenanceSigner.getPublicMetadata());
    });

    this.app.all('*', async (req, res) => {
      const correlationId = uuidv4();
      const method = req.method.toUpperCase();
      res.setHeader('x-sentinel-correlation-id', correlationId);
      let provenanceProvider = 'unknown';
      const originalSend = res.send.bind(res);
      const originalJson = res.json.bind(res);
      res.send = (body) => {
        this.applyBufferedProvenanceHeaders(res, {
          body,
          statusCode: res.statusCode,
          provider: provenanceProvider,
          correlationId,
        });
        return originalSend(body);
      };
      res.json = (body) => {
        this.applyBufferedProvenanceHeaders(res, {
          body,
          statusCode: res.statusCode,
          provider: provenanceProvider,
          correlationId,
        });
        return originalJson(body);
      };
      const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
      let bodyText = rawBody.toString('utf8');
      const parsedPath = new URL(req.originalUrl, 'http://localhost');
      const requestStart = Date.now();
      const requestSpan = this.telemetry.startSpan('sentinel.request', {
        method,
        route: parsedPath.pathname,
        correlation_id: correlationId,
      });
      let requestFinalized = false;

      const finalizeRequestTelemetry = ({ decision, status, providerName, error }) => {
        if (requestFinalized) {
          return;
        }
        requestFinalized = true;
        const latencyMs = Date.now() - requestStart;
        const attrs = {
          decision,
          status_code: Number(status || 0),
          provider: providerName || 'unknown',
          effective_mode: this.computeEffectiveMode(),
        };
        this.telemetry.recordLatencyMs(latencyMs, attrs);
        if (decision === 'blocked_policy' || decision === 'blocked_pii' || decision === 'blocked_egress') {
          this.telemetry.addBlocked(attrs);
        }
        if (decision === 'upstream_error' || decision === 'stream_error') {
          this.telemetry.addUpstreamError(attrs);
        }
        this.telemetry.endSpan(requestSpan, attrs, error);
      };

      if (method === 'TRACE' || method === 'CONNECT') {
        finalizeRequestTelemetry({
          decision: 'method_not_allowed',
          status: 405,
          providerName: 'unknown',
        });
        return res.status(405).json({
          error: 'METHOD_NOT_ALLOWED',
          message: `HTTP method ${method} is not allowed by Sentinel.`,
          correlation_id: correlationId,
        });
      }

      this.stats.requests_total += 1;
      this.telemetry.addRequest({
        method,
        route: parsedPath.pathname,
      });

      let routePlan;
      let provider;
      let baseUrl;
      let resolvedIp = null;
      let resolvedFamily = null;
      let upstreamHostname = null;
      let upstreamHostHeader = null;
      let breakerKey = null;
      let cacheProviderKey = null;
      try {
        routePlan = await resolveUpstreamPlan(req, this.config);
        const primary = routePlan.primary;
        provider = primary.provider;
        provenanceProvider = provider;
        baseUrl = primary.baseUrl;
        resolvedIp = primary.resolvedIp || null;
        resolvedFamily = primary.resolvedFamily || null;
        upstreamHostname = primary.upstreamHostname || null;
        upstreamHostHeader = primary.upstreamHostHeader || null;
        breakerKey = primary.breakerKey || provider;
        cacheProviderKey = routePlan.selectedGroup || routePlan.requestedTarget || provider;

        res.setHeader('x-sentinel-route-target', routePlan.requestedTarget);
        res.setHeader('x-sentinel-route-contract', routePlan.desiredContract);
        res.setHeader('x-sentinel-route-source', routePlan.routeSource);
        if (routePlan.selectedGroup) {
          res.setHeader('x-sentinel-route-group', routePlan.selectedGroup);
        }
        if (routePlan.canary) {
          this.stats.canary_routed += 1;
          res.setHeader('x-sentinel-canary-split', routePlan.canary.name);
          res.setHeader('x-sentinel-canary-bucket', String(routePlan.canary.bucket));
          if (routePlan.canary.canaryKeyHash) {
            res.setHeader('x-sentinel-canary-key-hash', routePlan.canary.canaryKeyHash);
          }
        }
      } catch (error) {
        const diagnostics = {
          errorSource: 'sentinel',
          upstreamError: false,
          provider: 'unknown',
          retryCount: 0,
          circuitState: 'closed',
          correlationId,
        };
        responseHeaderDiagnostics(res, diagnostics);
        finalizeRequestTelemetry({
          decision: 'invalid_provider_target',
          status: 400,
          providerName: 'unknown',
        });
        return res.status(400).json({ error: 'INVALID_PROVIDER_TARGET', message: error.message });
      }

      const contentType = String(req.headers['content-type'] || '').toLowerCase();
      let bodyJson = null;
      if (contentType.includes('application/json') && bodyText.length > 0) {
        const parsedBody = tryParseJson(bodyText);
        if (!parsedBody.ok) {
          const diagnostics = {
            errorSource: 'sentinel',
            upstreamError: false,
            provider,
            retryCount: 0,
            circuitState: this.circuitBreakers.getProviderState(breakerKey).state,
            correlationId,
          };
          responseHeaderDiagnostics(res, diagnostics);
          finalizeRequestTelemetry({
            decision: 'invalid_json',
            status: 400,
            providerName: provider,
            error: parsedBody.error,
          });
          return res.status(400).json({
            error: 'INVALID_JSON_BODY',
            message: 'Request body is not valid JSON.',
            correlation_id: correlationId,
          });
        }
        bodyJson = parsedBody.value;
      }
      const wantsStream =
        String(req.headers.accept || '').toLowerCase().includes('text/event-stream') ||
        (bodyJson && bodyJson.stream === true);
      const warnings = [];
      const effectiveMode = this.computeEffectiveMode();
      let precomputedLocalScan = null;
      let precomputedInjection = null;

      const canUseScanWorkers =
        this.scanWorkerPool?.enabled === true &&
        this.config.pii?.enabled !== false &&
        this.config.pii?.semantic?.enabled !== true &&
        bodyText.length > 0;
      if (canUseScanWorkers) {
        try {
          const workerScan = await this.scanWorkerPool.scan({
            text: bodyText,
            pii: {
              maxScanBytes: this.config.pii.max_scan_bytes,
              regexSafetyCapBytes: this.config.pii.regex_safety_cap_bytes,
              redactionMode: this.config.pii?.redaction?.mode,
              redactionSalt: this.config.pii?.redaction?.salt,
            },
            injection: {
              enabled: this.config.injection?.enabled !== false,
              maxScanBytes: this.config.injection?.max_scan_bytes,
            },
          });
          precomputedLocalScan = workerScan.piiResult || null;
          precomputedInjection = workerScan.injectionResult || null;
        } catch (error) {
          this.stats.scan_worker_fallbacks += 1;
          warnings.push('scan_worker_fallback_main_thread');
          this.stats.warnings_total += 1;
        }
      }

      let injectionResult = precomputedInjection;
      if (this.neuralInjectionClassifier.enabled && bodyText.length > 0) {
        const baseInjection = injectionResult || this.policyEngine.scanInjection(bodyText);
        const neuralResult = await this.neuralInjectionClassifier.classify(bodyText, {
          maxScanBytes: this.config.injection?.neural?.max_scan_bytes,
          timeoutMs: this.config.injection?.neural?.timeout_ms,
        });
        if (neuralResult.error) {
          warnings.push('injection_neural_error');
          this.stats.warnings_total += 1;
        }
        injectionResult = mergeInjectionResults(baseInjection, neuralResult, this.config.injection?.neural || {});
      }

      let providerHostname;
      try {
        providerHostname = new URL(baseUrl).hostname;
      } catch {
        const diagnostics = {
          errorSource: 'sentinel',
          upstreamError: false,
          provider,
          retryCount: 0,
          circuitState: 'closed',
          correlationId,
        };
        responseHeaderDiagnostics(res, diagnostics);
        finalizeRequestTelemetry({
          decision: 'invalid_provider_url',
          status: 400,
          providerName: provider,
        });
        return res.status(400).json({ error: 'INVALID_PROVIDER_URL', message: `Invalid provider URL: ${baseUrl}` });
      }

      const policyDecision = this.policyEngine.check({
        method,
        hostname: providerHostname,
        pathname: parsedPath.pathname,
        bodyText,
        bodyJson,
        requestBytes: rawBody.length,
        headers: req.headers,
        provider,
        rateLimitKey: req.headers['x-sentinel-agent-id'],
        injectionResult,
      });

      const injectionScore = Number(policyDecision.injection?.score || 0);
      if (injectionScore > 0) {
        this.stats.injection_detected += 1;
      }

      if (policyDecision.matched && policyDecision.action === 'block') {
        if (effectiveMode === 'enforce') {
          if (policyDecision.reason === 'prompt_injection_detected') {
            const deceived = await this.maybeServeDeceptionResponse({
              res,
              trigger: 'injection',
              provider,
              effectiveMode,
              wantsStream,
              injectionScore,
              correlationId,
              requestStart,
              requestBytes: rawBody.length,
              piiTypes: [],
              redactedCount: 0,
              warnings,
              routePlan,
              finalizeRequestTelemetry,
            });
            if (deceived) {
              return;
            }
          }
          this.stats.blocked_total += 1;
          this.stats.policy_blocked += 1;
          if (policyDecision.reason === 'prompt_injection_detected') {
            this.stats.injection_blocked += 1;
          }
          const diagnostics = {
            errorSource: 'sentinel',
            upstreamError: false,
            provider,
            retryCount: 0,
            circuitState: this.circuitBreakers.getProviderState(breakerKey).state,
            correlationId,
          };

          responseHeaderDiagnostics(res, diagnostics);
          this.auditLogger.write({
            timestamp: new Date().toISOString(),
            correlation_id: correlationId,
            config_version: this.config.version,
            mode: effectiveMode,
            decision: 'blocked',
            reasons: [policyDecision.reason || 'policy_violation'],
            rule: policyDecision.rule,
            pii_types: [],
            redactions: 0,
            duration_ms: 0,
            request_bytes: rawBody.length,
            response_status: 403,
            response_bytes: 0,
            provider,
          });
          this.writeStatus();
          finalizeRequestTelemetry({
            decision: 'blocked_policy',
            status: 403,
            providerName: provider,
          });
          return res.status(403).json({
            error: 'POLICY_VIOLATION',
            reason: policyDecision.reason,
            rule: policyDecision.rule,
            message: policyDecision.message,
            injection_score: injectionScore || undefined,
            correlation_id: correlationId,
          });
        }
        warnings.push(`policy:${policyDecision.rule || 'blocked-rule'}`);
        if (policyDecision.reason === 'prompt_injection_detected') {
          warnings.push(`injection:${injectionScore.toFixed(3)}`);
        }
        this.stats.warnings_total += 1;
      }

      let piiBlocked = false;
      let redactedCount = 0;
      let piiTypes = [];
      let piiProviderUsed = 'local';
      const egressConfig = this.getEgressConfig();
      const loopDecision = this.loopBreaker.evaluate({
        headers: req.headers || {},
        provider,
        method,
        path: parsedPath.pathname,
        bodyText,
        bodyJson,
      });
      if (loopDecision.detected) {
        this.stats.loop_detected += 1;
        if (effectiveMode === 'enforce' && loopDecision.shouldBlock) {
          const deceived = await this.maybeServeDeceptionResponse({
            res,
            trigger: 'loop',
            provider,
            effectiveMode,
            wantsStream,
            injectionScore,
            correlationId,
            requestStart,
            requestBytes: rawBody.length,
            piiTypes,
            redactedCount,
            warnings,
            routePlan,
            finalizeRequestTelemetry,
          });
          if (deceived) {
            return;
          }
          this.stats.blocked_total += 1;
          this.stats.loop_blocked += 1;
          const diagnostics = {
            errorSource: 'sentinel',
            upstreamError: false,
            provider,
            retryCount: 0,
            circuitState: this.circuitBreakers.getProviderState(breakerKey).state,
            correlationId,
          };
          responseHeaderDiagnostics(res, diagnostics);
          res.setHeader('x-sentinel-loop-breaker', 'blocked');
          this.auditLogger.write({
            timestamp: new Date().toISOString(),
            correlation_id: correlationId,
            config_version: this.config.version,
            mode: effectiveMode,
            decision: 'blocked_loop',
            reasons: ['agent_loop_detected'],
            pii_types: [],
            redactions: 0,
            duration_ms: Date.now() - requestStart,
            request_bytes: rawBody.length,
            response_status: 429,
            response_bytes: 0,
            provider,
            loop_streak: loopDecision.streak,
            loop_threshold: loopDecision.repeatThreshold,
            loop_key: loopDecision.key,
            loop_hash_prefix: loopDecision.hash_prefix,
          });
          this.writeStatus();
          finalizeRequestTelemetry({
            decision: 'blocked_policy',
            status: 429,
            providerName: provider,
          });
          return res.status(429).json({
            error: 'AGENT_LOOP_DETECTED',
            reason: 'agent_loop_detected',
            streak: loopDecision.streak,
            threshold: loopDecision.repeatThreshold,
            correlation_id: correlationId,
          });
        }
        warnings.push(`loop_detected:${loopDecision.streak}`);
        res.setHeader('x-sentinel-loop-breaker', 'warn');
        this.stats.warnings_total += 1;
      }

      if (this.config.pii.enabled) {
        let piiEvaluation;
        try {
          piiEvaluation = await this.piiProviderEngine.scan(bodyText, req.headers, {
            precomputedLocal: precomputedLocalScan,
          });
        } catch (error) {
          if (String(error.kind || '').startsWith('rapidapi_')) {
            this.stats.rapidapi_error_count += 1;
          }
          const diagnostics = {
            errorSource: 'sentinel',
            upstreamError: false,
            provider,
            retryCount: 0,
            circuitState: this.circuitBreakers.getProviderState(breakerKey).state,
            correlationId,
          };
          responseHeaderDiagnostics(res, diagnostics);
          finalizeRequestTelemetry({
            decision: 'pii_provider_error',
            status: 502,
            providerName: provider,
            error,
          });
          return res.status(502).json({
            error: 'PII_PROVIDER_ERROR',
            message: 'PII provider failed and fallback is disabled',
            correlation_id: correlationId,
          });
        }

        const piiResult = piiEvaluation.result;
        const piiMeta = piiEvaluation.meta;
        piiProviderUsed = piiMeta.providerUsed;
        res.setHeader('x-sentinel-pii-provider', piiProviderUsed);
        if (piiMeta.fallbackUsed) {
          this.stats.pii_provider_fallbacks += 1;
          if (String(piiMeta.fallbackReason || '').startsWith('rapidapi_')) {
            this.stats.rapidapi_error_count += 1;
          }
          warnings.push('pii_provider_fallback_local');
          if (piiMeta.fallbackReason === 'rapidapi_quota') {
            warnings.push('pii_provider_quota_exceeded');
          }
        }

        if (piiResult && piiResult.findings.length > 0) {
          piiTypes = flattenFindings(piiResult.findings);
          const topSeverity = highestSeverity(piiResult.findings);
          const severityAction = this.config.pii.severity_actions[topSeverity] || 'log';

          if (severityAction === 'block' && effectiveMode === 'enforce') {
            piiBlocked = true;
          }

          if (severityAction === 'redact') {
            bodyText = piiResult.redactedText;
            redactedCount = piiResult.findings.length;
            if (bodyJson) {
              const reparsed = safeJsonParse(bodyText);
              if (reparsed) {
                bodyJson = reparsed;
              }
            }
          }

          if (!piiBlocked) {
            warnings.push(`pii:${topSeverity}`);
            this.stats.warnings_total += 1;
          }
        }
      }

      if (piiBlocked) {
        this.stats.blocked_total += 1;
        this.stats.pii_blocked += 1;

        const diagnostics = {
          errorSource: 'sentinel',
          upstreamError: false,
          provider,
          retryCount: 0,
          circuitState: this.circuitBreakers.getProviderState(breakerKey).state,
          correlationId,
        };
        responseHeaderDiagnostics(res, diagnostics);
        if (warnings.length > 0) {
          res.setHeader('x-sentinel-warning', warnings.join(','));
        }
        res.setHeader('x-sentinel-pii-provider', piiProviderUsed);

        this.auditLogger.write({
          timestamp: new Date().toISOString(),
          correlation_id: correlationId,
          config_version: this.config.version,
          mode: effectiveMode,
          decision: 'blocked',
          reasons: ['pii_detected'],
          pii_types: piiTypes,
          redactions: redactedCount,
          duration_ms: 0,
          request_bytes: rawBody.length,
          response_status: 403,
          response_bytes: 0,
          provider,
        });
        this.writeStatus();
        finalizeRequestTelemetry({
          decision: 'blocked_pii',
          status: 403,
          providerName: provider,
        });

        return res.status(403).json({
          error: 'PII_DETECTED',
          reason: 'pii_detected',
          pii_types: piiTypes,
          correlation_id: correlationId,
        });
      }

      if (req.headers['x-sentinel-optimize'] === 'true' && bodyJson && Array.isArray(bodyJson.messages)) {
        try {
          const result = this.optimizerPlugin.optimize(bodyJson.messages, {
            provider,
            profile: req.headers['x-sentinel-optimizer-profile'] || 'default',
          });
          if (result && result.improved && Array.isArray(result.messages)) {
            bodyJson.messages = result.messages;
            bodyText = JSON.stringify(bodyJson);
          }
        } catch (error) {
          logger.warn('Optimizer plugin failed', { error: error.message, correlationId });
          warnings.push('optimizer:plugin_error');
        }
      }

      const bodyBuffer = bodyJson ? Buffer.from(JSON.stringify(bodyJson)) : Buffer.from(bodyText || '', 'utf8');
      const forwardHeaders = scrubForwardHeaders(req.headers);

      const budgetEstimate = this.budgetStore.estimateRequest({
        provider,
        method,
        requestBodyBuffer: bodyBuffer,
      });
      if (budgetEstimate.enabled === true) {
        setBudgetHeaders(res, budgetEstimate);
        if (budgetEstimate.applies) {
          res.setHeader('x-sentinel-budget-estimated-request-usd', formatBudgetUsd(budgetEstimate.estimatedRequestCostUsd));
          res.setHeader('x-sentinel-budget-projected-usd', formatBudgetUsd(budgetEstimate.projectedUsd));
        }
      }
      if (!budgetEstimate.allowed && budgetEstimate.reason === 'daily_limit_exceeded') {
        if (effectiveMode === 'enforce' && this.budgetStore.action === 'block') {
          this.stats.blocked_total += 1;
          this.stats.budget_blocked += 1;

          const diagnostics = {
            errorSource: 'sentinel',
            upstreamError: false,
            provider,
            retryCount: 0,
            circuitState: this.circuitBreakers.getProviderState(breakerKey).state,
            correlationId,
          };
          responseHeaderDiagnostics(res, diagnostics);
          this.auditLogger.write({
            timestamp: new Date().toISOString(),
            correlation_id: correlationId,
            config_version: this.config.version,
            mode: effectiveMode,
            decision: 'blocked_budget',
            reasons: ['daily_budget_exceeded'],
            pii_types: piiTypes,
            redactions: redactedCount,
            duration_ms: Date.now() - requestStart,
            request_bytes: bodyBuffer.length,
            response_status: 402,
            response_bytes: 0,
            provider,
            budget_limit_usd: budgetEstimate.dailyLimitUsd,
            budget_spent_usd: budgetEstimate.spentUsd,
            budget_projected_usd: budgetEstimate.projectedUsd,
          });
          this.writeStatus();
          finalizeRequestTelemetry({
            decision: 'blocked_budget',
            status: 402,
            providerName: provider,
          });
          return res.status(402).json({
            error: 'BUDGET_EXCEEDED',
            reason: 'daily_budget_exceeded',
            budget: {
              daily_limit_usd: budgetEstimate.dailyLimitUsd,
              spent_usd: budgetEstimate.spentUsd,
              projected_usd: budgetEstimate.projectedUsd,
              remaining_usd: budgetEstimate.remainingUsd,
              estimated_request_usd: budgetEstimate.estimatedRequestCostUsd,
            },
            correlation_id: correlationId,
          });
        }

        warnings.push('budget_limit_exceeded');
        this.stats.budget_limit_warnings += 1;
        this.stats.warnings_total += 1;
      }

      const start = Date.now();
      const pathWithQuery = `${parsedPath.pathname}${parsedPath.search}`;
      const vcrRequestMeta = {
        provider: cacheProviderKey,
        method,
        pathWithQuery,
        bodyBuffer,
        contentType: req.headers['content-type'],
        wantsStream,
      };
      let vcrLookup;
      try {
        vcrLookup = await this.vcrStore.lookup(vcrRequestMeta);
      } catch (error) {
        vcrLookup = {
          hit: false,
          strictReplay: false,
        };
        warnings.push('vcr_lookup_error');
        this.stats.warnings_total += 1;
      }
      let replayedFromVcr = false;
      let replayedFromSemanticCache = false;
      let semanticCacheHeader = null;
      let upstream;
      if (vcrLookup.hit) {
        replayedFromVcr = true;
        this.stats.vcr_replay_hits += 1;
        res.setHeader('x-sentinel-vcr', 'replay-hit');
        upstream = {
          ok: true,
          status: vcrLookup.response.status,
          isStream: false,
          body: vcrLookup.response.bodyBuffer,
          responseHeaders: vcrLookup.response.headers || {},
          diagnostics: {
            errorSource: 'sentinel',
            upstreamError: false,
            provider,
            retryCount: 0,
            circuitState: this.circuitBreakers.getProviderState(breakerKey).state,
            correlationId,
          },
        };
      } else {
        if (this.vcrStore.enabled && this.vcrStore.mode === 'replay') {
          this.stats.vcr_replay_misses += 1;
          res.setHeader('x-sentinel-vcr', 'replay-miss');
          if (vcrLookup.strictReplay) {
            const diagnostics = {
              errorSource: 'sentinel',
              upstreamError: false,
              provider,
              retryCount: 0,
              circuitState: this.circuitBreakers.getProviderState(breakerKey).state,
              correlationId,
            };
            responseHeaderDiagnostics(res, diagnostics);
            finalizeRequestTelemetry({
              decision: 'vcr_replay_miss',
              status: 424,
              providerName: provider,
            });
            return res.status(424).json({
              error: 'VCR_REPLAY_MISS',
              message: 'No matching VCR tape entry found for request',
              correlation_id: correlationId,
            });
          }
          warnings.push('vcr_replay_miss_passthrough');
          this.stats.warnings_total += 1;
        }

        if (this.semanticCache.isEnabled()) {
          try {
            const cacheLookup = await this.semanticCache.lookup({
              provider: cacheProviderKey,
              method,
              pathWithQuery,
              wantsStream,
              bodyJson,
              bodyText,
            });
            if (cacheLookup.hit) {
              replayedFromSemanticCache = true;
              semanticCacheHeader = 'hit';
              this.stats.semantic_cache_hits += 1;
              upstream = {
                ok: true,
                status: cacheLookup.response.status,
                isStream: false,
                body: cacheLookup.response.bodyBuffer,
                responseHeaders: cacheLookup.response.headers || {},
                diagnostics: {
                  errorSource: 'sentinel',
                  upstreamError: false,
                  provider,
                  retryCount: 0,
                  circuitState: this.circuitBreakers.getProviderState(breakerKey).state,
                  correlationId,
                },
              };
              res.setHeader('x-sentinel-semantic-cache', 'hit');
              res.setHeader('x-sentinel-semantic-similarity', String(cacheLookup.similarity));
            } else if (cacheLookup.reason === 'miss') {
              semanticCacheHeader = 'miss';
              this.stats.semantic_cache_misses += 1;
            } else {
              semanticCacheHeader = 'bypass';
            }
          } catch (error) {
            warnings.push('semantic_cache_error');
            this.stats.warnings_total += 1;
          }
        }

        if (!replayedFromSemanticCache) {
          upstream = await this.upstreamClient.forwardRequest({
            routePlan,
            req,
            pathWithQuery,
            method,
            bodyBuffer,
            bodyJson,
            correlationId,
            wantsStream,
            forwardHeaders,
          });
        }
      }

      const durationMs = Date.now() - start;
      const diagnostics = upstream.diagnostics;
      const routedProvider = upstream.route?.selectedProvider || provider;
      provenanceProvider = routedProvider;
      const routedTarget = upstream.route?.selectedTarget || routePlan.primary.targetName;
      const routedBreakerKey = upstream.route?.selectedBreakerKey || breakerKey;

      res.setHeader('x-sentinel-upstream-target', routedTarget);
      if (upstream.route?.failoverUsed) {
        this.stats.failover_events += 1;
        res.setHeader('x-sentinel-failover-used', 'true');
        res.setHeader('x-sentinel-failover-count', String(Math.max(0, upstream.route.failoverChain.length - 1)));
        const chainHeader = upstream.route.failoverChain
          .map((item) => `${item.target}:${item.status}`)
          .join('>');
        if (chainHeader.length > 0) {
          res.setHeader('x-sentinel-failover-chain', chainHeader.slice(0, 256));
        }
      } else {
        res.setHeader('x-sentinel-failover-used', 'false');
        res.setHeader('x-sentinel-failover-count', '0');
      }

      if (warnings.length > 0) {
        res.setHeader('x-sentinel-warning', warnings.join(','));
      }
      res.setHeader('x-sentinel-pii-provider', piiProviderUsed);
      if (semanticCacheHeader && !res.getHeader('x-sentinel-semantic-cache')) {
        res.setHeader('x-sentinel-semantic-cache', semanticCacheHeader);
      }

      if (!upstream.ok) {
        this.stats.upstream_errors += 1;
        responseHeaderDiagnostics(res, diagnostics);
        for (const [key, value] of Object.entries(filterUpstreamResponseHeaders(upstream.responseHeaders || {}))) {
          res.setHeader(key, value);
        }

        this.auditLogger.write({
          timestamp: new Date().toISOString(),
          correlation_id: correlationId,
          config_version: this.config.version,
          mode: effectiveMode,
          decision: 'upstream_error',
          reasons: [upstream.body.error || 'upstream_error'],
          pii_types: piiTypes,
          redactions: redactedCount,
          duration_ms: durationMs,
          request_bytes: bodyBuffer.length,
          response_status: upstream.status,
          response_bytes: Buffer.byteLength(JSON.stringify(upstream.body)),
          provider: routedProvider,
          upstream_target: routedTarget,
          failover_used: upstream.route?.failoverUsed === true,
          route_source: routePlan.routeSource,
          route_group: routePlan.selectedGroup || undefined,
          route_contract: routePlan.desiredContract,
          requested_target: routePlan.requestedTarget,
        });

        this.writeStatus();
        finalizeRequestTelemetry({
          decision: 'upstream_error',
          status: upstream.status,
          providerName: routedProvider,
        });
        return res.status(upstream.status).json(upstream.body);
      }

      if (upstream.status >= 400) {
        responseHeaderDiagnostics(res, diagnostics);
      }

      for (const [key, value] of Object.entries(filterUpstreamResponseHeaders(upstream.responseHeaders || {}))) {
        res.setHeader(key, value);
      }

      if (upstream.isStream) {
        res.status(upstream.status);
        let streamedBytes = 0;
        let streamOut = upstream.bodyStream;
        let streamTerminatedForPII = false;
        const streamEgressTypes = new Set();
        let streamProjectedRedaction = null;
        let streamBlockedSeverity = null;
        const upstreamContentType = String(upstream.responseHeaders?.['content-type'] || '').toLowerCase();
        const streamProof = this.provenanceSigner.createStreamContext({
          statusCode: upstream.status,
          provider: routedProvider,
          correlationId,
        });
        const canAddProofTrailers =
          Boolean(streamProof) &&
          this.provenanceSigner.signStreamTrailers === true &&
          typeof res.addTrailers === 'function';
        if (canAddProofTrailers) {
          res.setHeader(
            'trailer',
            'x-sentinel-signature-v, x-sentinel-signature-alg, x-sentinel-signature-key-id, x-sentinel-signature-input, x-sentinel-payload-sha256, x-sentinel-signature'
          );
          res.setHeader('x-sentinel-signature-status', 'stream-trailer');
        } else if (this.provenanceSigner.isEnabled()) {
          res.setHeader('x-sentinel-signature-status', 'stream-unsigned');
        }

        if (egressConfig.enabled && egressConfig.streamEnabled && upstreamContentType.includes('text/event-stream')) {
          const streamRedactor = new SSERedactionTransform({
            scanner: this.piiScanner,
            maxScanBytes: egressConfig.maxScanBytes,
            maxLineBytes: egressConfig.sseLineMaxBytes,
            severityActions: this.config.pii?.severity_actions || {},
            effectiveMode,
            streamBlockMode: egressConfig.streamBlockMode,
            onDetection: ({ action, severity, findings, projectedRedaction }) => {
              this.stats.egress_detected += 1;
              streamBlockedSeverity = severity || streamBlockedSeverity;
              for (const finding of findings || []) {
                if (finding?.id) {
                  streamEgressTypes.add(String(finding.id));
                }
              }
              if (typeof projectedRedaction === 'string' && projectedRedaction.length > 0 && !streamProjectedRedaction) {
                streamProjectedRedaction = projectedRedaction.slice(0, 512);
              }
              if (action === 'redact') {
                this.stats.egress_stream_redacted += 1;
              }
              if (action === 'block' && egressConfig.streamBlockMode === 'terminate' && !streamTerminatedForPII) {
                streamTerminatedForPII = true;
                this.stats.blocked_total += 1;
                this.stats.egress_blocked += 1;
                if (!res.headersSent) {
                  res.setHeader('x-sentinel-egress-action', 'stream_terminate');
                }
                warnings.push('egress_stream_blocked');
                this.stats.warnings_total += 1;
                setImmediate(() => {
                  if (typeof upstream.bodyStream.destroy === 'function') {
                    upstream.bodyStream.destroy(new Error('EGRESS_STREAM_BLOCKED'));
                  }
                  if (typeof streamOut.destroy === 'function') {
                    streamOut.destroy(new Error('EGRESS_STREAM_BLOCKED'));
                  }
                  if (!res.destroyed) {
                    res.destroy(new Error('EGRESS_STREAM_BLOCKED'));
                  }
                });
              }
            },
          });
          streamOut = streamOut.pipe(streamRedactor);
          res.setHeader('x-sentinel-egress-stream', egressConfig.streamBlockMode === 'terminate' ? 'terminate' : 'redact');
        }

        streamOut.on('data', (chunk) => {
          streamedBytes += chunk.length;
          if (streamProof) {
            streamProof.update(chunk);
          }
        });

        let streamBudgetFinalizePromise = null;
        const finalizeStreamBudget = async () => {
          if (streamBudgetFinalizePromise) {
            return streamBudgetFinalizePromise;
          }

          streamBudgetFinalizePromise = (async () => {
            try {
              const budgetCharge = await this.budgetStore.recordStream({
                provider: routedProvider,
                requestBodyBuffer: bodyBuffer,
                streamedBytes,
                replayedFromVcr,
                replayedFromSemanticCache,
                correlationId,
              });
              if (budgetCharge?.charged) {
                this.stats.budget_charged_usd = Number(
                  (this.stats.budget_charged_usd + Number(budgetCharge.chargedUsd || 0)).toFixed(6)
                );
              }
              return budgetCharge;
            } catch {
              warnings.push('budget_record_error');
              this.stats.warnings_total += 1;
              return null;
            }
          })();

          return streamBudgetFinalizePromise;
        };

        streamOut.on('end', async () => {
          if (canAddProofTrailers) {
            const proof = streamProof.finalize();
            if (proof) {
              res.addTrailers(ProvenanceSigner.proofHeaders(proof));
            }
          }
          const budgetCharge = await finalizeStreamBudget();

          this.auditLogger.write({
            timestamp: new Date().toISOString(),
            correlation_id: correlationId,
            config_version: this.config.version,
            mode: effectiveMode,
            decision: 'forwarded_stream',
              reasons: warnings,
              pii_types: piiTypes,
              egress_pii_types: Array.from(streamEgressTypes).sort(),
              egress_projected_redaction: streamProjectedRedaction || undefined,
              egress_block_severity: streamBlockedSeverity || undefined,
              redactions: redactedCount,
              duration_ms: Date.now() - start,
              request_bytes: bodyBuffer.length,
            response_status: upstream.status,
            response_bytes: streamedBytes,
            provider: routedProvider,
            upstream_target: routedTarget,
            failover_used: upstream.route?.failoverUsed === true,
            budget_charged_usd: budgetCharge?.chargedUsd,
            budget_spent_usd: budgetCharge?.spentUsd,
            budget_remaining_usd: budgetCharge?.remainingUsd,
            route_source: routePlan.routeSource,
            route_group: routePlan.selectedGroup || undefined,
            route_contract: routePlan.desiredContract,
            requested_target: routePlan.requestedTarget,
          });
          this.writeStatus();
          finalizeRequestTelemetry({
            decision: 'forwarded_stream',
            status: upstream.status,
            providerName: routedProvider,
          });
        });

        streamOut.on('error', (error) => {
          void (async () => {
            const budgetCharge = await finalizeStreamBudget();
            if (streamTerminatedForPII && String(error.message || '') === 'EGRESS_STREAM_BLOCKED') {
              this.auditLogger.write({
                timestamp: new Date().toISOString(),
                correlation_id: correlationId,
                config_version: this.config.version,
                mode: effectiveMode,
                decision: 'blocked_egress_stream',
                reasons: ['egress_stream_blocked'],
                pii_types: piiTypes,
                egress_pii_types: Array.from(streamEgressTypes).sort(),
                egress_projected_redaction: streamProjectedRedaction || undefined,
                egress_block_severity: streamBlockedSeverity || undefined,
                redactions: redactedCount,
                duration_ms: Date.now() - start,
                request_bytes: bodyBuffer.length,
                response_status: 499,
                response_bytes: streamedBytes,
                provider: routedProvider,
                upstream_target: routedTarget,
                failover_used: upstream.route?.failoverUsed === true,
                route_source: routePlan.routeSource,
                route_group: routePlan.selectedGroup || undefined,
                route_contract: routePlan.desiredContract,
                requested_target: routePlan.requestedTarget,
                budget_charged_usd: budgetCharge?.chargedUsd,
                budget_spent_usd: budgetCharge?.spentUsd,
                budget_remaining_usd: budgetCharge?.remainingUsd,
              });
              this.writeStatus();
              finalizeRequestTelemetry({
                decision: 'blocked_egress',
                status: 499,
                providerName: routedProvider,
              });
              return;
            }
            this.stats.upstream_errors += 1;
            this.auditLogger.write({
              timestamp: new Date().toISOString(),
              correlation_id: correlationId,
              config_version: this.config.version,
              mode: effectiveMode,
              decision: 'stream_error',
              reasons: [error.message || 'stream_error'],
              pii_types: piiTypes,
              redactions: redactedCount,
              duration_ms: Date.now() - start,
              request_bytes: bodyBuffer.length,
              response_status: upstream.status,
              response_bytes: streamedBytes,
              provider: routedProvider,
              upstream_target: routedTarget,
              failover_used: upstream.route?.failoverUsed === true,
              route_source: routePlan.routeSource,
              route_group: routePlan.selectedGroup || undefined,
              route_contract: routePlan.desiredContract,
              requested_target: routePlan.requestedTarget,
              budget_charged_usd: budgetCharge?.chargedUsd,
              budget_spent_usd: budgetCharge?.spentUsd,
              budget_remaining_usd: budgetCharge?.remainingUsd,
            });
            this.writeStatus();
            finalizeRequestTelemetry({
              decision: 'stream_error',
              status: upstream.status,
              providerName: routedProvider,
              error,
            });
            if (!res.destroyed) {
              res.destroy(error);
            }
          })().catch((handlerError) => {
            logger.warn('stream error handler failed', {
              correlationId,
              error: handlerError.message,
            });
          });
        });

        streamOut.pipe(res);
        return;
      }

      let outboundBody = upstream.body;
      if (!replayedFromVcr && this.vcrStore.enabled && this.vcrStore.mode === 'record' && Buffer.isBuffer(upstream.body)) {
        this.vcrStore.record(vcrRequestMeta, {
          status: upstream.status,
          headers: upstream.responseHeaders || {},
          bodyBuffer: upstream.body,
        });
        this.stats.vcr_records += 1;
        res.setHeader('x-sentinel-vcr', 'recorded');
      }
      if (egressConfig.enabled) {
        const egressResult = scanBufferedResponse({
          bodyBuffer: outboundBody,
          contentType: upstream.responseHeaders?.['content-type'],
          scanner: this.piiScanner,
          maxScanBytes: egressConfig.maxScanBytes,
          severityActions: this.config.pii?.severity_actions || {},
          effectiveMode,
        });

        if (egressResult.detected) {
          this.stats.egress_detected += 1;
          warnings.push(`egress_pii:${egressResult.severity}`);
          if (egressResult.redacted) {
            this.stats.egress_redacted += 1;
            outboundBody = egressResult.bodyBuffer;
            res.setHeader('x-sentinel-egress-action', 'redact');
          }
          if (egressResult.redactionSkipped) {
            warnings.push('egress_redaction_skipped_truncated');
            this.stats.warnings_total += 1;
          }

          if (egressResult.blocked) {
            this.stats.blocked_total += 1;
            this.stats.egress_blocked += 1;
            const diagnostics = {
              errorSource: 'sentinel',
              upstreamError: false,
              provider: routedProvider,
              retryCount: upstream.diagnostics.retryCount || 0,
              circuitState: this.circuitBreakers.getProviderState(routedBreakerKey).state,
              correlationId,
            };
            responseHeaderDiagnostics(res, diagnostics);
            res.setHeader('x-sentinel-egress-action', 'block');
            this.auditLogger.write({
              timestamp: new Date().toISOString(),
              correlation_id: correlationId,
              config_version: this.config.version,
              mode: effectiveMode,
              decision: 'blocked_egress',
              reasons: ['egress_pii_detected'],
              pii_types: egressResult.piiTypes,
              redactions: 0,
              duration_ms: durationMs,
              request_bytes: bodyBuffer.length,
              response_status: 403,
              response_bytes: 0,
              provider: routedProvider,
              upstream_target: routedTarget,
              failover_used: upstream.route?.failoverUsed === true,
              route_source: routePlan.routeSource,
              route_group: routePlan.selectedGroup || undefined,
              route_contract: routePlan.desiredContract,
              requested_target: routePlan.requestedTarget,
            });
            this.writeStatus();
            finalizeRequestTelemetry({
              decision: 'blocked_egress',
              status: 403,
              providerName: routedProvider,
            });
            return res.status(403).json({
              error: 'EGRESS_PII_DETECTED',
              reason: 'egress_pii_detected',
              pii_types: egressResult.piiTypes,
              correlation_id: correlationId,
            });
          }
        }
      }

      if (warnings.length > 0) {
        res.setHeader('x-sentinel-warning', warnings.join(','));
      }

      if (!replayedFromVcr && !replayedFromSemanticCache && this.semanticCache.isEnabled()) {
        const cacheSafeForStore =
          upstream.status >= 200 &&
          upstream.status < 300 &&
          injectionScore === 0 &&
          piiTypes.length === 0 &&
          redactedCount === 0 &&
          !warnings.some((item) => {
            const warning = String(item);
            return (
              warning.startsWith('policy:') ||
              warning.startsWith('pii:') ||
              warning.startsWith('injection:') ||
              warning.startsWith('egress_pii:') ||
              warning.includes('fallback') ||
              warning.includes('error')
            );
          });
        if (cacheSafeForStore) {
          try {
            const stored = await this.semanticCache.store({
              provider: cacheProviderKey,
              method,
              pathWithQuery,
              wantsStream,
              bodyJson,
              bodyText,
              responseStatus: upstream.status,
              responseHeaders: upstream.responseHeaders || {},
              responseBodyBuffer: outboundBody,
            });
            if (stored.stored) {
              this.stats.semantic_cache_stores += 1;
              res.setHeader('x-sentinel-semantic-cache', 'store');
            }
          } catch {
            warnings.push('semantic_cache_store_error');
            this.stats.warnings_total += 1;
          }
        }
      }

      let budgetCharge = null;
      try {
        budgetCharge = await this.budgetStore.recordBuffered({
          provider: routedProvider,
          requestBodyBuffer: bodyBuffer,
          responseBodyBuffer: outboundBody,
          replayedFromVcr,
          replayedFromSemanticCache,
          correlationId,
        });
        if (budgetCharge.charged) {
          this.stats.budget_charged_usd = Number(
            (this.stats.budget_charged_usd + Number(budgetCharge.chargedUsd || 0)).toFixed(6)
          );
          res.setHeader('x-sentinel-budget-charged-usd', formatBudgetUsd(budgetCharge.chargedUsd));
        }
        if (budgetCharge.enabled === true) {
          setBudgetHeaders(res, budgetCharge);
        }
      } catch {
        warnings.push('budget_record_error');
        this.stats.warnings_total += 1;
      }

      this.auditLogger.write({
        timestamp: new Date().toISOString(),
        correlation_id: correlationId,
        config_version: this.config.version,
        mode: effectiveMode,
        decision: 'forwarded',
        reasons: warnings,
        pii_types: piiTypes,
        redactions: redactedCount,
        duration_ms: durationMs,
        request_bytes: bodyBuffer.length,
        response_status: upstream.status,
        response_bytes: outboundBody.length,
        provider: routedProvider,
        upstream_target: routedTarget,
        failover_used: upstream.route?.failoverUsed === true,
        budget_charged_usd: budgetCharge?.chargedUsd,
        budget_spent_usd: budgetCharge?.spentUsd,
        budget_remaining_usd: budgetCharge?.remainingUsd,
        route_source: routePlan.routeSource,
        route_group: routePlan.selectedGroup || undefined,
        route_contract: routePlan.desiredContract,
        requested_target: routePlan.requestedTarget,
      });

      this.writeStatus();
      finalizeRequestTelemetry({
        decision: 'forwarded',
        status: upstream.status,
        providerName: routedProvider,
      });
      res.status(upstream.status).send(outboundBody);
    });
  }

  start() {
    const host = this.config.proxy.host;
    const port = this.options.portOverride || this.config.proxy.port;

    fs.writeFileSync(PID_FILE_PATH, String(process.pid), 'utf8');

    RuntimeOverrideManager.writeOverride(OVERRIDE_FILE_PATH, false);
    this.overrideManager.startPolling(() => {
      this.writeStatus();
    });

    this.statusInterval = setInterval(() => {
      this.writeStatus();
    }, 2000);

    this.server = this.app.listen(port, host, () => {
      logger.info('Sentinel started', {
        host,
        port,
        configured_mode: this.config.mode,
        effective_mode: this.computeEffectiveMode(),
      });
      this.writeStatus();
    });

    const dashboardConfig = this.config.runtime?.dashboard || {};
    if (dashboardConfig.enabled === true) {
      this.dashboardServer = new DashboardServer({
        host: dashboardConfig.host,
        port: dashboardConfig.port,
        allowRemote: dashboardConfig.allow_remote === true,
        authToken: dashboardConfig.auth_token,
        statusProvider: () => this.currentStatusPayload(),
      });
      this.dashboardServer
        .start()
        .then(() => {
          logger.info('Sentinel dashboard started', {
            host: dashboardConfig.host,
            port: dashboardConfig.port,
            allow_remote: dashboardConfig.allow_remote === true,
          });
        })
        .catch((error) => {
          logger.warn('Sentinel dashboard failed to start', {
            error: error.message,
          });
          this.dashboardServer = null;
        });
    }

    return this.server;
  }

  async stop() {
    this.overrideManager.stopPolling();
    if (this.statusInterval) {
      clearInterval(this.statusInterval);
      this.statusInterval = null;
    }

    this.writeStatus();

    await new Promise((resolve) => {
      if (!this.server) {
        resolve();
        return;
      }
      this.server.close(resolve);
    });

    await this.upstreamClient.close();
    if (this.scanWorkerPool) {
      await this.scanWorkerPool.close();
    }
    if (this.dashboardServer) {
      await this.dashboardServer.stop();
      this.dashboardServer = null;
    }
    await this.vcrStore.flush();
    await this.budgetStore.flush();
    await this.auditLogger.close({ timeoutMs: 5000 });

    if (fs.existsSync(PID_FILE_PATH)) {
      fs.unlinkSync(PID_FILE_PATH);
    }

    this.server = null;
    this.writeStatus();
  }
}

module.exports = {
  SentinelServer,
};
