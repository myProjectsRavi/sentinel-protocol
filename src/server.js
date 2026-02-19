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
const { TwoWayPIIVault } = require('./pii/two-way-vault');
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
const { HoneytokenInjector } = require('./security/honeytoken-injector');
const { SwarmProtocol } = require('./security/swarm-protocol');
const { PolymorphicPromptEngine } = require('./security/polymorphic-prompt');
const { SyntheticPoisoner } = require('./security/synthetic-poisoner');
const { CognitiveRollback } = require('./runtime/cognitive-rollback');
const { LatencyNormalizer } = require('./runtime/latency-normalizer');
const { IntentThrottle } = require('./runtime/intent-throttle');
const { IntentDriftDetector } = require('./runtime/intent-drift');
const { CanaryToolTrap } = require('./engines/canary-tool-trap');
const { ParallaxValidator } = require('./engines/parallax-validator');
const { OmniShield } = require('./engines/omni-shield');
const { ExperimentalSandbox } = require('./sandbox/experimental-sandbox');
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

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
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
      pii_vault_tokenized: 0,
      pii_vault_detokenized: 0,
      upstream_errors: 0,
      egress_detected: 0,
      egress_redacted: 0,
      egress_blocked: 0,
      egress_stream_redacted: 0,
      egress_entropy_detected: 0,
      egress_entropy_redacted: 0,
      egress_entropy_blocked: 0,
      omni_shield_detected: 0,
      omni_shield_blocked: 0,
      omni_shield_sanitized: 0,
      omni_shield_plugin_errors: 0,
      sandbox_detected: 0,
      sandbox_blocked: 0,
      sandbox_errors: 0,
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
      intent_throttle_matches: 0,
      intent_throttle_blocked: 0,
      intent_throttle_errors: 0,
      intent_drift_evaluated: 0,
      intent_drift_detected: 0,
      intent_drift_blocked: 0,
      intent_drift_errors: 0,
      swarm_inbound_verified: 0,
      swarm_inbound_rejected: 0,
      swarm_replay_rejected: 0,
      swarm_outbound_signed: 0,
      swarm_timestamp_skew_rejected: 0,
      swarm_unknown_node_rejected: 0,
      polymorph_applied: 0,
      synthetic_poisoning_injected: 0,
      cognitive_rollback_suggested: 0,
      cognitive_rollback_auto: 0,
      deception_engaged: 0,
      deception_streamed: 0,
      honeytoken_injected: 0,
      latency_normalized: 0,
      canary_tool_injected: 0,
      canary_tool_triggered: 0,
      parallax_evaluated: 0,
      parallax_vetoed: 0,
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
    this.piiVault = new TwoWayPIIVault(config.runtime?.pii_vault || {});
    this.neuralInjectionClassifier = new NeuralInjectionClassifier(config.injection?.neural || {});
    this.circuitBreakers = new CircuitBreakerManager(config.runtime.upstream.circuit_breaker);
    this.swarmProtocol = new SwarmProtocol(config.runtime?.swarm || {});
    this.swarmNodeMetrics = new Map();
    this.upstreamClient = new UpstreamClient({
      timeoutMs: config.proxy.timeout_ms,
      retryConfig: config.runtime.upstream.retry,
      circuitBreakers: this.circuitBreakers,
      telemetry: this.telemetry,
      authVaultConfig: config.runtime?.upstream?.auth_vault || {},
      ghostModeConfig: config.runtime?.upstream?.ghost_mode || {},
      swarmProtocol: this.swarmProtocol,
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
    this.honeytokenInjector = new HoneytokenInjector(this.config.runtime?.honeytoken || {});
    this.polymorphicPrompt = new PolymorphicPromptEngine(this.config.runtime?.polymorphic_prompt || {});
    this.syntheticPoisoner = new SyntheticPoisoner(this.config.runtime?.synthetic_poisoning || {});
    this.cognitiveRollback = new CognitiveRollback(this.config.runtime?.cognitive_rollback || {});
    this.latencyNormalizer = new LatencyNormalizer(this.config.runtime?.latency_normalization || {});
    this.intentThrottle = new IntentThrottle(this.config.runtime?.intent_throttle || {}, {
      embedText: async (text, options = {}) => {
        if (!this.scanWorkerPool?.enabled) {
          throw new Error('embedder_unavailable');
        }
        const result = await this.scanWorkerPool.embed({
          text,
          modelId: options.modelId,
          cacheDir: options.cacheDir,
          maxPromptChars: options.maxPromptChars,
        });
        return Array.isArray(result?.vector) ? result.vector : [];
      },
    });
    this.intentDrift = new IntentDriftDetector(this.config.runtime?.intent_drift || {}, {
      embedText: async (text, options = {}) => {
        if (!this.scanWorkerPool?.enabled) {
          throw new Error('embedder_unavailable');
        }
        const result = await this.scanWorkerPool.embed({
          text,
          modelId: options.modelId,
          cacheDir: options.cacheDir,
          maxPromptChars: options.maxPromptChars,
        });
        return Array.isArray(result?.vector) ? result.vector : [];
      },
    });
    this.canaryToolTrap = new CanaryToolTrap(this.config.runtime?.canary_tools || {});
    this.parallaxValidator = new ParallaxValidator(this.config.runtime?.parallax || {}, {
      upstreamClient: this.upstreamClient,
      config: this.config,
    });
    this.omniShield = new OmniShield(this.config.runtime?.omni_shield || {});
    this.experimentalSandbox = new ExperimentalSandbox(this.config.runtime?.sandbox_experimental || {});
    if (this.config.runtime?.semantic_cache?.enabled === true && !this.semanticCache.isEnabled()) {
      logger.warn('Semantic cache disabled at runtime because worker pool is unavailable', {
        semantic_cache_enabled: true,
        worker_pool_enabled: this.scanWorkerPool?.enabled === true,
      });
    }
    if (this.config.runtime?.intent_throttle?.enabled === true && this.scanWorkerPool?.enabled !== true) {
      logger.warn('Intent throttle is enabled but worker pool is unavailable; throttle will remain in monitor-only fallback', {
        intent_throttle_enabled: true,
        worker_pool_enabled: false,
      });
    }
    if (this.config.runtime?.intent_drift?.enabled === true && this.scanWorkerPool?.enabled !== true) {
      logger.warn('Intent drift is enabled but worker pool is unavailable; drift detector will remain in monitor-only fallback', {
        intent_drift_enabled: true,
        worker_pool_enabled: false,
      });
    }
    if (this.config.runtime?.swarm?.enabled === true && this.swarmProtocol.trustedNodes?.size <= 1) {
      logger.warn('Swarm protocol enabled with minimal trusted node set; inbound verification may only trust local node', {
        swarm_enabled: true,
        trusted_nodes: Math.max(0, this.swarmProtocol.trustedNodes?.size - 1),
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
      pii_vault_enabled: this.piiVault.isEnabled(),
      pii_vault_mode: this.piiVault.mode,
      loop_breaker_enabled: this.loopBreaker.enabled,
      deception_enabled: this.deceptionEngine.isEnabled(),
      provenance_enabled: this.provenanceSigner.isEnabled(),
      swarm_enabled: this.swarmProtocol.isEnabled(),
      swarm_mode: this.swarmProtocol.mode,
      swarm_allowed_clock_skew_ms: this.swarmProtocol.allowedClockSkewMs,
      swarm_node_metrics: this.getSwarmNodeMetricsSnapshot(),
      honeytoken_enabled: this.honeytokenInjector.isEnabled(),
      polymorphic_prompt_enabled: this.polymorphicPrompt.isEnabled(),
      synthetic_poisoning_enabled: this.syntheticPoisoner.isEnabled(),
      synthetic_poisoning_mode: this.syntheticPoisoner.mode,
      cognitive_rollback_enabled: this.cognitiveRollback.isEnabled(),
      cognitive_rollback_mode: this.cognitiveRollback.mode,
      omni_shield_enabled: this.omniShield.isEnabled(),
      omni_shield_mode: this.omniShield.mode,
      sandbox_experimental_enabled: this.experimentalSandbox.isEnabled(),
      sandbox_experimental_mode: this.experimentalSandbox.mode,
      latency_normalization_enabled: this.latencyNormalizer.isEnabled(),
      intent_throttle_enabled: this.intentThrottle.isEnabled(),
      intent_throttle_mode: this.intentThrottle.mode,
      intent_drift_enabled: this.intentDrift.isEnabled(),
      intent_drift_mode: this.intentDrift.mode,
      canary_tools_enabled: this.canaryToolTrap.isEnabled(),
      parallax_enabled: this.parallaxValidator.isEnabled(),
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

  recordSwarmObservation(decision = {}) {
    if (!decision || decision.present !== true) {
      return;
    }
    const nodeId = String(decision.nodeId || 'unknown');
    const existing = this.swarmNodeMetrics.get(nodeId) || {
      verified: 0,
      rejected: 0,
      replay_rejected: 0,
      timestamp_skew_rejected: 0,
      unknown_node_rejected: 0,
      reasons: {},
      last_skew_ms: null,
      max_abs_skew_ms: 0,
      last_seen_at: null,
    };
    if (decision.verified === true) {
      existing.verified += 1;
    } else {
      existing.rejected += 1;
      const reason = String(decision.reason || 'unknown');
      existing.reasons[reason] = (existing.reasons[reason] || 0) + 1;
      if (reason === 'replay_nonce') {
        existing.replay_rejected += 1;
      } else if (reason === 'timestamp_skew') {
        existing.timestamp_skew_rejected += 1;
      } else if (reason === 'unknown_node') {
        existing.unknown_node_rejected += 1;
      }
    }
    if (Number.isFinite(Number(decision.ageMs))) {
      const skew = Number(decision.ageMs);
      existing.last_skew_ms = skew;
      const absSkew = Math.abs(skew);
      if (absSkew > Number(existing.max_abs_skew_ms || 0)) {
        existing.max_abs_skew_ms = absSkew;
      }
    }
    existing.last_seen_at = new Date().toISOString();
    this.swarmNodeMetrics.set(nodeId, existing);
    while (this.swarmNodeMetrics.size > 128) {
      const oldest = this.swarmNodeMetrics.keys().next().value;
      if (!oldest) {
        break;
      }
      this.swarmNodeMetrics.delete(oldest);
    }
  }

  getSwarmNodeMetricsSnapshot() {
    const snapshot = {};
    for (const [nodeId, metric] of this.swarmNodeMetrics.entries()) {
      snapshot[nodeId] = {
        verified: Number(metric.verified || 0),
        rejected: Number(metric.rejected || 0),
        replay_rejected: Number(metric.replay_rejected || 0),
        timestamp_skew_rejected: Number(metric.timestamp_skew_rejected || 0),
        unknown_node_rejected: Number(metric.unknown_node_rejected || 0),
        reasons: metric.reasons || {},
        last_skew_ms: Number.isFinite(Number(metric.last_skew_ms)) ? Number(metric.last_skew_ms) : null,
        max_abs_skew_ms: Number(metric.max_abs_skew_ms || 0),
        last_seen_at: metric.last_seen_at || null,
      };
    }
    return snapshot;
  }

  getEgressConfig() {
    const egress = this.config?.pii?.egress || {};
    const entropy = egress.entropy || {};
    return {
      enabled: egress.enabled !== false,
      maxScanBytes: positiveIntOr(egress.max_scan_bytes, 65536),
      streamEnabled: egress.stream_enabled !== false,
      sseLineMaxBytes: positiveIntOr(egress.sse_line_max_bytes, 16384),
      streamBlockMode: egress.stream_block_mode === 'terminate' ? 'terminate' : 'redact',
      entropy: {
        enabled: entropy.enabled === true,
        mode: String(entropy.mode || 'monitor').toLowerCase() === 'block' ? 'block' : 'monitor',
        threshold: Number.isFinite(Number(entropy.threshold)) ? Number(entropy.threshold) : 4.5,
        min_token_length: positiveIntOr(entropy.min_token_length, 24),
        max_scan_bytes: positiveIntOr(entropy.max_scan_bytes, 65536),
        max_findings: positiveIntOr(entropy.max_findings, 8),
        min_unique_ratio: Number.isFinite(Number(entropy.min_unique_ratio)) ? Number(entropy.min_unique_ratio) : 0.3,
        detect_base64: entropy.detect_base64 !== false,
        detect_hex: entropy.detect_hex !== false,
        detect_generic: entropy.detect_generic !== false,
        redact_replacement: String(entropy.redact_replacement || '[REDACTED_HIGH_ENTROPY]'),
      },
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

  async maybeNormalizeBlockedLatency({ res, statusCode, requestStart }) {
    const plan = this.latencyNormalizer.planDelay({
      elapsedMs: Date.now() - Number(requestStart || Date.now()),
      statusCode,
    });
    if (!plan.apply) {
      return plan;
    }
    if (!this.latencyNormalizer.tryAcquire()) {
      return {
        ...plan,
        apply: false,
        delayMs: 0,
        reason: 'normalization_capacity_reached',
      };
    }
    try {
      await sleep(plan.delayMs);
      if (!res.headersSent) {
        res.setHeader('x-sentinel-latency-normalized', 'true');
        res.setHeader('x-sentinel-latency-delay-ms', String(plan.delayMs));
        res.setHeader('x-sentinel-latency-target-ms', String(plan.targetMs || 0));
      }
      this.stats.latency_normalized += 1;
      return plan;
    } finally {
      this.latencyNormalizer.release();
    }
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

    this.app.get('/_sentinel/swarm/public-key', (req, res) => {
      if (!this.swarmProtocol.isEnabled()) {
        res.status(404).json({
          error: 'SWARM_DISABLED',
        });
        return;
      }
      res.status(200).json(this.swarmProtocol.getPublicMetadata());
    });

    this.app.all('*', async (req, res) => {
      const correlationId = uuidv4();
      const piiVaultSessionKey = this.piiVault.deriveSessionKey(req.headers || {}, correlationId);
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
      const pathWithQuery = `${parsedPath.pathname}${parsedPath.search}`;
      let precomputedLocalScan = null;
      let precomputedInjection = null;
      let omniShieldDecision = null;
      let omniShieldSanitizeDecision = null;
      let sandboxDecision = null;

      const swarmInboundDecision = this.swarmProtocol.verifyInboundEnvelope({
        headers: req.headers || {},
        method,
        pathWithQuery,
        bodyBuffer: rawBody,
      });
      if (swarmInboundDecision.present) {
        res.setHeader('x-sentinel-swarm-verified', String(swarmInboundDecision.verified));
        res.setHeader('x-sentinel-swarm-reason', String(swarmInboundDecision.reason || 'unknown'));
        res.setHeader(
          'x-sentinel-swarm-allowed-skew-ms',
          String(swarmInboundDecision.allowedClockSkewMs || this.swarmProtocol.allowedClockSkewMs || 0)
        );
        if (Number.isFinite(Number(swarmInboundDecision.ageMs))) {
          res.setHeader('x-sentinel-swarm-clock-skew-ms', String(Number(swarmInboundDecision.ageMs)));
        }
        if (swarmInboundDecision.nodeId) {
          res.setHeader('x-sentinel-swarm-node-id', swarmInboundDecision.nodeId);
        }
      }
      this.recordSwarmObservation(swarmInboundDecision);
      if (swarmInboundDecision.verified) {
        this.stats.swarm_inbound_verified += 1;
      } else if (swarmInboundDecision.present || swarmInboundDecision.required) {
        this.stats.swarm_inbound_rejected += 1;
        if (swarmInboundDecision.reason === 'replay_nonce') {
          this.stats.swarm_replay_rejected += 1;
        } else if (swarmInboundDecision.reason === 'timestamp_skew') {
          this.stats.swarm_timestamp_skew_rejected += 1;
        } else if (swarmInboundDecision.reason === 'unknown_node') {
          this.stats.swarm_unknown_node_rejected += 1;
        }
        if (effectiveMode === 'enforce' && swarmInboundDecision.shouldBlock) {
          const diagnostics = {
            errorSource: 'sentinel',
            upstreamError: false,
            provider,
            retryCount: 0,
            circuitState: this.circuitBreakers.getProviderState(breakerKey).state,
            correlationId,
          };
          responseHeaderDiagnostics(res, diagnostics);
          const statusCode = swarmInboundDecision.reason === 'replay_nonce' ? 409 : 401;
          await this.maybeNormalizeBlockedLatency({
            res,
            statusCode,
            requestStart,
          });
          this.stats.blocked_total += 1;
          this.stats.policy_blocked += 1;
          this.auditLogger.write({
            timestamp: new Date().toISOString(),
            correlation_id: correlationId,
            config_version: this.config.version,
            mode: effectiveMode,
            decision: 'blocked_swarm',
            reasons: [String(swarmInboundDecision.reason || 'swarm_verification_failed')],
            pii_types: [],
            redactions: 0,
            duration_ms: Date.now() - requestStart,
            request_bytes: rawBody.length,
            response_status: statusCode,
            response_bytes: 0,
            provider,
            swarm_node_id: swarmInboundDecision.nodeId,
            swarm_key_id: swarmInboundDecision.keyId,
            swarm_nonce: swarmInboundDecision.nonce,
            swarm_clock_skew_ms: Number.isFinite(Number(swarmInboundDecision.ageMs))
              ? Number(swarmInboundDecision.ageMs)
              : undefined,
            swarm_allowed_clock_skew_ms: Number(
              swarmInboundDecision.allowedClockSkewMs || this.swarmProtocol.allowedClockSkewMs || 0
            ),
          });
          this.writeStatus();
          finalizeRequestTelemetry({
            decision: 'blocked_policy',
            status: statusCode,
            providerName: provider,
          });
          return res.status(statusCode).json({
            error: 'SWARM_VERIFICATION_FAILED',
            reason: swarmInboundDecision.reason,
            swarm_node_id: swarmInboundDecision.nodeId,
            correlation_id: correlationId,
          });
        }
        warnings.push(`swarm:${swarmInboundDecision.reason}`);
        this.stats.warnings_total += 1;
      }

      omniShieldDecision = this.omniShield.inspect({
        bodyJson,
        effectiveMode,
      });
      if (omniShieldDecision.detected) {
        this.stats.omni_shield_detected += 1;
        warnings.push('omni_shield:image_payload_detected');
        this.stats.warnings_total += 1;
        if (this.omniShield.observability) {
          res.setHeader('x-sentinel-omni-shield', omniShieldDecision.shouldBlock ? 'block' : 'monitor');
          res.setHeader(
            'x-sentinel-omni-shield-findings',
            String(Array.isArray(omniShieldDecision.findings) ? omniShieldDecision.findings.length : 0)
          );
        }
      }
      if (omniShieldDecision.detected && this.omniShield.plugin?.enabled === true) {
        omniShieldSanitizeDecision = await this.omniShield.sanitizePayload({
          bodyJson,
          findings: omniShieldDecision.findings,
          effectiveMode,
        });
        if (this.omniShield.plugin?.observability) {
          res.setHeader('x-sentinel-omni-shield-plugin', String(omniShieldSanitizeDecision.reason || 'ok'));
          if (Number.isFinite(Number(omniShieldSanitizeDecision.rewrites))) {
            res.setHeader(
              'x-sentinel-omni-shield-plugin-rewrites',
              String(Number(omniShieldSanitizeDecision.rewrites || 0))
            );
          }
        }
        if (omniShieldSanitizeDecision.error) {
          this.stats.omni_shield_plugin_errors += 1;
          warnings.push('omni_shield:plugin_error');
          this.stats.warnings_total += 1;
        }
        if (omniShieldSanitizeDecision.applied && omniShieldSanitizeDecision.bodyJson) {
          bodyJson = omniShieldSanitizeDecision.bodyJson;
          bodyText = JSON.stringify(bodyJson);
          this.stats.omni_shield_sanitized += Number(omniShieldSanitizeDecision.rewrites || 0);
          warnings.push(`omni_shield:sanitized:${Number(omniShieldSanitizeDecision.rewrites || 0)}`);
          this.stats.warnings_total += 1;
          omniShieldDecision = this.omniShield.inspect({
            bodyJson,
            effectiveMode,
          });
        }
        if (omniShieldSanitizeDecision.shouldBlock) {
          this.stats.blocked_total += 1;
          this.stats.omni_shield_blocked += 1;
          const diagnostics = {
            errorSource: 'sentinel',
            upstreamError: false,
            provider,
            retryCount: 0,
            circuitState: this.circuitBreakers.getProviderState(breakerKey).state,
            correlationId,
          };
          responseHeaderDiagnostics(res, diagnostics);
          await this.maybeNormalizeBlockedLatency({
            res,
            statusCode: 403,
            requestStart,
          });
          this.auditLogger.write({
            timestamp: new Date().toISOString(),
            correlation_id: correlationId,
            config_version: this.config.version,
            mode: effectiveMode,
            decision: 'blocked_omni_shield_plugin',
            reasons: [String(omniShieldSanitizeDecision.reason || 'plugin_fail_closed')],
            pii_types: [],
            redactions: 0,
            duration_ms: Date.now() - requestStart,
            request_bytes: rawBody.length,
            response_status: 403,
            response_bytes: 0,
            provider,
            omni_shield_plugin_error: omniShieldSanitizeDecision.error,
            omni_shield_plugin_rewrites: omniShieldSanitizeDecision.rewrites,
            omni_shield_plugin_unsupported: omniShieldSanitizeDecision.unsupported,
          });
          this.writeStatus();
          finalizeRequestTelemetry({
            decision: 'blocked_policy',
            status: 403,
            providerName: provider,
          });
          return res.status(403).json({
            error: 'OMNI_SHIELD_PLUGIN_BLOCKED',
            reason: omniShieldSanitizeDecision.reason,
            correlation_id: correlationId,
          });
        }
      }
      if (omniShieldDecision.shouldBlock) {
        this.stats.blocked_total += 1;
        this.stats.omni_shield_blocked += 1;
        const diagnostics = {
          errorSource: 'sentinel',
          upstreamError: false,
          provider,
          retryCount: 0,
          circuitState: this.circuitBreakers.getProviderState(breakerKey).state,
          correlationId,
        };
        responseHeaderDiagnostics(res, diagnostics);
        await this.maybeNormalizeBlockedLatency({
          res,
          statusCode: 403,
          requestStart,
        });
        this.auditLogger.write({
          timestamp: new Date().toISOString(),
          correlation_id: correlationId,
          config_version: this.config.version,
          mode: effectiveMode,
          decision: 'blocked_omni_shield',
          reasons: ['omni_shield_image_policy'],
          pii_types: [],
          redactions: 0,
          duration_ms: Date.now() - requestStart,
          request_bytes: rawBody.length,
          response_status: 403,
          response_bytes: 0,
          provider,
          omni_shield_findings: omniShieldDecision.violating_findings || omniShieldDecision.findings || [],
          omni_shield_plugin_applied: Boolean(omniShieldSanitizeDecision?.applied),
          omni_shield_plugin_rewrites: omniShieldSanitizeDecision?.rewrites || 0,
        });
        this.writeStatus();
        finalizeRequestTelemetry({
          decision: 'blocked_policy',
          status: 403,
          providerName: provider,
        });
        return res.status(403).json({
          error: 'OMNI_SHIELD_BLOCKED',
          reason: 'omni_shield_image_policy',
          findings: (omniShieldDecision.violating_findings || omniShieldDecision.findings || []).map((item) => ({
            kind: item.kind,
            reason: item.reason,
            role: item.role,
            message_index: item.message_index,
            part_index: item.part_index,
            media_type: item.media_type || null,
            bytes: item.bytes,
          })),
          correlation_id: correlationId,
        });
      }

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
          await this.maybeNormalizeBlockedLatency({
            res,
            statusCode: 403,
            requestStart,
          });
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
      let piiVaultDecision = null;
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
          await this.maybeNormalizeBlockedLatency({
            res,
            statusCode: 429,
            requestStart,
          });
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

      let intentThrottleDecision = null;
      let intentDriftDecision = null;
      let syntheticPoisonDecision = null;
      if (this.intentThrottle.isEnabled()) {
        try {
          intentThrottleDecision = await this.intentThrottle.evaluate({
            headers: req.headers || {},
            bodyJson,
            bodyText,
          });
        } catch (error) {
          intentThrottleDecision = {
            enabled: true,
            matched: false,
            shouldBlock: false,
            reason: 'embedding_error',
            error: String(error.message || error),
          };
        }

        if (intentThrottleDecision?.matched) {
          this.stats.intent_throttle_matches += 1;
          res.setHeader('x-sentinel-intent-throttle', String(intentThrottleDecision.reason || 'intent_match'));
          if (intentThrottleDecision.cluster) {
            res.setHeader('x-sentinel-intent-cluster', String(intentThrottleDecision.cluster).slice(0, 64));
          }
          if (Number.isFinite(Number(intentThrottleDecision.similarity))) {
            res.setHeader('x-sentinel-intent-similarity', String(intentThrottleDecision.similarity));
          }

          if (effectiveMode === 'enforce' && intentThrottleDecision.shouldBlock) {
            syntheticPoisonDecision = this.syntheticPoisoner.inject({
              bodyJson,
              trigger: intentThrottleDecision.reason,
            });
            if (syntheticPoisonDecision.applied) {
              bodyJson = syntheticPoisonDecision.bodyJson;
              bodyText = syntheticPoisonDecision.bodyText;
              this.stats.synthetic_poisoning_injected += 1;
              warnings.push('synthetic_poisoning:injected');
              this.stats.warnings_total += 1;
              if (this.syntheticPoisoner.observability) {
                res.setHeader('x-sentinel-synthetic-poisoning', 'injected');
                res.setHeader(
                  'x-sentinel-synthetic-trigger',
                  String(syntheticPoisonDecision.meta?.trigger || intentThrottleDecision.reason || '')
                );
              }
            } else {
              if (this.syntheticPoisoner.isEnabled() && this.syntheticPoisoner.observability) {
                res.setHeader(
                  'x-sentinel-synthetic-poisoning',
                  String(syntheticPoisonDecision.reason || 'not_applied')
                );
              }
              this.stats.blocked_total += 1;
              this.stats.intent_throttle_blocked += 1;

              const diagnostics = {
                errorSource: 'sentinel',
                upstreamError: false,
                provider,
                retryCount: 0,
                circuitState: this.circuitBreakers.getProviderState(breakerKey).state,
                correlationId,
              };
              responseHeaderDiagnostics(res, diagnostics);
              await this.maybeNormalizeBlockedLatency({
                res,
                statusCode: 429,
                requestStart,
              });
              this.auditLogger.write({
                timestamp: new Date().toISOString(),
                correlation_id: correlationId,
                config_version: this.config.version,
                mode: effectiveMode,
                decision: 'blocked_intent_throttle',
                reasons: [String(intentThrottleDecision.reason || 'intent_velocity_exceeded')],
                pii_types: [],
                redactions: 0,
                duration_ms: Date.now() - requestStart,
                request_bytes: rawBody.length,
                response_status: 429,
                response_bytes: 0,
                provider,
                intent_cluster: intentThrottleDecision.cluster,
                intent_similarity: intentThrottleDecision.similarity,
                intent_threshold: intentThrottleDecision.threshold,
                intent_count: intentThrottleDecision.count,
                intent_max_events_per_window: intentThrottleDecision.maxEventsPerWindow,
                intent_window_ms: intentThrottleDecision.windowMs,
                intent_cooldown_ms: intentThrottleDecision.cooldownMs,
                intent_blocked_until: intentThrottleDecision.blockedUntil,
                synthetic_poison_reason: syntheticPoisonDecision?.reason,
              });
              this.writeStatus();
              finalizeRequestTelemetry({
                decision: 'blocked_policy',
                status: 429,
                providerName: provider,
              });
              return res.status(429).json({
                error: 'INTENT_THROTTLED',
                reason: intentThrottleDecision.reason,
                cluster: intentThrottleDecision.cluster,
                similarity: intentThrottleDecision.similarity,
                count: intentThrottleDecision.count,
                threshold: intentThrottleDecision.threshold,
                max_events_per_window: intentThrottleDecision.maxEventsPerWindow,
                window_ms: intentThrottleDecision.windowMs,
                cooldown_ms: intentThrottleDecision.cooldownMs,
                blocked_until: intentThrottleDecision.blockedUntil || 0,
                correlation_id: correlationId,
              });
            }
          }

          warnings.push(`intent_throttle:${intentThrottleDecision.cluster || intentThrottleDecision.reason}`);
          this.stats.warnings_total += 1;
        } else if (
          intentThrottleDecision?.reason === 'embedding_error' ||
          intentThrottleDecision?.reason === 'embedder_unavailable'
        ) {
          this.stats.intent_throttle_errors += 1;
          warnings.push(`intent_throttle:${intentThrottleDecision.reason}`);
          this.stats.warnings_total += 1;
        }
      }

      if (this.intentDrift.isEnabled()) {
        try {
          intentDriftDecision = await this.intentDrift.evaluate({
            headers: req.headers || {},
            bodyJson,
            correlationId,
            effectiveMode,
          });
        } catch (error) {
          intentDriftDecision = {
            enabled: true,
            evaluated: false,
            drifted: false,
            shouldBlock: false,
            reason: 'embedding_error',
            error: String(error.message || error),
          };
        }

        if (intentDriftDecision?.evaluated) {
          this.stats.intent_drift_evaluated += 1;
        }
        if (intentDriftDecision?.enabled && this.intentDrift.observability) {
          res.setHeader('x-sentinel-intent-drift', String(intentDriftDecision.reason || 'not_evaluated'));
          const distanceForHeader = Number.isFinite(Number(intentDriftDecision.adjustedDistance))
            ? intentDriftDecision.adjustedDistance
            : intentDriftDecision.distance;
          if (Number.isFinite(Number(distanceForHeader))) {
            res.setHeader('x-sentinel-intent-drift-distance', String(distanceForHeader));
          }
          if (Number.isFinite(Number(intentDriftDecision.adjustedDistance))) {
            res.setHeader('x-sentinel-intent-drift-adjusted-distance', String(intentDriftDecision.adjustedDistance));
          }
          if (Number.isFinite(Number(intentDriftDecision.riskDelta))) {
            res.setHeader('x-sentinel-intent-drift-risk-delta', String(intentDriftDecision.riskDelta));
          }
          if (Number.isFinite(Number(intentDriftDecision.threshold))) {
            res.setHeader('x-sentinel-intent-drift-threshold', String(intentDriftDecision.threshold));
          }
          if (Number.isFinite(Number(intentDriftDecision.turnCount))) {
            res.setHeader('x-sentinel-intent-drift-turn', String(intentDriftDecision.turnCount));
          }
        }

        if (intentDriftDecision?.drifted) {
          this.stats.intent_drift_detected += 1;
          warnings.push(`intent_drift:${intentDriftDecision.reason || 'drift_threshold_exceeded'}`);
          this.stats.warnings_total += 1;

          if (effectiveMode === 'enforce' && intentDriftDecision.shouldBlock) {
            this.stats.blocked_total += 1;
            this.stats.policy_blocked += 1;
            this.stats.intent_drift_blocked += 1;
            const diagnostics = {
              errorSource: 'sentinel',
              upstreamError: false,
              provider,
              retryCount: 0,
              circuitState: this.circuitBreakers.getProviderState(breakerKey).state,
              correlationId,
            };
            responseHeaderDiagnostics(res, diagnostics);
            await this.maybeNormalizeBlockedLatency({
              res,
              statusCode: 409,
              requestStart,
            });
            this.auditLogger.write({
              timestamp: new Date().toISOString(),
              correlation_id: correlationId,
              config_version: this.config.version,
              mode: effectiveMode,
              decision: 'blocked_intent_drift',
              reasons: [String(intentDriftDecision.reason || 'drift_threshold_exceeded')],
              pii_types: [],
              redactions: 0,
              duration_ms: Date.now() - requestStart,
              request_bytes: rawBody.length,
              response_status: 409,
              response_bytes: 0,
              provider,
              intent_drift_distance: intentDriftDecision.distance,
              intent_drift_adjusted_distance: intentDriftDecision.adjustedDistance,
              intent_drift_risk_delta: intentDriftDecision.riskDelta,
              intent_drift_similarity: intentDriftDecision.similarity,
              intent_drift_threshold: intentDriftDecision.threshold,
              intent_drift_turn_count: intentDriftDecision.turnCount,
              intent_drift_anchor_hash: intentDriftDecision.anchorHash,
              intent_drift_blocked_until: intentDriftDecision.blockedUntil,
            });
            this.writeStatus();
            finalizeRequestTelemetry({
              decision: 'blocked_policy',
              status: 409,
              providerName: provider,
            });
            return res.status(409).json({
              error: 'INTENT_DRIFT_DETECTED',
              reason: intentDriftDecision.reason,
              distance: intentDriftDecision.distance,
              adjusted_distance: intentDriftDecision.adjustedDistance,
              risk_delta: intentDriftDecision.riskDelta,
              threshold: intentDriftDecision.threshold,
              similarity: intentDriftDecision.similarity,
              turn_count: intentDriftDecision.turnCount,
              blocked_until: intentDriftDecision.blockedUntil || 0,
              correlation_id: correlationId,
            });
          }
        } else if (
          intentDriftDecision?.reason === 'embedding_error' ||
          intentDriftDecision?.reason === 'embedder_unavailable' ||
          intentDriftDecision?.reason === 'anchor_embedding_failed' ||
          intentDriftDecision?.reason === 'current_embedding_failed'
        ) {
          this.stats.intent_drift_errors += 1;
          warnings.push(`intent_drift:${intentDriftDecision.reason}`);
          this.stats.warnings_total += 1;
        }
      }

      if (this.experimentalSandbox.isEnabled()) {
        try {
          sandboxDecision = this.experimentalSandbox.inspect({
            bodyJson,
            effectiveMode,
          });
        } catch (error) {
          sandboxDecision = {
            enabled: true,
            detected: false,
            shouldBlock: false,
            findings: [],
            reason: 'sandbox_error',
            error: String(error.message || error),
          };
        }

        if (sandboxDecision?.detected) {
          this.stats.sandbox_detected += 1;
          warnings.push('sandbox_experimental:detected');
          this.stats.warnings_total += 1;
          if (this.experimentalSandbox.observability) {
            res.setHeader('x-sentinel-sandbox', sandboxDecision.shouldBlock ? 'block' : 'monitor');
            res.setHeader(
              'x-sentinel-sandbox-findings',
              String(Array.isArray(sandboxDecision.findings) ? sandboxDecision.findings.length : 0)
            );
          }
        } else if (sandboxDecision?.reason === 'sandbox_error') {
          this.stats.sandbox_errors += 1;
          warnings.push('sandbox_experimental:error');
          this.stats.warnings_total += 1;
        }

        if (sandboxDecision?.shouldBlock) {
          this.stats.blocked_total += 1;
          this.stats.policy_blocked += 1;
          this.stats.sandbox_blocked += 1;

          const diagnostics = {
            errorSource: 'sentinel',
            upstreamError: false,
            provider,
            retryCount: 0,
            circuitState: this.circuitBreakers.getProviderState(breakerKey).state,
            correlationId,
          };
          responseHeaderDiagnostics(res, diagnostics);
          await this.maybeNormalizeBlockedLatency({
            res,
            statusCode: 403,
            requestStart,
          });

          this.auditLogger.write({
            timestamp: new Date().toISOString(),
            correlation_id: correlationId,
            config_version: this.config.version,
            mode: effectiveMode,
            decision: 'blocked_sandbox_experimental',
            reasons: ['sandbox_experimental_policy'],
            pii_types: [],
            redactions: 0,
            duration_ms: Date.now() - requestStart,
            request_bytes: rawBody.length,
            response_status: 403,
            response_bytes: 0,
            provider,
            sandbox_findings: sandboxDecision.findings || [],
          });
          this.writeStatus();
          finalizeRequestTelemetry({
            decision: 'blocked_policy',
            status: 403,
            providerName: provider,
          });
          return res.status(403).json({
            error: 'SANDBOX_EXPERIMENTAL_BLOCKED',
            reason: 'sandbox_experimental_policy',
            findings: (sandboxDecision.findings || []).slice(0, 10),
            correlation_id: correlationId,
          });
        }
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

        if (!piiBlocked && piiResult && piiResult.findings.length > 0 && this.piiVault.isEnabled()) {
          piiVaultDecision = this.piiVault.applyIngress({
            text: bodyText,
            findings: piiResult.findings,
            sessionKey: piiVaultSessionKey,
          });
          if (piiVaultDecision.detected) {
            if (piiVaultDecision.applied) {
              bodyText = piiVaultDecision.text;
              const reparsed = safeJsonParse(bodyText);
              if (reparsed) {
                bodyJson = reparsed;
              }
              this.stats.pii_vault_tokenized += Number(piiVaultDecision.replacements || 0);
              warnings.push(`pii_vault:tokenized:${piiVaultDecision.replacements || 0}`);
              this.stats.warnings_total += 1;
              if (this.piiVault.observability) {
                res.setHeader('x-sentinel-pii-vault', 'tokenized');
                res.setHeader(
                  'x-sentinel-pii-vault-mappings',
                  String(Array.isArray(piiVaultDecision.mappings) ? piiVaultDecision.mappings.length : 0)
                );
              }
            } else if (piiVaultDecision.monitorOnly) {
              warnings.push('pii_vault:monitor');
              this.stats.warnings_total += 1;
              if (this.piiVault.observability) {
                res.setHeader('x-sentinel-pii-vault', 'monitor');
              }
            }
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
        await this.maybeNormalizeBlockedLatency({
          res,
          statusCode: 403,
          requestStart,
        });

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

      let polymorphDecision = null;
      if (this.polymorphicPrompt.isEnabled()) {
        polymorphDecision = this.polymorphicPrompt.mutate({
          bodyJson,
          headers: req.headers || {},
        });
        if (polymorphDecision.applied) {
          bodyJson = polymorphDecision.bodyJson;
          bodyText = polymorphDecision.bodyText;
          this.stats.polymorph_applied += 1;
          if (this.polymorphicPrompt.observability) {
            res.setHeader('x-sentinel-polymorph', 'applied');
            res.setHeader('x-sentinel-polymorph-epoch', String(polymorphDecision.meta?.epoch || 0));
            res.setHeader('x-sentinel-polymorph-replacements', String(polymorphDecision.meta?.replacements || 0));
          }
        } else if (this.polymorphicPrompt.observability) {
          res.setHeader('x-sentinel-polymorph', String(polymorphDecision.reason || 'bypass'));
        }
      }

      const parallaxInputBodyJson =
        bodyJson && typeof bodyJson === 'object'
          ? JSON.parse(JSON.stringify(bodyJson))
          : null;

      let honeytokenDecision = null;
      if (this.honeytokenInjector.isEnabled()) {
        const injected = this.honeytokenInjector.inject({
          bodyJson,
          bodyText,
          provider,
          path: parsedPath.pathname,
        });
        if (injected.applied) {
          bodyJson = injected.bodyJson;
          bodyText = injected.bodyText;
          honeytokenDecision = injected.meta;
          this.stats.honeytoken_injected += 1;
          res.setHeader('x-sentinel-honeytoken', 'injected');
          res.setHeader('x-sentinel-honeytoken-mode', injected.meta.mode);
          res.setHeader('x-sentinel-honeytoken-id', String(injected.meta.token_hash).slice(0, 16));
        }
      }

      let canaryToolDecision = null;
      if (this.canaryToolTrap.isEnabled()) {
        const canaryInjected = this.canaryToolTrap.inject(bodyJson, { provider });
        if (canaryInjected.applied) {
          bodyJson = canaryInjected.bodyJson;
          bodyText = canaryInjected.bodyText;
          canaryToolDecision = canaryInjected.meta;
          this.stats.canary_tool_injected += 1;
          res.setHeader('x-sentinel-canary-tool', 'injected');
          res.setHeader('x-sentinel-canary-tool-name', canaryInjected.meta.tool_name);
        }
      }
      let canaryTriggered = null;
      let parallaxDecision = null;
      let cognitiveRollbackDecision = null;

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
          await this.maybeNormalizeBlockedLatency({
            res,
            statusCode: 402,
            requestStart,
          });
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

      if (upstream.swarm?.signed) {
        this.stats.swarm_outbound_signed += 1;
        res.setHeader('x-sentinel-swarm-outbound', 'signed');
        res.setHeader('x-sentinel-swarm-outbound-node-id', String(upstream.swarm.nodeId || ''));
      } else if (this.swarmProtocol.isEnabled() && upstream.swarm?.reason) {
        res.setHeader('x-sentinel-swarm-outbound', String(upstream.swarm.reason));
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
          honeytoken_applied: Boolean(honeytokenDecision),
          honeytoken_mode: honeytokenDecision?.mode,
          honeytoken_token_hash: honeytokenDecision?.token_hash,
          canary_tool_injected: Boolean(canaryToolDecision),
          canary_tool_name: canaryToolDecision?.tool_name || canaryTriggered?.toolName,
          canary_tool_triggered: Boolean(canaryTriggered?.triggered),
          parallax_evaluated: Boolean(parallaxDecision?.evaluated),
          parallax_veto: Boolean(parallaxDecision?.veto),
          parallax_risk: parallaxDecision?.risk,
          parallax_secondary_provider: parallaxDecision?.secondaryProvider,
          parallax_high_risk_tools: parallaxDecision?.highRiskTools,
          cognitive_rollback_suggested: Boolean(cognitiveRollbackDecision?.applicable),
          cognitive_rollback_mode: cognitiveRollbackDecision?.mode,
          cognitive_rollback_trigger: cognitiveRollbackDecision?.trigger,
          cognitive_rollback_dropped_messages: cognitiveRollbackDecision?.droppedMessages,
          omni_shield_detected: Boolean(omniShieldDecision?.detected),
          omni_shield_findings: omniShieldDecision?.findings,
          intent_drift_evaluated: Boolean(intentDriftDecision?.evaluated),
          intent_drift_reason: intentDriftDecision?.reason,
          intent_drift_drifted: Boolean(intentDriftDecision?.drifted),
          intent_drift_distance: intentDriftDecision?.distance,
          intent_drift_threshold: intentDriftDecision?.threshold,
          intent_drift_turn_count: intentDriftDecision?.turnCount,
          sandbox_detected: Boolean(sandboxDecision?.detected),
          sandbox_findings: sandboxDecision?.findings,
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
        let streamTerminatedForEntropy = false;
        const streamEgressTypes = new Set();
        let streamProjectedRedaction = null;
        let streamBlockedSeverity = null;
        let streamVaultReplacements = 0;
        const streamEntropyFindings = [];
        let streamEntropyProjectedRedaction = null;
        let streamEntropyMode = null;
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
            entropyConfig: egressConfig.entropy,
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
            onEntropy: ({ action, findings, threshold, projectedRedaction, truncated }) => {
              this.stats.egress_entropy_detected += 1;
              streamEntropyMode = action;
              if (!res.headersSent) {
                res.setHeader('x-sentinel-egress-entropy', String(action || 'monitor'));
              }
              if (truncated === true) {
                warnings.push('egress_entropy_scan_truncated');
                this.stats.warnings_total += 1;
              }
              for (const finding of findings || []) {
                streamEntropyFindings.push({
                  kind: finding.kind,
                  entropy: finding.entropy,
                  token_hash: finding.token_hash,
                  threshold,
                });
              }
              if (
                typeof projectedRedaction === 'string' &&
                projectedRedaction.length > 0 &&
                !streamEntropyProjectedRedaction
              ) {
                streamEntropyProjectedRedaction = projectedRedaction.slice(0, 512);
              }
              if (action === 'redact') {
                this.stats.egress_entropy_redacted += 1;
              }
              if (action === 'block' && egressConfig.streamBlockMode === 'terminate' && !streamTerminatedForEntropy) {
                streamTerminatedForEntropy = true;
                this.stats.blocked_total += 1;
                this.stats.egress_entropy_blocked += 1;
                if (!res.headersSent) {
                  res.setHeader('x-sentinel-egress-entropy', 'stream_terminate');
                }
                warnings.push('egress_entropy_stream_blocked');
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

        const vaultStream = this.piiVault.createEgressStreamTransform({
          sessionKey: piiVaultSessionKey,
          contentType: upstreamContentType,
          onMetrics: ({ replacements }) => {
            streamVaultReplacements = Number(replacements || 0);
            if (streamVaultReplacements > 0) {
              this.stats.pii_vault_detokenized += streamVaultReplacements;
            }
          },
        });
        if (vaultStream) {
          streamOut = streamOut.pipe(vaultStream);
          if (this.piiVault.observability && !res.headersSent) {
            res.setHeader('x-sentinel-pii-vault-egress', 'detokenize_stream');
          }
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
          this.latencyNormalizer.recordSuccess(Date.now() - requestStart);
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
              egress_entropy_findings: streamEntropyFindings,
              egress_entropy_mode: streamEntropyMode || undefined,
              egress_entropy_projected_redaction: streamEntropyProjectedRedaction || undefined,
              pii_vault_detokenized: streamVaultReplacements,
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
            honeytoken_applied: Boolean(honeytokenDecision),
            honeytoken_mode: honeytokenDecision?.mode,
            honeytoken_token_hash: honeytokenDecision?.token_hash,
            canary_tool_injected: Boolean(canaryToolDecision),
            canary_tool_name: canaryToolDecision?.tool_name || canaryTriggered?.toolName,
            canary_tool_triggered: Boolean(canaryTriggered?.triggered),
            parallax_evaluated: Boolean(parallaxDecision?.evaluated),
            parallax_veto: Boolean(parallaxDecision?.veto),
            parallax_risk: parallaxDecision?.risk,
            parallax_secondary_provider: parallaxDecision?.secondaryProvider,
            parallax_high_risk_tools: parallaxDecision?.highRiskTools,
            cognitive_rollback_suggested: Boolean(cognitiveRollbackDecision?.applicable),
            cognitive_rollback_mode: cognitiveRollbackDecision?.mode,
            cognitive_rollback_trigger: cognitiveRollbackDecision?.trigger,
            cognitive_rollback_dropped_messages: cognitiveRollbackDecision?.droppedMessages,
            omni_shield_detected: Boolean(omniShieldDecision?.detected),
            omni_shield_findings: omniShieldDecision?.findings,
            intent_drift_evaluated: Boolean(intentDriftDecision?.evaluated),
            intent_drift_reason: intentDriftDecision?.reason,
            intent_drift_drifted: Boolean(intentDriftDecision?.drifted),
            intent_drift_distance: intentDriftDecision?.distance,
            intent_drift_threshold: intentDriftDecision?.threshold,
            intent_drift_turn_count: intentDriftDecision?.turnCount,
            sandbox_detected: Boolean(sandboxDecision?.detected),
            sandbox_findings: sandboxDecision?.findings,
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
            if ((streamTerminatedForPII || streamTerminatedForEntropy) && String(error.message || '') === 'EGRESS_STREAM_BLOCKED') {
              this.auditLogger.write({
                timestamp: new Date().toISOString(),
                correlation_id: correlationId,
                config_version: this.config.version,
                mode: effectiveMode,
                decision: 'blocked_egress_stream',
                reasons: [streamTerminatedForEntropy ? 'egress_entropy_stream_blocked' : 'egress_stream_blocked'],
                pii_types: piiTypes,
                egress_pii_types: Array.from(streamEgressTypes).sort(),
                egress_projected_redaction: streamProjectedRedaction || undefined,
                egress_block_severity: streamBlockedSeverity || undefined,
                egress_entropy_findings: streamEntropyFindings,
                egress_entropy_mode: streamEntropyMode || undefined,
                egress_entropy_projected_redaction: streamEntropyProjectedRedaction || undefined,
                pii_vault_detokenized: streamVaultReplacements,
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
                honeytoken_applied: Boolean(honeytokenDecision),
                honeytoken_mode: honeytokenDecision?.mode,
                honeytoken_token_hash: honeytokenDecision?.token_hash,
                canary_tool_injected: Boolean(canaryToolDecision),
                canary_tool_name: canaryToolDecision?.tool_name || canaryTriggered?.toolName,
                canary_tool_triggered: Boolean(canaryTriggered?.triggered),
                parallax_evaluated: Boolean(parallaxDecision?.evaluated),
                parallax_veto: Boolean(parallaxDecision?.veto),
                parallax_risk: parallaxDecision?.risk,
                parallax_secondary_provider: parallaxDecision?.secondaryProvider,
                parallax_high_risk_tools: parallaxDecision?.highRiskTools,
                cognitive_rollback_suggested: Boolean(cognitiveRollbackDecision?.applicable),
                cognitive_rollback_mode: cognitiveRollbackDecision?.mode,
                cognitive_rollback_trigger: cognitiveRollbackDecision?.trigger,
                cognitive_rollback_dropped_messages: cognitiveRollbackDecision?.droppedMessages,
                omni_shield_detected: Boolean(omniShieldDecision?.detected),
                omni_shield_findings: omniShieldDecision?.findings,
                intent_drift_evaluated: Boolean(intentDriftDecision?.evaluated),
                intent_drift_reason: intentDriftDecision?.reason,
                intent_drift_drifted: Boolean(intentDriftDecision?.drifted),
                intent_drift_distance: intentDriftDecision?.distance,
                intent_drift_threshold: intentDriftDecision?.threshold,
                intent_drift_turn_count: intentDriftDecision?.turnCount,
                sandbox_detected: Boolean(sandboxDecision?.detected),
                sandbox_findings: sandboxDecision?.findings,
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
              pii_vault_detokenized: streamVaultReplacements,
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
              honeytoken_applied: Boolean(honeytokenDecision),
              honeytoken_mode: honeytokenDecision?.mode,
              honeytoken_token_hash: honeytokenDecision?.token_hash,
              canary_tool_injected: Boolean(canaryToolDecision),
              canary_tool_name: canaryToolDecision?.tool_name || canaryTriggered?.toolName,
              canary_tool_triggered: Boolean(canaryTriggered?.triggered),
              parallax_evaluated: Boolean(parallaxDecision?.evaluated),
              parallax_veto: Boolean(parallaxDecision?.veto),
              parallax_risk: parallaxDecision?.risk,
              parallax_secondary_provider: parallaxDecision?.secondaryProvider,
              parallax_high_risk_tools: parallaxDecision?.highRiskTools,
              cognitive_rollback_suggested: Boolean(cognitiveRollbackDecision?.applicable),
              cognitive_rollback_mode: cognitiveRollbackDecision?.mode,
              cognitive_rollback_trigger: cognitiveRollbackDecision?.trigger,
              cognitive_rollback_dropped_messages: cognitiveRollbackDecision?.droppedMessages,
              omni_shield_detected: Boolean(omniShieldDecision?.detected),
              omni_shield_findings: omniShieldDecision?.findings,
              intent_drift_evaluated: Boolean(intentDriftDecision?.evaluated),
              intent_drift_reason: intentDriftDecision?.reason,
              intent_drift_drifted: Boolean(intentDriftDecision?.drifted),
              intent_drift_distance: intentDriftDecision?.distance,
              intent_drift_threshold: intentDriftDecision?.threshold,
              intent_drift_turn_count: intentDriftDecision?.turnCount,
              sandbox_detected: Boolean(sandboxDecision?.detected),
              sandbox_findings: sandboxDecision?.findings,
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
          entropyConfig: egressConfig.entropy,
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
            await this.maybeNormalizeBlockedLatency({
              res,
              statusCode: 403,
              requestStart,
            });
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

        if (egressResult.entropy?.detected) {
          this.stats.egress_entropy_detected += 1;
          warnings.push(`egress_entropy:${egressResult.entropy.action}`);
          const entropyFindings = Array.isArray(egressResult.entropy.findings)
            ? egressResult.entropy.findings
            : [];
          res.setHeader('x-sentinel-egress-entropy', egressResult.entropy.action || 'monitor');
          res.setHeader('x-sentinel-egress-entropy-findings', String(entropyFindings.length));
          if (egressResult.entropy.truncated) {
            warnings.push('egress_entropy_scan_truncated');
            this.stats.warnings_total += 1;
          }
          if (egressResult.entropy.blocked) {
            this.stats.blocked_total += 1;
            this.stats.egress_entropy_blocked += 1;
            const diagnostics = {
              errorSource: 'sentinel',
              upstreamError: false,
              provider: routedProvider,
              retryCount: upstream.diagnostics.retryCount || 0,
              circuitState: this.circuitBreakers.getProviderState(routedBreakerKey).state,
              correlationId,
            };
            responseHeaderDiagnostics(res, diagnostics);
            await this.maybeNormalizeBlockedLatency({
              res,
              statusCode: 403,
              requestStart,
            });
            this.auditLogger.write({
              timestamp: new Date().toISOString(),
              correlation_id: correlationId,
              config_version: this.config.version,
              mode: effectiveMode,
              decision: 'blocked_egress_entropy',
              reasons: ['egress_entropy_detected'],
              pii_types: piiTypes,
              egress_entropy_findings: entropyFindings,
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
              error: 'EGRESS_ENTROPY_DETECTED',
              reason: 'egress_entropy_detected',
              findings: entropyFindings.map((item) => ({
                kind: item.kind,
                entropy: item.entropy,
                token_hash: item.token_hash,
                length: item.length,
              })),
              correlation_id: correlationId,
            });
          }
        }
      }

      canaryTriggered = null;
      if (this.canaryToolTrap.isEnabled()) {
        canaryTriggered = this.canaryToolTrap.detectTriggered(
          outboundBody,
          upstream.responseHeaders?.['content-type']
        );
        if (canaryTriggered.triggered) {
          this.stats.canary_tool_triggered += 1;
          warnings.push('canary_tool_triggered');
          this.stats.warnings_total += 1;
          res.setHeader('x-sentinel-canary-tool-triggered', 'true');
          res.setHeader('x-sentinel-canary-tool-name', canaryTriggered.toolName);

          const rollbackCandidate = this.cognitiveRollback.suggest({
            bodyJson: parallaxInputBodyJson || bodyJson,
            trigger: 'canary_tool_triggered',
          });
          if (rollbackCandidate.applicable) {
            cognitiveRollbackDecision = rollbackCandidate;
            this.stats.cognitive_rollback_suggested += 1;
            warnings.push('cognitive_rollback_suggested');
            this.stats.warnings_total += 1;
            if (this.cognitiveRollback.observability) {
              res.setHeader(
                'x-sentinel-cognitive-rollback',
                this.cognitiveRollback.shouldAuto() ? 'auto' : 'suggested'
              );
              res.setHeader('x-sentinel-cognitive-rollback-trigger', 'canary_tool_triggered');
              res.setHeader(
                'x-sentinel-cognitive-rollback-dropped',
                String(rollbackCandidate.droppedMessages || 0)
              );
            }
          }

          if (effectiveMode === 'enforce' && this.canaryToolTrap.mode === 'block') {
            if (rollbackCandidate.applicable && this.cognitiveRollback.shouldAuto()) {
              this.stats.cognitive_rollback_auto += 1;
              const diagnostics = {
                errorSource: 'sentinel',
                upstreamError: false,
                provider: routedProvider,
                retryCount: upstream.diagnostics.retryCount || 0,
                circuitState: this.circuitBreakers.getProviderState(routedBreakerKey).state,
                correlationId,
              };
              responseHeaderDiagnostics(res, diagnostics);
              this.auditLogger.write({
                timestamp: new Date().toISOString(),
                correlation_id: correlationId,
                config_version: this.config.version,
                mode: effectiveMode,
                decision: 'cognitive_rollback_required',
                reasons: ['canary_tool_triggered'],
                pii_types: piiTypes,
                redactions: redactedCount,
                duration_ms: durationMs,
                request_bytes: bodyBuffer.length,
                response_status: 409,
                response_bytes: 0,
                provider: routedProvider,
                upstream_target: routedTarget,
                canary_tool_name: canaryTriggered.toolName,
                cognitive_rollback_trigger: 'canary_tool_triggered',
                cognitive_rollback_dropped_messages: rollbackCandidate.droppedMessages,
                route_source: routePlan.routeSource,
                route_group: routePlan.selectedGroup || undefined,
                route_contract: routePlan.desiredContract,
                requested_target: routePlan.requestedTarget,
              });
              this.writeStatus();
              finalizeRequestTelemetry({
                decision: 'blocked_policy',
                status: 409,
                providerName: routedProvider,
              });
              return res.status(409).json({
                error: 'COGNITIVE_ROLLBACK_REQUIRED',
                reason: 'canary_tool_triggered',
                rollback: {
                  mode: this.cognitiveRollback.mode,
                  trigger: 'canary_tool_triggered',
                  dropped_messages: rollbackCandidate.droppedMessages,
                  messages: rollbackCandidate.bodyJson.messages,
                },
                correlation_id: correlationId,
              });
            }

            this.stats.blocked_total += 1;
            const diagnostics = {
              errorSource: 'sentinel',
              upstreamError: false,
              provider: routedProvider,
              retryCount: upstream.diagnostics.retryCount || 0,
              circuitState: this.circuitBreakers.getProviderState(routedBreakerKey).state,
              correlationId,
            };
            responseHeaderDiagnostics(res, diagnostics);
            await this.maybeNormalizeBlockedLatency({
              res,
              statusCode: 403,
              requestStart,
            });
            this.auditLogger.write({
              timestamp: new Date().toISOString(),
              correlation_id: correlationId,
              config_version: this.config.version,
              mode: effectiveMode,
              decision: 'blocked_canary_tool',
              reasons: ['canary_tool_triggered'],
              pii_types: piiTypes,
              redactions: redactedCount,
              duration_ms: durationMs,
              request_bytes: bodyBuffer.length,
              response_status: 403,
              response_bytes: 0,
              provider: routedProvider,
              upstream_target: routedTarget,
              canary_tool_name: canaryTriggered.toolName,
              route_source: routePlan.routeSource,
              route_group: routePlan.selectedGroup || undefined,
              route_contract: routePlan.desiredContract,
              requested_target: routePlan.requestedTarget,
            });
            this.writeStatus();
            finalizeRequestTelemetry({
              decision: 'blocked_policy',
              status: 403,
              providerName: routedProvider,
            });
            return res.status(403).json({
              error: 'CANARY_TOOL_TRIGGERED',
              reason: 'canary_tool_triggered',
              tool_name: canaryTriggered.toolName,
              correlation_id: correlationId,
            });
          }
        }
      }

      parallaxDecision = null;
      if (this.parallaxValidator.isEnabled()) {
        parallaxDecision = await this.parallaxValidator.evaluate({
          req,
          correlationId,
          requestBodyJson: parallaxInputBodyJson || bodyJson,
          responseBody: outboundBody,
          responseContentType: upstream.responseHeaders?.['content-type'],
        });
        if (parallaxDecision.evaluated) {
          this.stats.parallax_evaluated += 1;
        }
        if (parallaxDecision.error) {
          warnings.push(`parallax_error:${parallaxDecision.error}`);
          this.stats.warnings_total += 1;
        } else if (parallaxDecision.evaluated && parallaxDecision.veto) {
          this.stats.parallax_vetoed += 1;
          warnings.push('parallax_veto');
          this.stats.warnings_total += 1;
          res.setHeader('x-sentinel-parallax', 'veto');
          res.setHeader('x-sentinel-parallax-risk', String(parallaxDecision.risk));
          res.setHeader('x-sentinel-parallax-provider', String(parallaxDecision.secondaryProvider || 'unknown'));

          const rollbackCandidate = this.cognitiveRollback.suggest({
            bodyJson: parallaxInputBodyJson || bodyJson,
            trigger: 'parallax_veto',
          });
          if (rollbackCandidate.applicable) {
            cognitiveRollbackDecision = rollbackCandidate;
            this.stats.cognitive_rollback_suggested += 1;
            warnings.push('cognitive_rollback_suggested');
            this.stats.warnings_total += 1;
            if (this.cognitiveRollback.observability) {
              res.setHeader(
                'x-sentinel-cognitive-rollback',
                this.cognitiveRollback.shouldAuto() ? 'auto' : 'suggested'
              );
              res.setHeader('x-sentinel-cognitive-rollback-trigger', 'parallax_veto');
              res.setHeader(
                'x-sentinel-cognitive-rollback-dropped',
                String(rollbackCandidate.droppedMessages || 0)
              );
            }
          }

          if (effectiveMode === 'enforce' && this.parallaxValidator.mode === 'block') {
            if (rollbackCandidate.applicable && this.cognitiveRollback.shouldAuto()) {
              this.stats.cognitive_rollback_auto += 1;
              const diagnostics = {
                errorSource: 'sentinel',
                upstreamError: false,
                provider: routedProvider,
                retryCount: upstream.diagnostics.retryCount || 0,
                circuitState: this.circuitBreakers.getProviderState(routedBreakerKey).state,
                correlationId,
              };
              responseHeaderDiagnostics(res, diagnostics);
              this.auditLogger.write({
                timestamp: new Date().toISOString(),
                correlation_id: correlationId,
                config_version: this.config.version,
                mode: effectiveMode,
                decision: 'cognitive_rollback_required',
                reasons: ['parallax_veto'],
                pii_types: piiTypes,
                redactions: redactedCount,
                duration_ms: durationMs,
                request_bytes: bodyBuffer.length,
                response_status: 409,
                response_bytes: 0,
                provider: routedProvider,
                upstream_target: routedTarget,
                parallax_risk: parallaxDecision.risk,
                parallax_reason: parallaxDecision.reason,
                parallax_secondary_provider: parallaxDecision.secondaryProvider,
                parallax_high_risk_tools: parallaxDecision.highRiskTools,
                cognitive_rollback_trigger: 'parallax_veto',
                cognitive_rollback_dropped_messages: rollbackCandidate.droppedMessages,
                route_source: routePlan.routeSource,
                route_group: routePlan.selectedGroup || undefined,
                route_contract: routePlan.desiredContract,
                requested_target: routePlan.requestedTarget,
              });
              this.writeStatus();
              finalizeRequestTelemetry({
                decision: 'blocked_policy',
                status: 409,
                providerName: routedProvider,
              });
              return res.status(409).json({
                error: 'COGNITIVE_ROLLBACK_REQUIRED',
                reason: 'parallax_veto',
                rollback: {
                  mode: this.cognitiveRollback.mode,
                  trigger: 'parallax_veto',
                  dropped_messages: rollbackCandidate.droppedMessages,
                  messages: rollbackCandidate.bodyJson.messages,
                },
                correlation_id: correlationId,
              });
            }

            this.stats.blocked_total += 1;
            const diagnostics = {
              errorSource: 'sentinel',
              upstreamError: false,
              provider: routedProvider,
              retryCount: upstream.diagnostics.retryCount || 0,
              circuitState: this.circuitBreakers.getProviderState(routedBreakerKey).state,
              correlationId,
            };
            responseHeaderDiagnostics(res, diagnostics);
            await this.maybeNormalizeBlockedLatency({
              res,
              statusCode: 403,
              requestStart,
            });
            this.auditLogger.write({
              timestamp: new Date().toISOString(),
              correlation_id: correlationId,
              config_version: this.config.version,
              mode: effectiveMode,
              decision: 'blocked_parallax',
              reasons: ['parallax_veto'],
              pii_types: piiTypes,
              redactions: redactedCount,
              duration_ms: durationMs,
              request_bytes: bodyBuffer.length,
              response_status: 403,
              response_bytes: 0,
              provider: routedProvider,
              upstream_target: routedTarget,
              parallax_risk: parallaxDecision.risk,
              parallax_reason: parallaxDecision.reason,
              parallax_secondary_provider: parallaxDecision.secondaryProvider,
              parallax_high_risk_tools: parallaxDecision.highRiskTools,
              route_source: routePlan.routeSource,
              route_group: routePlan.selectedGroup || undefined,
              route_contract: routePlan.desiredContract,
              requested_target: routePlan.requestedTarget,
            });
            this.writeStatus();
            finalizeRequestTelemetry({
              decision: 'blocked_policy',
              status: 403,
              providerName: routedProvider,
            });
            return res.status(403).json({
              error: 'PARALLAX_VETO',
              reason: 'parallax_veto',
              risk: parallaxDecision.risk,
              secondary_provider: parallaxDecision.secondaryProvider,
              high_risk_tools: parallaxDecision.highRiskTools,
              correlation_id: correlationId,
            });
          }
        } else if (parallaxDecision.evaluated) {
          res.setHeader('x-sentinel-parallax', 'allow');
          if (Number.isFinite(Number(parallaxDecision.risk))) {
            res.setHeader('x-sentinel-parallax-risk', String(parallaxDecision.risk));
          }
          if (parallaxDecision.secondaryProvider) {
            res.setHeader('x-sentinel-parallax-provider', String(parallaxDecision.secondaryProvider));
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

      let responseBodyForClient = outboundBody;
      const vaultEgress = this.piiVault.applyEgressBuffer({
        bodyBuffer: outboundBody,
        contentType: upstream.responseHeaders?.['content-type'],
        sessionKey: piiVaultSessionKey,
      });
      if (vaultEgress.changed) {
        responseBodyForClient = vaultEgress.bodyBuffer;
        this.stats.pii_vault_detokenized += Number(vaultEgress.replacements || 0);
        warnings.push(`pii_vault:detokenized:${vaultEgress.replacements || 0}`);
        this.stats.warnings_total += 1;
        if (this.piiVault.observability) {
          res.setHeader('x-sentinel-pii-vault-egress', 'detokenize');
          res.setHeader('x-sentinel-pii-vault-egress-replacements', String(vaultEgress.replacements || 0));
        }
      }

      let budgetCharge = null;
      try {
        budgetCharge = await this.budgetStore.recordBuffered({
          provider: routedProvider,
          requestBodyBuffer: bodyBuffer,
          responseBodyBuffer: responseBodyForClient,
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
        response_bytes: responseBodyForClient.length,
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
        honeytoken_applied: Boolean(honeytokenDecision),
        honeytoken_mode: honeytokenDecision?.mode,
        honeytoken_token_hash: honeytokenDecision?.token_hash,
        canary_tool_injected: Boolean(canaryToolDecision),
        canary_tool_name: canaryToolDecision?.tool_name || canaryTriggered?.toolName,
        canary_tool_triggered: Boolean(canaryTriggered?.triggered),
        parallax_evaluated: Boolean(parallaxDecision?.evaluated),
        parallax_veto: Boolean(parallaxDecision?.veto),
        parallax_risk: parallaxDecision?.risk,
        parallax_secondary_provider: parallaxDecision?.secondaryProvider,
        parallax_high_risk_tools: parallaxDecision?.highRiskTools,
        cognitive_rollback_suggested: Boolean(cognitiveRollbackDecision?.applicable),
        cognitive_rollback_mode: cognitiveRollbackDecision?.mode,
        cognitive_rollback_trigger: cognitiveRollbackDecision?.trigger,
        cognitive_rollback_dropped_messages: cognitiveRollbackDecision?.droppedMessages,
        omni_shield_detected: Boolean(omniShieldDecision?.detected),
        omni_shield_findings: omniShieldDecision?.findings,
        intent_drift_evaluated: Boolean(intentDriftDecision?.evaluated),
        intent_drift_reason: intentDriftDecision?.reason,
        intent_drift_drifted: Boolean(intentDriftDecision?.drifted),
        intent_drift_distance: intentDriftDecision?.distance,
        intent_drift_threshold: intentDriftDecision?.threshold,
        intent_drift_turn_count: intentDriftDecision?.turnCount,
        sandbox_detected: Boolean(sandboxDecision?.detected),
        sandbox_findings: sandboxDecision?.findings,
        pii_vault_detokenized: vaultEgress.replacements || 0,
      });

      if (upstream.status < 400) {
        this.latencyNormalizer.recordSuccess(Date.now() - requestStart);
      }
      this.writeStatus();
      finalizeRequestTelemetry({
        decision: 'forwarded',
        status: upstream.status,
        providerName: routedProvider,
      });
      res.status(upstream.status).send(responseBodyForClient);
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
