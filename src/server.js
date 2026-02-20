const fs = require('fs');
const express = require('express');

const logger = require('./utils/logger');
const { PIIScanner } = require('./engines/pii-scanner');
const { PolicyEngine } = require('./engines/policy-engine');
const { InMemoryRateLimiter } = require('./engines/rate-limiter');
const { NeuralInjectionClassifier } = require('./engines/neural-injection-classifier');
const { UpstreamClient } = require('./upstream/client');
const { RuntimeOverrideManager } = require('./runtime/override');
const { CircuitBreakerManager } = require('./resilience/circuit-breaker');
const { AuditLogger } = require('./logging/audit-logger');
const { StatusStore } = require('./status/store');
const { loadOptimizerPlugin } = require('./optimizer/loader');
const { createTelemetry } = require('./telemetry');
const { PrometheusExporter } = require('./telemetry/prometheus');
const { MiddlewarePipeline } = require('./core/middleware-pipeline');
const { PluginRegistry } = require('./core/plugin-registry');
const { PIIProviderEngine } = require('./pii/provider-engine');
const { TwoWayPIIVault } = require('./pii/two-way-vault');
const { ScanWorkerPool } = require('./workers/scan-pool');
const { VCRStore } = require('./runtime/vcr-store');
const { SemanticCache } = require('./cache/semantic-cache');
const { BudgetStore } = require('./accounting/budget-store');
const { DashboardServer } = require('./monitor/dashboard-server');
const { LoopBreaker } = require('./engines/loop-breaker');
const { AutoImmune } = require('./engines/auto-immune');
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
const { ShadowOS } = require('./sandbox/shadow-os');
const { EpistemicAnchor } = require('./runtime/epistemic-anchor');
const {
  initRequestEnvelope,
  attachProvenanceInterceptors,
  createTelemetryFinalizer,
} = require('./stages/ingress-stage');
const { resolveRouting, applyUpstreamOutcomeHeaders } = require('./stages/routing-stage');
const {
  rejectUnsupportedMethod,
  runPipelineOrRespond,
  parseJsonBodyOrRespond,
  mergePipelineWarnings,
} = require('./stages/policy-stage');
const { runAutoImmuneStage } = require('./stages/policy/auto-immune-stage');
const { runSwarmStage } = require('./stages/policy/swarm-stage');
const { runOmniShieldStage } = require('./stages/policy/omni-shield-stage');
const { runLoopStage } = require('./stages/policy/loop-stage');
const { runIntentStage } = require('./stages/policy/intent-stage');
const { runSandboxStage } = require('./stages/policy/sandbox-stage');
const {
  runInjectionAndPolicyStage,
  runPiiStage,
} = require('./stages/policy/pii-injection-stage');
const {
  applyForwardingHeaders,
  applyUpstreamResponseHeaders,
  handleUpstreamErrorResponse,
} = require('./stages/egress-stage');
const { runStreamEgressStage } = require('./stages/egress/stream-egress-stage');
const { runBufferedEgressAndFinalizeStage } = require('./stages/egress/buffered-egress-stage');
const { writeAuditAndStatus } = require('./stages/audit-stage');
const {
  responseHeaderDiagnostics,
  formatBudgetUsd,
  setBudgetHeaders,
  scrubForwardHeaders,
  positiveIntOr,
  sleep,
} = require('./stages/shared');
const {
  PID_FILE_PATH,
  STATUS_FILE_PATH,
  OVERRIDE_FILE_PATH,
  AUDIT_LOG_PATH,
  ensureSentinelHome,
} = require('./utils/paths');

class SentinelServer {
  constructor(config, options = {}) {
    ensureSentinelHome();

    this.config = config;
    this.options = options;
    this.app = express();
    this.pipeline = new MiddlewarePipeline({ logger });
    this.pluginRegistry = new PluginRegistry({
      logger,
      pipeline: this.pipeline,
    });
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
      shadow_os_evaluated: 0,
      shadow_os_detected: 0,
      shadow_os_blocked: 0,
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
      auto_immune_matches: 0,
      auto_immune_blocked: 0,
      auto_immune_learned: 0,
      intent_throttle_matches: 0,
      intent_throttle_blocked: 0,
      intent_throttle_errors: 0,
      intent_drift_evaluated: 0,
      intent_drift_detected: 0,
      intent_drift_blocked: 0,
      intent_drift_errors: 0,
      epistemic_anchor_evaluated: 0,
      epistemic_anchor_detected: 0,
      epistemic_anchor_blocked: 0,
      epistemic_anchor_errors: 0,
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

    this.rateLimiter = new InMemoryRateLimiter(config.runtime?.rate_limiter || {});
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
    this.prometheus = new PrometheusExporter({
      version: '1.0.0',
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
    this.autoImmune = new AutoImmune(this.config.runtime?.auto_immune || {});
    this.deceptionEngine = new DeceptionEngine(this.config.runtime?.deception || {});
    this.provenanceSigner = new ProvenanceSigner(this.config.runtime?.provenance || {});
    this.honeytokenInjector = new HoneytokenInjector(this.config.runtime?.honeytoken || {});
    this.polymorphicPrompt = new PolymorphicPromptEngine(this.config.runtime?.polymorphic_prompt || {});
    this.syntheticPoisoner = new SyntheticPoisoner(this.config.runtime?.synthetic_poisoning || {});
    this.cognitiveRollback = new CognitiveRollback(this.config.runtime?.cognitive_rollback || {});
    this.latencyNormalizer = new LatencyNormalizer(this.config.runtime?.latency_normalization || {});
    const embedText = this.createEmbeddingDelegate();
    this.intentThrottle = new IntentThrottle(this.config.runtime?.intent_throttle || {}, {
      embedText,
    });
    this.intentDrift = new IntentDriftDetector(this.config.runtime?.intent_drift || {}, {
      embedText,
    });
    this.canaryToolTrap = new CanaryToolTrap(this.config.runtime?.canary_tools || {});
    this.parallaxValidator = new ParallaxValidator(this.config.runtime?.parallax || {}, {
      upstreamClient: this.upstreamClient,
      config: this.config,
    });
    this.omniShield = new OmniShield(this.config.runtime?.omni_shield || {});
    this.experimentalSandbox = new ExperimentalSandbox(this.config.runtime?.sandbox_experimental || {});
    this.shadowOS = new ShadowOS(this.config.runtime?.shadow_os || {});
    this.epistemicAnchor = new EpistemicAnchor(this.config.runtime?.epistemic_anchor || {}, {
      embedText,
    });
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
    if (this.config.runtime?.epistemic_anchor?.enabled === true && this.scanWorkerPool?.enabled !== true) {
      logger.warn('Epistemic anchor is enabled but worker pool is unavailable; anchor checks will remain in monitor-only fallback', {
        epistemic_anchor_enabled: true,
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
    this.lastStatusWriteError = null;
    this.optimizerPlugin = loadOptimizerPlugin();
    this.dashboardServer = null;
    this.pluginRegistry.registerAll(this.options.plugins || []);
    if (this.options.plugin) {
      this.pluginRegistry.register(this.options.plugin);
    }

    this.setupApp();
  }

  createEmbeddingDelegate() {
    return async (text, options = {}) => {
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
    };
  }

  use(plugin) {
    this.pluginRegistry.register(plugin);
    return this;
  }

  async executePipelineStage(stage, context) {
    return this.pipeline.execute(stage, context);
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
      pii_vault_stats: this.piiVault.getStats ? this.piiVault.getStats() : undefined,
      loop_breaker_enabled: this.loopBreaker.enabled,
      auto_immune_enabled: this.autoImmune.isEnabled(),
      auto_immune_mode: this.autoImmune.mode,
      auto_immune_stats: this.autoImmune.getStats(),
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
      shadow_os_enabled: this.shadowOS.isEnabled(),
      shadow_os_mode: this.shadowOS.mode,
      shadow_os_stats: this.shadowOS.getStats(),
      epistemic_anchor_enabled: this.epistemicAnchor.isEnabled(),
      epistemic_anchor_mode: this.epistemicAnchor.mode,
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
      plugins_registered: this.pluginRegistry.list(),
      uptime_seconds: Math.floor((Date.now() - this.startedAt) / 1000),
      version: this.config.version,
      counters: this.stats,
      pid: process.pid,
    };
  }

  writeStatus() {
    try {
      this.statusStore.write(this.currentStatusPayload());
      this.lastStatusWriteError = null;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (this.lastStatusWriteError !== message) {
        logger.warn('Sentinel status persistence unavailable; continuing without status file updates', {
          status_file: STATUS_FILE_PATH,
          error: message,
        });
        this.lastStatusWriteError = message;
      }
    }
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

      writeAuditAndStatus(this, {
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

    this.app.get('/_sentinel/metrics', (req, res) => {
      const payload = this.prometheus.renderMetrics({
        counters: this.stats,
        providers: this.circuitBreakers.snapshot(),
      });
      res.setHeader('content-type', 'text/plain; version=0.0.4; charset=utf-8');
      res.status(200).send(payload);
    });

    this.app.all('*', async (req, res) => {
      const providerRef = { value: 'unknown' };
      const {
        correlationId,
        piiVaultSessionKey,
        method,
        rawBody,
        parsedPath,
        requestStart,
        pipelineContext,
      } = initRequestEnvelope({ server: this, req, res });
      let bodyText = pipelineContext.get('body_text', '');
      attachProvenanceInterceptors({
        server: this,
        res,
        correlationId,
        providerRef,
      });

      res.once('finish', () => {
        pipelineContext
          .set('response_status', res.statusCode)
          .set('response_headers', typeof res.getHeaders === 'function' ? res.getHeaders() : {});
        this.executePipelineStage('response:finished', pipelineContext).catch((error) => {
          logger.warn('response:finished pipeline stage failed', {
            correlation_id: correlationId,
            error: error.message,
          });
        });
      });
      const requestSpan = this.telemetry.startSpan('sentinel.request', {
        method,
        route: parsedPath.pathname,
        correlation_id: correlationId,
      });
      const finalizeRequestTelemetry = createTelemetryFinalizer({
        server: this,
        requestStart,
        requestSpan,
      });

      if (rejectUnsupportedMethod({ method, res, correlationId, finalizeRequestTelemetry })) {
        return;
      }

      this.stats.requests_total += 1;
      this.telemetry.addRequest({
        method,
        route: parsedPath.pathname,
      });
      if (await runPipelineOrRespond({
        server: this,
        stageName: 'request:received',
        pipelineContext,
        res,
        provider: 'unknown',
        finalizeRequestTelemetry,
      })) {
        return;
      }

      let routePlan;
      let provider;
      let baseUrl;
      let breakerKey = null;
      let cacheProviderKey = null;
      const routingResult = await resolveRouting({
        server: this,
        req,
        res,
        correlationId,
        finalizeRequestTelemetry,
      });
      if (routingResult.handled) {
        return;
      }
      routePlan = routingResult.routing.routePlan;
      provider = routingResult.routing.provider;
      providerRef.value = provider;
      baseUrl = routingResult.routing.baseUrl;
      breakerKey = routingResult.routing.breakerKey;
      cacheProviderKey = routingResult.routing.cacheProviderKey;

      const parsedBodyResult = parseJsonBodyOrRespond({
        bodyText,
        req,
        provider,
        breakerKey,
        correlationId,
        server: this,
        res,
        finalizeRequestTelemetry,
      });
      if (parsedBodyResult.handled) {
        return;
      }
      let bodyJson = parsedBodyResult.bodyJson;
      pipelineContext
        .set('provider', provider)
        .set('route_plan', routePlan)
        .set('body_json', bodyJson)
        .set('body_text', bodyText);
      if (await runPipelineOrRespond({
        server: this,
        stageName: 'request:prepared',
        pipelineContext,
        res,
        provider,
        finalizeRequestTelemetry,
      })) {
        return;
      }
      bodyJson = pipelineContext.get('body_json', bodyJson);
      bodyText = pipelineContext.get('body_text', bodyText);
      const wantsStream =
        String(req.headers.accept || '').toLowerCase().includes('text/event-stream') ||
        (bodyJson && bodyJson.stream === true);
      const warnings = [];
      const effectiveMode = this.computeEffectiveMode();
      const pathWithQuery = `${parsedPath.pathname}${parsedPath.search}`;
      let precomputedLocalScan = null;
      let precomputedInjection = null;
      let omniShieldDecision = null;
      let sandboxDecision = null;
      const runOrchestratedStage = async (stageName, execute, stageProvider = provider) => {
        pipelineContext.set('stage_name', stageName);
        if (await runPipelineOrRespond({
          server: this,
          stageName: `stage:${stageName}:before`,
          pipelineContext,
          res,
          provider: stageProvider || 'unknown',
          finalizeRequestTelemetry,
        })) {
          return {
            handled: true,
            result: null,
          };
        }

        const result = await execute();
        pipelineContext.set(`stage:${stageName}:result`, result);

        if (await runPipelineOrRespond({
          server: this,
          stageName: `stage:${stageName}:after`,
          pipelineContext,
          res,
          provider: stageProvider || 'unknown',
          finalizeRequestTelemetry,
        })) {
          return {
            handled: true,
            result,
          };
        }
        return {
          handled: false,
          result,
        };
      };

      const autoImmuneExecution = await runOrchestratedStage('auto_immune', async () =>
        runAutoImmuneStage({
          server: this,
          res,
          bodyText,
          effectiveMode,
          provider,
          breakerKey,
          correlationId,
          requestStart,
          rawBody,
          warnings,
          finalizeRequestTelemetry,
        })
      );
      if (autoImmuneExecution.handled) {
        return;
      }
      const autoImmuneResult = autoImmuneExecution.result;
      if (autoImmuneResult.handled) {
        return;
      }

      const swarmStageExecution = await runOrchestratedStage('swarm', async () =>
        runSwarmStage({
          server: this,
          req,
          res,
          method,
          pathWithQuery,
          rawBody,
          effectiveMode,
          provider,
          breakerKey,
          correlationId,
          requestStart,
          warnings,
          finalizeRequestTelemetry,
        })
      );
      if (swarmStageExecution.handled) {
        return;
      }
      const swarmStageResult = swarmStageExecution.result;
      if (swarmStageResult.handled) {
        return;
      }

      const omniShieldStageExecution = await runOrchestratedStage('omni_shield', async () =>
        runOmniShieldStage({
          server: this,
          res,
          bodyJson,
          bodyText,
          effectiveMode,
          provider,
          breakerKey,
          correlationId,
          requestStart,
          rawBody,
          warnings,
          finalizeRequestTelemetry,
        })
      );
      if (omniShieldStageExecution.handled) {
        return;
      }
      const omniShieldStageResult = omniShieldStageExecution.result;
      bodyJson = omniShieldStageResult.bodyJson;
      bodyText = omniShieldStageResult.bodyText;
      omniShieldDecision = omniShieldStageResult.omniShieldDecision;
      if (omniShieldStageResult.handled) {
        return;
      }

      const injectionPolicyExecution = await runOrchestratedStage('injection_policy', async () =>
        runInjectionAndPolicyStage({
          server: this,
          req,
          res,
          method,
          parsedPath,
          baseUrl,
          rawBody,
          bodyText,
          bodyJson,
          provider,
          breakerKey,
          correlationId,
          effectiveMode,
          requestStart,
          wantsStream,
          routePlan,
          warnings,
          finalizeRequestTelemetry,
          precomputedLocalScan,
          precomputedInjection,
        })
      );
      if (injectionPolicyExecution.handled) {
        return;
      }
      const injectionPolicyResult = injectionPolicyExecution.result;
      bodyText = injectionPolicyResult.bodyText;
      bodyJson = injectionPolicyResult.bodyJson;
      precomputedLocalScan = injectionPolicyResult.precomputedLocalScan;
      const injectionScore = Number(injectionPolicyResult.injectionScore || 0);
      if (injectionPolicyResult.handled) {
        return;
      }

      let redactedCount = 0;
      let piiTypes = [];
      let piiProviderUsed = 'local';
      const egressConfig = this.getEgressConfig();
      const loopStageExecution = await runOrchestratedStage('loop', async () =>
        runLoopStage({
          server: this,
          req,
          res,
          provider,
          method,
          parsedPath,
          bodyText,
          bodyJson,
          effectiveMode,
          wantsStream,
          injectionScore,
          correlationId,
          requestStart,
          rawBody,
          piiTypes,
          redactedCount,
          warnings,
          routePlan,
          breakerKey,
          finalizeRequestTelemetry,
        })
      );
      if (loopStageExecution.handled) {
        return;
      }
      const loopStageResult = loopStageExecution.result;
      if (loopStageResult.handled) {
        return;
      }

      let intentDriftDecision = null;
      const intentStageExecution = await runOrchestratedStage('intent', async () =>
        runIntentStage({
          server: this,
          req,
          res,
          bodyJson,
          bodyText,
          provider,
          breakerKey,
          effectiveMode,
          correlationId,
          requestStart,
          rawBody,
          warnings,
          finalizeRequestTelemetry,
        })
      );
      if (intentStageExecution.handled) {
        return;
      }
      const intentStageResult = intentStageExecution.result;
      bodyJson = intentStageResult.bodyJson;
      bodyText = intentStageResult.bodyText;
      intentDriftDecision = intentStageResult.intentDriftDecision;
      if (intentStageResult.handled) {
        return;
      }

      const sandboxStageExecution = await runOrchestratedStage('sandbox', async () =>
        runSandboxStage({
          server: this,
          res,
          bodyJson,
          effectiveMode,
          provider,
          breakerKey,
          correlationId,
          requestStart,
          rawBody,
          warnings,
          finalizeRequestTelemetry,
        })
      );
      if (sandboxStageExecution.handled) {
        return;
      }
      const sandboxStageResult = sandboxStageExecution.result;
      sandboxDecision = sandboxStageResult.sandboxDecision;
      if (sandboxStageResult.handled) {
        return;
      }

      const piiStageExecution = await runOrchestratedStage('pii', async () =>
        runPiiStage({
          server: this,
          req,
          res,
          bodyText,
          bodyJson,
          precomputedLocalScan,
          piiVaultSessionKey,
          provider,
          breakerKey,
          correlationId,
          effectiveMode,
          requestStart,
          rawBody,
          warnings,
          finalizeRequestTelemetry,
          piiTypes,
          redactedCount,
          piiProviderUsed,
        })
      );
      if (piiStageExecution.handled) {
        return;
      }
      const piiStageResult = piiStageExecution.result;
      bodyText = piiStageResult.bodyText;
      bodyJson = piiStageResult.bodyJson;
      piiTypes = piiStageResult.piiTypes;
      redactedCount = piiStageResult.redactedCount;
      piiProviderUsed = piiStageResult.piiProviderUsed;
      if (piiStageResult.handled) {
        return;
      }

      const optimizerStageExecution = await runOrchestratedStage('optimizer', async () => {
        let optimizedBodyJson = bodyJson;
        let optimizedBodyText = bodyText;
        if (req.headers['x-sentinel-optimize'] === 'true' && optimizedBodyJson && Array.isArray(optimizedBodyJson.messages)) {
          try {
            const result = this.optimizerPlugin.optimize(optimizedBodyJson.messages, {
              provider,
              profile: req.headers['x-sentinel-optimizer-profile'] || 'default',
            });
            if (result && result.improved && Array.isArray(result.messages)) {
              optimizedBodyJson.messages = result.messages;
              optimizedBodyText = JSON.stringify(optimizedBodyJson);
            }
          } catch (error) {
            logger.warn('Optimizer plugin failed', { error: error.message, correlationId });
            warnings.push('optimizer:plugin_error');
          }
        }
        return {
          bodyJson: optimizedBodyJson,
          bodyText: optimizedBodyText,
        };
      });
      if (optimizerStageExecution.handled) {
        return;
      }
      const optimizerStageResult = optimizerStageExecution.result;
      bodyJson = optimizerStageResult.bodyJson;
      bodyText = optimizerStageResult.bodyText;

      const polymorphStageExecution = await runOrchestratedStage('polymorphic_prompt', async () => {
        let polymorphDecision = null;
        let polymorphBodyJson = bodyJson;
        let polymorphBodyText = bodyText;
        if (this.polymorphicPrompt.isEnabled()) {
          polymorphDecision = this.polymorphicPrompt.mutate({
            bodyJson: polymorphBodyJson,
            headers: req.headers || {},
          });
          if (polymorphDecision.applied) {
            polymorphBodyJson = polymorphDecision.bodyJson;
            polymorphBodyText = polymorphDecision.bodyText;
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
        return {
          bodyJson: polymorphBodyJson,
          bodyText: polymorphBodyText,
          polymorphDecision,
        };
      });
      if (polymorphStageExecution.handled) {
        return;
      }
      const polymorphStageResult = polymorphStageExecution.result;
      bodyJson = polymorphStageResult.bodyJson;
      bodyText = polymorphStageResult.bodyText;

      const parallaxInputBodyJson =
        bodyJson && typeof bodyJson === 'object'
          ? JSON.parse(JSON.stringify(bodyJson))
          : null;

      const honeytokenStageExecution = await runOrchestratedStage('honeytoken_inject', async () => {
        let honeytokenDecision = null;
        let honeytokenBodyJson = bodyJson;
        let honeytokenBodyText = bodyText;
        if (this.honeytokenInjector.isEnabled()) {
          const injected = this.honeytokenInjector.inject({
            bodyJson: honeytokenBodyJson,
            bodyText: honeytokenBodyText,
            provider,
            path: parsedPath.pathname,
          });
          if (injected.applied) {
            honeytokenBodyJson = injected.bodyJson;
            honeytokenBodyText = injected.bodyText;
            honeytokenDecision = injected.meta;
            this.stats.honeytoken_injected += 1;
            res.setHeader('x-sentinel-honeytoken', 'injected');
            res.setHeader('x-sentinel-honeytoken-mode', injected.meta.mode);
            res.setHeader('x-sentinel-honeytoken-id', String(injected.meta.token_hash).slice(0, 16));
          }
        }
        return {
          bodyJson: honeytokenBodyJson,
          bodyText: honeytokenBodyText,
          honeytokenDecision,
        };
      });
      if (honeytokenStageExecution.handled) {
        return;
      }
      const honeytokenStageResult = honeytokenStageExecution.result;
      bodyJson = honeytokenStageResult.bodyJson;
      bodyText = honeytokenStageResult.bodyText;
      let honeytokenDecision = honeytokenStageResult.honeytokenDecision;

      const canaryInjectStageExecution = await runOrchestratedStage('canary_tool_inject', async () => {
        let canaryToolDecision = null;
        let canaryBodyJson = bodyJson;
        let canaryBodyText = bodyText;
        if (this.canaryToolTrap.isEnabled()) {
          const canaryInjected = this.canaryToolTrap.inject(canaryBodyJson, { provider });
          if (canaryInjected.applied) {
            canaryBodyJson = canaryInjected.bodyJson;
            canaryBodyText = canaryInjected.bodyText;
            canaryToolDecision = canaryInjected.meta;
            this.stats.canary_tool_injected += 1;
            res.setHeader('x-sentinel-canary-tool', 'injected');
            res.setHeader('x-sentinel-canary-tool-name', canaryInjected.meta.tool_name);
          }
        }
        return {
          bodyJson: canaryBodyJson,
          bodyText: canaryBodyText,
          canaryToolDecision,
        };
      });
      if (canaryInjectStageExecution.handled) {
        return;
      }
      const canaryInjectStageResult = canaryInjectStageExecution.result;
      bodyJson = canaryInjectStageResult.bodyJson;
      bodyText = canaryInjectStageResult.bodyText;
      let canaryToolDecision = canaryInjectStageResult.canaryToolDecision;
      let canaryTriggered = null;
      let parallaxDecision = null;
      let cognitiveRollbackDecision = null;

      const bodyBuffer = bodyJson ? Buffer.from(JSON.stringify(bodyJson)) : Buffer.from(bodyText || '', 'utf8');
      const forwardHeaders = scrubForwardHeaders(req.headers);
      pipelineContext
        .set('provider', provider)
        .set('body_json', bodyJson)
        .set('body_text', bodyText)
        .set('body_buffer', bodyBuffer)
        .set('forward_headers', forwardHeaders)
        .set('warnings', warnings);
      if (await runPipelineOrRespond({
        server: this,
        stageName: 'request:before_forward',
        pipelineContext,
        res,
        provider,
        finalizeRequestTelemetry,
      })) {
        return;
      }
      bodyJson = pipelineContext.get('body_json', bodyJson);
      bodyText = pipelineContext.get('body_text', bodyText);
      const effectiveBodyBuffer = pipelineContext.get('body_buffer', bodyBuffer);
      const effectiveForwardHeaders = pipelineContext.get('forward_headers', forwardHeaders);
      const pluginWarnings = pipelineContext.get('warnings', []);
      mergePipelineWarnings({ warnings, pluginWarnings, stats: this.stats });

      const budgetEstimateStageExecution = await runOrchestratedStage('budget_estimate', async () =>
        this.budgetStore.estimateRequest({
          provider,
          method,
          requestBodyBuffer: effectiveBodyBuffer,
        }),
      provider);
      if (budgetEstimateStageExecution.handled) {
        return;
      }
      const budgetEstimate = budgetEstimateStageExecution.result;
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
        bodyBuffer: effectiveBodyBuffer,
        contentType: req.headers['content-type'],
        wantsStream,
      };
      let vcrLookup;
      try {
        const vcrLookupStageExecution = await runOrchestratedStage('vcr_lookup', async () =>
          this.vcrStore.lookup(vcrRequestMeta),
        provider);
        if (vcrLookupStageExecution.handled) {
          return;
        }
        vcrLookup = vcrLookupStageExecution.result;
      } catch {
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
            const semanticLookupStageExecution = await runOrchestratedStage('semantic_cache_lookup', async () =>
              this.semanticCache.lookup({
                provider: cacheProviderKey,
                method,
                pathWithQuery,
                wantsStream,
                bodyJson,
                bodyText,
              }),
            provider);
            if (semanticLookupStageExecution.handled) {
              return;
            }
            const cacheLookup = semanticLookupStageExecution.result;
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
          } catch {
            warnings.push('semantic_cache_error');
            this.stats.warnings_total += 1;
          }
        }

        if (!replayedFromSemanticCache) {
          const upstreamForwardStageExecution = await runOrchestratedStage('upstream_forward', async () =>
            this.upstreamClient.forwardRequest({
              routePlan,
              req,
              pathWithQuery,
              method,
              bodyBuffer: effectiveBodyBuffer,
              bodyJson,
              correlationId,
              wantsStream,
              forwardHeaders: effectiveForwardHeaders,
            }),
          provider);
          if (upstreamForwardStageExecution.handled) {
            return;
          }
          upstream = upstreamForwardStageExecution.result;
        }
      }

      const durationMs = Date.now() - start;
      const diagnostics = upstream.diagnostics;
      const routedProvider = upstream.route?.selectedProvider || provider;
      providerRef.value = routedProvider;
      const routedTarget = upstream.route?.selectedTarget || routePlan.primary.targetName;
      const routedBreakerKey = upstream.route?.selectedBreakerKey || breakerKey;

      applyUpstreamOutcomeHeaders({
        server: this,
        res,
        upstream,
        routePlan,
        routedTarget,
      });
      applyForwardingHeaders({
        res,
        warnings,
        piiProviderUsed,
        semanticCacheHeader,
      });

      if (!upstream.ok) {
        return handleUpstreamErrorResponse({
          server: this,
          res,
          upstream,
          diagnostics,
          routedProvider,
          correlationId,
          finalizeRequestTelemetry,
          auditPayload: {
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
        },
        });
      }

      if (upstream.status >= 400) {
        responseHeaderDiagnostics(res, diagnostics);
      }

      applyUpstreamResponseHeaders(res, upstream.responseHeaders || {});

      const streamStageExecution = await runOrchestratedStage('stream_egress', async () =>
        runStreamEgressStage({
          server: this,
          res,
          upstream,
          egressConfig,
          effectiveMode,
          correlationId,
          routedProvider,
          piiVaultSessionKey,
          warnings,
          bodyBuffer,
          requestStart,
          start,
          replayedFromVcr,
          replayedFromSemanticCache,
          routePlan,
          honeytokenDecision,
          canaryToolDecision,
          canaryTriggered,
          parallaxDecision,
          cognitiveRollbackDecision,
          omniShieldDecision,
          intentDriftDecision,
          sandboxDecision,
          redactedCount,
          piiTypes,
          routedTarget,
          finalizeRequestTelemetry,
        }),
      routedProvider);
      if (streamStageExecution.handled) {
        return;
      }
      const streamStageResult = streamStageExecution.result;
      if (streamStageResult.handled) {
        return;
      }

      const bufferedEgressStageExecution = await runBufferedEgressAndFinalizeStage({
        server: this,
        req,
        res,
        upstream,
        egressConfig,
        effectiveMode,
        correlationId,
        routedProvider,
        routedTarget,
        routedBreakerKey,
        routePlan,
        warnings,
        bodyBuffer,
        requestStart,
        durationMs,
        runOrchestratedStage,
        replayedFromVcr,
        replayedFromSemanticCache,
        vcrRequestMeta,
        piiVaultSessionKey,
        parallaxInputBodyJson,
        bodyJson,
        method,
        pathWithQuery,
        wantsStream,
        bodyText,
        cacheProviderKey,
        injectionScore,
        piiTypes,
        redactedCount,
        honeytokenDecision,
        canaryToolDecision,
        canaryTriggered,
        parallaxDecision,
        cognitiveRollbackDecision,
        omniShieldDecision,
        intentDriftDecision,
        sandboxDecision,
        finalizeRequestTelemetry,
      });
      if (bufferedEgressStageExecution.handled) {
        return;
      }
    });
  }

  start() {
    const host = this.config.proxy.host;
    const port = this.options.portOverride ?? this.config.proxy.port;

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
