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
const { AgentObservability } = require('./telemetry/agent-observability');
const { MiddlewarePipeline } = require('./core/middleware-pipeline');
const { PluginRegistry } = require('./core/plugin-registry');
const { PIIProviderEngine } = require('./pii/provider-engine');
const { TwoWayPIIVault } = require('./pii/two-way-vault');
const { ScanWorkerPool } = require('./workers/scan-pool');
const { VCRStore } = require('./runtime/vcr-store');
const { SemanticCache } = require('./cache/semantic-cache');
const { BudgetStore } = require('./accounting/budget-store');
const { AIBOMGenerator } = require('./governance/aibom-generator');
const { computeSecurityPosture } = require('./governance/security-posture');
const { DashboardServer } = require('./monitor/dashboard-server');
const { handleWebSocketUpgrade } = require('./websocket/upgrade-handler');
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
const { PromptRebuffEngine } = require('./engines/prompt-rebuff');
const { ParallaxValidator } = require('./engines/parallax-validator');
const { OmniShield } = require('./engines/omni-shield');
const { ExperimentalSandbox } = require('./sandbox/experimental-sandbox');
const { ShadowOS } = require('./sandbox/shadow-os');
const { EpistemicAnchor } = require('./runtime/epistemic-anchor');
const { AgenticThreatShield } = require('./security/agentic-threat-shield');
const { A2ACardVerifier } = require('./security/a2a-card-verifier');
const { ConsensusProtocol } = require('./security/consensus-protocol');
const { CrossTenantIsolator } = require('./security/cross-tenant-isolator');
const { ColdStartAnalyzer } = require('./security/cold-start-analyzer');
const { BehavioralFingerprint } = require('./security/behavioral-fingerprint');
const { ThreatIntelMesh } = require('./security/threat-intel-mesh');
const { MCPPoisoningDetector } = require('./security/mcp-poisoning-detector');
const { MCPShadowDetector } = require('./security/mcp-shadow-detector');
const { MemoryPoisoningSentinel } = require('./security/memory-poisoning-sentinel');
const { CascadeIsolator } = require('./security/cascade-isolator');
const { AgentIdentityFederation } = require('./security/agent-identity-federation');
const { ToolUseAnomalyDetector } = require('./security/tool-use-anomaly');
const { SerializationFirewall } = require('./security/serialization-firewall');
const { ContextIntegrityGuardian } = require('./security/context-integrity-guardian');
const { ContextCompressionGuard } = require('./security/context-compression-guard');
const { ToolSchemaValidator } = require('./security/tool-schema-validator');
const { MultiModalInjectionShield } = require('./security/multimodal-injection-shield');
const { SupplyChainValidator } = require('./security/supply-chain-validator');
const { SandboxEnforcer } = require('./security/sandbox-enforcer');
const { MemoryIntegrityMonitor } = require('./security/memory-integrity-monitor');
const { MCPCertificatePinning } = require('./security/mcp-certificate-pinning');
const { OutputClassifier } = require('./egress/output-classifier');
const { StegoExfilDetector } = require('./egress/stego-exfil-detector');
const { ReasoningTraceMonitor } = require('./egress/reasoning-trace-monitor');
const { HallucinationTripwire } = require('./egress/hallucination-tripwire');
const { OutputProvenanceSigner, sha256Text } = require('./egress/output-provenance-signer');
const { TokenWatermark } = require('./egress/token-watermark');
const { OutputSchemaValidator } = require('./egress/output-schema-validator');
const { SemanticDriftCanary } = require('./security/semantic-drift-canary');
const { BudgetAutopilot } = require('./optimizer/budget-autopilot');
const { CostEfficiencyOptimizer } = require('./optimizer/cost-efficiency-optimizer');
const { ZKConfigValidator } = require('./config/zk-config-validator');
const { EvidenceVault } = require('./governance/evidence-vault');
const { ThreatPropagationGraph } = require('./governance/threat-propagation-graph');
const { AttackCorpusEvolver } = require('./governance/attack-corpus-evolver');
const { ForensicDebugger } = require('./governance/forensic-debugger');
const { AdversarialEvalHarness } = require('./governance/adversarial-eval-harness');
const { PolicyGradientAnalyzer } = require('./governance/policy-gradient-analyzer');
const { CapabilityIntrospection } = require('./governance/capability-introspection');
const { ComputeAttestation } = require('./governance/compute-attestation');
const { AnomalyTelemetry } = require('./telemetry/anomaly-telemetry');
const { LFRLEngine } = require('./engines/lfrl-engine');
const { SelfHealingImmuneSystem } = require('./engines/self-healing-immune');
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
const { runAgenticStage } = require('./stages/policy/agentic-stage');
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
const { writeAudit, writeAuditAndStatus } = require('./stages/audit-stage');
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

const DEFAULT_ENGINE_DECISION = Object.freeze({
  enabled: false,
  detected: false,
  shouldBlock: false,
  reason: 'disabled',
  findings: [],
});

const DEFAULT_SHED_ENGINE_ORDER = Object.freeze([
  'anomaly_telemetry',
  'attack_corpus_evolver',
  'threat_graph',
  'evidence_vault',
  'forensic_debugger',
  'adversarial_eval_harness',
  'semantic_drift_canary',
  'output_schema_validator',
  'output_classifier',
  'budget_autopilot',
  'agent_observability',
  'capability_introspection',
  'policy_gradient_analyzer',
]);

const PLAYGROUND_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Sentinel Playground</title>
  <style>
    :root { color-scheme: dark; }
    body {
      margin: 0;
      font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: radial-gradient(circle at top left, #13293d, #080d14 55%);
      color: #d9ecff;
    }
    .wrap { max-width: 1080px; margin: 0 auto; padding: 20px; }
    h1 { margin: 0 0 8px; font-size: 24px; }
    p.sub { margin: 0 0 16px; color: #a7bfd8; }
    textarea {
      width: 100%;
      min-height: 170px;
      border-radius: 10px;
      border: 1px solid #2f4a67;
      background: #0c1520;
      color: #d9ecff;
      padding: 12px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 13px;
      box-sizing: border-box;
    }
    .bar { display: flex; gap: 10px; margin: 12px 0 14px; align-items: center; }
    button {
      background: #0f5ed7;
      border: none;
      color: white;
      border-radius: 8px;
      padding: 10px 14px;
      font-size: 14px;
      cursor: pointer;
    }
    button:hover { background: #146af0; }
    .muted { color: #98b2ce; font-size: 13px; }
    .cards {
      margin-top: 8px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 10px;
    }
    .card {
      border: 1px solid #2d4764;
      background: #0c1520;
      border-radius: 10px;
      padding: 10px;
    }
    .k { font-size: 12px; color: #95b2d0; }
    .v { margin-top: 6px; font-weight: 700; font-size: 18px; }
    .table-wrap {
      margin-top: 14px;
      border: 1px solid #2d4764;
      border-radius: 10px;
      overflow: hidden;
    }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 8px 10px; border-bottom: 1px solid #1f3449; text-align: left; }
    th { color: #94b4d5; background: #0c1520; }
    .yes { color: #ff9494; font-weight: 700; }
    .no { color: #89f0b0; font-weight: 700; }
    pre {
      margin-top: 14px;
      border: 1px solid #2d4764;
      border-radius: 10px;
      padding: 10px;
      background: #0c1520;
      overflow: auto;
      font-size: 12px;
      line-height: 1.35;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Sentinel Playground</h1>
    <p class="sub">Paste prompt/context and run local deterministic analysis across active Sentinel engines.</p>
    <textarea id="prompt" placeholder="Paste prompt, tool_calls JSON, or model output to inspect..."></textarea>
    <div class="bar">
      <button id="analyze" type="button">Analyze</button>
      <span class="muted">No external API calls. Local analysis only.</span>
    </div>
    <div class="cards">
      <div class="card"><div class="k">Engines Evaluated</div><div id="engines" class="v">0</div></div>
      <div class="card"><div class="k">Detections</div><div id="detections" class="v">0</div></div>
      <div class="card"><div class="k">Block-Eligible</div><div id="blocks" class="v">0</div></div>
      <div class="card"><div class="k">Risk Level</div><div id="risk" class="v">low</div></div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Engine</th><th>Enabled</th><th>Detected</th><th>Block</th><th>Reason</th></tr></thead>
        <tbody id="engine-table"></tbody>
      </table>
    </div>
    <pre id="json">{}</pre>
  </div>
  <script>
    const promptEl = document.getElementById('prompt');
    const btn = document.getElementById('analyze');
    const table = document.getElementById('engine-table');
    const raw = document.getElementById('json');
    const fields = {
      engines: document.getElementById('engines'),
      detections: document.getElementById('detections'),
      blocks: document.getElementById('blocks'),
      risk: document.getElementById('risk'),
    };

    function row(engine, payload) {
      const tr = document.createElement('tr');
      const detectedClass = payload.detected ? 'yes' : 'no';
      const blockedClass = payload.shouldBlock ? 'yes' : 'no';
      tr.innerHTML = '<td>' + engine + '</td>'
        + '<td>' + (payload.enabled ? 'yes' : 'no') + '</td>'
        + '<td class=\"' + detectedClass + '\">' + (payload.detected ? 'yes' : 'no') + '</td>'
        + '<td class=\"' + blockedClass + '\">' + (payload.shouldBlock ? 'yes' : 'no') + '</td>'
        + '<td>' + String(payload.reason || '-') + '</td>';
      return tr;
    }

    async function analyze() {
      const payload = { prompt: promptEl.value || '' };
      const response = await fetch('/_sentinel/playground/analyze', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      fields.engines.textContent = String(data.summary?.engines_evaluated || 0);
      fields.detections.textContent = String(data.summary?.detections || 0);
      fields.blocks.textContent = String(data.summary?.block_eligible || 0);
      fields.risk.textContent = String(data.summary?.risk || 'unknown');

      table.innerHTML = '';
      const engines = data.engines || {};
      Object.keys(engines).sort().forEach((name) => {
        table.appendChild(row(name, engines[name] || {}));
      });
      raw.textContent = JSON.stringify(data, null, 2);
    }

    btn.addEventListener('click', () => {
      analyze().catch((error) => {
        raw.textContent = JSON.stringify({ error: String(error && error.message || error) }, null, 2);
      });
    });
  </script>
</body>
</html>`;

function parseJsonMaybe(value) {
  try {
    return JSON.parse(String(value || ''));
  } catch {
    return null;
  }
}

function createDisabledRuntimeEngine(options = {}) {
  const extras = options.extras && typeof options.extras === 'object' ? options.extras : {};
  const mode = String(options.mode || 'monitor').toLowerCase();
  const base = {
    enabled: false,
    mode,
    observability: false,
    exposeVerifyEndpoint: false,
    exposePublicKeyEndpoint: false,
    signStreamTrailers: false,
    nonStreamDelayMs: 0,
    trustedNodes: new Map(),
    allowedClockSkewMs: 0,
    compiledRules: [],
    signatures: new Map(),
    snapshots: [],
    action: 'warn',
    ...extras,
    isEnabled: () => false,
    inspect: () => DEFAULT_ENGINE_DECISION,
    evaluate: () => DEFAULT_ENGINE_DECISION,
    track: () => DEFAULT_ENGINE_DECISION,
    latest: () => null,
    snapshot: () => ({ enabled: false }),
    snapshotMetrics: () => ({ enabled: false }),
    getStats: () => ({ enabled: false }),
    getPublicMetadata: () => ({ enabled: false }),
    createStreamContext: () => null,
    create: () => null,
    verify: () => ({ valid: false, reason: 'disabled' }),
    createEnvelope: () => null,
    verifyEnvelope: () => ({ valid: false, reason: 'disabled' }),
    exportSnapshot: () => ({ enabled: false, signatures: [] }),
    safeExport: () => ({ enabled: false, score: 100, findings: [] }),
    run: () => ({ enabled: false }),
    maybeRun: () => null,
    append: () => null,
    ingest: () => {},
    ingestAuditEvent: () => null,
    observeAuditEvent: () => {},
    observe: () => {},
    recommend: () => ({ enabled: false }),
    recommendRoute: () => ({ enabled: false, recommendation: null, candidates: [] }),
    lookup: () => null,
    store: () => null,
    flush: async () => {},
    injectForwardHeaders: (headers = {}) => ({ ...headers }),
    startRequest: () => null,
    finishRequest: () => {},
    emitLifecycle: () => {},
  };

  return new Proxy(base, {
    get(target, property) {
      if (Reflect.has(target, property)) {
        return Reflect.get(target, property);
      }
      if (typeof property === 'symbol') {
        return undefined;
      }
      return () => DEFAULT_ENGINE_DECISION;
    },
  });
}

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
      output_classifier_detected: 0,
      output_classifier_blocked: 0,
      output_classifier_toxicity_detected: 0,
      output_classifier_code_execution_detected: 0,
      output_classifier_hallucination_detected: 0,
      output_classifier_unauthorized_disclosure_detected: 0,
      stego_exfil_detected: 0,
      stego_exfil_blocked: 0,
      reasoning_trace_detected: 0,
      reasoning_trace_blocked: 0,
      hallucination_tripwire_detected: 0,
      hallucination_tripwire_blocked: 0,
      semantic_drift_detected: 0,
      semantic_drift_blocked: 0,
      output_provenance_signed: 0,
      token_watermark_signed: 0,
      compute_attestation_signed: 0,
      output_schema_validator_detected: 0,
      output_schema_validator_blocked: 0,
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
      agentic_threat_detected: 0,
      agentic_threat_blocked: 0,
      agentic_threat_errors: 0,
      agentic_analysis_truncated: 0,
      agentic_identity_invalid: 0,
      a2a_card_detected: 0,
      a2a_card_blocked: 0,
      consensus_detected: 0,
      consensus_blocked: 0,
      cross_tenant_detected: 0,
      cross_tenant_blocked: 0,
      cross_tenant_leaks: 0,
      cold_start_detected: 0,
      cold_start_blocked: 0,
      mcp_poisoning_detected: 0,
      mcp_poisoning_blocked: 0,
      mcp_config_drift: 0,
      mcp_shadow_detected: 0,
      mcp_shadow_blocked: 0,
      mcp_shadow_schema_drift: 0,
      mcp_shadow_late_registration: 0,
      mcp_shadow_name_collision: 0,
      memory_poisoning_detected: 0,
      memory_poisoning_blocked: 0,
      cascade_detected: 0,
      cascade_blocked: 0,
      agent_identity_detected: 0,
      agent_identity_blocked: 0,
      tool_use_anomaly_detected: 0,
      tool_use_anomaly_blocked: 0,
      behavioral_fingerprint_detected: 0,
      behavioral_fingerprint_blocked: 0,
      serialization_firewall_detected: 0,
      serialization_firewall_blocked: 0,
      context_integrity_detected: 0,
      context_integrity_blocked: 0,
      context_compression_detected: 0,
      context_compression_blocked: 0,
      tool_schema_detected: 0,
      tool_schema_blocked: 0,
      tool_schema_sanitized: 0,
      multimodal_injection_detected: 0,
      multimodal_injection_blocked: 0,
      mcp_certificate_pinning_detected: 0,
      mcp_certificate_pinning_blocked: 0,
      mcp_certificate_pinning_rotation: 0,
      supply_chain_detected: 0,
      supply_chain_blocked: 0,
      sandbox_enforcer_detected: 0,
      sandbox_enforcer_blocked: 0,
      memory_integrity_detected: 0,
      memory_integrity_blocked: 0,
      threat_intel_detected: 0,
      threat_intel_blocked: 0,
      self_healing_detected: 0,
      self_healing_blocked: 0,
      lfrl_matches: 0,
      lfrl_blocked: 0,
      semantic_dsl_matched: 0,
      budget_autopilot_recommendations: 0,
      cost_efficiency_detected: 0,
      cost_efficiency_blocked: 0,
      cost_efficiency_memory_shed: 0,
      cost_efficiency_memory_restored: 0,
      evidence_vault_entries: 0,
      threat_graph_events: 0,
      attack_corpus_candidates: 0,
      anomaly_events_total: 0,
      capability_snapshots: 0,
      policy_gradient_runs: 0,
      adversarial_eval_runs: 0,
      adversarial_eval_regressions: 0,
      zk_config_findings: 0,
      auto_immune_matches: 0,
      auto_immune_blocked: 0,
      auto_immune_learned: 0,
      prompt_rebuff_detected: 0,
      prompt_rebuff_blocked: 0,
      prompt_rebuff_errors: 0,
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
      websocket_upgrades_total: 0,
      websocket_forwarded: 0,
      websocket_blocked: 0,
      websocket_errors: 0,
      dashboard_requests_total: 0,
      dashboard_api_requests_total: 0,
      dashboard_denied_total: 0,
      lazy_engine_loaded: 0,
      lazy_engine_skipped: 0,
    };
    this.lazyEngineState = {
      enabled: true,
      loaded: [],
      skipped: [],
    };
    this.memoryShedState = new Map();
    this.lastMemoryShedAt = 0;
    this.shedEngineOrderRuntimeKeys = [];

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
    this.agentObservability = new AgentObservability(this.config.runtime?.agent_observability || {});
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
    this.rawAuditWrite = this.auditLogger.write.bind(this.auditLogger);
    this.auditLogger.write = (payload) => writeAudit(this, payload);
    this.vcrStore = new VCRStore(this.config.runtime?.vcr || {});
    this.budgetStore = new BudgetStore(this.config.runtime?.budget || {});
    this.aibom = new AIBOMGenerator();
    const runtimeConfig = this.config.runtime || {};
    this.runtimeEngineKeyByProp = new Map();
    const optionalEngine = (propName, runtimeKey, factory, engineOptions = {}) => {
      this.runtimeEngineKeyByProp.set(propName, runtimeKey);
      const engineConfig = runtimeConfig[runtimeKey] && typeof runtimeConfig[runtimeKey] === 'object'
        ? runtimeConfig[runtimeKey]
        : {};
      const mode = typeof engineConfig.mode === 'string' ? engineConfig.mode : (engineOptions.mode || 'monitor');
      if (engineConfig.enabled === true) {
        try {
          const instance = factory(engineConfig);
          this.lazyEngineState.loaded.push(runtimeKey);
          return instance;
        } catch (error) {
          logger.warn('Runtime engine failed to initialize; disabling for this run', {
            runtime_key: runtimeKey,
            error: error.message,
          });
        }
      }
      this.lazyEngineState.skipped.push(runtimeKey);
      return createDisabledRuntimeEngine({
        mode,
        extras: engineOptions.disabledExtras || {},
      });
    };

    this.semanticCache = optionalEngine('semanticCache', 'semantic_cache', (engineConfig) => new SemanticCache(engineConfig, {
      scanWorkerPool: this.scanWorkerPool,
    }), {
      disabledExtras: {
        lookup: async () => null,
        store: () => {},
      },
    });
    this.loopBreaker = optionalEngine('loopBreaker', 'loop_breaker', (engineConfig) => new LoopBreaker(engineConfig), {
      disabledExtras: { enabled: false },
    });
    this.autoImmune = optionalEngine('autoImmune', 'auto_immune', (engineConfig) => new AutoImmune(engineConfig));
    this.deceptionEngine = optionalEngine('deceptionEngine', 'deception', (engineConfig) => new DeceptionEngine(engineConfig));
    this.provenanceSigner = optionalEngine('provenanceSigner', 'provenance', (engineConfig) => new ProvenanceSigner(engineConfig), {
      disabledExtras: { exposePublicKeyEndpoint: false, signStreamTrailers: false },
    });
    this.honeytokenInjector = optionalEngine('honeytokenInjector', 'honeytoken', (engineConfig) => new HoneytokenInjector(engineConfig));
    this.polymorphicPrompt = optionalEngine(
      'polymorphicPrompt',
      'polymorphic_prompt',
      (engineConfig) => new PolymorphicPromptEngine(engineConfig)
    );
    this.syntheticPoisoner = optionalEngine('syntheticPoisoner', 'synthetic_poisoning', (engineConfig) => new SyntheticPoisoner(engineConfig));
    this.cognitiveRollback = optionalEngine('cognitiveRollback', 'cognitive_rollback', (engineConfig) => new CognitiveRollback(engineConfig));
    this.latencyNormalizer = optionalEngine('latencyNormalizer', 'latency_normalization', (engineConfig) => new LatencyNormalizer(engineConfig));
    const embedText = this.createEmbeddingDelegate();
    this.intentThrottle = optionalEngine('intentThrottle', 'intent_throttle', (engineConfig) => new IntentThrottle(engineConfig, {
      embedText,
    }));
    this.intentDrift = optionalEngine('intentDrift', 'intent_drift', (engineConfig) => new IntentDriftDetector(engineConfig, {
      embedText,
    }));
    this.canaryToolTrap = optionalEngine('canaryToolTrap', 'canary_tools', (engineConfig) => new CanaryToolTrap(engineConfig));
    this.promptRebuff = optionalEngine('promptRebuff', 'prompt_rebuff', (engineConfig) => new PromptRebuffEngine(engineConfig));
    this.mcpPoisoningDetector = optionalEngine('mcpPoisoningDetector', 'mcp_poisoning', (engineConfig) => new MCPPoisoningDetector(engineConfig));
    this.mcpShadowDetector = optionalEngine('mcpShadowDetector', 'mcp_shadow', (engineConfig) => new MCPShadowDetector(engineConfig));
    this.mcpCertificatePinning = optionalEngine(
      'mcpCertificatePinning',
      'mcp_certificate_pinning',
      (engineConfig) => new MCPCertificatePinning(engineConfig)
    );
    this.memoryPoisoningSentinel = optionalEngine(
      'memoryPoisoningSentinel',
      'memory_poisoning',
      (engineConfig) => new MemoryPoisoningSentinel(engineConfig)
    );
    this.cascadeIsolator = optionalEngine('cascadeIsolator', 'cascade_isolator', (engineConfig) => new CascadeIsolator(engineConfig));
    this.agentIdentityFederation = optionalEngine(
      'agentIdentityFederation',
      'agent_identity_federation',
      (engineConfig) => new AgentIdentityFederation(engineConfig)
    );
    this.toolUseAnomalyDetector = optionalEngine('toolUseAnomalyDetector', 'tool_use_anomaly', (engineConfig) => new ToolUseAnomalyDetector(engineConfig));
    this.behavioralFingerprint = optionalEngine('behavioralFingerprint', 'behavioral_fingerprint', (engineConfig) => new BehavioralFingerprint(engineConfig));
    this.threatIntelMesh = optionalEngine('threatIntelMesh', 'threat_intel_mesh', (engineConfig) => new ThreatIntelMesh(engineConfig), {
      disabledExtras: {
        signatures: new Map(),
      },
    });
    this.lfrlEngine = optionalEngine('lfrlEngine', 'lfrl', (engineConfig) => new LFRLEngine(engineConfig), {
      disabledExtras: {
        compiledRules: [],
      },
    });
    this.selfHealingImmune = optionalEngine(
      'selfHealingImmune',
      'self_healing_immune',
      (engineConfig) => new SelfHealingImmuneSystem(engineConfig),
      {
        disabledExtras: {
          signatures: new Map(),
        },
      }
    );
    this.serializationFirewall = optionalEngine('serializationFirewall', 'serialization_firewall', (engineConfig) => new SerializationFirewall(engineConfig));
    this.contextIntegrityGuardian = optionalEngine('contextIntegrityGuardian', 'context_integrity_guardian', (engineConfig) => new ContextIntegrityGuardian(engineConfig));
    this.contextCompressionGuard = optionalEngine(
      'contextCompressionGuard',
      'context_compression_guard',
      (engineConfig) => new ContextCompressionGuard(engineConfig)
    );
    this.toolSchemaValidator = optionalEngine('toolSchemaValidator', 'tool_schema_validator', (engineConfig) => new ToolSchemaValidator(engineConfig));
    this.multimodalInjectionShield = optionalEngine(
      'multimodalInjectionShield',
      'multimodal_injection_shield',
      (engineConfig) => new MultiModalInjectionShield(engineConfig)
    );
    this.supplyChainValidator = optionalEngine('supplyChainValidator', 'supply_chain_validator', (engineConfig) => new SupplyChainValidator(engineConfig));
    this.sandboxEnforcer = optionalEngine('sandboxEnforcer', 'sandbox_enforcer', (engineConfig) => new SandboxEnforcer(engineConfig));
    this.memoryIntegrityMonitor = optionalEngine('memoryIntegrityMonitor', 'memory_integrity_monitor', (engineConfig) => new MemoryIntegrityMonitor(engineConfig));
    this.outputClassifier = optionalEngine('outputClassifier', 'output_classifier', (engineConfig) => new OutputClassifier(engineConfig));
    this.outputSchemaValidator = optionalEngine('outputSchemaValidator', 'output_schema_validator', (engineConfig) => new OutputSchemaValidator(engineConfig));
    this.budgetAutopilot = optionalEngine('budgetAutopilot', 'budget_autopilot', (engineConfig) => new BudgetAutopilot(engineConfig));
    this.costEfficiencyOptimizer = optionalEngine(
      'costEfficiencyOptimizer',
      'cost_efficiency_optimizer',
      (engineConfig) => new CostEfficiencyOptimizer(engineConfig),
      {
        mode: 'monitor',
        disabledExtras: {
          mode: 'monitor',
        },
      }
    );
    this.evidenceVault = optionalEngine('evidenceVault', 'evidence_vault', (engineConfig) => new EvidenceVault(engineConfig));
    this.threatPropagationGraph = optionalEngine('threatPropagationGraph', 'threat_graph', (engineConfig) => new ThreatPropagationGraph(engineConfig));
    this.attackCorpusEvolver = optionalEngine('attackCorpusEvolver', 'attack_corpus_evolver', (engineConfig) => new AttackCorpusEvolver(engineConfig));
    this.forensicDebugger = optionalEngine('forensicDebugger', 'forensic_debugger', (engineConfig) => new ForensicDebugger(engineConfig));
    this.adversarialEvalHarness = optionalEngine(
      'adversarialEvalHarness',
      'adversarial_eval_harness',
      (engineConfig) => new AdversarialEvalHarness(engineConfig)
    );
    this.anomalyTelemetry = optionalEngine('anomalyTelemetry', 'anomaly_telemetry', (engineConfig) => new AnomalyTelemetry(engineConfig));
    this.zkConfigValidator = optionalEngine('zkConfigValidator', 'zk_config_validator', (engineConfig) => new ZKConfigValidator(engineConfig));
    this.parallaxValidator = optionalEngine('parallaxValidator', 'parallax', (engineConfig) => new ParallaxValidator(engineConfig, {
      upstreamClient: this.upstreamClient,
      config: this.config,
    }));
    this.omniShield = optionalEngine('omniShield', 'omni_shield', (engineConfig) => new OmniShield(engineConfig));
    this.experimentalSandbox = optionalEngine('experimentalSandbox', 'sandbox_experimental', (engineConfig) => new ExperimentalSandbox(engineConfig));
    this.shadowOS = optionalEngine('shadowOS', 'shadow_os', (engineConfig) => new ShadowOS(engineConfig));
    this.epistemicAnchor = optionalEngine('epistemicAnchor', 'epistemic_anchor', (engineConfig) => new EpistemicAnchor(engineConfig, {
      embedText,
    }));
    this.agenticThreatShield = optionalEngine('agenticThreatShield', 'agentic_threat_shield', (engineConfig) => new AgenticThreatShield(engineConfig));
    this.a2aCardVerifier = optionalEngine('a2aCardVerifier', 'a2a_card_verifier', (engineConfig) => new A2ACardVerifier(engineConfig));
    this.consensusProtocol = optionalEngine('consensusProtocol', 'consensus_protocol', (engineConfig) => new ConsensusProtocol(engineConfig));
    this.crossTenantIsolator = optionalEngine('crossTenantIsolator', 'cross_tenant_isolator', (engineConfig) => new CrossTenantIsolator(engineConfig));
    this.coldStartAnalyzer = optionalEngine('coldStartAnalyzer', 'cold_start_analyzer', (engineConfig) => new ColdStartAnalyzer(engineConfig));
    this.stegoExfilDetector = optionalEngine('stegoExfilDetector', 'stego_exfil_detector', (engineConfig) => new StegoExfilDetector(engineConfig));
    this.reasoningTraceMonitor = optionalEngine('reasoningTraceMonitor', 'reasoning_trace_monitor', (engineConfig) => new ReasoningTraceMonitor(engineConfig));
    this.hallucinationTripwire = optionalEngine('hallucinationTripwire', 'hallucination_tripwire', (engineConfig) => new HallucinationTripwire(engineConfig));
    this.semanticDriftCanary = optionalEngine('semanticDriftCanary', 'semantic_drift_canary', (engineConfig) => new SemanticDriftCanary(engineConfig));
    this.outputProvenanceSigner = optionalEngine(
      'outputProvenanceSigner',
      'output_provenance',
      (engineConfig) => new OutputProvenanceSigner(engineConfig),
      {
        disabledExtras: { exposeVerifyEndpoint: false },
      }
    );
    this.tokenWatermark = optionalEngine('tokenWatermark', 'token_watermark', (engineConfig) => new TokenWatermark(engineConfig), {
      disabledExtras: { exposeVerifyEndpoint: false },
    });
    this.computeAttestation = optionalEngine('computeAttestation', 'compute_attestation', (engineConfig) => new ComputeAttestation(engineConfig), {
      disabledExtras: { exposeVerifyEndpoint: false },
    });
    this.capabilityIntrospection = optionalEngine(
      'capabilityIntrospection',
      'capability_introspection',
      (engineConfig) => new CapabilityIntrospection(engineConfig)
    );
    this.policyGradientAnalyzer = optionalEngine(
      'policyGradientAnalyzer',
      'policy_gradient_analyzer',
      (engineConfig) => new PolicyGradientAnalyzer(engineConfig)
    );
    this.stats.lazy_engine_loaded = this.lazyEngineState.loaded.length;
    this.stats.lazy_engine_skipped = this.lazyEngineState.skipped.length;
    this.shedEngineOrderRuntimeKeys = this.resolveShedEngineOrder();
    this.refreshZkConfigAssessment();
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
    this.activeWebSocketTunnels = 0;
    this.webSocketSockets = new Set();
    this.serverSockets = new Set();
    this.lastStatusWriteError = null;
    this.optimizerPlugin = loadOptimizerPlugin();
    this.dashboardServer = null;
    this.lastBudgetAutopilotRecommendation = null;
    this.pluginRegistry.registerAll(this.options.plugins || []);
    if (this.options.plugin) {
      this.pluginRegistry.register(this.options.plugin);
    }
    this.postureScorer =
      typeof this.options.postureScorer === 'function'
        ? this.options.postureScorer
        : computeSecurityPosture;

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

  refreshZkConfigAssessment() {
    if (!this.zkConfigValidator?.isEnabled?.()) {
      this.zkConfigAssessment = {
        enabled: false,
      };
      return this.zkConfigAssessment;
    }
    const assessment = this.zkConfigValidator.evaluate(this.config, {
      knownRuntimeKeys: Object.keys(this.config?.runtime || {}),
    });
    this.zkConfigAssessment = assessment;
    this.stats.zk_config_findings = Array.isArray(assessment?.findings) ? assessment.findings.length : 0;
    return assessment;
  }

  resolveShedEngineOrder() {
    const configuredOrder = Array.isArray(this.costEfficiencyOptimizer?.shedEngineOrder)
      ? this.costEfficiencyOptimizer.shedEngineOrder
      : [];
    const runtimeKeys = configuredOrder.length > 0 ? configuredOrder : DEFAULT_SHED_ENGINE_ORDER;
    const order = [];
    for (const runtimeKey of runtimeKeys) {
      const propName = Array.from(this.runtimeEngineKeyByProp.entries())
        .find(([, key]) => key === runtimeKey)?.[0];
      if (!propName || order.includes(propName)) {
        continue;
      }
      order.push(propName);
    }
    return order;
  }

  applyMemoryPressurePolicy({ decision, warnings, res }) {
    if (!decision || typeof decision !== 'object' || !this.costEfficiencyOptimizer?.isEnabled?.()) {
      return { shed: 0, restored: 0 };
    }

    const rss = Number(decision.memory_rss_bytes || 0);
    const level = String(decision.memory_level || 'normal');
    const restoreThreshold = Math.floor(
      Math.max(
        1,
        Number(this.costEfficiencyOptimizer.memoryWarnBytes || 0) * 0.85
      )
    );
    const now = Date.now();
    const cooldownMs = Number(this.costEfficiencyOptimizer.shedCooldownMs || 30000);
    let shed = 0;
    let restored = 0;

    const canActNow = (now - this.lastMemoryShedAt) >= cooldownMs;
    if (canActNow && this.costEfficiencyOptimizer.shedOnMemoryPressure === true && (level === 'critical' || level === 'hard_cap')) {
      const maxShed = Number(this.costEfficiencyOptimizer.maxShedEngines || 16);
      const targetShedCount = level === 'hard_cap' ? 3 : 1;
      for (const propName of this.shedEngineOrderRuntimeKeys) {
        if (shed >= targetShedCount || this.memoryShedState.size >= maxShed) {
          break;
        }
        if (this.memoryShedState.has(propName)) {
          continue;
        }
        const engine = this[propName];
        if (!engine || typeof engine.isEnabled !== 'function' || !engine.isEnabled()) {
          continue;
        }
        const previous = {
          enabled: engine.enabled === true,
          mode: typeof engine.mode === 'string' ? engine.mode : 'monitor',
        };
        engine.enabled = false;
        if (typeof engine.mode === 'string') {
          engine.mode = 'monitor';
        }
        this.memoryShedState.set(propName, previous);
        shed += 1;
      }
      if (shed > 0) {
        this.lastMemoryShedAt = now;
        this.stats.cost_efficiency_memory_shed += shed;
        warnings.push(`cost_memory_shed:${shed}`);
        this.stats.warnings_total += 1;
        if (res && this.costEfficiencyOptimizer.observability) {
          res.setHeader('x-sentinel-memory-shed', String(shed));
          res.setHeader('x-sentinel-memory-shed-active', String(this.memoryShedState.size));
        }
      }
    }

    if (this.memoryShedState.size > 0 && level === 'normal' && rss > 0 && rss <= restoreThreshold && canActNow) {
      for (const [propName, previous] of this.memoryShedState.entries()) {
        const engine = this[propName];
        if (!engine) {
          this.memoryShedState.delete(propName);
          continue;
        }
        engine.enabled = previous.enabled === true;
        if (typeof engine.mode === 'string') {
          engine.mode = previous.mode || engine.mode;
        }
        this.memoryShedState.delete(propName);
        restored += 1;
      }
      if (restored > 0) {
        this.lastMemoryShedAt = now;
        this.stats.cost_efficiency_memory_restored += restored;
        warnings.push(`cost_memory_restored:${restored}`);
        this.stats.warnings_total += 1;
        if (res && this.costEfficiencyOptimizer.observability) {
          res.setHeader('x-sentinel-memory-restored', String(restored));
          res.setHeader('x-sentinel-memory-shed-active', String(this.memoryShedState.size));
        }
      }
    }
    return { shed, restored };
  }

  currentStatusPayload() {
    const budgetSnapshot = this.budgetStore.snapshot();
    const budgetAutopilotConfig =
      this.config.runtime?.budget_autopilot && typeof this.config.runtime.budget_autopilot === 'object'
        ? this.config.runtime.budget_autopilot
        : {};
    const budgetAutopilotRecommendation = this.budgetAutopilot.isEnabled()
      ? this.budgetAutopilot.recommend({
          budgetRemainingUsd: Number(budgetSnapshot.remainingUsd || 0),
          slaP95Ms: Number(budgetAutopilotConfig.sla_p95_ms || 2000),
          horizonHours: Number(budgetAutopilotConfig.horizon_hours || 24),
        })
      : null;
    const recommendationProvider = budgetAutopilotRecommendation?.recommendation || null;
    if (recommendationProvider && recommendationProvider !== this.lastBudgetAutopilotRecommendation) {
      this.stats.budget_autopilot_recommendations += 1;
      this.lastBudgetAutopilotRecommendation = recommendationProvider;
    }

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
      agentic_threat_shield_enabled: this.agenticThreatShield.isEnabled(),
      agentic_threat_shield_mode: this.agenticThreatShield.mode,
      a2a_card_verifier_enabled: this.a2aCardVerifier.isEnabled(),
      a2a_card_verifier_mode: this.a2aCardVerifier.mode,
      consensus_protocol_enabled: this.consensusProtocol.isEnabled(),
      consensus_protocol_mode: this.consensusProtocol.mode,
      cross_tenant_isolator_enabled: this.crossTenantIsolator.isEnabled(),
      cross_tenant_isolator_mode: this.crossTenantIsolator.mode,
      cold_start_analyzer_enabled: this.coldStartAnalyzer.isEnabled(),
      cold_start_analyzer_mode: this.coldStartAnalyzer.mode,
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
      mcp_poisoning_enabled: this.mcpPoisoningDetector.isEnabled(),
      mcp_poisoning_mode: this.mcpPoisoningDetector.mode,
      mcp_shadow_enabled: this.mcpShadowDetector.isEnabled(),
      mcp_shadow_mode: this.mcpShadowDetector.mode,
      mcp_certificate_pinning_enabled: this.mcpCertificatePinning.isEnabled(),
      mcp_certificate_pinning_mode: this.mcpCertificatePinning.mode,
      memory_poisoning_enabled: this.memoryPoisoningSentinel.isEnabled(),
      memory_poisoning_mode: this.memoryPoisoningSentinel.mode,
      cascade_isolator_enabled: this.cascadeIsolator.isEnabled(),
      cascade_isolator_mode: this.cascadeIsolator.mode,
      agent_identity_federation_enabled: this.agentIdentityFederation.isEnabled(),
      agent_identity_federation_mode: this.agentIdentityFederation.mode,
      tool_use_anomaly_enabled: this.toolUseAnomalyDetector.isEnabled(),
      tool_use_anomaly_mode: this.toolUseAnomalyDetector.mode,
      behavioral_fingerprint_enabled: this.behavioralFingerprint.isEnabled(),
      behavioral_fingerprint_mode: this.behavioralFingerprint.mode,
      serialization_firewall_enabled: this.serializationFirewall.isEnabled(),
      serialization_firewall_mode: this.serializationFirewall.mode,
      context_integrity_guardian_enabled: this.contextIntegrityGuardian.isEnabled(),
      context_integrity_guardian_mode: this.contextIntegrityGuardian.mode,
      context_compression_guard_enabled: this.contextCompressionGuard.isEnabled(),
      context_compression_guard_mode: this.contextCompressionGuard.mode,
      tool_schema_validator_enabled: this.toolSchemaValidator.isEnabled(),
      tool_schema_validator_mode: this.toolSchemaValidator.mode,
      multimodal_injection_shield_enabled: this.multimodalInjectionShield.isEnabled(),
      multimodal_injection_shield_mode: this.multimodalInjectionShield.mode,
      supply_chain_validator_enabled: this.supplyChainValidator.isEnabled(),
      supply_chain_validator_mode: this.supplyChainValidator.mode,
      sandbox_enforcer_enabled: this.sandboxEnforcer.isEnabled(),
      sandbox_enforcer_mode: this.sandboxEnforcer.mode,
      memory_integrity_monitor_enabled: this.memoryIntegrityMonitor.isEnabled(),
      memory_integrity_monitor_mode: this.memoryIntegrityMonitor.mode,
      threat_intel_mesh_enabled: this.threatIntelMesh.isEnabled(),
      threat_intel_mesh_mode: this.threatIntelMesh.mode,
      threat_intel_mesh_signatures: this.threatIntelMesh.signatures?.size || 0,
      lfrl_enabled: this.lfrlEngine.isEnabled(),
      lfrl_mode: this.lfrlEngine.mode,
      lfrl_rules_loaded: Array.isArray(this.lfrlEngine.compiledRules) ? this.lfrlEngine.compiledRules.length : 0,
      self_healing_immune_enabled: this.selfHealingImmune.isEnabled(),
      self_healing_immune_mode: this.selfHealingImmune.mode,
      self_healing_signatures: this.selfHealingImmune.signatures?.size || 0,
      semantic_firewall_dsl_enabled: this.config.runtime?.semantic_firewall_dsl?.enabled === true,
      prompt_rebuff_enabled: this.promptRebuff.isEnabled(),
      prompt_rebuff_mode: this.promptRebuff.mode,
      output_classifier_enabled: this.outputClassifier.isEnabled(),
      stego_exfil_detector_enabled: this.stegoExfilDetector.isEnabled(),
      stego_exfil_detector_mode: this.stegoExfilDetector.mode,
      reasoning_trace_monitor_enabled: this.reasoningTraceMonitor.isEnabled(),
      reasoning_trace_monitor_mode: this.reasoningTraceMonitor.mode,
      hallucination_tripwire_enabled: this.hallucinationTripwire.isEnabled(),
      hallucination_tripwire_mode: this.hallucinationTripwire.mode,
      semantic_drift_canary_enabled: this.semanticDriftCanary.isEnabled(),
      semantic_drift_canary_mode: this.semanticDriftCanary.mode,
      output_provenance_enabled: this.outputProvenanceSigner.isEnabled(),
      token_watermark_enabled: this.tokenWatermark.isEnabled(),
      compute_attestation_enabled: this.computeAttestation.isEnabled(),
      output_schema_validator_enabled: this.outputSchemaValidator.isEnabled(),
      budget_autopilot_enabled: this.budgetAutopilot.isEnabled(),
      budget_autopilot_mode: this.budgetAutopilot.mode,
      budget_autopilot_recommendation: budgetAutopilotRecommendation,
      cost_efficiency_optimizer_enabled: this.costEfficiencyOptimizer.isEnabled(),
      cost_efficiency_optimizer_mode: this.costEfficiencyOptimizer.mode,
      cost_efficiency_optimizer_snapshot: this.costEfficiencyOptimizer.snapshot(),
      memory_shed_active_engines: this.memoryShedState.size,
      memory_shed_order: this.shedEngineOrderRuntimeKeys
        .map((propName) => this.runtimeEngineKeyByProp.get(propName))
        .filter(Boolean),
      lazy_engine_loading_enabled: this.lazyEngineState.enabled,
      lazy_engine_loaded: this.lazyEngineState.loaded.length,
      lazy_engine_skipped: this.lazyEngineState.skipped.length,
      lazy_engine_loaded_keys: this.lazyEngineState.loaded.slice(0, 256),
      lazy_engine_skipped_keys: this.lazyEngineState.skipped.slice(0, 256),
      evidence_vault_enabled: this.evidenceVault.isEnabled(),
      evidence_vault_stats: this.evidenceVault.getStats(),
      threat_graph_enabled: this.threatPropagationGraph.isEnabled(),
      attack_corpus_evolver_enabled: this.attackCorpusEvolver.isEnabled(),
      forensic_debugger_enabled: this.forensicDebugger.isEnabled(),
      forensic_debugger_snapshots: Array.isArray(this.forensicDebugger.snapshots)
        ? this.forensicDebugger.snapshots.length
        : 0,
      capability_introspection_enabled: this.capabilityIntrospection.isEnabled(),
      policy_gradient_analyzer_enabled: this.policyGradientAnalyzer.isEnabled(),
      adversarial_eval_harness_enabled: this.adversarialEvalHarness.isEnabled(),
      adversarial_eval_latest: this.adversarialEvalHarness.latest(),
      anomaly_telemetry_enabled: this.anomalyTelemetry.isEnabled(),
      anomaly_telemetry_snapshot: this.anomalyTelemetry.snapshot(),
      zk_config_validator_enabled: this.zkConfigValidator.isEnabled(),
      zk_config_assessment: this.zkConfigAssessment || this.refreshZkConfigAssessment(),
      agent_observability_enabled: this.agentObservability.isEnabled(),
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
      aibom: this.aibom.exportArtifact(),
      websocket_enabled: this.config.runtime?.websocket?.enabled !== false,
      websocket_mode: this.config.runtime?.websocket?.mode || 'monitor',
      websocket_active_tunnels: this.activeWebSocketTunnels,
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

  recordDashboardAccess(event = {}) {
    const path = String(event.path || '/');
    const method = String(event.method || 'GET').toUpperCase();
    const isApiRequest = path.startsWith('/api/') || path === '/health';
    this.stats.dashboard_requests_total += 1;
    if (isApiRequest) {
      this.stats.dashboard_api_requests_total += 1;
    }
    if (event.allowed === false) {
      this.stats.dashboard_denied_total += 1;
    }

    this.auditLogger.write({
      timestamp: new Date().toISOString(),
      correlation_id: String(event.requestId || `dashboard-${Date.now().toString(36)}`),
      config_version: this.config.version,
      mode: this.computeEffectiveMode(),
      decision: event.allowed === false ? 'dashboard_access_denied' : 'dashboard_access',
      reasons: [String(event.reason || (event.allowed === false ? 'dashboard_denied' : 'dashboard_ok'))],
      pii_types: [],
      redactions: 0,
      duration_ms: Number(event.durationMs || 0),
      request_bytes: 0,
      response_status: Number(event.statusCode || 0),
      response_bytes: 0,
      provider: 'dashboard',
      dashboard_method: method,
      dashboard_path: path,
      dashboard_api_request: isApiRequest,
      dashboard_remote_address: String(event.remoteAddress || ''),
      dashboard_local_only: event.localOnly !== false,
      dashboard_auth_required: event.authRequired === true,
      dashboard_authenticated: event.authenticated === true,
      dashboard_team: String(event.team || ''),
      dashboard_team_header: String(event.teamHeader || ''),
    });
    this.writeStatus();
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

  getRuntimeConfigHash() {
    const payload = {
      version: this.config?.version,
      mode: this.config?.mode,
      runtime: this.config?.runtime || {},
      rules: this.config?.rules || [],
      pii: this.config?.pii || {},
      injection: this.config?.injection || {},
    };
    return sha256Text(JSON.stringify(payload));
  }

  applyBufferedProvenanceHeaders(res, { body, statusCode, provider, correlationId }) {
    if (res.headersSent) {
      return;
    }

    const responseBuffer = this.toResponseBodyBuffer(body);

    if (this.provenanceSigner.isEnabled() && !res.getHeader('x-sentinel-signature')) {
      const proof = this.provenanceSigner.signBufferedResponse({
        bodyBuffer: responseBuffer,
        statusCode,
        provider,
        correlationId,
      });
      if (!proof) {
        res.setHeader('x-sentinel-signature-status', 'skipped');
      } else {
        const proofHeaders = ProvenanceSigner.proofHeaders(proof);
        for (const [key, value] of Object.entries(proofHeaders)) {
          res.setHeader(key, value);
        }
        res.setHeader('x-sentinel-signature-status', 'signed');
      }
    }

    if (this.outputProvenanceSigner?.isEnabled?.() && !res.getHeader('x-sentinel-provenance')) {
      const envelope = this.outputProvenanceSigner.createEnvelope({
        outputBuffer: responseBuffer,
        statusCode,
        provider,
        correlationId,
        modelId: String(res.getHeader('x-sentinel-model-id') || ''),
        configHash: this.getRuntimeConfigHash(),
      });
      if (envelope?.envelope) {
        res.setHeader('x-sentinel-provenance', envelope.envelope);
        this.stats.output_provenance_signed += 1;
      }
    }

    if (this.tokenWatermark?.isEnabled?.() && !res.getHeader('x-sentinel-token-watermark')) {
      const watermark = this.tokenWatermark.createEnvelope({
        outputBuffer: responseBuffer,
        statusCode,
        provider,
        correlationId,
        modelId: String(res.getHeader('x-sentinel-model-id') || ''),
        configHash: this.getRuntimeConfigHash(),
      });
      if (watermark?.envelope) {
        res.setHeader('x-sentinel-token-watermark', watermark.envelope);
        this.stats.token_watermark_signed += 1;
      }
    }

    if (this.computeAttestation?.isEnabled?.() && !res.getHeader('x-sentinel-attestation')) {
      const attestation = this.computeAttestation.create({
        configHash: this.getRuntimeConfigHash(),
        policyHash: sha256Text(JSON.stringify(this.config?.rules || [])),
        correlationId,
        provider,
      });
      if (attestation?.envelope) {
        res.setHeader('x-sentinel-attestation', attestation.envelope);
        this.stats.compute_attestation_signed += 1;
      }
    }
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
      const proofContext =
        streamProof &&
        typeof streamProof.update === 'function' &&
        typeof streamProof.finalize === 'function'
          ? streamProof
          : null;
      const canAddTrailers =
        Boolean(proofContext) &&
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
          if (proofContext) {
            proofContext.update(chunk);
          }
        },
      });

      if (canAddTrailers) {
        const proof = proofContext.finalize();
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

  async buildPlaygroundAnalysis({ prompt = '', correlationId = '' } = {}) {
    const text = String(prompt || '').slice(0, 32768);
    const requestId = String(correlationId || `playground-${Date.now().toString(36)}`);
    const rawBody = Buffer.from(text, 'utf8');
    const bodyJson = parseJsonMaybe(text);
    const effectiveMode = 'monitor';
    const headers = {
      'content-type': bodyJson ? 'application/json' : 'text/plain',
    };
    const engines = {};

    const addEngineResult = (name, payload = {}) => {
      const findingCount = Array.isArray(payload.findings)
        ? payload.findings.length
        : Array.isArray(payload.mismatches)
          ? payload.mismatches.length
          : 0;
      engines[name] = {
        enabled: payload.enabled !== false,
        detected: payload.detected === true || payload.shouldWarn === true,
        shouldBlock: payload.shouldBlock === true,
        reason: String(payload.reason || 'clean'),
        findings: findingCount,
      };
    };

    const runEngine = async (name, runner, mapper) => {
      try {
        const result = await runner();
        addEngineResult(name, typeof mapper === 'function' ? mapper(result) : result);
      } catch (error) {
        addEngineResult(name, {
          enabled: false,
          detected: false,
          shouldBlock: false,
          reason: `engine_error:${String(error?.message || 'unknown')}`,
          findings: [],
        });
      }
    };

    const piiResult = this.piiScanner.scan(text, {
      maxScanBytes: 65536,
      regexSafetyCapBytes: 32768,
    });
    addEngineResult('pii_scanner', {
      enabled: true,
      detected: Array.isArray(piiResult.findings) && piiResult.findings.length > 0,
      shouldBlock: false,
      reason: piiResult.findings?.length ? 'pii_detected' : 'clean',
      findings: piiResult.findings || [],
    });

    const injectionResult = this.policyEngine.scanInjection(text);
    addEngineResult('injection_scanner', {
      enabled: true,
      detected: Number(injectionResult?.score || 0) >= 0.5,
      shouldBlock: false,
      reason: Number(injectionResult?.score || 0) >= 0.5 ? 'injection_detected' : 'clean',
      findings: injectionResult?.matchedSignals || [],
    });

    await runEngine(
      'prompt_rebuff',
      () =>
        this.promptRebuff.evaluate({
          headers: {},
          correlationId: requestId,
          bodyText: text,
          injectionResult,
          effectiveMode,
        }),
      (result) => ({
        enabled: result?.enabled !== false,
        detected: result?.detected === true,
        shouldBlock: result?.shouldBlock === true,
        reason: result?.reason || 'clean',
        findings: result?.canarySignal?.value > 0 ? ['canary_signal'] : [],
      })
    );

    await runEngine(
      'serialization_firewall',
      () =>
        this.serializationFirewall.evaluate({
          headers,
          rawBody,
          bodyText: text,
          bodyJson,
          effectiveMode,
        })
    );

    await runEngine(
      'context_integrity_guardian',
      () =>
        this.contextIntegrityGuardian.evaluate({
          headers: {},
          bodyJson:
            bodyJson && typeof bodyJson === 'object'
              ? bodyJson
              : {
                messages: [
                  {
                    role: 'user',
                    content: text,
                  },
                ],
              },
          bodyText: text,
          correlationId: requestId,
          effectiveMode,
        })
    );

    await runEngine(
      'context_compression_guard',
      () =>
        this.contextCompressionGuard.evaluate({
          headers: {},
          bodyJson:
            bodyJson && typeof bodyJson === 'object'
              ? bodyJson
              : {
                messages: [
                  {
                    role: 'user',
                    content: text,
                  },
                ],
              },
          bodyText: text,
          correlationId: requestId,
          effectiveMode,
        })
    );

    await runEngine(
      'tool_schema_validator',
      () =>
        this.toolSchemaValidator.evaluate({
          headers: {},
          bodyJson: bodyJson && typeof bodyJson === 'object' ? bodyJson : {},
          provider: 'playground',
          path: '/_sentinel/playground/analyze',
          effectiveMode,
        })
    );

    await runEngine(
      'multimodal_injection_shield',
      () =>
        this.multiModalInjectionShield.evaluate({
          headers,
          rawBody,
          bodyText: text,
          bodyJson,
          effectiveMode,
        })
    );

    await runEngine(
      'output_classifier',
      () =>
        this.outputClassifier.classifyText(text, {
          effectiveMode,
        }),
      (result) => ({
        enabled: result?.enabled !== false,
        detected: result?.shouldWarn === true,
        shouldBlock: result?.shouldBlock === true,
        reason: result?.reasons?.[0] || 'clean',
        findings: Array.isArray(result?.warnedBy) ? result.warnedBy : [],
      })
    );

    await runEngine('stego_exfil_detector', () =>
      this.stegoExfilDetector.analyzeText(text, {
        effectiveMode,
      })
    );

    await runEngine('reasoning_trace_monitor', () =>
      this.reasoningTraceMonitor.analyzeText(text, {
        effectiveMode,
      })
    );

    await runEngine('hallucination_tripwire', () =>
      this.hallucinationTripwire.analyzeText(text, {
        effectiveMode,
      })
    );

    const engineList = Object.keys(engines);
    const detections = engineList.filter((name) => engines[name].detected === true).length;
    const blockEligible = engineList.filter((name) => engines[name].shouldBlock === true).length;
    const risk = blockEligible > 0
      ? 'high'
      : detections >= 4
        ? 'medium'
        : detections > 0
          ? 'low'
          : 'minimal';

    return {
      prompt_chars: text.length,
      runtime_engine_inventory: {
        configured_runtime_engines: this.runtimeEngineKeyByProp.size,
        loaded_runtime_engines: this.lazyEngineState.loaded.length,
        skipped_runtime_engines: this.lazyEngineState.skipped.length,
      },
      summary: {
        engines_evaluated: engineList.length,
        detections,
        block_eligible: blockEligible,
        risk,
      },
      engines,
    };
  }

  buildForensicEvaluators() {
    const defaultInjectionThreshold = Number(this.config?.injection?.threshold ?? 0.8);
    const defaultPromptRebuffThreshold = Number(this.config?.runtime?.prompt_rebuff?.block_threshold ?? 0.85);
    return [
      {
        name: 'injection_threshold_probe',
        run({ decision = {}, overrides = {} }) {
          const score = Number(
            decision.injection_score
            || decision.prompt_rebuff_score
            || decision.policy?.injection_score
            || 0
          );
          const threshold = Number(
            overrides.injection_threshold ?? defaultInjectionThreshold
          );
          return {
            blocked: score >= threshold,
            score,
            threshold,
          };
        },
      },
      {
        name: 'prompt_rebuff_probe',
        run({ decision = {}, overrides = {} }) {
          const score = Number(decision.prompt_rebuff_score || 0);
          const threshold = Number(
            overrides.prompt_rebuff_threshold ?? defaultPromptRebuffThreshold
          );
          return {
            blocked: score >= threshold,
            score,
            threshold,
          };
        },
      },
    ];
  }

  buildForensicReplay({ snapshot = {}, overrides = {} } = {}) {
    const replay = this.forensicDebugger.replay(
      snapshot,
      this.buildForensicEvaluators(),
      overrides
    );
    const replayDecision = replay.results[0]?.result || {};
    const diff = this.forensicDebugger.diff(snapshot.decision || {}, replayDecision);
    return {
      snapshot_id: snapshot.id || null,
      replay,
      diff,
    };
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
      let posture = null;
      try {
        const postureConfig = this.config.runtime?.posture_scoring || {};
        if (postureConfig.enabled !== false) {
          posture = this.postureScorer({
            config: this.config,
            counters: this.stats,
            options: {
              warnThreshold: postureConfig.warn_threshold,
              criticalThreshold: postureConfig.critical_threshold,
              includeCounters: postureConfig.include_counters,
            },
          });
        }
      } catch (error) {
        logger.warn('health posture scoring failed', {
          error: error.message,
        });
        posture = {
          error: 'posture_unavailable',
        };
      }
      res.status(200).json({
        status: 'ok',
        posture,
      });
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

    this.app.post('/_sentinel/provenance/verify', (req, res) => {
      if (!this.outputProvenanceSigner?.isEnabled?.() || this.outputProvenanceSigner.exposeVerifyEndpoint !== true) {
        res.status(404).json({
          error: 'OUTPUT_PROVENANCE_DISABLED',
        });
        return;
      }

      let payload = {};
      try {
        payload = JSON.parse(Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '{}');
      } catch {
        payload = {};
      }
      const verification = this.outputProvenanceSigner.verifyEnvelope({
        envelope: payload.envelope || '',
        expectedOutputSha256: payload.output_sha256 || '',
      });
      res.status(verification.valid ? 200 : 400).json(verification);
    });

    this.app.post('/_sentinel/watermark/verify', (req, res) => {
      if (!this.tokenWatermark?.isEnabled?.() || this.tokenWatermark.exposeVerifyEndpoint !== true) {
        res.status(404).json({
          error: 'TOKEN_WATERMARK_DISABLED',
        });
        return;
      }

      let payload = {};
      try {
        payload = JSON.parse(Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '{}');
      } catch {
        payload = {};
      }
      const verification = this.tokenWatermark.verifyEnvelope({
        envelope: payload.envelope || '',
        expectedOutputSha256: payload.output_sha256 || '',
        expectedTokenFingerprint: payload.token_fingerprint_sha256 || '',
      });
      res.status(verification.valid ? 200 : 400).json(verification);
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

    this.app.get('/_sentinel/capabilities', (req, res) => {
      if (!this.capabilityIntrospection?.isEnabled?.()) {
        res.status(404).json({
          error: 'CAPABILITY_INTROSPECTION_DISABLED',
        });
        return;
      }
      const snapshot = this.capabilityIntrospection.snapshot(this);
      this.stats.capability_snapshots += 1;
      res.status(200).json(snapshot);
    });

    this.app.get('/_sentinel/attestation', (req, res) => {
      if (!this.computeAttestation?.isEnabled?.()) {
        res.status(404).json({
          error: 'ATTESTATION_DISABLED',
        });
        return;
      }
      const report = this.computeAttestation.create({
        configHash: this.getRuntimeConfigHash(),
        policyHash: sha256Text(JSON.stringify(this.config?.rules || [])),
        correlationId: String(req.headers?.['x-sentinel-correlation-id'] || ''),
        provider: 'sentinel',
      });
      this.stats.compute_attestation_signed += report?.envelope ? 1 : 0;
      res.status(200).json(report || { envelope: null });
    });

    this.app.post('/_sentinel/attestation/verify', (req, res) => {
      if (!this.computeAttestation?.isEnabled?.() || this.computeAttestation.exposeVerifyEndpoint !== true) {
        res.status(404).json({
          error: 'ATTESTATION_DISABLED',
        });
        return;
      }
      let payload = {};
      try {
        payload = JSON.parse(Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '{}');
      } catch {
        payload = {};
      }
      const verification = this.computeAttestation.verify(String(payload.envelope || ''));
      res.status(verification.valid ? 200 : 400).json(verification);
    });

    this.app.post('/_sentinel/policy/gradient', (req, res) => {
      if (!this.policyGradientAnalyzer?.isEnabled?.()) {
        res.status(404).json({
          error: 'POLICY_GRADIENT_ANALYZER_DISABLED',
        });
        return;
      }
      let payload = {};
      try {
        payload = JSON.parse(Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '{}');
      } catch {
        payload = {};
      }
      const report = this.policyGradientAnalyzer.analyze({
        events: Array.isArray(payload.events) ? payload.events : [],
        current: payload.current && typeof payload.current === 'object' ? payload.current : {},
        proposed: payload.proposed && typeof payload.proposed === 'object' ? payload.proposed : {},
      });
      this.stats.policy_gradient_runs += 1;
      res.status(200).json(report);
    });

    this.app.get('/_sentinel/anomalies', (req, res) => {
      if (!this.anomalyTelemetry?.isEnabled?.()) {
        res.status(404).json({
          error: 'ANOMALY_TELEMETRY_DISABLED',
        });
        return;
      }
      res.status(200).json(this.anomalyTelemetry.snapshot());
    });

    this.app.get('/_sentinel/threat-intel', (req, res) => {
      if (!this.threatIntelMesh?.isEnabled?.()) {
        res.status(404).json({
          error: 'THREAT_INTEL_MESH_DISABLED',
        });
        return;
      }
      res.status(200).json(this.threatIntelMesh.exportSnapshot());
    });

    this.app.get('/_sentinel/zk-config', (req, res) => {
      if (!this.zkConfigValidator?.isEnabled?.()) {
        res.status(404).json({
          error: 'ZK_CONFIG_VALIDATOR_DISABLED',
        });
        return;
      }
      const exportPayload = this.zkConfigValidator.safeExport(this.config, {
        knownRuntimeKeys: Object.keys(this.config?.runtime || {}),
      });
      this.zkConfigAssessment = exportPayload;
      this.stats.zk_config_findings = Array.isArray(exportPayload.findings) ? exportPayload.findings.length : 0;
      res.status(200).json(exportPayload);
    });

    this.app.post('/_sentinel/adversarial-eval/run', (req, res) => {
      if (!this.adversarialEvalHarness?.isEnabled?.()) {
        res.status(404).json({
          error: 'ADVERSARIAL_EVAL_HARNESS_DISABLED',
        });
        return;
      }
      let payload = {};
      try {
        payload = JSON.parse(Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '{}');
      } catch {
        payload = {};
      }
      const result = this.adversarialEvalHarness.run({
        cases: Array.isArray(payload.cases) ? payload.cases : [],
        adapters: {
          injectionScan: (text) => this.policyEngine.scanInjection(String(text || '')),
          promptRebuff: (text) => {
            if (!this.promptRebuff?.isEnabled?.()) {
              return { detected: false, score: 0 };
            }
            const injectionResult = this.policyEngine.scanInjection(String(text || ''));
            return this.promptRebuff.evaluate({
              headers: {},
              correlationId: 'adversarial-eval',
              bodyText: String(text || ''),
              injectionResult,
              effectiveMode: 'monitor',
            });
          },
        },
        runId: String(payload.run_id || ''),
      });
      if (result?.report) {
        this.stats.adversarial_eval_runs += 1;
        if (result.report.summary?.regression_detected === true) {
          this.stats.adversarial_eval_regressions += 1;
        }
      }
      res.status(200).json(result);
    });

    this.app.get('/_sentinel/forensic/snapshots', (req, res) => {
      if (!this.forensicDebugger?.isEnabled?.()) {
        res.status(404).json({
          error: 'FORENSIC_DEBUGGER_DISABLED',
        });
        return;
      }
      const requested = Number(req.query?.limit);
      const limit = Number.isFinite(requested)
        ? Math.max(1, Math.min(Math.floor(requested), 200))
        : 50;
      const snapshots = this.forensicDebugger.listSnapshots({ limit });
      res.status(200).json({
        count: snapshots.length,
        snapshots,
      });
    });

    this.app.get('/_sentinel/forensic/snapshots/:id', (req, res) => {
      if (!this.forensicDebugger?.isEnabled?.()) {
        res.status(404).json({
          error: 'FORENSIC_DEBUGGER_DISABLED',
        });
        return;
      }
      const snapshotId = String(req.params?.id || '');
      const includePayload = String(req.query?.include_payload || '').toLowerCase() === 'true';
      const snapshot = this.forensicDebugger.getSnapshot(snapshotId, {
        includePayload,
      });
      if (!snapshot) {
        res.status(404).json({
          error: 'FORENSIC_SNAPSHOT_NOT_FOUND',
        });
        return;
      }
      res.status(200).json(snapshot);
    });

    this.app.post('/_sentinel/forensic/replay', (req, res) => {
      if (!this.forensicDebugger?.isEnabled?.()) {
        res.status(404).json({
          error: 'FORENSIC_DEBUGGER_DISABLED',
        });
        return;
      }
      let payload = {};
      try {
        payload = JSON.parse(Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '{}');
      } catch {
        payload = {};
      }
      const snapshotId = String(payload.snapshot_id || '');
      const snapshot = snapshotId
        ? this.forensicDebugger.getSnapshot(snapshotId, { includePayload: true })
        : this.forensicDebugger.latestSnapshot({ includePayload: true });

      if (!snapshot) {
        res.status(404).json({
          error: 'FORENSIC_SNAPSHOT_NOT_FOUND',
        });
        return;
      }
      const overrides = payload.overrides && typeof payload.overrides === 'object'
        ? payload.overrides
        : {};
      const report = this.buildForensicReplay({
        snapshot,
        overrides,
      });
      res.status(200).json(report);
    });

    this.app.get('/_sentinel/metrics', (req, res) => {
      const payload = this.prometheus.renderMetrics({
        counters: this.stats,
        providers: this.circuitBreakers.snapshot(),
        agentObservability: this.agentObservability.snapshotMetrics(),
      });
      res.setHeader('content-type', 'text/plain; version=0.0.4; charset=utf-8');
      res.status(200).send(payload);
    });

    this.app.get('/_sentinel/playground', (req, res) => {
      res.setHeader('cache-control', 'no-store');
      res.status(200).type('html').send(PLAYGROUND_HTML);
    });

    this.app.post('/_sentinel/playground/analyze', async (req, res) => {
      let payload = {};
      try {
        if (Buffer.isBuffer(req.body)) {
          payload = parseJsonMaybe(req.body.toString('utf8')) || {};
        } else if (typeof req.body === 'string') {
          payload = parseJsonMaybe(req.body) || {};
        } else if (req.body && typeof req.body === 'object') {
          payload = req.body;
        }
      } catch {
        payload = {};
      }

      const prompt = String(payload.prompt || '');
      if (!prompt.trim()) {
        res.status(400).json({
          error: 'PLAYGROUND_PROMPT_REQUIRED',
        });
        return;
      }

      try {
        const analysis = await this.buildPlaygroundAnalysis({
          prompt,
          correlationId: String(req.headers?.['x-sentinel-correlation-id'] || ''),
        });
        res.status(200).json(analysis);
      } catch (error) {
        logger.warn('playground analysis failed', {
          error: String(error?.message || error),
        });
        res.status(500).json({
          error: 'PLAYGROUND_ANALYSIS_FAILED',
        });
      }
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
      const agentObservabilityContext = this.agentObservability.startRequest({
        correlationId,
        headers: req.headers || {},
        method,
        path: parsedPath.pathname,
        requestStart,
      });
      if (this.agentObservability.isEnabled()) {
        res.setHeader('traceparent', agentObservabilityContext.traceparent);
      }
      pipelineContext.set('agent_observability', agentObservabilityContext);
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
        onFinalize: ({ decision, status, providerName, error }) => {
          this.agentObservability.finishRequest(agentObservabilityContext, {
            decision,
            statusCode: status,
            provider: providerName,
            error,
          });
        },
      });

      if (rejectUnsupportedMethod({ method, res, correlationId, finalizeRequestTelemetry })) {
        return;
      }

      this.stats.requests_total += 1;
      this.telemetry.addRequest({
        method,
        route: parsedPath.pathname,
      });
      if (this.adversarialEvalHarness?.isEnabled?.()) {
        const evalRun = this.adversarialEvalHarness.maybeRun({
          requestCount: this.stats.requests_total,
          adapters: {
            injectionScan: (text) => this.policyEngine.scanInjection(String(text || '')),
            promptRebuff: (text) => {
              if (!this.promptRebuff?.isEnabled?.()) {
                return { detected: false, score: 0 };
              }
              return this.promptRebuff.evaluate({
                headers: {},
                correlationId: 'scheduled-adversarial-eval',
                bodyText: String(text || ''),
                injectionResult: this.policyEngine.scanInjection(String(text || '')),
                effectiveMode: 'monitor',
              });
            },
          },
        });
        if (evalRun?.executed) {
          this.stats.adversarial_eval_runs += 1;
          if (evalRun.report?.summary?.regression_detected === true) {
            this.stats.adversarial_eval_regressions += 1;
          }
        }
      }
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
      if (this.aibom && typeof this.aibom.recordRequest === 'function') {
        this.aibom.recordRequest({
          provider,
          headers: req.headers || {},
          body: bodyJson,
        });
      }
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
      const budgetSnapshotForCost = this.budgetStore.snapshot();
      let costEfficiencyDecision = null;
      if (this.costEfficiencyOptimizer?.isEnabled?.()) {
        try {
          costEfficiencyDecision = this.costEfficiencyOptimizer.evaluate({
            provider,
            bodyText,
            bodyJson,
            latencyMs: Date.now() - requestStart,
            budgetRemainingUsd: Number(budgetSnapshotForCost.remainingUsd || 0),
            effectiveMode,
          });
        } catch (error) {
          costEfficiencyDecision = {
            enabled: true,
            detected: false,
            shouldBlock: false,
            reason: 'cost_efficiency_error',
            findings: [],
            error: String(error.message || error),
          };
          warnings.push('cost_efficiency:error');
          this.stats.warnings_total += 1;
        }

        if (costEfficiencyDecision?.enabled && this.costEfficiencyOptimizer.observability) {
          res.setHeader(
            'x-sentinel-cost-efficiency',
            costEfficiencyDecision.detected ? String(costEfficiencyDecision.reason || 'detected') : 'clean'
          );
          if (costEfficiencyDecision.route_recommendation?.provider) {
            res.setHeader('x-sentinel-cost-route-recommendation', String(costEfficiencyDecision.route_recommendation.provider));
          }
        }
        if (costEfficiencyDecision?.detected) {
          this.stats.cost_efficiency_detected += 1;
          warnings.push(`cost_efficiency:${costEfficiencyDecision.reason || 'detected'}`);
          this.stats.warnings_total += 1;
        }
        if (costEfficiencyDecision?.enabled) {
          this.applyMemoryPressurePolicy({
            decision: costEfficiencyDecision,
            warnings,
            res,
          });
        }
        if (costEfficiencyDecision?.shouldBlock) {
          this.stats.blocked_total += 1;
          this.stats.policy_blocked += 1;
          this.stats.cost_efficiency_blocked += 1;
          res.setHeader('x-sentinel-blocked-by', 'cost_efficiency_optimizer');
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
            decision: 'blocked_cost_efficiency',
            reasons: [String(costEfficiencyDecision.reason || 'cost_efficiency_violation')],
            pii_types: [],
            redactions: 0,
            duration_ms: Date.now() - requestStart,
            request_bytes: rawBody.length,
            response_status: 429,
            response_bytes: 0,
            provider,
            cost_efficiency_findings: costEfficiencyDecision.findings || [],
          });
          this.writeStatus();
          finalizeRequestTelemetry({
            decision: 'blocked_policy',
            status: 429,
            providerName: provider,
          });
          res.status(429).json({
            error: 'COST_EFFICIENCY_BLOCKED',
            reason: costEfficiencyDecision.reason || 'cost_efficiency_violation',
            correlation_id: correlationId,
          });
          return;
        }
      }
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

        let result;
        try {
          result = await execute();
        } catch (error) {
          this.agentObservability.emitLifecycle(
            agentObservabilityContext,
            'agent.error',
            {
              stage: stageName,
              provider: stageProvider || 'unknown',
              error: String(error.message || error),
            }
          );
          throw error;
        }
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
          agentObservabilityContext,
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

      const agenticStageExecution = await runOrchestratedStage('agentic_threat_shield', async () =>
        runAgenticStage({
          server: this,
          req,
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
          agentObservabilityContext,
        })
      );
      if (agenticStageExecution.handled) {
        return;
      }
      const agenticStageResult = agenticStageExecution.result;
      if (agenticStageResult.handled) {
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
      let forwardHeaders = scrubForwardHeaders(req.headers);
      forwardHeaders = this.agentObservability.injectForwardHeaders(
        forwardHeaders,
        agentObservabilityContext
      );
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
          req,
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
    if (typeof this.server?.on === 'function') {
      this.server.on('connection', (socket) => {
        this.serverSockets.add(socket);
        socket.once('close', () => {
          this.serverSockets.delete(socket);
        });
      });
      this.server.on('upgrade', (req, socket, head) => {
        handleWebSocketUpgrade({
          server: this,
          req,
          socket,
          head,
        }).catch((error) => {
          this.stats.websocket_errors += 1;
          logger.warn('websocket upgrade handler failed', {
            error: error.message,
            url: req?.url,
          });
          if (!socket.destroyed) {
            socket.destroy(error);
          }
        });
      });
    }

    const dashboardConfig = this.config.runtime?.dashboard || {};
    if (dashboardConfig.enabled === true) {
      this.dashboardServer = new DashboardServer({
        host: dashboardConfig.host,
        port: dashboardConfig.port,
        allowRemote: dashboardConfig.allow_remote === true,
        authToken: dashboardConfig.auth_token,
        teamTokens: dashboardConfig.team_tokens,
        teamHeader: dashboardConfig.team_header,
        statusProvider: () => this.currentStatusPayload(),
        anomaliesProvider: () =>
          this.anomalyTelemetry?.isEnabled?.()
            ? this.anomalyTelemetry.snapshot()
            : { enabled: false, events_total: 0, heatmap: [] },
        forensicsProvider: () =>
          this.forensicDebugger?.isEnabled?.()
            ? {
              enabled: true,
              snapshots: this.forensicDebugger.listSnapshots({ limit: 20 }),
            }
            : {
              enabled: false,
              snapshots: [],
            },
        forensicReplayProvider: ({ snapshotId = '', overrides = {} } = {}) => {
          if (!this.forensicDebugger?.isEnabled?.()) {
            return {
              enabled: false,
              error: 'FORENSIC_DEBUGGER_DISABLED',
            };
          }
          const snapshot = snapshotId
            ? this.forensicDebugger.getSnapshot(snapshotId, { includePayload: true })
            : this.forensicDebugger.latestSnapshot({ includePayload: true });
          if (!snapshot) {
            return {
              enabled: true,
              error: 'FORENSIC_SNAPSHOT_NOT_FOUND',
            };
          }
          return this.buildForensicReplay({
            snapshot,
            overrides: overrides && typeof overrides === 'object' ? overrides : {},
          });
        },
        accessLogger: (event) => this.recordDashboardAccess(event),
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
    if (this.webSocketSockets.size > 0) {
      for (const socket of this.webSocketSockets) {
        try {
          socket.destroy();
        } catch {
          // best-effort shutdown
        }
      }
      this.webSocketSockets.clear();
    }
    if (this.serverSockets.size > 0) {
      for (const socket of this.serverSockets) {
        try {
          socket.destroy();
        } catch {
          // best-effort shutdown
        }
      }
      this.serverSockets.clear();
    }

    await new Promise((resolve) => {
      if (!this.server) {
        resolve();
        return;
      }
      const instance = this.server;
      let settled = false;
      const finish = () => {
        if (settled) {
          return;
        }
        settled = true;
        resolve();
      };
      const closeTimeout = setTimeout(() => {
        logger.warn('Sentinel shutdown close timeout; forcing connection cleanup', {
          open_connections: this.serverSockets.size,
          open_ws_sockets: this.webSocketSockets.size,
        });
        if (typeof instance.closeIdleConnections === 'function') {
          try {
            instance.closeIdleConnections();
          } catch {
            // best-effort shutdown
          }
        }
        if (typeof instance.closeAllConnections === 'function') {
          try {
            instance.closeAllConnections();
          } catch {
            // best-effort shutdown
          }
        }
        finish();
      }, 3000);
      closeTimeout.unref?.();
      instance.close(() => {
        clearTimeout(closeTimeout);
        finish();
      });
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
