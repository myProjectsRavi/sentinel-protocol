# `sentinel status --json` schema

`sentinel status --json` reads Sentinel's persisted local status snapshot and prints it as JSON. The command is intentionally local-only; it does not call a provider or control plane.

## Update cadence and consistency

The running server writes the status snapshot:

- when startup reaches the running state;
- after request paths that explicitly call `writeStatus()` (including upstream-error handling and security/audit decisions);
- when runtime override polling observes a change;
- on a 2-second periodic status interval;
- during shutdown, after the service state becomes stopped.

`counters.upstream_errors` is incremented exactly once when a request is returned through Sentinel's upstream-error response path. The same response writes an `upstream_error` audit event and persists status before the response is returned. It therefore counts request-level upstream failures surfaced to callers, not every internal retry attempt. Internal attempt-level telemetry is tracked separately by the OpenTelemetry upstream-error counter.

## Configured mode vs effective mode

| Field | Meaning |
|---|---|
| `configured_mode` | Mode loaded from configuration (`monitor`, `warn`, or `enforce`). It describes intent, not necessarily the mode currently applied to blocking decisions. |
| `effective_mode` | Mode currently applied by the server. It becomes `monitor` when `--dry-run` is active, fail-open is enabled, `runtime.fail_open` is enabled, or the emergency-open runtime override is active; otherwise it equals `configured_mode`. |
| `emergency_open` | Whether the persisted emergency-open runtime override is active. |

Dashboards and automation should use `effective_mode` when deciding what Sentinel is actually enforcing and retain `configured_mode` for configuration/drift reporting.

## Core top-level fields

| Field | Type | Semantics |
|---|---|---|
| `service_status` | string | `running` while the server is active; `stopped` after shutdown. |
| `configured_mode` | string | Configured policy mode. See mode notes above. |
| `effective_mode` | string | Runtime-effective policy mode. See mode notes above. |
| `emergency_open` | boolean | Emergency fail-open override state. |
| `providers` | object | Per-breaker/provider circuit metrics; schema below. |
| `pii_provider_mode` | string | Configured PII provider strategy. |
| `pii_provider_fallbacks` | number | Number of PII-provider fallback events observed by this process. |
| `rapidapi_error_count` | number | Number of RapidAPI PII-provider errors observed by this process. |
| `plugins_registered` | array | Registered plugin identifiers reported by the plugin registry. |
| `uptime_seconds` | number | Whole seconds since this SentinelServer instance was created. |
| `version` | number/string | Sentinel configuration schema version from the loaded config, not the npm package version. |
| `counters` | object | Process-local monotonic runtime counters. Important keys are documented below. |
| `pid` | number | PID of the running Sentinel CLI/server process that wrote the snapshot. |

## Provider circuit metrics

Each `providers.<breakerKey>` entry has the following fields:

| Field | Type | Semantics |
|---|---|---|
| `circuit_state` | string | `closed`, `open`, `half-open`, or `disabled`. |
| `failure_rate_window` | number | Failure fraction (0–1) across the breaker's bounded recent history window. |
| `consecutive_timeouts` | number | Consecutive timeout failures; reset by a success or non-timeout failure. |
| `total_forwarded` | number | Upstream attempts recorded by this breaker state, including successes and failures. A circuit-open fast rejection is not an upstream network attempt and therefore is not added here. |
| `total_failures` | number | Upstream attempts recorded as failures by the breaker. |
| `open_until` | number | Unix epoch milliseconds at which an open circuit becomes eligible for a half-open probe; `0` when not scheduled. |
| `half_open_successes` | number | Successful half-open probes accumulated toward closing the circuit. |

Example:

```json
{
  "providers": {
    "openai": {
      "circuit_state": "open",
      "failure_rate_window": 0.75,
      "consecutive_timeouts": 2,
      "total_forwarded": 12,
      "total_failures": 5,
      "open_until": 1786886000000,
      "half_open_successes": 0
    }
  }
}
```

## Runtime feature fields

Most optional runtime engines expose an `*_enabled` boolean and, when that engine has enforcement modes, a matching `*_mode` string. Snapshot/stat objects are runtime diagnostics and may gain additive fields in future minor releases.

| Field | Type | Semantics |
|---|---|---|
| `pii_vault_enabled` | boolean | Two-way PII vault enabled state. |
| `pii_vault_mode` | string | PII vault mode. |
| `pii_vault_stats` | object | PII vault runtime statistics. |
| `loop_breaker_enabled` | boolean | Agent loop breaker enabled state. |
| `agentic_threat_shield_enabled` | boolean | Agentic threat shield enabled state. |
| `agentic_threat_shield_mode` | string | Agentic threat shield mode. |
| `a2a_card_verifier_enabled` | boolean | A2A card verifier enabled state. |
| `a2a_card_verifier_mode` | string | A2A card verifier mode. |
| `consensus_protocol_enabled` | boolean | Consensus protocol enabled state. |
| `consensus_protocol_mode` | string | Consensus protocol mode. |
| `cross_tenant_isolator_enabled` | boolean | Cross-tenant isolator enabled state. |
| `cross_tenant_isolator_mode` | string | Cross-tenant isolator mode. |
| `cold_start_analyzer_enabled` | boolean | Cold-start analyzer enabled state. |
| `cold_start_analyzer_mode` | string | Cold-start analyzer mode. |
| `auto_immune_enabled` | boolean | Auto-immune engine enabled state. |
| `auto_immune_mode` | string | Auto-immune mode. |
| `auto_immune_stats` | object | Auto-immune runtime statistics. |
| `deception_enabled` | boolean | Deception engine enabled state. |
| `provenance_enabled` | boolean | Request provenance signing enabled state. |
| `swarm_enabled` | boolean | Swarm protocol enabled state. |
| `swarm_mode` | string | Swarm protocol mode. |
| `swarm_allowed_clock_skew_ms` | number | Accepted signed-message clock skew window in milliseconds. |
| `swarm_node_metrics` | object | Per-node verification/rejection counters and skew observations. |
| `honeytoken_enabled` | boolean | Honeytoken injection enabled state. |
| `polymorphic_prompt_enabled` | boolean | Polymorphic prompt moving-target defense enabled state. |
| `synthetic_poisoning_enabled` | boolean | Synthetic poisoning enabled state. |
| `synthetic_poisoning_mode` | string | Synthetic poisoning mode. |
| `cognitive_rollback_enabled` | boolean | Cognitive rollback enabled state. |
| `cognitive_rollback_mode` | string | Cognitive rollback mode. |
| `omni_shield_enabled` | boolean | Omni-Shield enabled state. |
| `omni_shield_mode` | string | Omni-Shield mode. |
| `sandbox_experimental_enabled` | boolean | Experimental sandbox enabled state. |
| `sandbox_experimental_mode` | string | Experimental sandbox mode. |
| `latency_normalization_enabled` | boolean | Latency normalization enabled state. |
| `intent_throttle_enabled` | boolean | Intent throttle enabled state. |
| `intent_throttle_mode` | string | Intent throttle mode. |
| `intent_drift_enabled` | boolean | Intent drift detector enabled state. |
| `intent_drift_mode` | string | Intent drift detector mode. |
| `mcp_poisoning_enabled` | boolean | MCP poisoning detector enabled state. |
| `mcp_poisoning_mode` | string | MCP poisoning detector mode. |
| `mcp_shadow_enabled` | boolean | MCP shadow detector enabled state. |
| `mcp_shadow_mode` | string | MCP shadow detector mode. |
| `mcp_certificate_pinning_enabled` | boolean | MCP certificate pinning enabled state. |
| `mcp_certificate_pinning_mode` | string | MCP certificate pinning mode. |
| `memory_poisoning_enabled` | boolean | Memory poisoning sentinel enabled state. |
| `memory_poisoning_mode` | string | Memory poisoning sentinel mode. |
| `cascade_isolator_enabled` | boolean | Cascade isolator enabled state. |
| `cascade_isolator_mode` | string | Cascade isolator mode. |
| `agent_identity_federation_enabled` | boolean | Agent identity federation enabled state. |
| `agent_identity_federation_mode` | string | Agent identity federation mode. |
| `tool_use_anomaly_enabled` | boolean | Tool-use anomaly detector enabled state. |
| `tool_use_anomaly_mode` | string | Tool-use anomaly detector mode. |
| `behavioral_fingerprint_enabled` | boolean | Behavioral fingerprinting enabled state. |
| `behavioral_fingerprint_mode` | string | Behavioral fingerprint mode. |
| `serialization_firewall_enabled` | boolean | Serialization firewall enabled state. |
| `serialization_firewall_mode` | string | Serialization firewall mode. |
| `context_integrity_guardian_enabled` | boolean | Context integrity guardian enabled state. |
| `context_integrity_guardian_mode` | string | Context integrity guardian mode. |
| `context_compression_guard_enabled` | boolean | Context-compression guard enabled state. |
| `context_compression_guard_mode` | string | Context-compression guard mode. |
| `tool_schema_validator_enabled` | boolean | Tool schema validator enabled state. |
| `tool_schema_validator_mode` | string | Tool schema validator mode. |
| `multimodal_injection_shield_enabled` | boolean | Multimodal injection shield enabled state. |
| `multimodal_injection_shield_mode` | string | Multimodal injection shield mode. |
| `supply_chain_validator_enabled` | boolean | Supply-chain validator enabled state. |
| `supply_chain_validator_mode` | string | Supply-chain validator mode. |
| `sandbox_enforcer_enabled` | boolean | Sandbox enforcer enabled state. |
| `sandbox_enforcer_mode` | string | Sandbox enforcer mode. |
| `memory_integrity_monitor_enabled` | boolean | Memory integrity monitor enabled state. |
| `memory_integrity_monitor_mode` | string | Memory integrity monitor mode. |
| `threat_intel_mesh_enabled` | boolean | Threat-intel mesh enabled state. |
| `threat_intel_mesh_mode` | string | Threat-intel mesh mode. |
| `threat_intel_mesh_signatures` | number | In-memory threat signatures currently loaded. |
| `threat_intel_mesh_peers` | number | Configured threat-intel peers. |
| `threat_intel_mesh_sync_enabled` | boolean | Peer synchronization enabled state. |
| `threat_intel_mesh_sync_runs` | number | Synchronization runs tracked by the mesh. |
| `threat_intel_mesh_sync_failures` | number | Synchronization failures tracked by the mesh. |
| `lfrl_enabled` | boolean | LFRL engine enabled state. |
| `lfrl_mode` | string | LFRL engine mode. |
| `lfrl_rules_loaded` | number | Compiled LFRL rules currently loaded. |
| `self_healing_immune_enabled` | boolean | Self-healing immune system enabled state. |
| `self_healing_immune_mode` | string | Self-healing immune mode. |
| `self_healing_signatures` | number | Self-healing signatures currently loaded. |
| `semantic_firewall_dsl_enabled` | boolean | Semantic firewall DSL enabled state. |
| `prompt_rebuff_enabled` | boolean | Prompt Rebuff enabled state. |
| `prompt_rebuff_mode` | string | Prompt Rebuff mode. |
| `output_classifier_enabled` | boolean | Output classifier enabled state. |
| `stego_exfil_detector_enabled` | boolean | Steganographic exfiltration detector enabled state. |
| `stego_exfil_detector_mode` | string | Steganographic exfiltration detector mode. |
| `reasoning_trace_monitor_enabled` | boolean | Reasoning-trace monitor enabled state. |
| `reasoning_trace_monitor_mode` | string | Reasoning-trace monitor mode. |
| `hallucination_tripwire_enabled` | boolean | Hallucination tripwire enabled state. |
| `hallucination_tripwire_mode` | string | Hallucination tripwire mode. |
| `semantic_drift_canary_enabled` | boolean | Semantic drift canary enabled state. |
| `semantic_drift_canary_mode` | string | Semantic drift canary mode. |
| `output_provenance_enabled` | boolean | Output provenance signing enabled state. |
| `token_watermark_enabled` | boolean | Token watermark enabled state. |
| `compute_attestation_enabled` | boolean | Compute attestation enabled state. |
| `output_schema_validator_enabled` | boolean | Output schema validator enabled state. |
| `budget_autopilot_enabled` | boolean | Budget autopilot enabled state. |
| `budget_autopilot_mode` | string | Budget autopilot mode. |
| `budget_autopilot_recommendation` | object/null | Current optimizer recommendation snapshot. |
| `cost_efficiency_optimizer_enabled` | boolean | Cost-efficiency optimizer enabled state. |
| `cost_efficiency_optimizer_mode` | string | Cost-efficiency optimizer mode. |
| `cost_efficiency_optimizer_snapshot` | object | Cost-efficiency optimizer runtime snapshot. |
| `memory_shed_active_engines` | number | Number of optional engines temporarily shed under memory pressure. |
| `memory_shed_order` | array | Runtime keys eligible for memory-pressure shedding, in priority order. |
| `lazy_engine_loading_enabled` | boolean | Lazy optional-engine loading enabled state. |
| `lazy_engine_loaded` | number | Number of lazily loaded engines. |
| `lazy_engine_skipped` | number | Number of optional engines skipped by lazy loading. |
| `lazy_engine_loaded_keys` | array | Loaded runtime engine keys, bounded to 256 entries. |
| `lazy_engine_skipped_keys` | array | Skipped runtime engine keys, bounded to 256 entries. |
| `evidence_vault_enabled` | boolean | Evidence vault enabled state. |
| `evidence_vault_stats` | object | Evidence vault runtime statistics. |
| `threat_graph_enabled` | boolean | Threat propagation graph enabled state. |
| `attack_corpus_evolver_enabled` | boolean | Attack corpus evolver enabled state. |
| `forensic_debugger_enabled` | boolean | Forensic debugger enabled state. |
| `forensic_debugger_snapshots` | number | In-memory forensic snapshots. |
| `capability_introspection_enabled` | boolean | Capability introspection enabled state. |
| `policy_gradient_analyzer_enabled` | boolean | Policy gradient analyzer enabled state. |
| `adversarial_eval_harness_enabled` | boolean | Adversarial evaluation harness enabled state. |
| `adversarial_eval_latest` | object/null | Latest adversarial-evaluation result. |
| `anomaly_telemetry_enabled` | boolean | Anomaly telemetry enabled state. |
| `anomaly_telemetry_snapshot` | object | Current anomaly telemetry snapshot. |
| `zk_config_validator_enabled` | boolean | ZK configuration validator enabled state. |
| `zk_config_assessment` | object | Latest ZK configuration assessment. |
| `agent_observability_enabled` | boolean | Agent observability enabled state. |
| `shadow_os_enabled` | boolean | ShadowOS enabled state. |
| `shadow_os_mode` | string | ShadowOS mode. |
| `shadow_os_stats` | object | ShadowOS runtime statistics. |
| `epistemic_anchor_enabled` | boolean | Epistemic anchor enabled state. |
| `epistemic_anchor_mode` | string | Epistemic anchor mode. |
| `canary_tools_enabled` | boolean | Canary tool trap enabled state. |
| `parallax_enabled` | boolean | Parallax validator enabled state. |
| `vcr_mode` | string | VCR runtime mode or `off`. |
| `semantic_cache_enabled` | boolean | Semantic cache effective enabled state. |

## Budget, dashboard, AIBOM and WebSocket fields

| Field | Type | Semantics |
|---|---|---|
| `budget_enabled` | boolean | Daily budget accounting enabled state. |
| `budget_action` | string | Configured action when budget policy triggers. |
| `budget_day_key` | string | Current accounting day key. |
| `budget_daily_limit_usd` | number | Daily configured USD budget. |
| `budget_spent_usd_today` | number | Estimated spend recorded today. |
| `budget_remaining_usd_today` | number | Remaining estimated daily budget. |
| `budget_requests_today` | number | Requests counted in the current budget day. |
| `dashboard_enabled` | boolean | Local dashboard enabled state. |
| `dashboard_host` | string | Dashboard bind host. |
| `dashboard_port` | number | Dashboard port. |
| `aibom` | object | Current local AI bill-of-materials artifact. |
| `websocket_enabled` | boolean | WebSocket interception enabled state. |
| `websocket_mode` | string | WebSocket interception mode. |
| `websocket_active_tunnels` | number | Currently active WebSocket tunnels. |

## Important `counters` fields

`counters` is the process-local runtime counter bag. Counters are monotonic for the life of the current process and reset on a fresh process start. New counters may be added without removing existing fields.

| Counter | Semantics |
|---|---|
| `requests_total` | Requests received by Sentinel. |
| `blocked_total` | Requests blocked by Sentinel. |
| `warnings_total` | Warning decisions emitted. |
| `upstream_errors` | Request-level upstream failures returned through the upstream-error path. 429, 5xx, timeout, transport, and circuit-open failures each increment this once when surfaced to the caller. Internal retries do not each increment this status counter. |
| `pii_provider_fallbacks` | PII-provider fallback count. |
| `rapidapi_error_count` | RapidAPI PII-provider error count. |
| `failover_events` | Upstream route failover events. |
| `canary_routed` | Requests routed by canary logic. |
| `websocket_upgrades_total` | WebSocket upgrade attempts seen. |
| `websocket_forwarded` | WebSocket upgrades forwarded. |
| `websocket_blocked` | WebSocket upgrades blocked. |
| `websocket_errors` | WebSocket processing errors. |

Engine-specific counters use descriptive prefixes (for example `intent_drift_*`, `omni_shield_*`, `swarm_*`, `sandbox_*`, `parallax_*`). Consumers should tolerate additive counters and ignore unknown keys.

## Stopped/no-snapshot behavior

If no status file exists, `sentinel status --json` returns a minimal stopped payload with `service_status: "stopped"` and conservative defaults for core feature fields. Consumers must not treat absent optional fields in this no-snapshot payload as evidence that those features have never been configured; it means there is no persisted running-server snapshot to inspect.
