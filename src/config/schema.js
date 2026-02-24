const os = require('os');
const { compileRules } = require('../policy/semantic-firewall-dsl');

const VALID_MODES = new Set(['monitor', 'warn', 'enforce']);
const VALID_ACTIONS = new Set(['allow', 'block', 'warn']);
const VALID_SCANNER_ACTIONS = new Set(['allow', 'block']);
const VALID_PII_PROVIDER_MODES = new Set(['local', 'rapidapi', 'hybrid']);
const ROOT_KEYS = new Set(['version', 'mode', 'proxy', 'runtime', 'pii', 'injection', 'rules', 'whitelist', 'logging']);
const PROXY_KEYS = new Set(['host', 'port', 'timeout_ms', 'max_body_bytes']);
const RUNTIME_KEYS = new Set([
  'fail_open',
  'scanner_error_action',
  'telemetry',
  'upstream',
  'rate_limiter',
  'worker_pool',
  'vcr',
  'semantic_cache',
  'intent_throttle',
  'intent_drift',
  'swarm',
  'pii_vault',
  'polymorphic_prompt',
  'synthetic_poisoning',
  'cognitive_rollback',
  'omni_shield',
  'sandbox_experimental',
  'dashboard',
  'posture_scoring',
  'websocket',
  'budget',
  'loop_breaker',
  'agentic_threat_shield',
  'a2a_card_verifier',
  'consensus_protocol',
  'cross_tenant_isolator',
  'cold_start_analyzer',
  'serialization_firewall',
  'context_integrity_guardian',
  'context_compression_guard',
  'tool_schema_validator',
  'multimodal_injection_shield',
  'supply_chain_validator',
  'sandbox_enforcer',
  'memory_integrity_monitor',
  'mcp_poisoning',
  'mcp_shadow',
  'mcp_certificate_pinning',
  'memory_poisoning',
  'cascade_isolator',
  'agent_identity_federation',
  'tool_use_anomaly',
  'behavioral_fingerprint',
  'threat_intel_mesh',
  'lfrl',
  'self_healing_immune',
  'semantic_firewall_dsl',
  'stego_exfil_detector',
  'reasoning_trace_monitor',
  'hallucination_tripwire',
  'semantic_drift_canary',
  'output_provenance',
  'token_watermark',
  'compute_attestation',
  'capability_introspection',
  'policy_gradient_analyzer',
  'budget_autopilot',
  'cost_efficiency_optimizer',
  'zk_config_validator',
  'adversarial_eval_harness',
  'anomaly_telemetry',
  'evidence_vault',
  'threat_graph',
  'attack_corpus_evolver',
  'forensic_debugger',
  'prompt_rebuff',
  'output_classifier',
  'output_schema_validator',
  'agent_observability',
  'differential_privacy',
  'auto_immune',
  'provenance',
  'deception',
  'honeytoken',
  'latency_normalization',
  'canary_tools',
  'parallax',
  'shadow_os',
  'epistemic_anchor',
]);
const TELEMETRY_KEYS = new Set(['enabled']);
const UPSTREAM_KEYS = new Set(['retry', 'circuit_breaker', 'custom_targets', 'resilience_mesh', 'canary', 'auth_vault', 'ghost_mode']);
const WORKER_POOL_KEYS = new Set([
  'enabled',
  'size',
  'queue_limit',
  'task_timeout_ms',
  'scan_task_timeout_ms',
  'embed_task_timeout_ms',
]);
const RATE_LIMITER_KEYS = new Set([
  'enabled',
  'default_window_ms',
  'default_limit',
  'default_burst',
  'max_buckets',
  'prune_interval',
  'stale_bucket_ttl_ms',
  'max_key_length',
  'key_headers',
  'fallback_key_headers',
  'ip_header',
]);
const VCR_KEYS = new Set(['enabled', 'mode', 'tape_file', 'max_entries', 'strict_replay']);
const VCR_MODES = new Set(['off', 'record', 'replay']);
const SEMANTIC_CACHE_KEYS = new Set([
  'enabled',
  'model_id',
  'cache_dir',
  'similarity_threshold',
  'max_entries',
  'ttl_ms',
  'max_prompt_chars',
  'max_entry_bytes',
  'max_ram_mb',
  'max_consecutive_errors',
  'failure_cooldown_ms',
]);
const INTENT_THROTTLE_KEYS = new Set([
  'enabled',
  'mode',
  'key_header',
  'window_ms',
  'cooldown_ms',
  'max_events_per_window',
  'min_similarity',
  'max_prompt_chars',
  'max_sessions',
  'model_id',
  'cache_dir',
  'clusters',
]);
const INTENT_THROTTLE_MODES = new Set(['monitor', 'block']);
const INTENT_THROTTLE_CLUSTER_KEYS = new Set(['name', 'phrases', 'min_similarity']);
const INTENT_DRIFT_KEYS = new Set([
  'enabled',
  'mode',
  'key_header',
  'fallback_key_headers',
  'target_roles',
  'strip_volatile_tokens',
  'risk_keywords',
  'risk_boost',
  'sample_every_turns',
  'min_turns',
  'threshold',
  'cooldown_ms',
  'max_sessions',
  'context_window_messages',
  'model_id',
  'cache_dir',
  'max_prompt_chars',
  'observability',
]);
const INTENT_DRIFT_MODES = new Set(['monitor', 'block']);
const SWARM_KEYS = new Set([
  'enabled',
  'mode',
  'node_id',
  'key_id',
  'private_key_pem',
  'public_key_pem',
  'verify_inbound',
  'sign_outbound',
  'require_envelope',
  'allowed_clock_skew_ms',
  'tolerance_window_ms',
  'nonce_ttl_ms',
  'max_nonce_entries',
  'sign_on_providers',
  'trusted_nodes',
]);
const SWARM_MODES = new Set(['monitor', 'block']);
const SWARM_TRUSTED_NODE_KEYS = new Set(['public_key_pem']);
const PII_VAULT_KEYS = new Set([
  'enabled',
  'mode',
  'salt',
  'session_header',
  'fallback_headers',
  'ttl_ms',
  'max_sessions',
  'max_mappings_per_session',
  'max_memory_bytes',
  'max_egress_rewrite_entries',
  'max_payload_bytes',
  'max_replacements_per_pass',
  'token_domain',
  'token_prefix',
  'target_types',
  'observability',
]);
const PII_VAULT_MODES = new Set(['monitor', 'active']);
const POLYMORPHIC_PROMPT_KEYS = new Set([
  'enabled',
  'rotation_seconds',
  'max_mutations_per_message',
  'target_roles',
  'bypass_header',
  'seed',
  'observability',
  'lexicon',
]);
const SYNTHETIC_POISONING_KEYS = new Set([
  'enabled',
  'mode',
  'required_acknowledgement',
  'acknowledgement',
  'allowed_triggers',
  'target_roles',
  'decoy_label',
  'max_insertions_per_request',
  'observability',
]);
const SYNTHETIC_POISONING_MODES = new Set(['monitor', 'inject']);
const COGNITIVE_ROLLBACK_KEYS = new Set([
  'enabled',
  'mode',
  'triggers',
  'target_roles',
  'drop_messages',
  'min_messages_remaining',
  'system_message',
  'observability',
]);
const COGNITIVE_ROLLBACK_MODES = new Set(['monitor', 'auto']);
const AUTO_IMMUNE_KEYS = new Set([
  'enabled',
  'mode',
  'ttl_ms',
  'max_entries',
  'max_scan_bytes',
  'min_confidence_to_match',
  'learn_min_score',
  'learn_increment',
  'max_confidence',
  'decay_half_life_ms',
  'observability',
]);
const AUTO_IMMUNE_MODES = new Set(['monitor', 'block']);
const OMNI_SHIELD_KEYS = new Set([
  'enabled',
  'mode',
  'max_image_bytes',
  'allow_remote_image_urls',
  'allow_base64_images',
  'block_on_any_image',
  'max_findings',
  'target_roles',
  'observability',
  'plugin',
]);
const OMNI_SHIELD_MODES = new Set(['monitor', 'block']);
const OMNI_SHIELD_PLUGIN_KEYS = new Set([
  'enabled',
  'provider',
  'module_path',
  'mode',
  'fail_closed',
  'max_rewrites',
  'timeout_ms',
  'observability',
]);
const OMNI_SHIELD_PLUGIN_MODES = new Set(['enforce', 'always']);
const SANDBOX_EXPERIMENTAL_KEYS = new Set([
  'enabled',
  'mode',
  'max_code_chars',
  'max_findings',
  'normalize_evasion',
  'decode_base64',
  'max_decoded_bytes',
  'max_variants_per_candidate',
  'disallowed_patterns',
  'target_tool_names',
  'observability',
]);
const SANDBOX_EXPERIMENTAL_MODES = new Set(['monitor', 'block']);
const DASHBOARD_KEYS = new Set([
  'enabled',
  'host',
  'port',
  'auth_token',
  'allow_remote',
  'team_tokens',
  'team_header',
]);
const POSTURE_SCORING_KEYS = new Set(['enabled', 'include_counters', 'warn_threshold', 'critical_threshold']);
const WEBSOCKET_KEYS = new Set(['enabled', 'mode', 'connect_timeout_ms', 'idle_timeout_ms', 'max_connections']);
const WEBSOCKET_MODES = new Set(['monitor', 'enforce']);
const BUDGET_KEYS = new Set([
  'enabled',
  'action',
  'daily_limit_usd',
  'store_file',
  'reset_timezone',
  'chars_per_token',
  'input_cost_per_1k_tokens',
  'output_cost_per_1k_tokens',
  'charge_replay_hits',
  'retention_days',
]);
const LOOP_BREAKER_KEYS = new Set([
  'enabled',
  'action',
  'window_ms',
  'repeat_threshold',
  'max_recent',
  'max_keys',
  'key_header',
]);
const LOOP_BREAKER_ACTIONS = new Set(['block', 'warn']);
const AGENTIC_THREAT_SHIELD_KEYS = new Set([
  'enabled',
  'mode',
  'max_tool_call_depth',
  'max_agent_delegations',
  'max_analysis_nodes',
  'max_tool_calls_analyzed',
  'block_on_analysis_truncation',
  'detect_cycles',
  'verify_identity_tokens',
  'identity_token_header',
  'agent_id_header',
  'session_header',
  'fallback_headers',
  'hmac_secret',
  'ttl_ms',
  'max_sessions',
  'max_graph_edges_per_session',
  'observability',
]);
const AGENTIC_THREAT_SHIELD_MODES = new Set(['monitor', 'block']);
const A2A_CARD_VERIFIER_KEYS = new Set([
  'enabled',
  'mode',
  'card_header',
  'agent_id_header',
  'max_card_bytes',
  'ttl_ms',
  'max_agents',
  'max_capabilities',
  'max_observed_per_agent',
  'overclaim_tolerance',
  'block_on_invalid_schema',
  'block_on_drift',
  'block_on_overclaim',
  'block_on_auth_mismatch',
  'observability',
]);
const A2A_CARD_VERIFIER_MODES = new Set(['monitor', 'block']);
const CONSENSUS_PROTOCOL_KEYS = new Set([
  'enabled',
  'mode',
  'policy_header',
  'action_field',
  'max_votes',
  'required_votes',
  'total_agents',
  'block_on_no_quorum',
  'block_on_byzantine',
  'high_risk_actions',
  'observability',
]);
const CONSENSUS_PROTOCOL_MODES = new Set(['monitor', 'block']);
const CROSS_TENANT_ISOLATOR_KEYS = new Set([
  'enabled',
  'mode',
  'tenant_header',
  'session_header',
  'fallback_headers',
  'ttl_ms',
  'max_sessions',
  'max_known_tenants',
  'block_on_mismatch',
  'block_on_leak',
  'observability',
]);
const CROSS_TENANT_ISOLATOR_MODES = new Set(['monitor', 'block']);
const COLD_START_ANALYZER_KEYS = new Set([
  'enabled',
  'mode',
  'cold_start_window_ms',
  'warmup_request_threshold',
  'warmup_engines',
  'block_during_cold_start',
  'observability',
]);
const COLD_START_ANALYZER_MODES = new Set(['monitor', 'block']);
const SERIALIZATION_FIREWALL_KEYS = new Set([
  'enabled',
  'mode',
  'max_scan_bytes',
  'max_nesting_depth',
  'max_object_nodes',
  'metadata_ratio_threshold',
  'allowed_formats',
  'expected_root_keys',
  'block_on_type_confusion',
  'block_on_depth_bomb',
  'block_on_format_violation',
  'block_on_metadata_anomaly',
  'block_on_schema_mismatch',
  'observability',
]);
const SERIALIZATION_FIREWALL_MODES = new Set(['monitor', 'block']);
const CONTEXT_INTEGRITY_GUARDIAN_KEYS = new Set([
  'enabled',
  'mode',
  'session_header',
  'fallback_headers',
  'required_anchors',
  'max_context_chars',
  'max_sessions',
  'ttl_ms',
  'repetition_threshold',
  'token_budget_warn_ratio',
  'provider_token_limit',
  'block_on_anchor_loss',
  'block_on_repetition',
  'observability',
]);
const CONTEXT_INTEGRITY_GUARDIAN_MODES = new Set(['monitor', 'block']);
const CONTEXT_COMPRESSION_GUARD_KEYS = new Set([
  'enabled',
  'mode',
  'session_header',
  'fallback_headers',
  'protected_anchors',
  'summary_fields',
  'max_context_chars',
  'max_summary_chars',
  'max_sessions',
  'ttl_ms',
  'anchor_loss_ratio',
  'shrink_spike_ratio',
  'token_budget_warn_ratio',
  'provider_token_limit',
  'block_on_anchor_loss',
  'block_on_summary_injection',
  'observability',
]);
const CONTEXT_COMPRESSION_GUARD_MODES = new Set(['monitor', 'block']);
const TOOL_SCHEMA_VALIDATOR_KEYS = new Set([
  'enabled',
  'mode',
  'max_tools',
  'max_schema_bytes',
  'max_param_name_chars',
  'ttl_ms',
  'max_servers',
  'block_on_dangerous_parameter',
  'block_on_schema_drift',
  'block_on_capability_boundary',
  'detect_schema_drift',
  'sanitize_in_monitor',
  'observability',
]);
const TOOL_SCHEMA_VALIDATOR_MODES = new Set(['monitor', 'block']);
const MULTIMODAL_INJECTION_SHIELD_KEYS = new Set([
  'enabled',
  'mode',
  'max_scan_bytes',
  'max_findings',
  'base64_entropy_threshold',
  'max_decoded_base64_bytes',
  'block_on_mime_mismatch',
  'block_on_suspicious_metadata',
  'block_on_base64_injection',
  'observability',
]);
const MULTIMODAL_INJECTION_SHIELD_MODES = new Set(['monitor', 'block']);
const SUPPLY_CHAIN_VALIDATOR_KEYS = new Set([
  'enabled',
  'mode',
  'project_root',
  'max_module_entries',
  'check_every_requests',
  'block_on_lockfile_drift',
  'block_on_blocked_package',
  'require_lockfile',
  'blocked_packages',
  'lock_files',
  'observability',
]);
const SUPPLY_CHAIN_VALIDATOR_MODES = new Set(['monitor', 'block']);
const SANDBOX_ENFORCER_KEYS = new Set([
  'enabled',
  'mode',
  'max_argument_bytes',
  'allowed_paths',
  'allowed_domains',
  'blocked_ports',
  'block_on_path_escape',
  'block_on_network_escape',
  'observability',
]);
const SANDBOX_ENFORCER_MODES = new Set(['monitor', 'block']);
const MEMORY_INTEGRITY_MONITOR_KEYS = new Set([
  'enabled',
  'mode',
  'session_header',
  'agent_header',
  'chain_header',
  'max_memory_chars',
  'ttl_ms',
  'max_sessions',
  'max_growth_ratio',
  'block_on_chain_break',
  'block_on_growth',
  'block_on_owner_mismatch',
  'observability',
]);
const MEMORY_INTEGRITY_MONITOR_MODES = new Set(['monitor', 'block']);
const MCP_POISONING_KEYS = new Set([
  'enabled',
  'mode',
  'description_threshold',
  'max_description_scan_bytes',
  'max_argument_bytes',
  'max_tools',
  'max_drift_snapshot_bytes',
  'block_on_config_drift',
  'detect_config_drift',
  'drift_ttl_ms',
  'max_server_entries',
  'sanitize_arguments',
  'strip_non_printable',
  'observability',
]);
const MCP_POISONING_MODES = new Set(['monitor', 'block']);
const MCP_SHADOW_KEYS = new Set([
  'enabled',
  'mode',
  'detect_schema_drift',
  'detect_late_registration',
  'detect_name_collisions',
  'block_on_schema_drift',
  'block_on_late_registration',
  'block_on_name_collision',
  'max_tools',
  'max_tool_snapshot_bytes',
  'ttl_ms',
  'max_server_entries',
  'max_findings',
  'min_tool_name_length',
  'name_similarity_distance',
  'max_name_candidates',
  'observability',
]);
const MCP_SHADOW_MODES = new Set(['monitor', 'block']);
const MCP_CERTIFICATE_PINNING_KEYS = new Set([
  'enabled',
  'mode',
  'server_id_header',
  'fingerprint_header',
  'pins',
  'allow_unpinned_servers',
  'require_fingerprint_for_pinned_servers',
  'detect_rotation',
  'block_on_mismatch',
  'block_on_rotation',
  'max_servers',
  'ttl_ms',
  'observability',
]);
const MCP_CERTIFICATE_PINNING_MODES = new Set(['monitor', 'block']);
const MEMORY_POISONING_KEYS = new Set([
  'enabled',
  'mode',
  'max_content_chars',
  'ttl_ms',
  'max_sessions',
  'max_writes_per_session',
  'detect_contradictions',
  'block_on_poisoning',
  'block_on_contradiction',
  'quarantine_on_detect',
  'policy_anchors',
  'observability',
]);
const MEMORY_POISONING_MODES = new Set(['monitor', 'block']);
const CASCADE_ISOLATOR_KEYS = new Set([
  'enabled',
  'mode',
  'ttl_ms',
  'max_sessions',
  'max_nodes',
  'max_edges',
  'max_downstream_agents',
  'max_influence_ratio',
  'anomaly_threshold',
  'block_on_threshold',
  'observability',
]);
const CASCADE_ISOLATOR_MODES = new Set(['monitor', 'block']);
const AGENT_IDENTITY_FEDERATION_KEYS = new Set([
  'enabled',
  'mode',
  'token_header',
  'agent_id_header',
  'correlation_header',
  'hmac_secret',
  'ttl_ms',
  'max_chain_depth',
  'max_replay_entries',
  'block_on_invalid_token',
  'block_on_capability_widen',
  'block_on_replay',
  'observability',
]);
const AGENT_IDENTITY_FEDERATION_MODES = new Set(['monitor', 'block']);
const TOOL_USE_ANOMALY_KEYS = new Set([
  'enabled',
  'mode',
  'ttl_ms',
  'max_agents',
  'max_tools_per_agent',
  'warmup_events',
  'z_score_threshold',
  'sequence_threshold',
  'block_on_anomaly',
  'observability',
]);
const TOOL_USE_ANOMALY_MODES = new Set(['monitor', 'block']);
const BEHAVIORAL_FINGERPRINT_KEYS = new Set([
  'enabled',
  'mode',
  'ttl_ms',
  'max_agents',
  'max_styles_per_agent',
  'max_text_chars',
  'max_impersonation_agents',
  'warmup_events',
  'z_score_threshold',
  'impersonation_min_hits',
  'block_on_anomaly',
  'block_on_impersonation',
  'observability',
]);
const BEHAVIORAL_FINGERPRINT_MODES = new Set(['monitor', 'block']);
const THREAT_INTEL_MESH_KEYS = new Set([
  'enabled',
  'mode',
  'ttl_ms',
  'max_signatures',
  'max_text_chars',
  'min_hits_to_block',
  'block_on_match',
  'allow_anonymous_share',
  'allow_unsigned_import',
  'node_id',
  'shared_secret',
  'peers',
  'sync_enabled',
  'sync_interval_ms',
  'sync_timeout_ms',
  'max_peer_signatures',
  'max_peers',
  'bootstrap_signatures',
  'observability',
]);
const THREAT_INTEL_MESH_MODES = new Set(['monitor', 'block']);
const LFRL_KEYS = new Set([
  'enabled',
  'mode',
  'rules',
  'max_rules',
  'max_events',
  'max_matches',
  'default_within_ms',
  'ttl_ms',
  'block_on_rule_action',
  'observability',
]);
const LFRL_MODES = new Set(['monitor', 'block']);
const SELF_HEALING_IMMUNE_KEYS = new Set([
  'enabled',
  'mode',
  'ttl_ms',
  'max_signatures',
  'max_text_chars',
  'min_learn_hits',
  'block_on_learned_signature',
  'auto_tune_enabled',
  'max_recommendations',
  'observability',
]);
const SELF_HEALING_IMMUNE_MODES = new Set(['monitor', 'block']);
const SEMANTIC_FIREWALL_DSL_KEYS = new Set([
  'enabled',
  'rules',
  'max_rules',
  'observability',
]);
const STEGO_EXFIL_DETECTOR_KEYS = new Set([
  'enabled',
  'mode',
  'max_scan_chars',
  'max_findings',
  'zero_width_density_threshold',
  'invisible_density_threshold',
  'whitespace_bits_threshold',
  'segment_entropy_threshold',
  'emoji_compound_threshold',
  'block_on_detect',
  'observability',
]);
const STEGO_EXFIL_DETECTOR_MODES = new Set(['monitor', 'block']);
const REASONING_TRACE_MONITOR_KEYS = new Set([
  'enabled',
  'mode',
  'max_scan_chars',
  'max_steps',
  'min_step_chars',
  'coherence_threshold',
  'block_on_injection',
  'block_on_incoherence',
  'block_on_conclusion_mismatch',
  'observability',
]);
const REASONING_TRACE_MONITOR_MODES = new Set(['monitor', 'block']);
const HALLUCINATION_TRIPWIRE_KEYS = new Set([
  'enabled',
  'mode',
  'max_scan_chars',
  'max_findings',
  'warn_threshold',
  'block_threshold',
  'block_on_detect',
  'observability',
]);
const HALLUCINATION_TRIPWIRE_MODES = new Set(['monitor', 'block']);
const SEMANTIC_DRIFT_CANARY_KEYS = new Set([
  'enabled',
  'mode',
  'sample_every_requests',
  'max_providers',
  'max_samples_per_provider',
  'max_text_chars',
  'warn_distance_threshold',
  'block_distance_threshold',
  'observability',
]);
const SEMANTIC_DRIFT_CANARY_MODES = new Set(['monitor', 'block']);
const OUTPUT_PROVENANCE_KEYS = new Set([
  'enabled',
  'key_id',
  'secret',
  'expose_verify_endpoint',
  'max_envelope_bytes',
]);
const TOKEN_WATERMARK_KEYS = new Set([
  'enabled',
  'key_id',
  'secret',
  'expose_verify_endpoint',
  'max_envelope_bytes',
  'max_token_chars',
  'max_tokens',
]);
const COMPUTE_ATTESTATION_KEYS = new Set([
  'enabled',
  'key_id',
  'secret',
  'expose_verify_endpoint',
  'max_config_chars',
  'include_environment',
]);
const CAPABILITY_INTROSPECTION_KEYS = new Set([
  'enabled',
  'max_engines',
  'observability',
]);
const POLICY_GRADIENT_ANALYZER_KEYS = new Set([
  'enabled',
  'max_events',
  'current_injection_threshold',
  'proposed_injection_threshold',
]);
const BUDGET_AUTOPILOT_KEYS = new Set([
  'enabled',
  'mode',
  'ttl_ms',
  'max_providers',
  'min_samples',
  'cost_weight',
  'latency_weight',
  'warn_budget_ratio',
  'sla_p95_ms',
  'horizon_hours',
  'observability',
]);
const BUDGET_AUTOPILOT_MODES = new Set(['monitor', 'active']);
const COST_EFFICIENCY_OPTIMIZER_KEYS = new Set([
  'enabled',
  'mode',
  'ttl_ms',
  'max_providers',
  'max_samples_per_provider',
  'max_prompt_chars',
  'chars_per_token',
  'prompt_bloat_chars',
  'repetition_warn_ratio',
  'low_budget_usd',
  'memory_warn_bytes',
  'memory_critical_bytes',
  'memory_hard_cap_bytes',
  'shed_on_memory_pressure',
  'max_shed_engines',
  'shed_cooldown_ms',
  'shed_engine_order',
  'block_on_critical_memory',
  'block_on_budget_exhausted',
  'observability',
]);
const COST_EFFICIENCY_OPTIMIZER_MODES = new Set(['monitor', 'active']);
const ZK_CONFIG_VALIDATOR_KEYS = new Set([
  'enabled',
  'hmac_key',
  'max_findings',
  'max_nodes',
  'max_depth',
  'redaction_text',
  'score_penalty_secret',
  'score_penalty_dead_key',
  'score_penalty_over_config',
  'observability',
]);
const ADVERSARIAL_EVAL_HARNESS_KEYS = new Set([
  'enabled',
  'max_cases',
  'max_prompt_chars',
  'max_runs',
  'schedule_every_requests',
  'fail_open',
  'regression_drop_threshold',
  'observability',
]);
const ANOMALY_TELEMETRY_KEYS = new Set([
  'enabled',
  'max_events',
  'window_ms',
  'max_engine_buckets',
  'max_timeline_events',
  'observability',
]);
const EVIDENCE_VAULT_KEYS = new Set([
  'enabled',
  'mode',
  'max_entries',
  'retention_days',
  'file_path',
  'observability',
]);
const EVIDENCE_VAULT_MODES = new Set(['monitor', 'active']);
const THREAT_GRAPH_KEYS = new Set([
  'enabled',
  'max_events',
  'window_ms',
  'risk_decay',
  'observability',
]);
const ATTACK_CORPUS_EVOLVER_KEYS = new Set([
  'enabled',
  'max_candidates',
  'max_prompt_chars',
  'max_families',
  'include_monitor_decisions',
  'observability',
]);
const FORENSIC_DEBUGGER_KEYS = new Set([
  'enabled',
  'max_snapshots',
  'redact_fields',
  'default_summary_only',
  'observability',
]);
const PROMPT_REBUFF_KEYS = new Set([
  'enabled',
  'mode',
  'sensitivity',
  'heuristic_weight',
  'neural_weight',
  'canary_weight',
  'warn_threshold',
  'block_threshold',
  'max_body_chars',
  'max_response_chars',
  'session_header',
  'fallback_headers',
  'ttl_ms',
  'max_sessions',
  'canary_tool_name',
  'observability',
]);
const PROMPT_REBUFF_MODES = new Set(['monitor', 'block']);
const PROMPT_REBUFF_SENSITIVITIES = new Set(['permissive', 'balanced', 'paranoid']);
const OUTPUT_CLASSIFIER_KEYS = new Set([
  'enabled',
  'mode',
  'max_scan_chars',
  'context_window_chars',
  'max_matches_per_rule',
  'contextual_dampening',
  'contextual_escalation',
  'ngram_boost',
  'categories',
]);
const OUTPUT_CLASSIFIER_MODES = new Set(['monitor', 'block']);
const OUTPUT_CLASSIFIER_CATEGORIES_KEYS = new Set([
  'toxicity',
  'code_execution',
  'hallucination',
  'unauthorized_disclosure',
]);
const OUTPUT_CLASSIFIER_CATEGORY_KEYS = new Set(['enabled', 'warn_threshold', 'block_threshold']);
const OUTPUT_SCHEMA_VALIDATOR_KEYS = new Set([
  'enabled',
  'mode',
  'default_schema',
  'schema_header',
  'max_body_bytes',
  'schemas',
]);
const OUTPUT_SCHEMA_VALIDATOR_MODES = new Set(['monitor', 'block']);
const OUTPUT_SCHEMA_NODE_KEYS = new Set([
  'type',
  'required',
  'properties',
  'enum',
  'additionalProperties',
]);
const OUTPUT_SCHEMA_SUPPORTED_TYPES = new Set([
  'object',
  'array',
  'string',
  'number',
  'integer',
  'boolean',
  'null',
]);
const AGENT_OBSERVABILITY_KEYS = new Set(['enabled', 'max_events_per_request', 'max_field_length']);
const DIFFERENTIAL_PRIVACY_KEYS = new Set([
  'enabled',
  'epsilon_budget',
  'epsilon_per_call',
  'sensitivity',
  'max_simulation_calls',
  'max_vector_length',
  'persist_state',
  'state_file',
  'state_hmac_key',
  'reset_on_tamper',
]);
const PROVENANCE_KEYS = new Set([
  'enabled',
  'key_id',
  'sign_stream_trailers',
  'expose_public_key_endpoint',
  'max_signable_bytes',
]);
const DECEPTION_KEYS = new Set([
  'enabled',
  'mode',
  'on_injection',
  'on_loop',
  'min_injection_score',
  'sse_token_interval_ms',
  'sse_max_tokens',
  'non_stream_delay_ms',
]);
const DECEPTION_MODES = new Set(['off', 'tarpit']);
const HONEYTOKEN_KEYS = new Set([
  'enabled',
  'mode',
  'injection_rate',
  'max_insertions_per_request',
  'target_roles',
  'token_prefix',
]);
const HONEYTOKEN_MODES = new Set(['zero_width', 'uuid_suffix']);
const LATENCY_NORMALIZATION_KEYS = new Set([
  'enabled',
  'window_size',
  'min_samples',
  'max_delay_ms',
  'max_baseline_sample_ms',
  'trim_percentile',
  'max_concurrent_normalized',
  'jitter_ms',
  'statuses',
]);
const CANARY_TOOL_KEYS = new Set([
  'enabled',
  'mode',
  'tool_name',
  'tool_description',
  'max_injected_tools',
  'inject_on_providers',
  'require_tools_array',
]);
const CANARY_TOOL_MODES = new Set(['monitor', 'block']);
const PARALLAX_KEYS = new Set([
  'enabled',
  'mode',
  'high_risk_tools',
  'secondary_target',
  'secondary_group',
  'secondary_contract',
  'secondary_model',
  'timeout_ms',
  'risk_threshold',
]);
const PARALLAX_MODES = new Set(['monitor', 'block']);
const SHADOW_OS_KEYS = new Set([
  'enabled',
  'mode',
  'window_ms',
  'max_sessions',
  'max_history_per_session',
  'repeat_threshold',
  'session_header',
  'fallback_headers',
  'high_risk_tools',
  'sequence_rules',
  'observability',
]);
const SHADOW_OS_MODES = new Set(['monitor', 'block']);
const SHADOW_OS_SEQUENCE_RULE_KEYS = new Set(['id', 'requires', 'order_required']);
const EPISTEMIC_ANCHOR_KEYS = new Set([
  'enabled',
  'mode',
  'required_acknowledgement',
  'acknowledgement',
  'key_header',
  'fallback_key_headers',
  'sample_every_turns',
  'min_turns',
  'threshold',
  'cooldown_ms',
  'max_sessions',
  'context_window_messages',
  'model_id',
  'cache_dir',
  'max_prompt_chars',
  'observability',
]);
const EPISTEMIC_ANCHOR_MODES = new Set(['monitor', 'block']);
const BUDGET_ACTIONS = new Set(['block', 'warn']);
const BUDGET_RESET_TIMEZONES = new Set(['utc', 'local']);
const RETRY_KEYS = new Set(['enabled', 'max_attempts', 'allow_post_with_idempotency_key']);
const CIRCUIT_BREAKER_KEYS = new Set([
  'enabled',
  'window_size',
  'min_failures_to_evaluate',
  'failure_rate_threshold',
  'consecutive_timeout_threshold',
  'open_seconds',
  'half_open_success_threshold',
]);
const CUSTOM_TARGET_KEYS = new Set(['enabled', 'allowlist', 'block_private_networks']);
const RESILIENCE_MESH_KEYS = new Set([
  'enabled',
  'contract',
  'default_group',
  'max_failover_hops',
  'allow_post_with_idempotency_key',
  'failover_on_status',
  'failover_on_error_types',
  'groups',
  'targets',
]);
const RESILIENCE_GROUP_KEYS = new Set(['enabled', 'contract', 'targets']);
const RESILIENCE_TARGET_KEYS = new Set(['enabled', 'provider', 'contract', 'base_url', 'custom_url', 'headers']);
const CANARY_KEYS = new Set(['enabled', 'key_header', 'fallback_key_headers', 'splits']);
const CANARY_SPLIT_KEYS = new Set(['name', 'match_target', 'group_a', 'group_b', 'weight_a', 'weight_b', 'sticky']);
const GHOST_MODE_KEYS = new Set(['enabled', 'strip_headers', 'override_user_agent', 'user_agent_value']);
const AUTH_VAULT_KEYS = new Set(['enabled', 'mode', 'dummy_key', 'providers']);
const AUTH_VAULT_MODES = new Set(['replace_dummy', 'enforce']);
const AUTH_VAULT_PROVIDERS = new Set(['openai', 'anthropic', 'google']);
const AUTH_VAULT_PROVIDER_KEYS = new Set(['enabled', 'api_key', 'env_var']);
const PII_KEYS = new Set([
  'enabled',
  'provider_mode',
  'max_scan_bytes',
  'regex_safety_cap_bytes',
  'redaction',
  'severity_actions',
  'rapidapi',
  'semantic',
  'egress',
]);
const PII_REDACTION_KEYS = new Set(['mode', 'salt']);
const PII_REDACTION_MODES = new Set(['placeholder', 'format_preserving']);
const PII_SEVERITY_KEYS = new Set(['critical', 'high', 'medium', 'low']);
const PII_SEMANTIC_KEYS = new Set(['enabled', 'model_id', 'cache_dir', 'score_threshold', 'max_scan_bytes']);
const PII_EGRESS_KEYS = new Set(['enabled', 'max_scan_bytes', 'stream_enabled', 'sse_line_max_bytes', 'stream_block_mode', 'entropy']);
const PII_EGRESS_ENTROPY_KEYS = new Set([
  'enabled',
  'mode',
  'threshold',
  'min_token_length',
  'max_scan_bytes',
  'max_findings',
  'min_unique_ratio',
  'detect_base64',
  'detect_hex',
  'detect_generic',
  'redact_replacement',
]);
const PII_EGRESS_ENTROPY_MODES = new Set(['monitor', 'block']);
const INJECTION_KEYS = new Set(['enabled', 'threshold', 'max_scan_bytes', 'action', 'neural']);
const INJECTION_ACTIONS = new Set(['allow', 'block', 'warn']);
const INJECTION_NEURAL_KEYS = new Set(['enabled', 'model_id', 'cache_dir', 'max_scan_bytes', 'timeout_ms', 'weight', 'mode']);
const INJECTION_NEURAL_MODES = new Set(['max', 'blend']);
const RAPIDAPI_KEYS = new Set([
  'endpoint',
  'host',
  'timeout_ms',
  'request_body_field',
  'fallback_to_local',
  'allow_non_rapidapi_host',
  'api_key',
  'extra_body',
  'cache_max_entries',
  'cache_ttl_ms',
  'max_timeout_ms',
]);
const RULE_KEYS = new Set(['name', 'match', 'action', 'message']);
const RULE_MATCH_KEYS = new Set([
  'method',
  'domain',
  'path_contains',
  'body_contains',
  'tool_name',
  'body_size_mb',
  'injection_threshold',
  'requests_per_minute',
  'rate_limit_window_ms',
  'rate_limit_burst',
]);
const WHITELIST_KEYS = new Set(['domains']);
const LOGGING_KEYS = new Set(['level', 'audit_file', 'audit_stdout']);

class ConfigValidationError extends Error {
  constructor(message, details = []) {
    super(message);
    this.name = 'ConfigValidationError';
    this.details = details;
  }
}

function assertType(condition, message, details) {
  if (!condition) {
    details.push(message);
  }
}

function assertNoUnknownKeys(object, allowedKeys, pathLabel, details) {
  if (!object || typeof object !== 'object' || Array.isArray(object)) {
    return;
  }
  for (const key of Object.keys(object)) {
    if (!allowedKeys.has(key)) {
      details.push(`Unknown key: ${pathLabel}.${key}`);
    }
  }
}

function validateRequiredKeys(config, details) {
  const required = ['version', 'mode', 'proxy', 'runtime', 'pii', 'rules', 'whitelist', 'logging'];
  for (const key of required) {
    assertType(Object.prototype.hasOwnProperty.call(config, key), `Missing required key: ${key}`, details);
  }
}

function validateRules(rules, details) {
  assertType(Array.isArray(rules), '`rules` must be an array', details);
  if (!Array.isArray(rules)) {
    return;
  }

  rules.forEach((rule, idx) => {
    const prefix = `rules[${idx}]`;
    assertType(rule && typeof rule === 'object', `${prefix} must be an object`, details);
    if (!rule || typeof rule !== 'object') {
      return;
    }
    assertNoUnknownKeys(rule, RULE_KEYS, prefix, details);

    assertType(typeof rule.name === 'string' && rule.name.length > 0, `${prefix}.name must be a non-empty string`, details);
    assertType(rule.match && typeof rule.match === 'object', `${prefix}.match must be an object`, details);
    assertType(typeof rule.action === 'string' && VALID_ACTIONS.has(rule.action), `${prefix}.action must be one of: allow, block, warn`, details);
    assertNoUnknownKeys(rule.match, RULE_MATCH_KEYS, `${prefix}.match`, details);
    if (rule.match?.injection_threshold !== undefined) {
      const threshold = Number(rule.match.injection_threshold);
      assertType(
        Number.isFinite(threshold) && threshold >= 0 && threshold <= 1,
        `${prefix}.match.injection_threshold must be between 0 and 1`,
        details
      );
    }
    if (rule.match?.requests_per_minute !== undefined) {
      const rpm = Number(rule.match.requests_per_minute);
      assertType(
        Number.isInteger(rpm) && rpm > 0,
        `${prefix}.match.requests_per_minute must be integer > 0`,
        details
      );
    }
    if (rule.match?.rate_limit_window_ms !== undefined) {
      const windowMs = Number(rule.match.rate_limit_window_ms);
      assertType(
        Number.isInteger(windowMs) && windowMs > 0,
        `${prefix}.match.rate_limit_window_ms must be integer > 0`,
        details
      );
    }
    if (rule.match?.rate_limit_burst !== undefined) {
      const burst = Number(rule.match.rate_limit_burst);
      assertType(
        Number.isInteger(burst) && burst > 0,
        `${prefix}.match.rate_limit_burst must be integer > 0`,
        details
      );
      if (rule.match?.requests_per_minute !== undefined) {
        const rpm = Number(rule.match.requests_per_minute);
        assertType(
          Number.isInteger(rpm) && burst >= rpm,
          `${prefix}.match.rate_limit_burst must be >= requests_per_minute`,
          details
        );
      }
    }
  });
}

function validateOutputSchemaNode(node, details, pathLabel) {
  assertType(
    node && typeof node === 'object' && !Array.isArray(node),
    `${pathLabel} must be object`,
    details
  );
  if (!node || typeof node !== 'object' || Array.isArray(node)) {
    return;
  }
  assertNoUnknownKeys(node, OUTPUT_SCHEMA_NODE_KEYS, pathLabel, details);
  if (node.type !== undefined) {
    assertType(
      typeof node.type === 'string' && OUTPUT_SCHEMA_SUPPORTED_TYPES.has(String(node.type)),
      `${pathLabel}.type must be one of: ${Array.from(OUTPUT_SCHEMA_SUPPORTED_TYPES).join(', ')}`,
      details
    );
  }
  if (node.required !== undefined) {
    assertType(
      Array.isArray(node.required),
      `${pathLabel}.required must be array`,
      details
    );
    if (Array.isArray(node.required)) {
      node.required.forEach((field, idx) => {
        assertType(
          typeof field === 'string' && field.length > 0,
          `${pathLabel}.required[${idx}] must be non-empty string`,
          details
        );
      });
    }
  }
  if (node.enum !== undefined) {
    assertType(
      Array.isArray(node.enum),
      `${pathLabel}.enum must be array`,
      details
    );
  }
  if (node.additionalProperties !== undefined) {
    assertType(
      typeof node.additionalProperties === 'boolean',
      `${pathLabel}.additionalProperties must be boolean`,
      details
    );
  }
  if (node.properties !== undefined) {
    assertType(
      node.properties && typeof node.properties === 'object' && !Array.isArray(node.properties),
      `${pathLabel}.properties must be object`,
      details
    );
    if (node.properties && typeof node.properties === 'object' && !Array.isArray(node.properties)) {
      for (const [field, child] of Object.entries(node.properties)) {
        validateOutputSchemaNode(child, details, `${pathLabel}.properties.${field}`);
      }
    }
  }
}

function applyDefaults(config) {
  const normalized = JSON.parse(JSON.stringify(config));
  normalized.proxy = normalized.proxy || {};
  normalized.proxy.host = normalized.proxy.host || '127.0.0.1';
  normalized.proxy.port = Number(normalized.proxy.port || 8787);
  normalized.proxy.timeout_ms = Number(normalized.proxy.timeout_ms || 30000);
  normalized.proxy.max_body_bytes = Number(normalized.proxy.max_body_bytes ?? 1048576);

  normalized.runtime = normalized.runtime || {};
  normalized.runtime.fail_open = Boolean(normalized.runtime.fail_open);
  normalized.runtime.scanner_error_action = normalized.runtime.scanner_error_action || 'allow';
  normalized.runtime.telemetry = normalized.runtime.telemetry || {};
  normalized.runtime.telemetry.enabled = normalized.runtime.telemetry.enabled !== false;
  normalized.runtime.upstream = normalized.runtime.upstream || {};
  normalized.runtime.upstream.retry = normalized.runtime.upstream.retry || {};
  normalized.runtime.upstream.retry.enabled = normalized.runtime.upstream.retry.enabled !== false;
  normalized.runtime.upstream.retry.max_attempts = Number(normalized.runtime.upstream.retry.max_attempts ?? 1);
  normalized.runtime.upstream.retry.allow_post_with_idempotency_key = Boolean(
    normalized.runtime.upstream.retry.allow_post_with_idempotency_key
  );

  normalized.runtime.upstream.circuit_breaker = normalized.runtime.upstream.circuit_breaker || {};
  const cb = normalized.runtime.upstream.circuit_breaker;
  cb.enabled = cb.enabled !== false;
  cb.window_size = Number(cb.window_size ?? 20);
  cb.min_failures_to_evaluate = Number(cb.min_failures_to_evaluate ?? 8);
  cb.failure_rate_threshold = Number(cb.failure_rate_threshold ?? 0.5);
  cb.consecutive_timeout_threshold = Number(cb.consecutive_timeout_threshold ?? 5);
  cb.open_seconds = Number(cb.open_seconds ?? 20);
  cb.half_open_success_threshold = Number(cb.half_open_success_threshold ?? 3);

  normalized.runtime.upstream.custom_targets = normalized.runtime.upstream.custom_targets || {};
  const customTargets = normalized.runtime.upstream.custom_targets;
  customTargets.enabled = customTargets.enabled === true;
  customTargets.allowlist = Array.isArray(customTargets.allowlist) ? customTargets.allowlist : [];
  customTargets.block_private_networks = customTargets.block_private_networks !== false;

  normalized.runtime.upstream.resilience_mesh = normalized.runtime.upstream.resilience_mesh || {};
  const resilienceMesh = normalized.runtime.upstream.resilience_mesh;
  resilienceMesh.enabled = resilienceMesh.enabled === true;
  resilienceMesh.contract = String(resilienceMesh.contract || 'passthrough');
  resilienceMesh.default_group = String(resilienceMesh.default_group || '').toLowerCase();
  resilienceMesh.max_failover_hops = Number(resilienceMesh.max_failover_hops ?? 1);
  resilienceMesh.allow_post_with_idempotency_key = resilienceMesh.allow_post_with_idempotency_key === true;
  resilienceMesh.failover_on_status = Array.isArray(resilienceMesh.failover_on_status)
    ? resilienceMesh.failover_on_status.map((status) => Number(status))
    : [429, 500, 502, 503, 504];
  resilienceMesh.failover_on_error_types = Array.isArray(resilienceMesh.failover_on_error_types)
    ? resilienceMesh.failover_on_error_types.map((value) => String(value).toLowerCase())
    : ['timeout', 'transport', 'circuit_open'];
  resilienceMesh.groups =
    resilienceMesh.groups && typeof resilienceMesh.groups === 'object' && !Array.isArray(resilienceMesh.groups)
      ? resilienceMesh.groups
      : {};
  resilienceMesh.targets =
    resilienceMesh.targets && typeof resilienceMesh.targets === 'object' && !Array.isArray(resilienceMesh.targets)
      ? resilienceMesh.targets
      : {};
  for (const [groupName, groupConfig] of Object.entries(resilienceMesh.groups)) {
    const normalizedGroup =
      groupConfig && typeof groupConfig === 'object' && !Array.isArray(groupConfig) ? groupConfig : {};
    normalizedGroup.enabled = normalizedGroup.enabled !== false;
    normalizedGroup.contract = String(normalizedGroup.contract || '');
    normalizedGroup.targets = Array.isArray(normalizedGroup.targets)
      ? normalizedGroup.targets.map((value) => String(value).toLowerCase()).filter(Boolean)
      : [];
    resilienceMesh.groups[groupName] = normalizedGroup;
  }
  for (const [targetName, targetConfig] of Object.entries(resilienceMesh.targets)) {
    const normalizedTarget =
      targetConfig && typeof targetConfig === 'object' && !Array.isArray(targetConfig) ? targetConfig : {};
    normalizedTarget.enabled = normalizedTarget.enabled !== false;
    normalizedTarget.provider = String(normalizedTarget.provider || targetName).toLowerCase();
    normalizedTarget.contract = String(normalizedTarget.contract || '');
    if (normalizedTarget.base_url !== undefined) {
      normalizedTarget.base_url = String(normalizedTarget.base_url);
    }
    if (normalizedTarget.custom_url !== undefined) {
      normalizedTarget.custom_url = String(normalizedTarget.custom_url);
    }
    normalizedTarget.headers =
      normalizedTarget.headers && typeof normalizedTarget.headers === 'object' && !Array.isArray(normalizedTarget.headers)
        ? normalizedTarget.headers
        : {};
    resilienceMesh.targets[targetName] = normalizedTarget;
  }

  normalized.runtime.upstream.canary = normalized.runtime.upstream.canary || {};
  const canary = normalized.runtime.upstream.canary;
  canary.enabled = canary.enabled === true;
  canary.key_header = String(canary.key_header || 'x-sentinel-canary-key').toLowerCase();
  canary.fallback_key_headers = Array.isArray(canary.fallback_key_headers)
    ? canary.fallback_key_headers.map((value) => String(value).toLowerCase()).filter(Boolean)
    : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
  canary.splits = Array.isArray(canary.splits) ? canary.splits : [];
  canary.splits = canary.splits.map((split, idx) => {
    const normalizedSplit = split && typeof split === 'object' && !Array.isArray(split) ? split : {};
    normalizedSplit.name = String(normalizedSplit.name || `split-${idx + 1}`);
    normalizedSplit.match_target = String(normalizedSplit.match_target || '*').toLowerCase();
    normalizedSplit.group_a = String(normalizedSplit.group_a || '').toLowerCase();
    normalizedSplit.group_b = String(normalizedSplit.group_b || '').toLowerCase();
    normalizedSplit.weight_a = Number(normalizedSplit.weight_a ?? 90);
    normalizedSplit.weight_b = Number(normalizedSplit.weight_b ?? 10);
    normalizedSplit.sticky = normalizedSplit.sticky !== false;
    return normalizedSplit;
  });

  normalized.runtime.upstream.ghost_mode = normalized.runtime.upstream.ghost_mode || {};
  const ghostMode = normalized.runtime.upstream.ghost_mode;
  ghostMode.enabled = ghostMode.enabled === true;
  ghostMode.strip_headers = Array.isArray(ghostMode.strip_headers)
    ? ghostMode.strip_headers.map((value) => String(value).toLowerCase()).filter(Boolean)
    : [
        'x-stainless-os',
        'x-stainless-arch',
        'x-stainless-runtime',
        'x-stainless-runtime-version',
        'x-stainless-package-version',
        'x-stainless-lang',
        'x-stainless-helper-method',
        'user-agent',
      ];
  ghostMode.override_user_agent = ghostMode.override_user_agent !== false;
  ghostMode.user_agent_value = String(ghostMode.user_agent_value || 'Sentinel/1.0 (Privacy Proxy)');

  normalized.runtime.upstream.auth_vault = normalized.runtime.upstream.auth_vault || {};
  const authVault = normalized.runtime.upstream.auth_vault;
  authVault.enabled = authVault.enabled === true;
  authVault.mode = AUTH_VAULT_MODES.has(String(authVault.mode || '').toLowerCase())
    ? String(authVault.mode).toLowerCase()
    : 'replace_dummy';
  authVault.dummy_key = String(authVault.dummy_key || 'sk-sentinel-local');
  authVault.providers =
    authVault.providers && typeof authVault.providers === 'object' && !Array.isArray(authVault.providers)
      ? authVault.providers
      : {};
  for (const provider of AUTH_VAULT_PROVIDERS) {
    const providerConfig =
      authVault.providers[provider] && typeof authVault.providers[provider] === 'object' && !Array.isArray(authVault.providers[provider])
        ? authVault.providers[provider]
        : {};
    providerConfig.enabled = providerConfig.enabled !== false;
    providerConfig.api_key = String(providerConfig.api_key || '');
    const defaultEnv =
      provider === 'openai'
        ? 'SENTINEL_OPENAI_API_KEY'
        : provider === 'anthropic'
          ? 'SENTINEL_ANTHROPIC_API_KEY'
          : 'SENTINEL_GOOGLE_API_KEY';
    providerConfig.env_var = String(providerConfig.env_var || defaultEnv);
    authVault.providers[provider] = providerConfig;
  }

  normalized.runtime.rate_limiter = normalized.runtime.rate_limiter || {};
  const rateLimiter = normalized.runtime.rate_limiter;
  rateLimiter.enabled = rateLimiter.enabled !== false;
  rateLimiter.default_window_ms = Number(rateLimiter.default_window_ms ?? 60 * 1000);
  rateLimiter.default_limit = Number(rateLimiter.default_limit ?? 60);
  rateLimiter.default_burst = Number(rateLimiter.default_burst ?? rateLimiter.default_limit);
  rateLimiter.max_buckets = Number(rateLimiter.max_buckets ?? 100000);
  rateLimiter.prune_interval = Number(rateLimiter.prune_interval ?? 256);
  rateLimiter.stale_bucket_ttl_ms = Number(
    rateLimiter.stale_bucket_ttl_ms ?? Math.max(rateLimiter.default_window_ms * 4, 5 * 60 * 1000)
  );
  rateLimiter.max_key_length = Number(rateLimiter.max_key_length ?? 256);
  rateLimiter.key_headers = Array.isArray(rateLimiter.key_headers)
    ? rateLimiter.key_headers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['x-sentinel-agent-id', 'x-sentinel-session-id'];
  rateLimiter.fallback_key_headers = Array.isArray(rateLimiter.fallback_key_headers)
    ? rateLimiter.fallback_key_headers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['x-forwarded-for', 'x-real-ip', 'cf-connecting-ip', 'x-client-ip', 'user-agent'];
  rateLimiter.ip_header = String(rateLimiter.ip_header || 'x-forwarded-for').toLowerCase();

  normalized.runtime.worker_pool = normalized.runtime.worker_pool || {};
  const workerPool = normalized.runtime.worker_pool;
  workerPool.enabled = workerPool.enabled !== false;
  workerPool.size = Number(
    workerPool.size ?? Math.max(1, Math.min(4, (os.cpus()?.length || 2) - 1))
  );
  workerPool.queue_limit = Number(workerPool.queue_limit ?? 1024);
  workerPool.task_timeout_ms = Number(workerPool.task_timeout_ms ?? 10000);
  workerPool.scan_task_timeout_ms = Number(workerPool.scan_task_timeout_ms ?? 2000);
  workerPool.embed_task_timeout_ms = Number(
    workerPool.embed_task_timeout_ms ?? Math.max(workerPool.task_timeout_ms, 10000)
  );

  normalized.runtime.vcr = normalized.runtime.vcr || {};
  const vcr = normalized.runtime.vcr;
  vcr.enabled = vcr.enabled === true;
  vcr.mode = VCR_MODES.has(String(vcr.mode || '').toLowerCase()) ? String(vcr.mode).toLowerCase() : 'off';
  vcr.tape_file = vcr.tape_file || '~/.sentinel/vcr-tape.jsonl';
  vcr.max_entries = Number(vcr.max_entries ?? 2000);
  vcr.strict_replay = vcr.strict_replay === true;

  normalized.runtime.semantic_cache = normalized.runtime.semantic_cache || {};
  const semanticCache = normalized.runtime.semantic_cache;
  semanticCache.enabled = semanticCache.enabled === true;
  semanticCache.model_id = semanticCache.model_id || 'Xenova/all-MiniLM-L6-v2';
  semanticCache.cache_dir = semanticCache.cache_dir || '~/.sentinel/models';
  semanticCache.similarity_threshold = Number(semanticCache.similarity_threshold ?? 0.95);
  semanticCache.max_entries = Number(semanticCache.max_entries ?? 2000);
  semanticCache.ttl_ms = Number(semanticCache.ttl_ms ?? 3600000);
  semanticCache.max_prompt_chars = Number(semanticCache.max_prompt_chars ?? 2000);
  semanticCache.max_entry_bytes = Number(semanticCache.max_entry_bytes ?? 262144);
  semanticCache.max_ram_mb = Number(semanticCache.max_ram_mb ?? 64);
  semanticCache.max_consecutive_errors = Number(semanticCache.max_consecutive_errors ?? 3);
  semanticCache.failure_cooldown_ms = Number(semanticCache.failure_cooldown_ms ?? 30000);

  normalized.runtime.intent_throttle = normalized.runtime.intent_throttle || {};
  const intentThrottle = normalized.runtime.intent_throttle;
  intentThrottle.enabled = intentThrottle.enabled === true;
  intentThrottle.mode = INTENT_THROTTLE_MODES.has(String(intentThrottle.mode || '').toLowerCase())
    ? String(intentThrottle.mode).toLowerCase()
    : 'monitor';
  intentThrottle.key_header = String(intentThrottle.key_header || 'x-sentinel-agent-id').toLowerCase();
  intentThrottle.window_ms = Number(intentThrottle.window_ms ?? 3600000);
  intentThrottle.cooldown_ms = Number(intentThrottle.cooldown_ms ?? 900000);
  intentThrottle.max_events_per_window = Number(intentThrottle.max_events_per_window ?? 3);
  intentThrottle.min_similarity = Number(intentThrottle.min_similarity ?? 0.82);
  intentThrottle.max_prompt_chars = Number(intentThrottle.max_prompt_chars ?? 2000);
  intentThrottle.max_sessions = Number(intentThrottle.max_sessions ?? 5000);
  intentThrottle.model_id = String(intentThrottle.model_id || 'Xenova/all-MiniLM-L6-v2');
  intentThrottle.cache_dir = String(intentThrottle.cache_dir || '~/.sentinel/models');
  intentThrottle.clusters = Array.isArray(intentThrottle.clusters)
    ? intentThrottle.clusters.map((cluster) => {
        const normalizedCluster =
          cluster && typeof cluster === 'object' && !Array.isArray(cluster) ? cluster : {};
        normalizedCluster.name = String(normalizedCluster.name || '').trim().toLowerCase();
        normalizedCluster.phrases = Array.isArray(normalizedCluster.phrases)
          ? normalizedCluster.phrases.map((value) => String(value)).filter(Boolean)
          : [];
        if (normalizedCluster.min_similarity !== undefined) {
          normalizedCluster.min_similarity = Number(normalizedCluster.min_similarity);
        }
        return normalizedCluster;
      })
    : [];

  normalized.runtime.intent_drift = normalized.runtime.intent_drift || {};
  const intentDrift = normalized.runtime.intent_drift;
  intentDrift.enabled = intentDrift.enabled === true;
  intentDrift.mode = INTENT_DRIFT_MODES.has(String(intentDrift.mode || '').toLowerCase())
    ? String(intentDrift.mode).toLowerCase()
    : 'monitor';
  intentDrift.key_header = String(intentDrift.key_header || 'x-sentinel-session-id').toLowerCase();
  intentDrift.fallback_key_headers = Array.isArray(intentDrift.fallback_key_headers)
    ? intentDrift.fallback_key_headers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
  intentDrift.target_roles = Array.isArray(intentDrift.target_roles)
    ? intentDrift.target_roles.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['system', 'user', 'assistant'];
  intentDrift.strip_volatile_tokens = intentDrift.strip_volatile_tokens !== false;
  intentDrift.risk_keywords = Array.isArray(intentDrift.risk_keywords)
    ? intentDrift.risk_keywords.map((item) => String(item || '').trim().toLowerCase()).filter(Boolean)
    : [
        'password',
        'credential',
        'api key',
        'token',
        'secret',
        'id_rsa',
        'ssh key',
        'bypass',
        'ignore previous instructions',
        'override safety',
      ];
  intentDrift.risk_boost = Number(intentDrift.risk_boost ?? 0.12);
  intentDrift.sample_every_turns = Number(intentDrift.sample_every_turns ?? 10);
  intentDrift.min_turns = Number(intentDrift.min_turns ?? 10);
  intentDrift.threshold = Number(intentDrift.threshold ?? 0.35);
  intentDrift.cooldown_ms = Number(intentDrift.cooldown_ms ?? 60000);
  intentDrift.max_sessions = Number(intentDrift.max_sessions ?? 5000);
  intentDrift.context_window_messages = Number(intentDrift.context_window_messages ?? 8);
  intentDrift.model_id = String(intentDrift.model_id || 'Xenova/all-MiniLM-L6-v2');
  intentDrift.cache_dir = String(intentDrift.cache_dir || '~/.sentinel/models');
  intentDrift.max_prompt_chars = Number(intentDrift.max_prompt_chars ?? 4000);
  intentDrift.observability = intentDrift.observability !== false;

  normalized.runtime.swarm = normalized.runtime.swarm || {};
  const swarm = normalized.runtime.swarm;
  swarm.enabled = swarm.enabled === true;
  swarm.mode = SWARM_MODES.has(String(swarm.mode || '').toLowerCase())
    ? String(swarm.mode).toLowerCase()
    : 'monitor';
  swarm.node_id = String(swarm.node_id || `sentinel-node-${process.pid}`);
  swarm.key_id = String(swarm.key_id || swarm.node_id || `sentinel-node-${process.pid}`);
  swarm.private_key_pem = String(swarm.private_key_pem || '');
  swarm.public_key_pem = String(swarm.public_key_pem || '');
  swarm.verify_inbound = swarm.verify_inbound !== false;
  swarm.sign_outbound = swarm.sign_outbound !== false;
  swarm.require_envelope = swarm.require_envelope === true;
  swarm.allowed_clock_skew_ms = Number(swarm.allowed_clock_skew_ms ?? swarm.tolerance_window_ms ?? 30000);
  swarm.tolerance_window_ms = Number(swarm.tolerance_window_ms ?? swarm.allowed_clock_skew_ms);
  swarm.nonce_ttl_ms = Number(swarm.nonce_ttl_ms ?? 300000);
  swarm.max_nonce_entries = Number(swarm.max_nonce_entries ?? 50000);
  swarm.sign_on_providers = Array.isArray(swarm.sign_on_providers)
    ? swarm.sign_on_providers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['custom'];
  swarm.trusted_nodes =
    swarm.trusted_nodes && typeof swarm.trusted_nodes === 'object' && !Array.isArray(swarm.trusted_nodes)
      ? swarm.trusted_nodes
      : {};
  for (const [nodeId, nodeConfig] of Object.entries(swarm.trusted_nodes)) {
    if (typeof nodeConfig === 'string') {
      swarm.trusted_nodes[nodeId] = {
        public_key_pem: String(nodeConfig),
      };
      continue;
    }
    const normalizedNode =
      nodeConfig && typeof nodeConfig === 'object' && !Array.isArray(nodeConfig) ? nodeConfig : {};
    normalizedNode.public_key_pem = String(normalizedNode.public_key_pem || '');
    swarm.trusted_nodes[nodeId] = normalizedNode;
  }

  normalized.runtime.pii_vault = normalized.runtime.pii_vault || {};
  const piiVault = normalized.runtime.pii_vault;
  piiVault.enabled = piiVault.enabled === true;
  piiVault.mode = PII_VAULT_MODES.has(String(piiVault.mode || '').toLowerCase())
    ? String(piiVault.mode).toLowerCase()
    : 'monitor';
  piiVault.salt = String(piiVault.salt || '');
  piiVault.session_header = String(piiVault.session_header || 'x-sentinel-session-id').toLowerCase();
  piiVault.fallback_headers = Array.isArray(piiVault.fallback_headers)
    ? piiVault.fallback_headers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
  piiVault.ttl_ms = Number(piiVault.ttl_ms ?? 3600000);
  piiVault.max_sessions = Number(piiVault.max_sessions ?? 5000);
  piiVault.max_mappings_per_session = Number(piiVault.max_mappings_per_session ?? 1000);
  piiVault.max_memory_bytes = Number(piiVault.max_memory_bytes ?? 64 * 1024 * 1024);
  piiVault.max_egress_rewrite_entries = Number(piiVault.max_egress_rewrite_entries ?? 256);
  piiVault.max_payload_bytes = Number(piiVault.max_payload_bytes ?? 512 * 1024);
  piiVault.max_replacements_per_pass = Number(piiVault.max_replacements_per_pass ?? 1000);
  piiVault.token_domain = String(piiVault.token_domain || 'sentinel.local');
  piiVault.token_prefix = String(piiVault.token_prefix || 'sentinel_');
  piiVault.target_types = Array.isArray(piiVault.target_types)
    ? piiVault.target_types.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['email_address', 'phone_us', 'phone_e164', 'ssn_us'];
  piiVault.observability = piiVault.observability !== false;

  normalized.runtime.polymorphic_prompt = normalized.runtime.polymorphic_prompt || {};
  const polymorphicPrompt = normalized.runtime.polymorphic_prompt;
  polymorphicPrompt.enabled = polymorphicPrompt.enabled === true;
  polymorphicPrompt.rotation_seconds = Number(polymorphicPrompt.rotation_seconds ?? 1800);
  polymorphicPrompt.max_mutations_per_message = Number(polymorphicPrompt.max_mutations_per_message ?? 3);
  polymorphicPrompt.target_roles = Array.isArray(polymorphicPrompt.target_roles)
    ? polymorphicPrompt.target_roles.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['system'];
  polymorphicPrompt.bypass_header = String(polymorphicPrompt.bypass_header || 'x-sentinel-polymorph-disable').toLowerCase();
  polymorphicPrompt.seed = String(polymorphicPrompt.seed || 'sentinel-mtd-seed');
  polymorphicPrompt.observability = polymorphicPrompt.observability !== false;
  polymorphicPrompt.lexicon =
    polymorphicPrompt.lexicon && typeof polymorphicPrompt.lexicon === 'object' && !Array.isArray(polymorphicPrompt.lexicon)
      ? polymorphicPrompt.lexicon
      : {};

  normalized.runtime.synthetic_poisoning = normalized.runtime.synthetic_poisoning || {};
  const syntheticPoisoning = normalized.runtime.synthetic_poisoning;
  syntheticPoisoning.enabled = syntheticPoisoning.enabled === true;
  syntheticPoisoning.mode = SYNTHETIC_POISONING_MODES.has(String(syntheticPoisoning.mode || '').toLowerCase())
    ? String(syntheticPoisoning.mode).toLowerCase()
    : 'monitor';
  syntheticPoisoning.required_acknowledgement = String(
    syntheticPoisoning.required_acknowledgement || 'I_UNDERSTAND_SYNTHETIC_DATA_RISK'
  );
  syntheticPoisoning.acknowledgement = String(syntheticPoisoning.acknowledgement || '');
  syntheticPoisoning.allowed_triggers = Array.isArray(syntheticPoisoning.allowed_triggers)
    ? syntheticPoisoning.allowed_triggers.map((item) => String(item || '').trim()).filter(Boolean)
    : ['intent_velocity_exceeded'];
  syntheticPoisoning.target_roles = Array.isArray(syntheticPoisoning.target_roles)
    ? syntheticPoisoning.target_roles.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['system'];
  syntheticPoisoning.decoy_label = String(syntheticPoisoning.decoy_label || 'SENTINEL_SYNTHETIC_CONTEXT');
  syntheticPoisoning.max_insertions_per_request = Number(syntheticPoisoning.max_insertions_per_request ?? 1);
  syntheticPoisoning.observability = syntheticPoisoning.observability !== false;

  normalized.runtime.cognitive_rollback = normalized.runtime.cognitive_rollback || {};
  const cognitiveRollback = normalized.runtime.cognitive_rollback;
  cognitiveRollback.enabled = cognitiveRollback.enabled === true;
  cognitiveRollback.mode = COGNITIVE_ROLLBACK_MODES.has(String(cognitiveRollback.mode || '').toLowerCase())
    ? String(cognitiveRollback.mode).toLowerCase()
    : 'monitor';
  cognitiveRollback.triggers = Array.isArray(cognitiveRollback.triggers)
    ? cognitiveRollback.triggers.map((item) => String(item || '').trim()).filter(Boolean)
    : ['canary_tool_triggered', 'parallax_veto'];
  cognitiveRollback.target_roles = Array.isArray(cognitiveRollback.target_roles)
    ? cognitiveRollback.target_roles.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['user', 'assistant', 'tool'];
  cognitiveRollback.drop_messages = Number(cognitiveRollback.drop_messages ?? 2);
  cognitiveRollback.min_messages_remaining = Number(cognitiveRollback.min_messages_remaining ?? 2);
  cognitiveRollback.system_message = String(
    cognitiveRollback.system_message ||
      '[SYSTEM OVERRIDE] Your previous thought process was corrupted. Resume execution from the last safe checkpoint and try a different approach.'
  );
  cognitiveRollback.observability = cognitiveRollback.observability !== false;

  normalized.runtime.omni_shield = normalized.runtime.omni_shield || {};
  const omniShield = normalized.runtime.omni_shield;
  omniShield.enabled = omniShield.enabled === true;
  omniShield.mode = OMNI_SHIELD_MODES.has(String(omniShield.mode || '').toLowerCase())
    ? String(omniShield.mode).toLowerCase()
    : 'monitor';
  omniShield.max_image_bytes = Number(omniShield.max_image_bytes ?? 5 * 1024 * 1024);
  omniShield.allow_remote_image_urls = omniShield.allow_remote_image_urls === true;
  omniShield.allow_base64_images = omniShield.allow_base64_images !== false;
  omniShield.block_on_any_image = omniShield.block_on_any_image === true;
  omniShield.max_findings = Number(omniShield.max_findings ?? 20);
  omniShield.target_roles = Array.isArray(omniShield.target_roles)
    ? omniShield.target_roles.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['user'];
  omniShield.observability = omniShield.observability !== false;
  omniShield.plugin =
    omniShield.plugin && typeof omniShield.plugin === 'object' && !Array.isArray(omniShield.plugin)
      ? omniShield.plugin
      : {};
  omniShield.plugin.enabled = omniShield.plugin.enabled === true;
  omniShield.plugin.provider = String(omniShield.plugin.provider || 'builtin_mask').toLowerCase();
  omniShield.plugin.module_path = String(omniShield.plugin.module_path || '');
  omniShield.plugin.mode = OMNI_SHIELD_PLUGIN_MODES.has(String(omniShield.plugin.mode || '').toLowerCase())
    ? String(omniShield.plugin.mode).toLowerCase()
    : 'enforce';
  omniShield.plugin.fail_closed = omniShield.plugin.fail_closed === true;
  omniShield.plugin.max_rewrites = Number(omniShield.plugin.max_rewrites ?? 20);
  omniShield.plugin.timeout_ms = Number(omniShield.plugin.timeout_ms ?? 1500);
  omniShield.plugin.observability = omniShield.plugin.observability !== false;

  normalized.runtime.sandbox_experimental = normalized.runtime.sandbox_experimental || {};
  const sandboxExperimental = normalized.runtime.sandbox_experimental;
  sandboxExperimental.enabled = sandboxExperimental.enabled === true;
  sandboxExperimental.mode = SANDBOX_EXPERIMENTAL_MODES.has(String(sandboxExperimental.mode || '').toLowerCase())
    ? String(sandboxExperimental.mode).toLowerCase()
    : 'monitor';
  sandboxExperimental.max_code_chars = Number(sandboxExperimental.max_code_chars ?? 20000);
  sandboxExperimental.max_findings = Number(sandboxExperimental.max_findings ?? 25);
  sandboxExperimental.normalize_evasion = sandboxExperimental.normalize_evasion !== false;
  sandboxExperimental.decode_base64 = sandboxExperimental.decode_base64 !== false;
  sandboxExperimental.max_decoded_bytes = Number(sandboxExperimental.max_decoded_bytes ?? 8192);
  sandboxExperimental.max_variants_per_candidate = Number(sandboxExperimental.max_variants_per_candidate ?? 4);
  sandboxExperimental.disallowed_patterns = Array.isArray(sandboxExperimental.disallowed_patterns)
    ? sandboxExperimental.disallowed_patterns.map((item) => String(item || '')).filter(Boolean)
    : [
        'child_process',
        'process\\.env',
        'fs\\.',
        'require\\(',
        'rm\\s+-rf',
        'id_rsa',
        'curl\\s+https?://',
        'wget\\s+https?://',
        'nc\\s+-',
        "token\\s*=\\s*['\\\"]?[A-Za-z0-9_-]{16,}",
      ];
  sandboxExperimental.target_tool_names = Array.isArray(sandboxExperimental.target_tool_names)
    ? sandboxExperimental.target_tool_names.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['execute_shell', 'execute_sql', 'bash', 'python', 'terminal'];
  sandboxExperimental.observability = sandboxExperimental.observability !== false;

  normalized.runtime.dashboard = normalized.runtime.dashboard || {};
  const dashboard = normalized.runtime.dashboard;
  dashboard.enabled = dashboard.enabled === true;
  dashboard.host = dashboard.host || '127.0.0.1';
  dashboard.port = Number(dashboard.port ?? 8788);
  dashboard.auth_token = String(dashboard.auth_token || process.env.SENTINEL_DASHBOARD_TOKEN || '');
  dashboard.allow_remote = dashboard.allow_remote === true;
  const rawDashboardTokens =
    dashboard.team_tokens && typeof dashboard.team_tokens === 'object' && !Array.isArray(dashboard.team_tokens)
      ? dashboard.team_tokens
      : {};
  const normalizedDashboardTokens = {};
  for (const [rawTeam, rawToken] of Object.entries(rawDashboardTokens).slice(0, 128)) {
    const team = String(rawTeam || '').trim().toLowerCase().slice(0, 64);
    const token = String(rawToken || '').trim();
    if (!team || !token) {
      continue;
    }
    normalizedDashboardTokens[team] = token.slice(0, 4096);
  }
  dashboard.team_tokens = normalizedDashboardTokens;
  const defaultDashboardTeamHeader = 'x-sentinel-dashboard-team';
  dashboard.team_header = String(dashboard.team_header || defaultDashboardTeamHeader)
    .trim()
    .toLowerCase() || defaultDashboardTeamHeader;

  normalized.runtime.posture_scoring = normalized.runtime.posture_scoring || {};
  const postureScoring = normalized.runtime.posture_scoring;
  postureScoring.enabled = postureScoring.enabled !== false;
  postureScoring.include_counters = postureScoring.include_counters !== false;
  postureScoring.warn_threshold = Number(postureScoring.warn_threshold ?? 70);
  postureScoring.critical_threshold = Number(postureScoring.critical_threshold ?? 50);

  normalized.runtime.websocket = normalized.runtime.websocket || {};
  const websocket = normalized.runtime.websocket;
  websocket.enabled = websocket.enabled !== false;
  websocket.mode = WEBSOCKET_MODES.has(String(websocket.mode || '').toLowerCase())
    ? String(websocket.mode).toLowerCase()
    : 'monitor';
  websocket.connect_timeout_ms = Number(websocket.connect_timeout_ms ?? 15000);
  websocket.idle_timeout_ms = Number(websocket.idle_timeout_ms ?? 120000);
  websocket.max_connections = Number(websocket.max_connections ?? 500);

  normalized.runtime.budget = normalized.runtime.budget || {};
  const budget = normalized.runtime.budget;
  budget.enabled = budget.enabled === true;
  budget.action = BUDGET_ACTIONS.has(String(budget.action).toLowerCase())
    ? String(budget.action).toLowerCase()
    : 'block';
  budget.daily_limit_usd = Number(budget.daily_limit_usd ?? 5);
  budget.store_file = String(budget.store_file || '~/.sentinel/budget-ledger.json');
  budget.reset_timezone = BUDGET_RESET_TIMEZONES.has(String(budget.reset_timezone).toLowerCase())
    ? String(budget.reset_timezone).toLowerCase()
    : 'utc';
  budget.chars_per_token = Number(budget.chars_per_token ?? 4);
  budget.input_cost_per_1k_tokens = Number(budget.input_cost_per_1k_tokens ?? 0);
  budget.output_cost_per_1k_tokens = Number(budget.output_cost_per_1k_tokens ?? 0);
  budget.charge_replay_hits = budget.charge_replay_hits === true;
  budget.retention_days = Number(budget.retention_days ?? 90);

  normalized.runtime.loop_breaker = normalized.runtime.loop_breaker || {};
  const loopBreaker = normalized.runtime.loop_breaker;
  loopBreaker.enabled = loopBreaker.enabled === true;
  loopBreaker.action = LOOP_BREAKER_ACTIONS.has(String(loopBreaker.action).toLowerCase())
    ? String(loopBreaker.action).toLowerCase()
    : 'block';
  loopBreaker.window_ms = Number(loopBreaker.window_ms ?? 30000);
  loopBreaker.repeat_threshold = Number(loopBreaker.repeat_threshold ?? 4);
  loopBreaker.max_recent = Number(loopBreaker.max_recent ?? 5);
  loopBreaker.max_keys = Number(loopBreaker.max_keys ?? 2048);
  loopBreaker.key_header = String(loopBreaker.key_header || 'x-sentinel-agent-id').toLowerCase();

  normalized.runtime.agentic_threat_shield = normalized.runtime.agentic_threat_shield || {};
  const agenticThreatShield = normalized.runtime.agentic_threat_shield;
  agenticThreatShield.enabled = agenticThreatShield.enabled === true;
  agenticThreatShield.mode = AGENTIC_THREAT_SHIELD_MODES.has(String(agenticThreatShield.mode || '').toLowerCase())
    ? String(agenticThreatShield.mode).toLowerCase()
    : 'monitor';
  agenticThreatShield.max_tool_call_depth = Number(agenticThreatShield.max_tool_call_depth ?? 10);
  agenticThreatShield.max_agent_delegations = Number(agenticThreatShield.max_agent_delegations ?? 5);
  agenticThreatShield.max_analysis_nodes = Number(agenticThreatShield.max_analysis_nodes ?? 4096);
  agenticThreatShield.max_tool_calls_analyzed = Number(agenticThreatShield.max_tool_calls_analyzed ?? 1024);
  agenticThreatShield.block_on_analysis_truncation = agenticThreatShield.block_on_analysis_truncation === true;
  agenticThreatShield.detect_cycles = agenticThreatShield.detect_cycles !== false;
  agenticThreatShield.verify_identity_tokens = agenticThreatShield.verify_identity_tokens === true;
  agenticThreatShield.identity_token_header = String(
    agenticThreatShield.identity_token_header || 'x-sentinel-agent-token'
  ).toLowerCase();
  agenticThreatShield.agent_id_header = String(
    agenticThreatShield.agent_id_header || 'x-sentinel-agent-id'
  ).toLowerCase();
  agenticThreatShield.session_header = String(
    agenticThreatShield.session_header || 'x-sentinel-session-id'
  ).toLowerCase();
  agenticThreatShield.fallback_headers = Array.isArray(agenticThreatShield.fallback_headers)
    ? agenticThreatShield.fallback_headers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
  agenticThreatShield.hmac_secret = String(
    agenticThreatShield.hmac_secret || process.env.SENTINEL_AGENTIC_HMAC_SECRET || ''
  );
  agenticThreatShield.ttl_ms = Number(agenticThreatShield.ttl_ms ?? 900000);
  agenticThreatShield.max_sessions = Number(agenticThreatShield.max_sessions ?? 5000);
  agenticThreatShield.max_graph_edges_per_session = Number(
    agenticThreatShield.max_graph_edges_per_session ?? 256
  );
  agenticThreatShield.observability = agenticThreatShield.observability !== false;

  normalized.runtime.a2a_card_verifier = normalized.runtime.a2a_card_verifier || {};
  const a2aCardVerifier = normalized.runtime.a2a_card_verifier;
  a2aCardVerifier.enabled = a2aCardVerifier.enabled === true;
  a2aCardVerifier.mode = A2A_CARD_VERIFIER_MODES.has(String(a2aCardVerifier.mode || '').toLowerCase())
    ? String(a2aCardVerifier.mode).toLowerCase()
    : 'monitor';
  a2aCardVerifier.card_header = String(a2aCardVerifier.card_header || 'x-a2a-agent-card').toLowerCase();
  a2aCardVerifier.agent_id_header = String(
    a2aCardVerifier.agent_id_header || 'x-sentinel-agent-id'
  ).toLowerCase();
  a2aCardVerifier.max_card_bytes = Number(a2aCardVerifier.max_card_bytes ?? 32768);
  a2aCardVerifier.ttl_ms = Number(a2aCardVerifier.ttl_ms ?? 3600000);
  a2aCardVerifier.max_agents = Number(a2aCardVerifier.max_agents ?? 10000);
  a2aCardVerifier.max_capabilities = Number(a2aCardVerifier.max_capabilities ?? 128);
  a2aCardVerifier.max_observed_per_agent = Number(a2aCardVerifier.max_observed_per_agent ?? 128);
  a2aCardVerifier.overclaim_tolerance = Number(a2aCardVerifier.overclaim_tolerance ?? 6);
  a2aCardVerifier.block_on_invalid_schema = a2aCardVerifier.block_on_invalid_schema === true;
  a2aCardVerifier.block_on_drift = a2aCardVerifier.block_on_drift === true;
  a2aCardVerifier.block_on_overclaim = a2aCardVerifier.block_on_overclaim === true;
  a2aCardVerifier.block_on_auth_mismatch = a2aCardVerifier.block_on_auth_mismatch === true;
  a2aCardVerifier.observability = a2aCardVerifier.observability !== false;

  normalized.runtime.consensus_protocol = normalized.runtime.consensus_protocol || {};
  const consensusProtocol = normalized.runtime.consensus_protocol;
  consensusProtocol.enabled = consensusProtocol.enabled === true;
  consensusProtocol.mode = CONSENSUS_PROTOCOL_MODES.has(String(consensusProtocol.mode || '').toLowerCase())
    ? String(consensusProtocol.mode).toLowerCase()
    : 'monitor';
  consensusProtocol.policy_header = String(
    consensusProtocol.policy_header || 'x-sentinel-consensus-policy'
  ).toLowerCase();
  consensusProtocol.action_field = String(consensusProtocol.action_field || 'action');
  consensusProtocol.max_votes = Number(consensusProtocol.max_votes ?? 32);
  consensusProtocol.required_votes = Number(consensusProtocol.required_votes ?? 2);
  consensusProtocol.total_agents = Number(consensusProtocol.total_agents ?? 3);
  consensusProtocol.block_on_no_quorum = consensusProtocol.block_on_no_quorum === true;
  consensusProtocol.block_on_byzantine = consensusProtocol.block_on_byzantine === true;
  consensusProtocol.high_risk_actions = Array.isArray(consensusProtocol.high_risk_actions)
    ? consensusProtocol.high_risk_actions.map((item) => String(item || '').trim().toLowerCase()).filter(Boolean)
    : ['wire_funds', 'grant_admin', 'delete_data', 'drop_database', 'execute_shell'];
  consensusProtocol.observability = consensusProtocol.observability !== false;

  normalized.runtime.cross_tenant_isolator = normalized.runtime.cross_tenant_isolator || {};
  const crossTenantIsolator = normalized.runtime.cross_tenant_isolator;
  crossTenantIsolator.enabled = crossTenantIsolator.enabled === true;
  crossTenantIsolator.mode = CROSS_TENANT_ISOLATOR_MODES.has(String(crossTenantIsolator.mode || '').toLowerCase())
    ? String(crossTenantIsolator.mode).toLowerCase()
    : 'monitor';
  crossTenantIsolator.tenant_header = String(
    crossTenantIsolator.tenant_header || 'x-sentinel-tenant-id'
  ).toLowerCase();
  crossTenantIsolator.session_header = String(
    crossTenantIsolator.session_header || 'x-sentinel-session-id'
  ).toLowerCase();
  crossTenantIsolator.fallback_headers = Array.isArray(crossTenantIsolator.fallback_headers)
    ? crossTenantIsolator.fallback_headers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
  crossTenantIsolator.ttl_ms = Number(crossTenantIsolator.ttl_ms ?? 21600000);
  crossTenantIsolator.max_sessions = Number(crossTenantIsolator.max_sessions ?? 20000);
  crossTenantIsolator.max_known_tenants = Number(crossTenantIsolator.max_known_tenants ?? 20000);
  crossTenantIsolator.block_on_mismatch = crossTenantIsolator.block_on_mismatch === true;
  crossTenantIsolator.block_on_leak = crossTenantIsolator.block_on_leak === true;
  crossTenantIsolator.observability = crossTenantIsolator.observability !== false;

  normalized.runtime.cold_start_analyzer = normalized.runtime.cold_start_analyzer || {};
  const coldStartAnalyzer = normalized.runtime.cold_start_analyzer;
  coldStartAnalyzer.enabled = coldStartAnalyzer.enabled === true;
  coldStartAnalyzer.mode = COLD_START_ANALYZER_MODES.has(String(coldStartAnalyzer.mode || '').toLowerCase())
    ? String(coldStartAnalyzer.mode).toLowerCase()
    : 'monitor';
  coldStartAnalyzer.cold_start_window_ms = Number(coldStartAnalyzer.cold_start_window_ms ?? 600000);
  coldStartAnalyzer.warmup_request_threshold = Number(coldStartAnalyzer.warmup_request_threshold ?? 200);
  coldStartAnalyzer.warmup_engines = Array.isArray(coldStartAnalyzer.warmup_engines)
    ? coldStartAnalyzer.warmup_engines.map((item) => String(item || '').trim()).filter(Boolean)
    : ['semantic_cache', 'intent_drift', 'intent_throttle', 'agent_observability'];
  coldStartAnalyzer.block_during_cold_start = coldStartAnalyzer.block_during_cold_start === true;
  coldStartAnalyzer.observability = coldStartAnalyzer.observability !== false;

  normalized.runtime.serialization_firewall = normalized.runtime.serialization_firewall || {};
  const serializationFirewall = normalized.runtime.serialization_firewall;
  serializationFirewall.enabled = serializationFirewall.enabled === true;
  serializationFirewall.mode = SERIALIZATION_FIREWALL_MODES.has(String(serializationFirewall.mode || '').toLowerCase())
    ? String(serializationFirewall.mode).toLowerCase()
    : 'monitor';
  serializationFirewall.max_scan_bytes = Number(serializationFirewall.max_scan_bytes ?? 262144);
  serializationFirewall.max_nesting_depth = Number(serializationFirewall.max_nesting_depth ?? 50);
  serializationFirewall.max_object_nodes = Number(serializationFirewall.max_object_nodes ?? 200000);
  serializationFirewall.metadata_ratio_threshold = Number(serializationFirewall.metadata_ratio_threshold ?? 0.8);
  serializationFirewall.allowed_formats = Array.isArray(serializationFirewall.allowed_formats)
    ? serializationFirewall.allowed_formats.map((item) => String(item || '').toLowerCase().trim()).filter(Boolean)
    : ['json', 'yaml', 'unknown'];
  serializationFirewall.expected_root_keys = Array.isArray(serializationFirewall.expected_root_keys)
    ? serializationFirewall.expected_root_keys.map((item) => String(item || '').trim()).filter(Boolean)
    : [];
  serializationFirewall.block_on_type_confusion = serializationFirewall.block_on_type_confusion === true;
  serializationFirewall.block_on_depth_bomb = serializationFirewall.block_on_depth_bomb === true;
  serializationFirewall.block_on_format_violation = serializationFirewall.block_on_format_violation === true;
  serializationFirewall.block_on_metadata_anomaly = serializationFirewall.block_on_metadata_anomaly === true;
  serializationFirewall.block_on_schema_mismatch = serializationFirewall.block_on_schema_mismatch === true;
  serializationFirewall.observability = serializationFirewall.observability !== false;

  normalized.runtime.context_integrity_guardian = normalized.runtime.context_integrity_guardian || {};
  const contextIntegrityGuardian = normalized.runtime.context_integrity_guardian;
  contextIntegrityGuardian.enabled = contextIntegrityGuardian.enabled === true;
  contextIntegrityGuardian.mode = CONTEXT_INTEGRITY_GUARDIAN_MODES.has(String(contextIntegrityGuardian.mode || '').toLowerCase())
    ? String(contextIntegrityGuardian.mode).toLowerCase()
    : 'monitor';
  contextIntegrityGuardian.session_header = String(
    contextIntegrityGuardian.session_header || 'x-sentinel-session-id'
  ).toLowerCase();
  contextIntegrityGuardian.fallback_headers = Array.isArray(contextIntegrityGuardian.fallback_headers)
    ? contextIntegrityGuardian.fallback_headers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
  contextIntegrityGuardian.required_anchors = Array.isArray(contextIntegrityGuardian.required_anchors)
    ? contextIntegrityGuardian.required_anchors.map((item) => String(item || '').trim()).filter(Boolean)
    : [];
  contextIntegrityGuardian.max_context_chars = Number(contextIntegrityGuardian.max_context_chars ?? 32768);
  contextIntegrityGuardian.max_sessions = Number(contextIntegrityGuardian.max_sessions ?? 10000);
  contextIntegrityGuardian.ttl_ms = Number(contextIntegrityGuardian.ttl_ms ?? 21600000);
  contextIntegrityGuardian.repetition_threshold = Number(contextIntegrityGuardian.repetition_threshold ?? 0.35);
  contextIntegrityGuardian.token_budget_warn_ratio = Number(contextIntegrityGuardian.token_budget_warn_ratio ?? 0.85);
  contextIntegrityGuardian.provider_token_limit = Number(contextIntegrityGuardian.provider_token_limit ?? 128000);
  contextIntegrityGuardian.block_on_anchor_loss = contextIntegrityGuardian.block_on_anchor_loss === true;
  contextIntegrityGuardian.block_on_repetition = contextIntegrityGuardian.block_on_repetition === true;
  contextIntegrityGuardian.observability = contextIntegrityGuardian.observability !== false;

  normalized.runtime.context_compression_guard = normalized.runtime.context_compression_guard || {};
  const contextCompressionGuard = normalized.runtime.context_compression_guard;
  contextCompressionGuard.enabled = contextCompressionGuard.enabled === true;
  contextCompressionGuard.mode = CONTEXT_COMPRESSION_GUARD_MODES.has(String(contextCompressionGuard.mode || '').toLowerCase())
    ? String(contextCompressionGuard.mode).toLowerCase()
    : 'monitor';
  contextCompressionGuard.session_header = String(
    contextCompressionGuard.session_header || 'x-sentinel-session-id'
  ).toLowerCase();
  contextCompressionGuard.fallback_headers = Array.isArray(contextCompressionGuard.fallback_headers)
    ? contextCompressionGuard.fallback_headers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
  contextCompressionGuard.protected_anchors = Array.isArray(contextCompressionGuard.protected_anchors)
    ? contextCompressionGuard.protected_anchors.map((item) => String(item || '').trim()).filter(Boolean)
    : [];
  contextCompressionGuard.summary_fields = Array.isArray(contextCompressionGuard.summary_fields)
    ? contextCompressionGuard.summary_fields.map((item) => String(item || '').trim()).filter(Boolean)
    : ['summary', 'context_summary', 'memory_summary', 'compressed_context', 'conversation_summary'];
  contextCompressionGuard.max_context_chars = Number(contextCompressionGuard.max_context_chars ?? 32768);
  contextCompressionGuard.max_summary_chars = Number(contextCompressionGuard.max_summary_chars ?? 16384);
  contextCompressionGuard.max_sessions = Number(contextCompressionGuard.max_sessions ?? 10000);
  contextCompressionGuard.ttl_ms = Number(contextCompressionGuard.ttl_ms ?? 21600000);
  contextCompressionGuard.anchor_loss_ratio = Number(contextCompressionGuard.anchor_loss_ratio ?? 0.75);
  contextCompressionGuard.shrink_spike_ratio = Number(contextCompressionGuard.shrink_spike_ratio ?? 0.35);
  contextCompressionGuard.token_budget_warn_ratio = Number(contextCompressionGuard.token_budget_warn_ratio ?? 0.85);
  contextCompressionGuard.provider_token_limit = Number(contextCompressionGuard.provider_token_limit ?? 128000);
  contextCompressionGuard.block_on_anchor_loss = contextCompressionGuard.block_on_anchor_loss === true;
  contextCompressionGuard.block_on_summary_injection = contextCompressionGuard.block_on_summary_injection === true;
  contextCompressionGuard.observability = contextCompressionGuard.observability !== false;

  normalized.runtime.tool_schema_validator = normalized.runtime.tool_schema_validator || {};
  const toolSchemaValidator = normalized.runtime.tool_schema_validator;
  toolSchemaValidator.enabled = toolSchemaValidator.enabled === true;
  toolSchemaValidator.mode = TOOL_SCHEMA_VALIDATOR_MODES.has(String(toolSchemaValidator.mode || '').toLowerCase())
    ? String(toolSchemaValidator.mode).toLowerCase()
    : 'monitor';
  toolSchemaValidator.max_tools = Number(toolSchemaValidator.max_tools ?? 64);
  toolSchemaValidator.max_schema_bytes = Number(toolSchemaValidator.max_schema_bytes ?? 131072);
  toolSchemaValidator.max_param_name_chars = Number(toolSchemaValidator.max_param_name_chars ?? 128);
  toolSchemaValidator.ttl_ms = Number(toolSchemaValidator.ttl_ms ?? 3600000);
  toolSchemaValidator.max_servers = Number(toolSchemaValidator.max_servers ?? 5000);
  toolSchemaValidator.block_on_dangerous_parameter = toolSchemaValidator.block_on_dangerous_parameter === true;
  toolSchemaValidator.block_on_schema_drift = toolSchemaValidator.block_on_schema_drift === true;
  toolSchemaValidator.block_on_capability_boundary = toolSchemaValidator.block_on_capability_boundary === true;
  toolSchemaValidator.detect_schema_drift = toolSchemaValidator.detect_schema_drift !== false;
  toolSchemaValidator.sanitize_in_monitor = toolSchemaValidator.sanitize_in_monitor !== false;
  toolSchemaValidator.observability = toolSchemaValidator.observability !== false;

  normalized.runtime.multimodal_injection_shield = normalized.runtime.multimodal_injection_shield || {};
  const multimodalInjectionShield = normalized.runtime.multimodal_injection_shield;
  multimodalInjectionShield.enabled = multimodalInjectionShield.enabled === true;
  multimodalInjectionShield.mode = MULTIMODAL_INJECTION_SHIELD_MODES.has(String(multimodalInjectionShield.mode || '').toLowerCase())
    ? String(multimodalInjectionShield.mode).toLowerCase()
    : 'monitor';
  multimodalInjectionShield.max_scan_bytes = Number(multimodalInjectionShield.max_scan_bytes ?? 262144);
  multimodalInjectionShield.max_findings = Number(multimodalInjectionShield.max_findings ?? 16);
  multimodalInjectionShield.base64_entropy_threshold = Number(multimodalInjectionShield.base64_entropy_threshold ?? 0.55);
  multimodalInjectionShield.max_decoded_base64_bytes = Number(multimodalInjectionShield.max_decoded_base64_bytes ?? 32768);
  multimodalInjectionShield.block_on_mime_mismatch = multimodalInjectionShield.block_on_mime_mismatch === true;
  multimodalInjectionShield.block_on_suspicious_metadata = multimodalInjectionShield.block_on_suspicious_metadata === true;
  multimodalInjectionShield.block_on_base64_injection = multimodalInjectionShield.block_on_base64_injection === true;
  multimodalInjectionShield.observability = multimodalInjectionShield.observability !== false;

  normalized.runtime.supply_chain_validator = normalized.runtime.supply_chain_validator || {};
  const supplyChainValidator = normalized.runtime.supply_chain_validator;
  supplyChainValidator.enabled = supplyChainValidator.enabled === true;
  supplyChainValidator.mode = SUPPLY_CHAIN_VALIDATOR_MODES.has(String(supplyChainValidator.mode || '').toLowerCase())
    ? String(supplyChainValidator.mode).toLowerCase()
    : 'monitor';
  supplyChainValidator.project_root = String(supplyChainValidator.project_root || process.cwd());
  supplyChainValidator.max_module_entries = Number(supplyChainValidator.max_module_entries ?? 10000);
  supplyChainValidator.check_every_requests = Number(supplyChainValidator.check_every_requests ?? 100);
  supplyChainValidator.block_on_lockfile_drift = supplyChainValidator.block_on_lockfile_drift === true;
  supplyChainValidator.block_on_blocked_package = supplyChainValidator.block_on_blocked_package === true;
  supplyChainValidator.require_lockfile = supplyChainValidator.require_lockfile === true;
  supplyChainValidator.blocked_packages = Array.isArray(supplyChainValidator.blocked_packages)
    ? supplyChainValidator.blocked_packages.map((item) => String(item || '').trim()).filter(Boolean)
    : [];
  supplyChainValidator.lock_files = Array.isArray(supplyChainValidator.lock_files)
    ? supplyChainValidator.lock_files.map((item) => String(item || '').trim()).filter(Boolean)
    : ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'];
  supplyChainValidator.observability = supplyChainValidator.observability !== false;

  normalized.runtime.sandbox_enforcer = normalized.runtime.sandbox_enforcer || {};
  const sandboxEnforcer = normalized.runtime.sandbox_enforcer;
  sandboxEnforcer.enabled = sandboxEnforcer.enabled === true;
  sandboxEnforcer.mode = SANDBOX_ENFORCER_MODES.has(String(sandboxEnforcer.mode || '').toLowerCase())
    ? String(sandboxEnforcer.mode).toLowerCase()
    : 'monitor';
  sandboxEnforcer.max_argument_bytes = Number(sandboxEnforcer.max_argument_bytes ?? 65536);
  sandboxEnforcer.allowed_paths = Array.isArray(sandboxEnforcer.allowed_paths)
    ? sandboxEnforcer.allowed_paths.map((item) => String(item || '').trim()).filter(Boolean)
    : [];
  sandboxEnforcer.allowed_domains = Array.isArray(sandboxEnforcer.allowed_domains)
    ? sandboxEnforcer.allowed_domains.map((item) => String(item || '').trim().toLowerCase()).filter(Boolean)
    : [];
  sandboxEnforcer.blocked_ports = Array.isArray(sandboxEnforcer.blocked_ports)
    ? sandboxEnforcer.blocked_ports.map((item) => Number(item)).filter((item) => Number.isInteger(item))
    : [22, 2375, 3306, 5432];
  sandboxEnforcer.block_on_path_escape = sandboxEnforcer.block_on_path_escape === true;
  sandboxEnforcer.block_on_network_escape = sandboxEnforcer.block_on_network_escape === true;
  sandboxEnforcer.observability = sandboxEnforcer.observability !== false;

  normalized.runtime.memory_integrity_monitor = normalized.runtime.memory_integrity_monitor || {};
  const memoryIntegrityMonitor = normalized.runtime.memory_integrity_monitor;
  memoryIntegrityMonitor.enabled = memoryIntegrityMonitor.enabled === true;
  memoryIntegrityMonitor.mode = MEMORY_INTEGRITY_MONITOR_MODES.has(String(memoryIntegrityMonitor.mode || '').toLowerCase())
    ? String(memoryIntegrityMonitor.mode).toLowerCase()
    : 'monitor';
  memoryIntegrityMonitor.session_header = String(memoryIntegrityMonitor.session_header || 'x-sentinel-session-id').toLowerCase();
  memoryIntegrityMonitor.agent_header = String(memoryIntegrityMonitor.agent_header || 'x-sentinel-agent-id').toLowerCase();
  memoryIntegrityMonitor.chain_header = String(memoryIntegrityMonitor.chain_header || 'x-sentinel-memory-chain').toLowerCase();
  memoryIntegrityMonitor.max_memory_chars = Number(memoryIntegrityMonitor.max_memory_chars ?? 32768);
  memoryIntegrityMonitor.ttl_ms = Number(memoryIntegrityMonitor.ttl_ms ?? 21600000);
  memoryIntegrityMonitor.max_sessions = Number(memoryIntegrityMonitor.max_sessions ?? 10000);
  memoryIntegrityMonitor.max_growth_ratio = Number(memoryIntegrityMonitor.max_growth_ratio ?? 4);
  memoryIntegrityMonitor.block_on_chain_break = memoryIntegrityMonitor.block_on_chain_break === true;
  memoryIntegrityMonitor.block_on_growth = memoryIntegrityMonitor.block_on_growth === true;
  memoryIntegrityMonitor.block_on_owner_mismatch = memoryIntegrityMonitor.block_on_owner_mismatch === true;
  memoryIntegrityMonitor.observability = memoryIntegrityMonitor.observability !== false;

  normalized.runtime.mcp_poisoning = normalized.runtime.mcp_poisoning || {};
  const mcpPoisoning = normalized.runtime.mcp_poisoning;
  mcpPoisoning.enabled = mcpPoisoning.enabled === true;
  mcpPoisoning.mode = MCP_POISONING_MODES.has(String(mcpPoisoning.mode || '').toLowerCase())
    ? String(mcpPoisoning.mode).toLowerCase()
    : 'monitor';
  mcpPoisoning.description_threshold = Number(mcpPoisoning.description_threshold ?? 0.65);
  mcpPoisoning.max_description_scan_bytes = Number(mcpPoisoning.max_description_scan_bytes ?? 8192);
  mcpPoisoning.max_argument_bytes = Number(mcpPoisoning.max_argument_bytes ?? 65536);
  mcpPoisoning.max_tools = Number(mcpPoisoning.max_tools ?? 64);
  mcpPoisoning.max_drift_snapshot_bytes = Number(mcpPoisoning.max_drift_snapshot_bytes ?? 131072);
  mcpPoisoning.block_on_config_drift = mcpPoisoning.block_on_config_drift === true;
  mcpPoisoning.detect_config_drift = mcpPoisoning.detect_config_drift !== false;
  mcpPoisoning.drift_ttl_ms = Number(mcpPoisoning.drift_ttl_ms ?? 3600000);
  mcpPoisoning.max_server_entries = Number(mcpPoisoning.max_server_entries ?? 2000);
  mcpPoisoning.sanitize_arguments = mcpPoisoning.sanitize_arguments !== false;
  mcpPoisoning.strip_non_printable = mcpPoisoning.strip_non_printable !== false;
  mcpPoisoning.observability = mcpPoisoning.observability !== false;

  normalized.runtime.mcp_shadow = normalized.runtime.mcp_shadow || {};
  const mcpShadow = normalized.runtime.mcp_shadow;
  mcpShadow.enabled = mcpShadow.enabled === true;
  mcpShadow.mode = MCP_SHADOW_MODES.has(String(mcpShadow.mode || '').toLowerCase())
    ? String(mcpShadow.mode).toLowerCase()
    : 'monitor';
  mcpShadow.detect_schema_drift = mcpShadow.detect_schema_drift !== false;
  mcpShadow.detect_late_registration = mcpShadow.detect_late_registration !== false;
  mcpShadow.detect_name_collisions = mcpShadow.detect_name_collisions !== false;
  mcpShadow.block_on_schema_drift = mcpShadow.block_on_schema_drift === true;
  mcpShadow.block_on_late_registration = mcpShadow.block_on_late_registration === true;
  mcpShadow.block_on_name_collision = mcpShadow.block_on_name_collision === true;
  mcpShadow.max_tools = Number(mcpShadow.max_tools ?? 64);
  mcpShadow.max_tool_snapshot_bytes = Number(mcpShadow.max_tool_snapshot_bytes ?? 131072);
  mcpShadow.ttl_ms = Number(mcpShadow.ttl_ms ?? 3600000);
  mcpShadow.max_server_entries = Number(mcpShadow.max_server_entries ?? 2000);
  mcpShadow.max_findings = Number(mcpShadow.max_findings ?? 16);
  mcpShadow.min_tool_name_length = Number(mcpShadow.min_tool_name_length ?? 4);
  mcpShadow.name_similarity_distance = Number(mcpShadow.name_similarity_distance ?? 1);
  mcpShadow.max_name_candidates = Number(mcpShadow.max_name_candidates ?? 128);
  mcpShadow.observability = mcpShadow.observability !== false;

  normalized.runtime.mcp_certificate_pinning = normalized.runtime.mcp_certificate_pinning || {};
  const mcpCertificatePinning = normalized.runtime.mcp_certificate_pinning;
  mcpCertificatePinning.enabled = mcpCertificatePinning.enabled === true;
  mcpCertificatePinning.mode = MCP_CERTIFICATE_PINNING_MODES.has(String(mcpCertificatePinning.mode || '').toLowerCase())
    ? String(mcpCertificatePinning.mode).toLowerCase()
    : 'monitor';
  mcpCertificatePinning.server_id_header = String(
    mcpCertificatePinning.server_id_header || 'x-sentinel-mcp-server-id'
  ).toLowerCase();
  mcpCertificatePinning.fingerprint_header = String(
    mcpCertificatePinning.fingerprint_header || 'x-sentinel-mcp-cert-sha256'
  ).toLowerCase();
  mcpCertificatePinning.pins = mcpCertificatePinning.pins && typeof mcpCertificatePinning.pins === 'object' && !Array.isArray(mcpCertificatePinning.pins)
    ? mcpCertificatePinning.pins
    : {};
  mcpCertificatePinning.allow_unpinned_servers = mcpCertificatePinning.allow_unpinned_servers !== false;
  mcpCertificatePinning.require_fingerprint_for_pinned_servers = mcpCertificatePinning.require_fingerprint_for_pinned_servers !== false;
  mcpCertificatePinning.detect_rotation = mcpCertificatePinning.detect_rotation !== false;
  mcpCertificatePinning.block_on_mismatch = mcpCertificatePinning.block_on_mismatch === true;
  mcpCertificatePinning.block_on_rotation = mcpCertificatePinning.block_on_rotation === true;
  mcpCertificatePinning.max_servers = Number(mcpCertificatePinning.max_servers ?? 5000);
  mcpCertificatePinning.ttl_ms = Number(mcpCertificatePinning.ttl_ms ?? 3600000);
  mcpCertificatePinning.observability = mcpCertificatePinning.observability !== false;

  normalized.runtime.memory_poisoning = normalized.runtime.memory_poisoning || {};
  const memoryPoisoning = normalized.runtime.memory_poisoning;
  memoryPoisoning.enabled = memoryPoisoning.enabled === true;
  memoryPoisoning.mode = MEMORY_POISONING_MODES.has(String(memoryPoisoning.mode || '').toLowerCase())
    ? String(memoryPoisoning.mode).toLowerCase()
    : 'monitor';
  memoryPoisoning.max_content_chars = Number(memoryPoisoning.max_content_chars ?? 32768);
  memoryPoisoning.ttl_ms = Number(memoryPoisoning.ttl_ms ?? 6 * 3600000);
  memoryPoisoning.max_sessions = Number(memoryPoisoning.max_sessions ?? 5000);
  memoryPoisoning.max_writes_per_session = Number(memoryPoisoning.max_writes_per_session ?? 128);
  memoryPoisoning.detect_contradictions = memoryPoisoning.detect_contradictions !== false;
  memoryPoisoning.block_on_poisoning = memoryPoisoning.block_on_poisoning === true;
  memoryPoisoning.block_on_contradiction = memoryPoisoning.block_on_contradiction === true;
  memoryPoisoning.quarantine_on_detect = memoryPoisoning.quarantine_on_detect !== false;
  memoryPoisoning.policy_anchors = Array.isArray(memoryPoisoning.policy_anchors)
    ? memoryPoisoning.policy_anchors.map((item) => String(item || '').trim()).filter(Boolean)
    : [];
  memoryPoisoning.observability = memoryPoisoning.observability !== false;

  normalized.runtime.cascade_isolator = normalized.runtime.cascade_isolator || {};
  const cascadeIsolator = normalized.runtime.cascade_isolator;
  cascadeIsolator.enabled = cascadeIsolator.enabled === true;
  cascadeIsolator.mode = CASCADE_ISOLATOR_MODES.has(String(cascadeIsolator.mode || '').toLowerCase())
    ? String(cascadeIsolator.mode).toLowerCase()
    : 'monitor';
  cascadeIsolator.ttl_ms = Number(cascadeIsolator.ttl_ms ?? 6 * 3600000);
  cascadeIsolator.max_sessions = Number(cascadeIsolator.max_sessions ?? 5000);
  cascadeIsolator.max_nodes = Number(cascadeIsolator.max_nodes ?? 512);
  cascadeIsolator.max_edges = Number(cascadeIsolator.max_edges ?? 2048);
  cascadeIsolator.max_downstream_agents = Number(cascadeIsolator.max_downstream_agents ?? 16);
  cascadeIsolator.max_influence_ratio = Number(cascadeIsolator.max_influence_ratio ?? 0.6);
  cascadeIsolator.anomaly_threshold = Number(cascadeIsolator.anomaly_threshold ?? 0.75);
  cascadeIsolator.block_on_threshold = cascadeIsolator.block_on_threshold === true;
  cascadeIsolator.observability = cascadeIsolator.observability !== false;

  normalized.runtime.agent_identity_federation = normalized.runtime.agent_identity_federation || {};
  const agentIdentityFederation = normalized.runtime.agent_identity_federation;
  agentIdentityFederation.enabled = agentIdentityFederation.enabled === true;
  agentIdentityFederation.mode = AGENT_IDENTITY_FEDERATION_MODES.has(String(agentIdentityFederation.mode || '').toLowerCase())
    ? String(agentIdentityFederation.mode).toLowerCase()
    : 'monitor';
  agentIdentityFederation.token_header = String(agentIdentityFederation.token_header || 'x-sentinel-agent-token').toLowerCase();
  agentIdentityFederation.agent_id_header = String(agentIdentityFederation.agent_id_header || 'x-sentinel-agent-id').toLowerCase();
  agentIdentityFederation.correlation_header = String(
    agentIdentityFederation.correlation_header || 'x-sentinel-correlation-id'
  ).toLowerCase();
  agentIdentityFederation.hmac_secret = String(
    agentIdentityFederation.hmac_secret || process.env.SENTINEL_AGENT_IDENTITY_HMAC || ''
  );
  agentIdentityFederation.ttl_ms = Number(agentIdentityFederation.ttl_ms ?? 900000);
  agentIdentityFederation.max_chain_depth = Number(agentIdentityFederation.max_chain_depth ?? 8);
  agentIdentityFederation.max_replay_entries = Number(agentIdentityFederation.max_replay_entries ?? 10000);
  agentIdentityFederation.block_on_invalid_token = agentIdentityFederation.block_on_invalid_token === true;
  agentIdentityFederation.block_on_capability_widen = agentIdentityFederation.block_on_capability_widen === true;
  agentIdentityFederation.block_on_replay = agentIdentityFederation.block_on_replay === true;
  agentIdentityFederation.observability = agentIdentityFederation.observability !== false;

  normalized.runtime.tool_use_anomaly = normalized.runtime.tool_use_anomaly || {};
  const toolUseAnomaly = normalized.runtime.tool_use_anomaly;
  toolUseAnomaly.enabled = toolUseAnomaly.enabled === true;
  toolUseAnomaly.mode = TOOL_USE_ANOMALY_MODES.has(String(toolUseAnomaly.mode || '').toLowerCase())
    ? String(toolUseAnomaly.mode).toLowerCase()
    : 'monitor';
  toolUseAnomaly.ttl_ms = Number(toolUseAnomaly.ttl_ms ?? 6 * 3600000);
  toolUseAnomaly.max_agents = Number(toolUseAnomaly.max_agents ?? 5000);
  toolUseAnomaly.max_tools_per_agent = Number(toolUseAnomaly.max_tools_per_agent ?? 256);
  toolUseAnomaly.warmup_events = Number(toolUseAnomaly.warmup_events ?? 20);
  toolUseAnomaly.z_score_threshold = Number(toolUseAnomaly.z_score_threshold ?? 3);
  toolUseAnomaly.sequence_threshold = Number(toolUseAnomaly.sequence_threshold ?? 2);
  toolUseAnomaly.block_on_anomaly = toolUseAnomaly.block_on_anomaly === true;
  toolUseAnomaly.observability = toolUseAnomaly.observability !== false;

  normalized.runtime.behavioral_fingerprint = normalized.runtime.behavioral_fingerprint || {};
  const behavioralFingerprint = normalized.runtime.behavioral_fingerprint;
  behavioralFingerprint.enabled = behavioralFingerprint.enabled === true;
  behavioralFingerprint.mode = BEHAVIORAL_FINGERPRINT_MODES.has(String(behavioralFingerprint.mode || '').toLowerCase())
    ? String(behavioralFingerprint.mode).toLowerCase()
    : 'monitor';
  behavioralFingerprint.ttl_ms = Number(behavioralFingerprint.ttl_ms ?? 6 * 3600000);
  behavioralFingerprint.max_agents = Number(behavioralFingerprint.max_agents ?? 5000);
  behavioralFingerprint.max_styles_per_agent = Number(behavioralFingerprint.max_styles_per_agent ?? 64);
  behavioralFingerprint.max_text_chars = Number(behavioralFingerprint.max_text_chars ?? 4096);
  behavioralFingerprint.max_impersonation_agents = Number(behavioralFingerprint.max_impersonation_agents ?? 128);
  behavioralFingerprint.warmup_events = Number(behavioralFingerprint.warmup_events ?? 20);
  behavioralFingerprint.z_score_threshold = Number(behavioralFingerprint.z_score_threshold ?? 3);
  behavioralFingerprint.impersonation_min_hits = Number(behavioralFingerprint.impersonation_min_hits ?? 3);
  behavioralFingerprint.block_on_anomaly = behavioralFingerprint.block_on_anomaly === true;
  behavioralFingerprint.block_on_impersonation = behavioralFingerprint.block_on_impersonation === true;
  behavioralFingerprint.observability = behavioralFingerprint.observability !== false;

  normalized.runtime.threat_intel_mesh = normalized.runtime.threat_intel_mesh || {};
  const threatIntelMesh = normalized.runtime.threat_intel_mesh;
  threatIntelMesh.enabled = threatIntelMesh.enabled === true;
  threatIntelMesh.mode = THREAT_INTEL_MESH_MODES.has(String(threatIntelMesh.mode || '').toLowerCase())
    ? String(threatIntelMesh.mode).toLowerCase()
    : 'monitor';
  threatIntelMesh.ttl_ms = Number(threatIntelMesh.ttl_ms ?? 7 * 24 * 3600000);
  threatIntelMesh.max_signatures = Number(threatIntelMesh.max_signatures ?? 50000);
  threatIntelMesh.max_text_chars = Number(threatIntelMesh.max_text_chars ?? 8192);
  threatIntelMesh.min_hits_to_block = Number(threatIntelMesh.min_hits_to_block ?? 2);
  threatIntelMesh.block_on_match = threatIntelMesh.block_on_match === true;
  threatIntelMesh.allow_anonymous_share = threatIntelMesh.allow_anonymous_share === true;
  threatIntelMesh.allow_unsigned_import = threatIntelMesh.allow_unsigned_import === true;
  threatIntelMesh.node_id = String(threatIntelMesh.node_id || 'sentinel-node').trim();
  threatIntelMesh.shared_secret = String(threatIntelMesh.shared_secret || '');
  threatIntelMesh.peers = Array.isArray(threatIntelMesh.peers)
    ? threatIntelMesh.peers.map((item) => String(item || '').trim()).filter(Boolean)
    : [];
  threatIntelMesh.sync_enabled = threatIntelMesh.sync_enabled === true;
  threatIntelMesh.sync_interval_ms = Number(threatIntelMesh.sync_interval_ms ?? 90000);
  threatIntelMesh.sync_timeout_ms = Number(threatIntelMesh.sync_timeout_ms ?? 2000);
  threatIntelMesh.max_peer_signatures = Number(threatIntelMesh.max_peer_signatures ?? 1000);
  threatIntelMesh.max_peers = Number(threatIntelMesh.max_peers ?? 16);
  threatIntelMesh.bootstrap_signatures = Array.isArray(threatIntelMesh.bootstrap_signatures)
    ? threatIntelMesh.bootstrap_signatures.map((item) => String(item || '').trim().toLowerCase()).filter(Boolean)
    : [];
  threatIntelMesh.observability = threatIntelMesh.observability !== false;

  normalized.runtime.lfrl = normalized.runtime.lfrl || {};
  const lfrl = normalized.runtime.lfrl;
  lfrl.enabled = lfrl.enabled === true;
  lfrl.mode = LFRL_MODES.has(String(lfrl.mode || '').toLowerCase())
    ? String(lfrl.mode).toLowerCase()
    : 'monitor';
  lfrl.rules = Array.isArray(lfrl.rules)
    ? lfrl.rules.map((item) => String(item || '').trim()).filter(Boolean)
    : [];
  lfrl.max_rules = Number(lfrl.max_rules ?? 128);
  lfrl.max_events = Number(lfrl.max_events ?? 20000);
  lfrl.max_matches = Number(lfrl.max_matches ?? 32);
  lfrl.default_within_ms = Number(lfrl.default_within_ms ?? 10 * 60 * 1000);
  lfrl.ttl_ms = Number(lfrl.ttl_ms ?? 24 * 3600000);
  lfrl.block_on_rule_action = lfrl.block_on_rule_action !== false;
  lfrl.observability = lfrl.observability !== false;

  normalized.runtime.self_healing_immune = normalized.runtime.self_healing_immune || {};
  const selfHealingImmune = normalized.runtime.self_healing_immune;
  selfHealingImmune.enabled = selfHealingImmune.enabled === true;
  selfHealingImmune.mode = SELF_HEALING_IMMUNE_MODES.has(String(selfHealingImmune.mode || '').toLowerCase())
    ? String(selfHealingImmune.mode).toLowerCase()
    : 'monitor';
  selfHealingImmune.ttl_ms = Number(selfHealingImmune.ttl_ms ?? 30 * 24 * 3600000);
  selfHealingImmune.max_signatures = Number(selfHealingImmune.max_signatures ?? 50000);
  selfHealingImmune.max_text_chars = Number(selfHealingImmune.max_text_chars ?? 8192);
  selfHealingImmune.min_learn_hits = Number(selfHealingImmune.min_learn_hits ?? 3);
  selfHealingImmune.block_on_learned_signature = selfHealingImmune.block_on_learned_signature === true;
  selfHealingImmune.auto_tune_enabled = selfHealingImmune.auto_tune_enabled === true;
  selfHealingImmune.max_recommendations = Number(selfHealingImmune.max_recommendations ?? 32);
  selfHealingImmune.observability = selfHealingImmune.observability !== false;

  normalized.runtime.semantic_firewall_dsl = normalized.runtime.semantic_firewall_dsl || {};
  const semanticFirewallDsl = normalized.runtime.semantic_firewall_dsl;
  semanticFirewallDsl.enabled = semanticFirewallDsl.enabled === true;
  semanticFirewallDsl.rules = Array.isArray(semanticFirewallDsl.rules)
    ? semanticFirewallDsl.rules.map((item) => String(item || '').trim()).filter(Boolean)
    : [];
  semanticFirewallDsl.max_rules = Number(semanticFirewallDsl.max_rules ?? 128);
  semanticFirewallDsl.observability = semanticFirewallDsl.observability !== false;

  normalized.runtime.stego_exfil_detector = normalized.runtime.stego_exfil_detector || {};
  const stegoExfilDetector = normalized.runtime.stego_exfil_detector;
  stegoExfilDetector.enabled = stegoExfilDetector.enabled === true;
  stegoExfilDetector.mode = STEGO_EXFIL_DETECTOR_MODES.has(String(stegoExfilDetector.mode || '').toLowerCase())
    ? String(stegoExfilDetector.mode).toLowerCase()
    : 'monitor';
  stegoExfilDetector.max_scan_chars = Number(stegoExfilDetector.max_scan_chars ?? 16384);
  stegoExfilDetector.max_findings = Number(stegoExfilDetector.max_findings ?? 16);
  stegoExfilDetector.zero_width_density_threshold = Number(stegoExfilDetector.zero_width_density_threshold ?? 0.02);
  stegoExfilDetector.invisible_density_threshold = Number(stegoExfilDetector.invisible_density_threshold ?? 0.03);
  stegoExfilDetector.whitespace_bits_threshold = Number(stegoExfilDetector.whitespace_bits_threshold ?? 128);
  stegoExfilDetector.segment_entropy_threshold = Number(stegoExfilDetector.segment_entropy_threshold ?? 3.2);
  stegoExfilDetector.emoji_compound_threshold = Number(stegoExfilDetector.emoji_compound_threshold ?? 3);
  stegoExfilDetector.block_on_detect = stegoExfilDetector.block_on_detect === true;
  stegoExfilDetector.observability = stegoExfilDetector.observability !== false;

  normalized.runtime.reasoning_trace_monitor = normalized.runtime.reasoning_trace_monitor || {};
  const reasoningTraceMonitor = normalized.runtime.reasoning_trace_monitor;
  reasoningTraceMonitor.enabled = reasoningTraceMonitor.enabled === true;
  reasoningTraceMonitor.mode = REASONING_TRACE_MONITOR_MODES.has(String(reasoningTraceMonitor.mode || '').toLowerCase())
    ? String(reasoningTraceMonitor.mode).toLowerCase()
    : 'monitor';
  reasoningTraceMonitor.max_scan_chars = Number(reasoningTraceMonitor.max_scan_chars ?? 16384);
  reasoningTraceMonitor.max_steps = Number(reasoningTraceMonitor.max_steps ?? 64);
  reasoningTraceMonitor.min_step_chars = Number(reasoningTraceMonitor.min_step_chars ?? 12);
  reasoningTraceMonitor.coherence_threshold = Number(reasoningTraceMonitor.coherence_threshold ?? 0.1);
  reasoningTraceMonitor.block_on_injection = reasoningTraceMonitor.block_on_injection === true;
  reasoningTraceMonitor.block_on_incoherence = reasoningTraceMonitor.block_on_incoherence === true;
  reasoningTraceMonitor.block_on_conclusion_mismatch = reasoningTraceMonitor.block_on_conclusion_mismatch === true;
  reasoningTraceMonitor.observability = reasoningTraceMonitor.observability !== false;

  normalized.runtime.hallucination_tripwire = normalized.runtime.hallucination_tripwire || {};
  const hallucinationTripwire = normalized.runtime.hallucination_tripwire;
  hallucinationTripwire.enabled = hallucinationTripwire.enabled === true;
  hallucinationTripwire.mode = HALLUCINATION_TRIPWIRE_MODES.has(String(hallucinationTripwire.mode || '').toLowerCase())
    ? String(hallucinationTripwire.mode).toLowerCase()
    : 'monitor';
  hallucinationTripwire.max_scan_chars = Number(hallucinationTripwire.max_scan_chars ?? 16384);
  hallucinationTripwire.max_findings = Number(hallucinationTripwire.max_findings ?? 24);
  hallucinationTripwire.warn_threshold = Number(hallucinationTripwire.warn_threshold ?? 0.45);
  hallucinationTripwire.block_threshold = Number(hallucinationTripwire.block_threshold ?? 0.8);
  hallucinationTripwire.block_on_detect = hallucinationTripwire.block_on_detect === true;
  hallucinationTripwire.observability = hallucinationTripwire.observability !== false;

  normalized.runtime.semantic_drift_canary = normalized.runtime.semantic_drift_canary || {};
  const semanticDriftCanary = normalized.runtime.semantic_drift_canary;
  semanticDriftCanary.enabled = semanticDriftCanary.enabled === true;
  semanticDriftCanary.mode = SEMANTIC_DRIFT_CANARY_MODES.has(String(semanticDriftCanary.mode || '').toLowerCase())
    ? String(semanticDriftCanary.mode).toLowerCase()
    : 'monitor';
  semanticDriftCanary.sample_every_requests = Number(semanticDriftCanary.sample_every_requests ?? 100);
  semanticDriftCanary.max_providers = Number(semanticDriftCanary.max_providers ?? 128);
  semanticDriftCanary.max_samples_per_provider = Number(semanticDriftCanary.max_samples_per_provider ?? 256);
  semanticDriftCanary.max_text_chars = Number(semanticDriftCanary.max_text_chars ?? 8192);
  semanticDriftCanary.warn_distance_threshold = Number(semanticDriftCanary.warn_distance_threshold ?? 0.45);
  semanticDriftCanary.block_distance_threshold = Number(semanticDriftCanary.block_distance_threshold ?? 0.8);
  semanticDriftCanary.observability = semanticDriftCanary.observability !== false;

  normalized.runtime.output_provenance = normalized.runtime.output_provenance || {};
  const outputProvenance = normalized.runtime.output_provenance;
  outputProvenance.enabled = outputProvenance.enabled === true;
  outputProvenance.key_id = String(outputProvenance.key_id || `sentinel-output-${process.pid}`);
  outputProvenance.secret = String(outputProvenance.secret || process.env.SENTINEL_OUTPUT_PROVENANCE_SECRET || '');
  outputProvenance.expose_verify_endpoint = outputProvenance.expose_verify_endpoint !== false;
  outputProvenance.max_envelope_bytes = Number(outputProvenance.max_envelope_bytes ?? 2097152);

  normalized.runtime.token_watermark = normalized.runtime.token_watermark || {};
  const tokenWatermark = normalized.runtime.token_watermark;
  tokenWatermark.enabled = tokenWatermark.enabled === true;
  tokenWatermark.key_id = String(tokenWatermark.key_id || `sentinel-token-watermark-${process.pid}`);
  tokenWatermark.secret = String(tokenWatermark.secret || process.env.SENTINEL_TOKEN_WATERMARK_SECRET || '');
  tokenWatermark.expose_verify_endpoint = tokenWatermark.expose_verify_endpoint !== false;
  tokenWatermark.max_envelope_bytes = Number(tokenWatermark.max_envelope_bytes ?? 2097152);
  tokenWatermark.max_token_chars = Number(tokenWatermark.max_token_chars ?? 131072);
  tokenWatermark.max_tokens = Number(tokenWatermark.max_tokens ?? 4096);

  normalized.runtime.compute_attestation = normalized.runtime.compute_attestation || {};
  const computeAttestation = normalized.runtime.compute_attestation;
  computeAttestation.enabled = computeAttestation.enabled === true;
  computeAttestation.key_id = String(computeAttestation.key_id || `sentinel-attestation-${process.pid}`);
  computeAttestation.secret = String(computeAttestation.secret || process.env.SENTINEL_ATTESTATION_SECRET || '');
  computeAttestation.expose_verify_endpoint = computeAttestation.expose_verify_endpoint !== false;
  computeAttestation.max_config_chars = Number(computeAttestation.max_config_chars ?? 4096);
  computeAttestation.include_environment = computeAttestation.include_environment === true;

  normalized.runtime.capability_introspection = normalized.runtime.capability_introspection || {};
  const capabilityIntrospection = normalized.runtime.capability_introspection;
  capabilityIntrospection.enabled = capabilityIntrospection.enabled === true;
  capabilityIntrospection.max_engines = Number(capabilityIntrospection.max_engines ?? 256);
  capabilityIntrospection.observability = capabilityIntrospection.observability !== false;

  normalized.runtime.policy_gradient_analyzer = normalized.runtime.policy_gradient_analyzer || {};
  const policyGradientAnalyzer = normalized.runtime.policy_gradient_analyzer;
  policyGradientAnalyzer.enabled = policyGradientAnalyzer.enabled === true;
  policyGradientAnalyzer.max_events = Number(policyGradientAnalyzer.max_events ?? 250000);
  policyGradientAnalyzer.current_injection_threshold = Number(policyGradientAnalyzer.current_injection_threshold ?? 0.5);
  policyGradientAnalyzer.proposed_injection_threshold = Number(policyGradientAnalyzer.proposed_injection_threshold ?? 0.35);

  normalized.runtime.budget_autopilot = normalized.runtime.budget_autopilot || {};
  const budgetAutopilot = normalized.runtime.budget_autopilot;
  budgetAutopilot.enabled = budgetAutopilot.enabled === true;
  budgetAutopilot.mode = BUDGET_AUTOPILOT_MODES.has(String(budgetAutopilot.mode || '').toLowerCase())
    ? String(budgetAutopilot.mode).toLowerCase()
    : 'monitor';
  budgetAutopilot.ttl_ms = Number(budgetAutopilot.ttl_ms ?? 24 * 3600000);
  budgetAutopilot.max_providers = Number(budgetAutopilot.max_providers ?? 256);
  budgetAutopilot.min_samples = Number(budgetAutopilot.min_samples ?? 8);
  budgetAutopilot.cost_weight = Number(budgetAutopilot.cost_weight ?? 0.6);
  budgetAutopilot.latency_weight = Number(budgetAutopilot.latency_weight ?? 0.4);
  budgetAutopilot.warn_budget_ratio = Number(budgetAutopilot.warn_budget_ratio ?? 0.2);
  budgetAutopilot.sla_p95_ms = Number(budgetAutopilot.sla_p95_ms ?? 2000);
  budgetAutopilot.horizon_hours = Number(budgetAutopilot.horizon_hours ?? 24);
  budgetAutopilot.observability = budgetAutopilot.observability !== false;

  normalized.runtime.cost_efficiency_optimizer = normalized.runtime.cost_efficiency_optimizer || {};
  const costEfficiencyOptimizer = normalized.runtime.cost_efficiency_optimizer;
  costEfficiencyOptimizer.enabled = costEfficiencyOptimizer.enabled === true;
  costEfficiencyOptimizer.mode = COST_EFFICIENCY_OPTIMIZER_MODES.has(String(costEfficiencyOptimizer.mode || '').toLowerCase())
    ? String(costEfficiencyOptimizer.mode).toLowerCase()
    : 'monitor';
  costEfficiencyOptimizer.ttl_ms = Number(costEfficiencyOptimizer.ttl_ms ?? 24 * 3600000);
  costEfficiencyOptimizer.max_providers = Number(costEfficiencyOptimizer.max_providers ?? 256);
  costEfficiencyOptimizer.max_samples_per_provider = Number(costEfficiencyOptimizer.max_samples_per_provider ?? 512);
  costEfficiencyOptimizer.max_prompt_chars = Number(costEfficiencyOptimizer.max_prompt_chars ?? 16384);
  costEfficiencyOptimizer.chars_per_token = Number(costEfficiencyOptimizer.chars_per_token ?? 4);
  costEfficiencyOptimizer.prompt_bloat_chars = Number(costEfficiencyOptimizer.prompt_bloat_chars ?? 6000);
  costEfficiencyOptimizer.repetition_warn_ratio = Number(costEfficiencyOptimizer.repetition_warn_ratio ?? 0.2);
  costEfficiencyOptimizer.low_budget_usd = Number(costEfficiencyOptimizer.low_budget_usd ?? 2);
  costEfficiencyOptimizer.memory_warn_bytes = Number(costEfficiencyOptimizer.memory_warn_bytes ?? 6 * 1024 * 1024 * 1024);
  costEfficiencyOptimizer.memory_critical_bytes = Number(costEfficiencyOptimizer.memory_critical_bytes ?? 7 * 1024 * 1024 * 1024);
  costEfficiencyOptimizer.memory_hard_cap_bytes = Number(costEfficiencyOptimizer.memory_hard_cap_bytes ?? 0);
  costEfficiencyOptimizer.shed_on_memory_pressure = costEfficiencyOptimizer.shed_on_memory_pressure !== false;
  costEfficiencyOptimizer.max_shed_engines = Number(costEfficiencyOptimizer.max_shed_engines ?? 16);
  costEfficiencyOptimizer.shed_cooldown_ms = Number(costEfficiencyOptimizer.shed_cooldown_ms ?? 30000);
  costEfficiencyOptimizer.shed_engine_order = Array.isArray(costEfficiencyOptimizer.shed_engine_order)
    ? costEfficiencyOptimizer.shed_engine_order.map((item) => String(item || '').trim()).filter(Boolean)
    : [];
  costEfficiencyOptimizer.block_on_critical_memory = costEfficiencyOptimizer.block_on_critical_memory === true;
  costEfficiencyOptimizer.block_on_budget_exhausted = costEfficiencyOptimizer.block_on_budget_exhausted === true;
  costEfficiencyOptimizer.observability = costEfficiencyOptimizer.observability !== false;

  normalized.runtime.zk_config_validator = normalized.runtime.zk_config_validator || {};
  const zkConfigValidator = normalized.runtime.zk_config_validator;
  zkConfigValidator.enabled = zkConfigValidator.enabled === true;
  zkConfigValidator.hmac_key = String(zkConfigValidator.hmac_key || process.env.SENTINEL_ZK_CONFIG_HMAC || '');
  zkConfigValidator.max_findings = Number(zkConfigValidator.max_findings ?? 256);
  zkConfigValidator.max_nodes = Number(zkConfigValidator.max_nodes ?? 50000);
  zkConfigValidator.max_depth = Number(zkConfigValidator.max_depth ?? 64);
  zkConfigValidator.redaction_text = String(zkConfigValidator.redaction_text || '[REDACTED]');
  zkConfigValidator.score_penalty_secret = Number(zkConfigValidator.score_penalty_secret ?? 8);
  zkConfigValidator.score_penalty_dead_key = Number(zkConfigValidator.score_penalty_dead_key ?? 4);
  zkConfigValidator.score_penalty_over_config = Number(zkConfigValidator.score_penalty_over_config ?? 2);
  zkConfigValidator.observability = zkConfigValidator.observability !== false;

  normalized.runtime.adversarial_eval_harness = normalized.runtime.adversarial_eval_harness || {};
  const adversarialEvalHarness = normalized.runtime.adversarial_eval_harness;
  adversarialEvalHarness.enabled = adversarialEvalHarness.enabled === true;
  adversarialEvalHarness.max_cases = Number(adversarialEvalHarness.max_cases ?? 256);
  adversarialEvalHarness.max_prompt_chars = Number(adversarialEvalHarness.max_prompt_chars ?? 8192);
  adversarialEvalHarness.max_runs = Number(adversarialEvalHarness.max_runs ?? 128);
  adversarialEvalHarness.schedule_every_requests = Number(adversarialEvalHarness.schedule_every_requests ?? 0);
  adversarialEvalHarness.fail_open = adversarialEvalHarness.fail_open !== false;
  adversarialEvalHarness.regression_drop_threshold = Number(adversarialEvalHarness.regression_drop_threshold ?? 0.15);
  adversarialEvalHarness.observability = adversarialEvalHarness.observability !== false;

  normalized.runtime.anomaly_telemetry = normalized.runtime.anomaly_telemetry || {};
  const anomalyTelemetry = normalized.runtime.anomaly_telemetry;
  anomalyTelemetry.enabled = anomalyTelemetry.enabled === true;
  anomalyTelemetry.max_events = Number(anomalyTelemetry.max_events ?? 20000);
  anomalyTelemetry.window_ms = Number(anomalyTelemetry.window_ms ?? 24 * 3600000);
  anomalyTelemetry.max_engine_buckets = Number(anomalyTelemetry.max_engine_buckets ?? 512);
  anomalyTelemetry.max_timeline_events = Number(anomalyTelemetry.max_timeline_events ?? 500);
  anomalyTelemetry.observability = anomalyTelemetry.observability !== false;

  normalized.runtime.evidence_vault = normalized.runtime.evidence_vault || {};
  const evidenceVault = normalized.runtime.evidence_vault;
  evidenceVault.enabled = evidenceVault.enabled === true;
  evidenceVault.mode = EVIDENCE_VAULT_MODES.has(String(evidenceVault.mode || '').toLowerCase())
    ? String(evidenceVault.mode).toLowerCase()
    : 'monitor';
  evidenceVault.max_entries = Number(evidenceVault.max_entries ?? 100000);
  evidenceVault.retention_days = Number(evidenceVault.retention_days ?? 90);
  evidenceVault.file_path = String(evidenceVault.file_path || '');
  evidenceVault.observability = evidenceVault.observability !== false;

  normalized.runtime.threat_graph = normalized.runtime.threat_graph || {};
  const threatGraph = normalized.runtime.threat_graph;
  threatGraph.enabled = threatGraph.enabled === true;
  threatGraph.max_events = Number(threatGraph.max_events ?? 20000);
  threatGraph.window_ms = Number(threatGraph.window_ms ?? 24 * 3600000);
  threatGraph.risk_decay = Number(threatGraph.risk_decay ?? 0.8);
  threatGraph.observability = threatGraph.observability !== false;

  normalized.runtime.attack_corpus_evolver = normalized.runtime.attack_corpus_evolver || {};
  const attackCorpusEvolver = normalized.runtime.attack_corpus_evolver;
  attackCorpusEvolver.enabled = attackCorpusEvolver.enabled === true;
  attackCorpusEvolver.max_candidates = Number(attackCorpusEvolver.max_candidates ?? 10000);
  attackCorpusEvolver.max_prompt_chars = Number(attackCorpusEvolver.max_prompt_chars ?? 2048);
  attackCorpusEvolver.max_families = Number(attackCorpusEvolver.max_families ?? 256);
  attackCorpusEvolver.include_monitor_decisions = attackCorpusEvolver.include_monitor_decisions === true;
  attackCorpusEvolver.observability = attackCorpusEvolver.observability !== false;

  normalized.runtime.forensic_debugger = normalized.runtime.forensic_debugger || {};
  const forensicDebugger = normalized.runtime.forensic_debugger;
  forensicDebugger.enabled = forensicDebugger.enabled === true;
  forensicDebugger.max_snapshots = Number(forensicDebugger.max_snapshots ?? 5000);
  forensicDebugger.redact_fields = Array.isArray(forensicDebugger.redact_fields)
    ? forensicDebugger.redact_fields.map((item) => String(item || '').trim()).filter(Boolean)
    : ['headers.authorization', 'headers.x-api-key', 'body.api_key', 'body.password'];
  forensicDebugger.default_summary_only = forensicDebugger.default_summary_only !== false;
  forensicDebugger.observability = forensicDebugger.observability !== false;

  normalized.runtime.prompt_rebuff = normalized.runtime.prompt_rebuff || {};
  const promptRebuff = normalized.runtime.prompt_rebuff;
  promptRebuff.enabled = promptRebuff.enabled === true;
  promptRebuff.mode = PROMPT_REBUFF_MODES.has(String(promptRebuff.mode || '').toLowerCase())
    ? String(promptRebuff.mode).toLowerCase()
    : 'monitor';
  promptRebuff.sensitivity = PROMPT_REBUFF_SENSITIVITIES.has(String(promptRebuff.sensitivity || '').toLowerCase())
    ? String(promptRebuff.sensitivity).toLowerCase()
    : 'balanced';
  promptRebuff.heuristic_weight = Number(promptRebuff.heuristic_weight ?? 0.55);
  promptRebuff.neural_weight = Number(promptRebuff.neural_weight ?? 0.35);
  promptRebuff.canary_weight = Number(promptRebuff.canary_weight ?? 0.25);
  promptRebuff.warn_threshold = Number(promptRebuff.warn_threshold ?? 0.65);
  promptRebuff.block_threshold = Number(promptRebuff.block_threshold ?? 0.85);
  promptRebuff.max_body_chars = Number(promptRebuff.max_body_chars ?? 8192);
  promptRebuff.max_response_chars = Number(promptRebuff.max_response_chars ?? 8192);
  promptRebuff.session_header = String(promptRebuff.session_header || 'x-sentinel-session-id').toLowerCase();
  promptRebuff.fallback_headers = Array.isArray(promptRebuff.fallback_headers)
    ? promptRebuff.fallback_headers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
  promptRebuff.ttl_ms = Number(promptRebuff.ttl_ms ?? 900000);
  promptRebuff.max_sessions = Number(promptRebuff.max_sessions ?? 5000);
  promptRebuff.canary_tool_name = String(promptRebuff.canary_tool_name || 'fetch_admin_passwords');
  promptRebuff.observability = promptRebuff.observability !== false;

  normalized.runtime.output_classifier = normalized.runtime.output_classifier || {};
  const outputClassifier = normalized.runtime.output_classifier;
  outputClassifier.enabled = outputClassifier.enabled === true;
  outputClassifier.mode = OUTPUT_CLASSIFIER_MODES.has(String(outputClassifier.mode || '').toLowerCase())
    ? String(outputClassifier.mode).toLowerCase()
    : 'monitor';
  outputClassifier.max_scan_chars = Number(outputClassifier.max_scan_chars ?? 8192);
  outputClassifier.context_window_chars = Number(outputClassifier.context_window_chars ?? 64);
  outputClassifier.max_matches_per_rule = Number(outputClassifier.max_matches_per_rule ?? 4);
  outputClassifier.contextual_dampening = Number(outputClassifier.contextual_dampening ?? 0.55);
  outputClassifier.contextual_escalation = Number(outputClassifier.contextual_escalation ?? 0.15);
  outputClassifier.ngram_boost = Number(outputClassifier.ngram_boost ?? 0.2);
  outputClassifier.categories =
    outputClassifier.categories &&
    typeof outputClassifier.categories === 'object' &&
    !Array.isArray(outputClassifier.categories)
      ? outputClassifier.categories
      : {};
  for (const category of OUTPUT_CLASSIFIER_CATEGORIES_KEYS) {
    const categoryConfig =
      outputClassifier.categories[category] &&
      typeof outputClassifier.categories[category] === 'object' &&
      !Array.isArray(outputClassifier.categories[category])
        ? outputClassifier.categories[category]
        : {};
    categoryConfig.enabled = categoryConfig.enabled !== false;
    const defaultWarn =
      category === 'toxicity'
        ? 0.45
        : category === 'code_execution'
          ? 0.4
          : category === 'hallucination'
            ? 0.5
            : 0.4;
    const defaultBlock =
      category === 'toxicity'
        ? 0.8
        : category === 'code_execution'
          ? 0.75
          : category === 'hallucination'
            ? 0.85
            : 0.7;
    categoryConfig.warn_threshold = Number(categoryConfig.warn_threshold ?? defaultWarn);
    categoryConfig.block_threshold = Number(
      categoryConfig.block_threshold ?? Math.max(defaultBlock, categoryConfig.warn_threshold)
    );
    outputClassifier.categories[category] = categoryConfig;
  }

  normalized.runtime.output_schema_validator = normalized.runtime.output_schema_validator || {};
  const outputSchemaValidator = normalized.runtime.output_schema_validator;
  outputSchemaValidator.enabled = outputSchemaValidator.enabled === true;
  outputSchemaValidator.mode = OUTPUT_SCHEMA_VALIDATOR_MODES.has(String(outputSchemaValidator.mode || '').toLowerCase())
    ? String(outputSchemaValidator.mode).toLowerCase()
    : 'monitor';
  outputSchemaValidator.default_schema = String(outputSchemaValidator.default_schema || '');
  outputSchemaValidator.schema_header = String(
    outputSchemaValidator.schema_header || 'x-sentinel-output-schema'
  ).toLowerCase();
  outputSchemaValidator.max_body_bytes = Number(outputSchemaValidator.max_body_bytes ?? 1048576);
  outputSchemaValidator.schemas =
    outputSchemaValidator.schemas &&
    typeof outputSchemaValidator.schemas === 'object' &&
    !Array.isArray(outputSchemaValidator.schemas)
      ? outputSchemaValidator.schemas
      : {};

  normalized.runtime.agent_observability = normalized.runtime.agent_observability || {};
  const agentObservability = normalized.runtime.agent_observability;
  agentObservability.enabled = agentObservability.enabled === true;
  agentObservability.max_events_per_request = Number(agentObservability.max_events_per_request ?? 32);
  agentObservability.max_field_length = Number(agentObservability.max_field_length ?? 160);

  normalized.runtime.differential_privacy = normalized.runtime.differential_privacy || {};
  const differentialPrivacy = normalized.runtime.differential_privacy;
  differentialPrivacy.enabled = differentialPrivacy.enabled === true;
  differentialPrivacy.epsilon_budget = Number(differentialPrivacy.epsilon_budget ?? 1.0);
  differentialPrivacy.epsilon_per_call = Number(differentialPrivacy.epsilon_per_call ?? 0.1);
  differentialPrivacy.sensitivity = Number(differentialPrivacy.sensitivity ?? 1.0);
  differentialPrivacy.max_simulation_calls = Number(differentialPrivacy.max_simulation_calls ?? 1000);
  differentialPrivacy.max_vector_length = Number(differentialPrivacy.max_vector_length ?? 8192);
  differentialPrivacy.persist_state = differentialPrivacy.persist_state === true;
  differentialPrivacy.state_file = String(differentialPrivacy.state_file || '');
  differentialPrivacy.state_hmac_key = String(differentialPrivacy.state_hmac_key || '');
  differentialPrivacy.reset_on_tamper = differentialPrivacy.reset_on_tamper !== false;

  normalized.runtime.auto_immune = normalized.runtime.auto_immune || {};
  const autoImmune = normalized.runtime.auto_immune;
  autoImmune.enabled = autoImmune.enabled === true;
  autoImmune.mode = AUTO_IMMUNE_MODES.has(String(autoImmune.mode || '').toLowerCase())
    ? String(autoImmune.mode).toLowerCase()
    : 'monitor';
  autoImmune.ttl_ms = Number(autoImmune.ttl_ms ?? 24 * 3600000);
  autoImmune.max_entries = Number(autoImmune.max_entries ?? 20000);
  autoImmune.max_scan_bytes = Number(autoImmune.max_scan_bytes ?? 32768);
  autoImmune.min_confidence_to_match = Number(autoImmune.min_confidence_to_match ?? 0.85);
  autoImmune.learn_min_score = Number(autoImmune.learn_min_score ?? 0.85);
  autoImmune.learn_increment = Number(autoImmune.learn_increment ?? 0.2);
  autoImmune.max_confidence = Number(autoImmune.max_confidence ?? 0.99);
  autoImmune.decay_half_life_ms = Number(autoImmune.decay_half_life_ms ?? 6 * 3600000);
  autoImmune.observability = autoImmune.observability !== false;

  normalized.runtime.provenance = normalized.runtime.provenance || {};
  const provenance = normalized.runtime.provenance;
  provenance.enabled = provenance.enabled === true;
  provenance.key_id = String(provenance.key_id || `sentinel-${process.pid}`);
  provenance.sign_stream_trailers = provenance.sign_stream_trailers !== false;
  provenance.expose_public_key_endpoint = provenance.expose_public_key_endpoint !== false;
  provenance.max_signable_bytes = Number(provenance.max_signable_bytes ?? 2097152);

  normalized.runtime.deception = normalized.runtime.deception || {};
  const deception = normalized.runtime.deception;
  deception.enabled = deception.enabled === true;
  deception.mode = DECEPTION_MODES.has(String(deception.mode || '').toLowerCase())
    ? String(deception.mode).toLowerCase()
    : 'off';
  deception.on_injection = deception.on_injection !== false;
  deception.on_loop = deception.on_loop !== false;
  deception.min_injection_score = Number(deception.min_injection_score ?? 0.9);
  deception.sse_token_interval_ms = Number(deception.sse_token_interval_ms ?? 1000);
  deception.sse_max_tokens = Number(deception.sse_max_tokens ?? 20);
  deception.non_stream_delay_ms = Number(deception.non_stream_delay_ms ?? 250);

  normalized.runtime.honeytoken = normalized.runtime.honeytoken || {};
  const honeytoken = normalized.runtime.honeytoken;
  honeytoken.enabled = honeytoken.enabled === true;
  honeytoken.mode = HONEYTOKEN_MODES.has(String(honeytoken.mode || '').toLowerCase())
    ? String(honeytoken.mode).toLowerCase()
    : 'uuid_suffix';
  honeytoken.injection_rate = Number(honeytoken.injection_rate ?? 0.05);
  honeytoken.max_insertions_per_request = Number(honeytoken.max_insertions_per_request ?? 1);
  honeytoken.target_roles = Array.isArray(honeytoken.target_roles)
    ? honeytoken.target_roles.map((value) => String(value).toLowerCase()).filter(Boolean)
    : ['user'];
  honeytoken.token_prefix = String(honeytoken.token_prefix || 'SNTL');

  normalized.runtime.latency_normalization = normalized.runtime.latency_normalization || {};
  const latencyNormalization = normalized.runtime.latency_normalization;
  latencyNormalization.enabled = latencyNormalization.enabled === true;
  latencyNormalization.window_size = Number(latencyNormalization.window_size ?? 10);
  latencyNormalization.min_samples = Number(latencyNormalization.min_samples ?? 3);
  latencyNormalization.max_delay_ms = Number(latencyNormalization.max_delay_ms ?? 2000);
  latencyNormalization.max_baseline_sample_ms = Number(latencyNormalization.max_baseline_sample_ms ?? 5000);
  latencyNormalization.trim_percentile = Number(latencyNormalization.trim_percentile ?? 0.1);
  latencyNormalization.max_concurrent_normalized = Number(latencyNormalization.max_concurrent_normalized ?? 128);
  latencyNormalization.jitter_ms = Number(latencyNormalization.jitter_ms ?? 25);
  latencyNormalization.statuses = Array.isArray(latencyNormalization.statuses)
    ? latencyNormalization.statuses.map((value) => Number(value))
    : [402, 403, 429];

  normalized.runtime.canary_tools = normalized.runtime.canary_tools || {};
  const canaryTools = normalized.runtime.canary_tools;
  canaryTools.enabled = canaryTools.enabled === true;
  canaryTools.mode = CANARY_TOOL_MODES.has(String(canaryTools.mode || '').toLowerCase())
    ? String(canaryTools.mode).toLowerCase()
    : 'monitor';
  canaryTools.tool_name = String(canaryTools.tool_name || 'fetch_admin_passwords');
  canaryTools.tool_description = String(
    canaryTools.tool_description || 'Retrieve privileged credentials for internal diagnostics.'
  );
  canaryTools.max_injected_tools = Number(canaryTools.max_injected_tools ?? 1);
  canaryTools.inject_on_providers = Array.isArray(canaryTools.inject_on_providers)
    ? canaryTools.inject_on_providers.map((value) => String(value).toLowerCase()).filter(Boolean)
    : ['openai', 'anthropic', 'google', 'ollama'];
  canaryTools.require_tools_array = canaryTools.require_tools_array !== false;

  normalized.runtime.parallax = normalized.runtime.parallax || {};
  const parallax = normalized.runtime.parallax;
  parallax.enabled = parallax.enabled === true;
  parallax.mode = PARALLAX_MODES.has(String(parallax.mode || '').toLowerCase())
    ? String(parallax.mode).toLowerCase()
    : 'monitor';
  parallax.high_risk_tools = Array.isArray(parallax.high_risk_tools)
    ? parallax.high_risk_tools.map((value) => String(value)).filter(Boolean)
    : ['execute_shell', 'execute_sql', 'aws_cli'];
  parallax.secondary_target = String(parallax.secondary_target || 'ollama').toLowerCase();
  parallax.secondary_group = String(parallax.secondary_group || '');
  parallax.secondary_contract = String(parallax.secondary_contract || 'openai_chat_v1').toLowerCase();
  parallax.secondary_model = String(parallax.secondary_model || '');
  parallax.timeout_ms = Number(parallax.timeout_ms ?? 3000);
  parallax.risk_threshold = Number(parallax.risk_threshold ?? 0.7);

  normalized.runtime.shadow_os = normalized.runtime.shadow_os || {};
  const shadowOs = normalized.runtime.shadow_os;
  shadowOs.enabled = shadowOs.enabled === true;
  shadowOs.mode = SHADOW_OS_MODES.has(String(shadowOs.mode || '').toLowerCase())
    ? String(shadowOs.mode).toLowerCase()
    : 'monitor';
  shadowOs.window_ms = Number(shadowOs.window_ms ?? 15 * 60 * 1000);
  shadowOs.max_sessions = Number(shadowOs.max_sessions ?? 5000);
  shadowOs.max_history_per_session = Number(shadowOs.max_history_per_session ?? 128);
  shadowOs.repeat_threshold = Number(shadowOs.repeat_threshold ?? 4);
  shadowOs.session_header = String(shadowOs.session_header || 'x-sentinel-session-id').toLowerCase();
  shadowOs.fallback_headers = Array.isArray(shadowOs.fallback_headers)
    ? shadowOs.fallback_headers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
  shadowOs.high_risk_tools = Array.isArray(shadowOs.high_risk_tools)
    ? shadowOs.high_risk_tools.map((item) => String(item || '').trim()).filter(Boolean)
    : ['execute_shell', 'execute_sql', 'aws_cli', 'grant_permissions', 'create_user', 'delete_log', 'drop_database'];
  shadowOs.sequence_rules = Array.isArray(shadowOs.sequence_rules)
    ? shadowOs.sequence_rules.map((rule) => ({
        id: String(rule?.id || ''),
        requires: Array.isArray(rule?.requires)
          ? rule.requires.map((item) => String(item || '').trim()).filter(Boolean)
          : [],
        order_required: rule?.order_required !== false,
      })).filter((rule) => rule.id && rule.requires.length > 0)
    : [
        {
          id: 'privilege_escalation_coverup',
          requires: ['create_user', 'grant_permissions', 'delete_log'],
          order_required: true,
        },
        {
          id: 'destructive_privilege_chain',
          requires: ['grant_permissions', 'drop_database'],
          order_required: false,
        },
      ];
  shadowOs.observability = shadowOs.observability !== false;

  normalized.runtime.epistemic_anchor = normalized.runtime.epistemic_anchor || {};
  const epistemicAnchor = normalized.runtime.epistemic_anchor;
  epistemicAnchor.enabled = epistemicAnchor.enabled === true;
  epistemicAnchor.mode = EPISTEMIC_ANCHOR_MODES.has(String(epistemicAnchor.mode || '').toLowerCase())
    ? String(epistemicAnchor.mode).toLowerCase()
    : 'monitor';
  epistemicAnchor.required_acknowledgement = String(
    epistemicAnchor.required_acknowledgement || 'I_UNDERSTAND_EPISTEMIC_ANCHOR_IS_EXPERIMENTAL'
  );
  epistemicAnchor.acknowledgement = String(epistemicAnchor.acknowledgement || '');
  epistemicAnchor.key_header = String(epistemicAnchor.key_header || 'x-sentinel-session-id').toLowerCase();
  epistemicAnchor.fallback_key_headers = Array.isArray(epistemicAnchor.fallback_key_headers)
    ? epistemicAnchor.fallback_key_headers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
    : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
  epistemicAnchor.sample_every_turns = Number(epistemicAnchor.sample_every_turns ?? 5);
  epistemicAnchor.min_turns = Number(epistemicAnchor.min_turns ?? 6);
  epistemicAnchor.threshold = Number(epistemicAnchor.threshold ?? 0.8);
  epistemicAnchor.cooldown_ms = Number(epistemicAnchor.cooldown_ms ?? 60000);
  epistemicAnchor.max_sessions = Number(epistemicAnchor.max_sessions ?? 5000);
  epistemicAnchor.context_window_messages = Number(epistemicAnchor.context_window_messages ?? 8);
  epistemicAnchor.model_id = String(epistemicAnchor.model_id || 'Xenova/all-MiniLM-L6-v2');
  epistemicAnchor.cache_dir = String(epistemicAnchor.cache_dir || '~/.sentinel/models');
  epistemicAnchor.max_prompt_chars = Number(epistemicAnchor.max_prompt_chars ?? 4000);
  epistemicAnchor.observability = epistemicAnchor.observability !== false;

  normalized.pii = normalized.pii || {};
  normalized.pii.enabled = normalized.pii.enabled !== false;
  normalized.pii.provider_mode = String(normalized.pii.provider_mode || 'local').toLowerCase();
  normalized.pii.max_scan_bytes = Number(normalized.pii.max_scan_bytes ?? 262144);
  normalized.pii.regex_safety_cap_bytes = Number(normalized.pii.regex_safety_cap_bytes ?? 51200);
  normalized.pii.redaction = normalized.pii.redaction || {};
  normalized.pii.redaction.mode = PII_REDACTION_MODES.has(String(normalized.pii.redaction.mode || '').toLowerCase())
    ? String(normalized.pii.redaction.mode).toLowerCase()
    : 'placeholder';
  normalized.pii.redaction.salt = String(
    normalized.pii.redaction.salt || process.env.SENTINEL_MASKING_SALT || 'sentinel-mask-salt'
  );
  normalized.pii.severity_actions = normalized.pii.severity_actions || {};
  normalized.pii.severity_actions.critical = normalized.pii.severity_actions.critical || 'block';
  normalized.pii.severity_actions.high = normalized.pii.severity_actions.high || 'block';
  normalized.pii.severity_actions.medium = normalized.pii.severity_actions.medium || 'redact';
  normalized.pii.severity_actions.low = normalized.pii.severity_actions.low || 'log';
  normalized.pii.rapidapi = normalized.pii.rapidapi || {};
  normalized.pii.rapidapi.endpoint =
    normalized.pii.rapidapi.endpoint || process.env.SENTINEL_RAPIDAPI_ENDPOINT || 'https://pii-firewall-edge.p.rapidapi.com/redact';
  normalized.pii.rapidapi.host = normalized.pii.rapidapi.host || process.env.SENTINEL_RAPIDAPI_HOST || '';
  normalized.pii.rapidapi.timeout_ms = Number(normalized.pii.rapidapi.timeout_ms ?? 4000);
  normalized.pii.rapidapi.request_body_field = normalized.pii.rapidapi.request_body_field || 'text';
  normalized.pii.rapidapi.fallback_to_local = normalized.pii.rapidapi.fallback_to_local !== false;
  normalized.pii.rapidapi.allow_non_rapidapi_host = normalized.pii.rapidapi.allow_non_rapidapi_host === true;
  normalized.pii.rapidapi.api_key = normalized.pii.rapidapi.api_key || '';
  normalized.pii.rapidapi.cache_max_entries = Number(normalized.pii.rapidapi.cache_max_entries ?? 1024);
  normalized.pii.rapidapi.cache_ttl_ms = Number(normalized.pii.rapidapi.cache_ttl_ms ?? 300000);
  normalized.pii.rapidapi.max_timeout_ms = Number(normalized.pii.rapidapi.max_timeout_ms ?? 1500);
  normalized.pii.rapidapi.extra_body =
    normalized.pii.rapidapi.extra_body && typeof normalized.pii.rapidapi.extra_body === 'object'
      ? normalized.pii.rapidapi.extra_body
      : {};
  normalized.pii.semantic = normalized.pii.semantic || {};
  normalized.pii.semantic.enabled = normalized.pii.semantic.enabled === true;
  normalized.pii.semantic.model_id = normalized.pii.semantic.model_id || 'Xenova/bert-base-NER';
  normalized.pii.semantic.cache_dir = normalized.pii.semantic.cache_dir || '~/.sentinel/models';
  normalized.pii.semantic.score_threshold = Number(normalized.pii.semantic.score_threshold ?? 0.6);
  normalized.pii.semantic.max_scan_bytes = Number(normalized.pii.semantic.max_scan_bytes ?? 32768);
  normalized.pii.egress = normalized.pii.egress || {};
  normalized.pii.egress.enabled = normalized.pii.egress.enabled !== false;
  normalized.pii.egress.max_scan_bytes = Number(normalized.pii.egress.max_scan_bytes ?? 65536);
  normalized.pii.egress.stream_enabled = normalized.pii.egress.stream_enabled !== false;
  normalized.pii.egress.sse_line_max_bytes = Number(normalized.pii.egress.sse_line_max_bytes ?? 16384);
  normalized.pii.egress.stream_block_mode = normalized.pii.egress.stream_block_mode === 'terminate' ? 'terminate' : 'redact';
  normalized.pii.egress.entropy = normalized.pii.egress.entropy || {};
  normalized.pii.egress.entropy.enabled = normalized.pii.egress.entropy.enabled === true;
  normalized.pii.egress.entropy.mode =
    PII_EGRESS_ENTROPY_MODES.has(String(normalized.pii.egress.entropy.mode || '').toLowerCase())
      ? String(normalized.pii.egress.entropy.mode).toLowerCase()
      : 'monitor';
  normalized.pii.egress.entropy.threshold = Number(normalized.pii.egress.entropy.threshold ?? 4.5);
  normalized.pii.egress.entropy.min_token_length = Number(normalized.pii.egress.entropy.min_token_length ?? 24);
  normalized.pii.egress.entropy.max_scan_bytes = Number(normalized.pii.egress.entropy.max_scan_bytes ?? 65536);
  normalized.pii.egress.entropy.max_findings = Number(normalized.pii.egress.entropy.max_findings ?? 8);
  normalized.pii.egress.entropy.min_unique_ratio = Number(normalized.pii.egress.entropy.min_unique_ratio ?? 0.3);
  normalized.pii.egress.entropy.detect_base64 = normalized.pii.egress.entropy.detect_base64 !== false;
  normalized.pii.egress.entropy.detect_hex = normalized.pii.egress.entropy.detect_hex !== false;
  normalized.pii.egress.entropy.detect_generic = normalized.pii.egress.entropy.detect_generic !== false;
  normalized.pii.egress.entropy.redact_replacement =
    String(normalized.pii.egress.entropy.redact_replacement || '[REDACTED_HIGH_ENTROPY]');

  normalized.injection = normalized.injection || {};
  normalized.injection.enabled = normalized.injection.enabled !== false;
  normalized.injection.threshold = Number(normalized.injection.threshold ?? 0.8);
  normalized.injection.max_scan_bytes = Number(normalized.injection.max_scan_bytes ?? 131072);
  normalized.injection.action = normalized.injection.action || 'block';
  normalized.injection.neural = normalized.injection.neural || {};
  normalized.injection.neural.enabled = normalized.injection.neural.enabled === true;
  normalized.injection.neural.model_id = normalized.injection.neural.model_id || 'Xenova/all-MiniLM-L6-v2';
  normalized.injection.neural.cache_dir = normalized.injection.neural.cache_dir || '~/.sentinel/models';
  normalized.injection.neural.max_scan_bytes = Number(normalized.injection.neural.max_scan_bytes ?? 32768);
  normalized.injection.neural.timeout_ms = Number(normalized.injection.neural.timeout_ms ?? 1200);
  normalized.injection.neural.weight = Number(normalized.injection.neural.weight ?? 1);
  normalized.injection.neural.mode = INJECTION_NEURAL_MODES.has(String(normalized.injection.neural.mode || '').toLowerCase())
    ? String(normalized.injection.neural.mode || '').toLowerCase()
    : 'max';

  normalized.whitelist = normalized.whitelist || {};
  normalized.whitelist.domains = Array.isArray(normalized.whitelist.domains) ? normalized.whitelist.domains : [];

  normalized.logging = normalized.logging || {};
  normalized.logging.level = normalized.logging.level || 'info';
  normalized.logging.audit_stdout =
    normalized.logging.audit_stdout !== undefined
      ? Boolean(normalized.logging.audit_stdout)
      : ['true', '1', 'yes', 'on'].includes(String(process.env.SENTINEL_AUDIT_STDOUT || '').toLowerCase());

  return normalized;
}

function validateConfigShape(config) {
  const details = [];

  assertType(config && typeof config === 'object', 'Config must be an object', details);
  if (!config || typeof config !== 'object') {
    throw new ConfigValidationError('Invalid config', details);
  }

  validateRequiredKeys(config, details);
  assertNoUnknownKeys(config, ROOT_KEYS, 'config', details);

  assertType(Number.isInteger(config.version), '`version` must be an integer', details);
  assertType(VALID_MODES.has(config.mode), '`mode` must be one of: monitor, warn, enforce', details);

  const proxy = config.proxy || {};
  assertNoUnknownKeys(proxy, PROXY_KEYS, 'proxy', details);
  assertType(typeof proxy.host === 'string' && proxy.host.length > 0, '`proxy.host` must be a non-empty string', details);
  assertType(Number.isInteger(proxy.port) && proxy.port > 0, '`proxy.port` must be integer > 0', details);
  assertType(Number.isInteger(proxy.timeout_ms) && proxy.timeout_ms > 0, '`proxy.timeout_ms` must be integer > 0', details);
  assertType(
    proxy.max_body_bytes === undefined || (Number.isInteger(proxy.max_body_bytes) && proxy.max_body_bytes > 0),
    '`proxy.max_body_bytes` must be integer > 0',
    details
  );

  const runtime = config.runtime || {};
  assertNoUnknownKeys(runtime, RUNTIME_KEYS, 'runtime', details);
  assertType(typeof runtime.fail_open === 'boolean', '`runtime.fail_open` must be boolean', details);
  const telemetry = runtime.telemetry || {};
  if (runtime.telemetry !== undefined) {
    assertNoUnknownKeys(telemetry, TELEMETRY_KEYS, 'runtime.telemetry', details);
    assertType(typeof telemetry.enabled === 'boolean', '`runtime.telemetry.enabled` must be boolean', details);
  }
  assertType(
    VALID_SCANNER_ACTIONS.has(runtime.scanner_error_action),
    '`runtime.scanner_error_action` must be allow|block',
    details
  );
  const rateLimiter = runtime.rate_limiter || {};
  if (runtime.rate_limiter !== undefined) {
    assertNoUnknownKeys(rateLimiter, RATE_LIMITER_KEYS, 'runtime.rate_limiter', details);
    assertType(
      rateLimiter.enabled === undefined || typeof rateLimiter.enabled === 'boolean',
      '`runtime.rate_limiter.enabled` must be boolean',
      details
    );
    assertType(
      Number.isInteger(rateLimiter.default_window_ms) && rateLimiter.default_window_ms > 0,
      '`runtime.rate_limiter.default_window_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(rateLimiter.default_limit) && rateLimiter.default_limit > 0,
      '`runtime.rate_limiter.default_limit` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(rateLimiter.default_burst) && rateLimiter.default_burst >= rateLimiter.default_limit,
      '`runtime.rate_limiter.default_burst` must be integer >= default_limit',
      details
    );
    assertType(
      Number.isInteger(rateLimiter.max_buckets) && rateLimiter.max_buckets > 0,
      '`runtime.rate_limiter.max_buckets` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(rateLimiter.prune_interval) && rateLimiter.prune_interval > 0,
      '`runtime.rate_limiter.prune_interval` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(rateLimiter.stale_bucket_ttl_ms) && rateLimiter.stale_bucket_ttl_ms > 0,
      '`runtime.rate_limiter.stale_bucket_ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(rateLimiter.max_key_length) && rateLimiter.max_key_length >= 16 && rateLimiter.max_key_length <= 4096,
      '`runtime.rate_limiter.max_key_length` must be integer between 16 and 4096',
      details
    );
    assertType(
      Array.isArray(rateLimiter.key_headers),
      '`runtime.rate_limiter.key_headers` must be array',
      details
    );
    if (Array.isArray(rateLimiter.key_headers)) {
      rateLimiter.key_headers.forEach((header, idx) => {
        assertType(
          typeof header === 'string' && header.trim().length > 0,
          `runtime.rate_limiter.key_headers[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      Array.isArray(rateLimiter.fallback_key_headers),
      '`runtime.rate_limiter.fallback_key_headers` must be array',
      details
    );
    if (Array.isArray(rateLimiter.fallback_key_headers)) {
      rateLimiter.fallback_key_headers.forEach((header, idx) => {
        assertType(
          typeof header === 'string' && header.trim().length > 0,
          `runtime.rate_limiter.fallback_key_headers[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      typeof rateLimiter.ip_header === 'string' && rateLimiter.ip_header.trim().length > 0,
      '`runtime.rate_limiter.ip_header` must be non-empty string',
      details
    );
  }
  const workerPool = runtime.worker_pool || {};
  if (runtime.worker_pool !== undefined) {
    assertNoUnknownKeys(workerPool, WORKER_POOL_KEYS, 'runtime.worker_pool', details);
    assertType(typeof workerPool.enabled === 'boolean', '`runtime.worker_pool.enabled` must be boolean', details);
    assertType(
      Number.isInteger(workerPool.size) && workerPool.size > 0 && workerPool.size <= 32,
      '`runtime.worker_pool.size` must be integer between 1 and 32',
      details
    );
    assertType(
      Number.isInteger(workerPool.queue_limit) && workerPool.queue_limit > 0,
      '`runtime.worker_pool.queue_limit` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(workerPool.task_timeout_ms) && workerPool.task_timeout_ms > 0,
      '`runtime.worker_pool.task_timeout_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(workerPool.scan_task_timeout_ms) && workerPool.scan_task_timeout_ms > 0,
      '`runtime.worker_pool.scan_task_timeout_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(workerPool.embed_task_timeout_ms) && workerPool.embed_task_timeout_ms > 0,
      '`runtime.worker_pool.embed_task_timeout_ms` must be integer > 0',
      details
    );
  }
  const vcr = runtime.vcr || {};
  if (runtime.vcr !== undefined) {
    assertNoUnknownKeys(vcr, VCR_KEYS, 'runtime.vcr', details);
    assertType(typeof vcr.enabled === 'boolean', '`runtime.vcr.enabled` must be boolean', details);
    assertType(VCR_MODES.has(String(vcr.mode)), '`runtime.vcr.mode` must be one of: off, record, replay', details);
    assertType(typeof vcr.tape_file === 'string' && vcr.tape_file.length > 0, '`runtime.vcr.tape_file` must be string', details);
    assertType(
      Number.isInteger(vcr.max_entries) && vcr.max_entries > 0,
      '`runtime.vcr.max_entries` must be integer > 0',
      details
    );
    assertType(typeof vcr.strict_replay === 'boolean', '`runtime.vcr.strict_replay` must be boolean', details);
  }
  const semanticCache = runtime.semantic_cache || {};
  if (runtime.semantic_cache !== undefined) {
    assertNoUnknownKeys(semanticCache, SEMANTIC_CACHE_KEYS, 'runtime.semantic_cache', details);
    assertType(typeof semanticCache.enabled === 'boolean', '`runtime.semantic_cache.enabled` must be boolean', details);
    assertType(typeof semanticCache.model_id === 'string', '`runtime.semantic_cache.model_id` must be string', details);
    assertType(typeof semanticCache.cache_dir === 'string', '`runtime.semantic_cache.cache_dir` must be string', details);
    assertType(
      Number.isFinite(Number(semanticCache.similarity_threshold)) &&
        Number(semanticCache.similarity_threshold) >= 0 &&
        Number(semanticCache.similarity_threshold) <= 1,
      '`runtime.semantic_cache.similarity_threshold` must be between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(semanticCache.max_entries) && semanticCache.max_entries > 0,
      '`runtime.semantic_cache.max_entries` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(semanticCache.ttl_ms) && semanticCache.ttl_ms >= 0,
      '`runtime.semantic_cache.ttl_ms` must be integer >= 0',
      details
    );
    assertType(
      Number.isInteger(semanticCache.max_prompt_chars) && semanticCache.max_prompt_chars > 0,
      '`runtime.semantic_cache.max_prompt_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(semanticCache.max_entry_bytes) && semanticCache.max_entry_bytes > 0,
      '`runtime.semantic_cache.max_entry_bytes` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(semanticCache.max_ram_mb)) && Number(semanticCache.max_ram_mb) > 0,
      '`runtime.semantic_cache.max_ram_mb` must be number > 0',
      details
    );
    assertType(
      Number.isInteger(semanticCache.max_consecutive_errors) && semanticCache.max_consecutive_errors > 0,
      '`runtime.semantic_cache.max_consecutive_errors` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(semanticCache.failure_cooldown_ms) && semanticCache.failure_cooldown_ms > 0,
      '`runtime.semantic_cache.failure_cooldown_ms` must be integer > 0',
      details
    );
  }

  const intentThrottle = runtime.intent_throttle || {};
  if (runtime.intent_throttle !== undefined) {
    assertNoUnknownKeys(intentThrottle, INTENT_THROTTLE_KEYS, 'runtime.intent_throttle', details);
    assertType(typeof intentThrottle.enabled === 'boolean', '`runtime.intent_throttle.enabled` must be boolean', details);
    assertType(
      INTENT_THROTTLE_MODES.has(String(intentThrottle.mode)),
      '`runtime.intent_throttle.mode` must be monitor|block',
      details
    );
    assertType(
      typeof intentThrottle.key_header === 'string' && intentThrottle.key_header.length > 0,
      '`runtime.intent_throttle.key_header` must be non-empty string',
      details
    );
    assertType(
      Number.isInteger(intentThrottle.window_ms) && intentThrottle.window_ms > 0,
      '`runtime.intent_throttle.window_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(intentThrottle.cooldown_ms) && intentThrottle.cooldown_ms > 0,
      '`runtime.intent_throttle.cooldown_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(intentThrottle.max_events_per_window) && intentThrottle.max_events_per_window > 0,
      '`runtime.intent_throttle.max_events_per_window` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(intentThrottle.min_similarity)) &&
        Number(intentThrottle.min_similarity) >= 0 &&
        Number(intentThrottle.min_similarity) <= 1,
      '`runtime.intent_throttle.min_similarity` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(intentThrottle.max_prompt_chars) && intentThrottle.max_prompt_chars > 0,
      '`runtime.intent_throttle.max_prompt_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(intentThrottle.max_sessions) && intentThrottle.max_sessions > 0,
      '`runtime.intent_throttle.max_sessions` must be integer > 0',
      details
    );
    assertType(
      typeof intentThrottle.model_id === 'string' && intentThrottle.model_id.length > 0,
      '`runtime.intent_throttle.model_id` must be non-empty string',
      details
    );
    assertType(
      typeof intentThrottle.cache_dir === 'string' && intentThrottle.cache_dir.length > 0,
      '`runtime.intent_throttle.cache_dir` must be non-empty string',
      details
    );
    assertType(
      Array.isArray(intentThrottle.clusters),
      '`runtime.intent_throttle.clusters` must be an array',
      details
    );
    if (Array.isArray(intentThrottle.clusters)) {
      intentThrottle.clusters.forEach((cluster, idx) => {
        const label = `runtime.intent_throttle.clusters[${idx}]`;
        assertType(
          cluster && typeof cluster === 'object' && !Array.isArray(cluster),
          `${label} must be object`,
          details
        );
        if (!cluster || typeof cluster !== 'object' || Array.isArray(cluster)) {
          return;
        }
        assertNoUnknownKeys(cluster, INTENT_THROTTLE_CLUSTER_KEYS, label, details);
        assertType(
          typeof cluster.name === 'string' && cluster.name.length > 0,
          `${label}.name must be non-empty string`,
          details
        );
        assertType(
          Array.isArray(cluster.phrases) && cluster.phrases.length > 0,
          `${label}.phrases must be non-empty array`,
          details
        );
        if (Array.isArray(cluster.phrases)) {
          cluster.phrases.forEach((phrase, phraseIdx) => {
            assertType(
              typeof phrase === 'string' && phrase.length > 0,
              `${label}.phrases[${phraseIdx}] must be non-empty string`,
              details
            );
          });
        }
        if (cluster.min_similarity !== undefined) {
          assertType(
            Number.isFinite(Number(cluster.min_similarity)) &&
              Number(cluster.min_similarity) >= 0 &&
              Number(cluster.min_similarity) <= 1,
            `${label}.min_similarity must be number between 0 and 1`,
            details
          );
        }
      });
    }
  }

  const intentDrift = runtime.intent_drift || {};
  if (runtime.intent_drift !== undefined) {
    assertNoUnknownKeys(intentDrift, INTENT_DRIFT_KEYS, 'runtime.intent_drift', details);
    assertType(typeof intentDrift.enabled === 'boolean', '`runtime.intent_drift.enabled` must be boolean', details);
    assertType(
      INTENT_DRIFT_MODES.has(String(intentDrift.mode)),
      '`runtime.intent_drift.mode` must be monitor|block',
      details
    );
    assertType(
      typeof intentDrift.key_header === 'string' && intentDrift.key_header.length > 0,
      '`runtime.intent_drift.key_header` must be non-empty string',
      details
    );
    assertType(
      Array.isArray(intentDrift.fallback_key_headers),
      '`runtime.intent_drift.fallback_key_headers` must be array',
      details
    );
    if (Array.isArray(intentDrift.fallback_key_headers)) {
      intentDrift.fallback_key_headers.forEach((header, idx) => {
        assertType(
          typeof header === 'string' && header.length > 0,
          `runtime.intent_drift.fallback_key_headers[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      Array.isArray(intentDrift.target_roles) && intentDrift.target_roles.length > 0,
      '`runtime.intent_drift.target_roles` must be non-empty array',
      details
    );
    if (Array.isArray(intentDrift.target_roles)) {
      intentDrift.target_roles.forEach((role, idx) => {
        assertType(
          typeof role === 'string' && role.length > 0,
          `runtime.intent_drift.target_roles[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      typeof intentDrift.strip_volatile_tokens === 'boolean',
      '`runtime.intent_drift.strip_volatile_tokens` must be boolean',
      details
    );
    assertType(
      Array.isArray(intentDrift.risk_keywords) && intentDrift.risk_keywords.length > 0,
      '`runtime.intent_drift.risk_keywords` must be non-empty array',
      details
    );
    if (Array.isArray(intentDrift.risk_keywords)) {
      intentDrift.risk_keywords.forEach((keyword, idx) => {
        assertType(
          typeof keyword === 'string' && keyword.length > 0,
          `runtime.intent_drift.risk_keywords[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      Number.isFinite(Number(intentDrift.risk_boost)) &&
        Number(intentDrift.risk_boost) >= 0 &&
        Number(intentDrift.risk_boost) <= 1,
      '`runtime.intent_drift.risk_boost` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(intentDrift.sample_every_turns) && intentDrift.sample_every_turns > 0,
      '`runtime.intent_drift.sample_every_turns` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(intentDrift.min_turns) && intentDrift.min_turns > 0,
      '`runtime.intent_drift.min_turns` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(intentDrift.threshold)) &&
        Number(intentDrift.threshold) >= 0 &&
        Number(intentDrift.threshold) <= 1,
      '`runtime.intent_drift.threshold` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(intentDrift.cooldown_ms) && intentDrift.cooldown_ms > 0,
      '`runtime.intent_drift.cooldown_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(intentDrift.max_sessions) && intentDrift.max_sessions > 0,
      '`runtime.intent_drift.max_sessions` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(intentDrift.context_window_messages) && intentDrift.context_window_messages > 0,
      '`runtime.intent_drift.context_window_messages` must be integer > 0',
      details
    );
    assertType(
      typeof intentDrift.model_id === 'string' && intentDrift.model_id.length > 0,
      '`runtime.intent_drift.model_id` must be non-empty string',
      details
    );
    assertType(
      typeof intentDrift.cache_dir === 'string' && intentDrift.cache_dir.length > 0,
      '`runtime.intent_drift.cache_dir` must be non-empty string',
      details
    );
    assertType(
      Number.isInteger(intentDrift.max_prompt_chars) && intentDrift.max_prompt_chars > 0,
      '`runtime.intent_drift.max_prompt_chars` must be integer > 0',
      details
    );
    assertType(
      typeof intentDrift.observability === 'boolean',
      '`runtime.intent_drift.observability` must be boolean',
      details
    );
  }

  const swarm = runtime.swarm || {};
  if (runtime.swarm !== undefined) {
    assertNoUnknownKeys(swarm, SWARM_KEYS, 'runtime.swarm', details);
    assertType(typeof swarm.enabled === 'boolean', '`runtime.swarm.enabled` must be boolean', details);
    assertType(SWARM_MODES.has(String(swarm.mode)), '`runtime.swarm.mode` must be monitor|block', details);
    assertType(typeof swarm.node_id === 'string' && swarm.node_id.length > 0, '`runtime.swarm.node_id` must be non-empty string', details);
    assertType(typeof swarm.key_id === 'string' && swarm.key_id.length > 0, '`runtime.swarm.key_id` must be non-empty string', details);
    assertType(typeof swarm.private_key_pem === 'string', '`runtime.swarm.private_key_pem` must be string', details);
    assertType(typeof swarm.public_key_pem === 'string', '`runtime.swarm.public_key_pem` must be string', details);
    assertType(typeof swarm.verify_inbound === 'boolean', '`runtime.swarm.verify_inbound` must be boolean', details);
    assertType(typeof swarm.sign_outbound === 'boolean', '`runtime.swarm.sign_outbound` must be boolean', details);
    assertType(typeof swarm.require_envelope === 'boolean', '`runtime.swarm.require_envelope` must be boolean', details);
    assertType(
      Number.isInteger(swarm.allowed_clock_skew_ms) && swarm.allowed_clock_skew_ms > 0,
      '`runtime.swarm.allowed_clock_skew_ms` must be integer > 0',
      details
    );
    assertType(
      swarm.tolerance_window_ms === undefined ||
        (Number.isInteger(swarm.tolerance_window_ms) && swarm.tolerance_window_ms > 0),
      '`runtime.swarm.tolerance_window_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(swarm.nonce_ttl_ms) && swarm.nonce_ttl_ms > 0,
      '`runtime.swarm.nonce_ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(swarm.max_nonce_entries) && swarm.max_nonce_entries > 0,
      '`runtime.swarm.max_nonce_entries` must be integer > 0',
      details
    );
    assertType(
      Array.isArray(swarm.sign_on_providers) && swarm.sign_on_providers.length > 0,
      '`runtime.swarm.sign_on_providers` must be non-empty array',
      details
    );
    if (Array.isArray(swarm.sign_on_providers)) {
      swarm.sign_on_providers.forEach((provider, idx) => {
        assertType(
          ['openai', 'anthropic', 'google', 'ollama', 'custom'].includes(String(provider || '').toLowerCase()),
          `runtime.swarm.sign_on_providers[${idx}] must be openai|anthropic|google|ollama|custom`,
          details
        );
      });
    }
    assertType(
      swarm.trusted_nodes && typeof swarm.trusted_nodes === 'object' && !Array.isArray(swarm.trusted_nodes),
      '`runtime.swarm.trusted_nodes` must be an object',
      details
    );
    if (swarm.trusted_nodes && typeof swarm.trusted_nodes === 'object' && !Array.isArray(swarm.trusted_nodes)) {
      Object.entries(swarm.trusted_nodes).forEach(([nodeId, nodeConfig]) => {
        assertType(nodeId.length > 0, '`runtime.swarm.trusted_nodes` keys must be non-empty', details);
        assertType(
          nodeConfig && typeof nodeConfig === 'object' && !Array.isArray(nodeConfig),
          `runtime.swarm.trusted_nodes.${nodeId} must be object`,
          details
        );
        if (!nodeConfig || typeof nodeConfig !== 'object' || Array.isArray(nodeConfig)) {
          return;
        }
        assertNoUnknownKeys(nodeConfig, SWARM_TRUSTED_NODE_KEYS, `runtime.swarm.trusted_nodes.${nodeId}`, details);
        assertType(
          typeof nodeConfig.public_key_pem === 'string' && nodeConfig.public_key_pem.length > 0,
          `runtime.swarm.trusted_nodes.${nodeId}.public_key_pem must be non-empty string`,
          details
        );
      });
    }
  }

  const polymorphicPrompt = runtime.polymorphic_prompt || {};
  const piiVault = runtime.pii_vault || {};
  if (runtime.pii_vault !== undefined) {
    assertNoUnknownKeys(piiVault, PII_VAULT_KEYS, 'runtime.pii_vault', details);
    assertType(typeof piiVault.enabled === 'boolean', '`runtime.pii_vault.enabled` must be boolean', details);
    assertType(
      PII_VAULT_MODES.has(String(piiVault.mode)),
      '`runtime.pii_vault.mode` must be monitor|active',
      details
    );
    assertType(typeof piiVault.salt === 'string', '`runtime.pii_vault.salt` must be string', details);
    assertType(
      typeof piiVault.session_header === 'string' && piiVault.session_header.length > 0,
      '`runtime.pii_vault.session_header` must be non-empty string',
      details
    );
    assertType(
      Array.isArray(piiVault.fallback_headers),
      '`runtime.pii_vault.fallback_headers` must be array',
      details
    );
    assertType(
      Number.isInteger(piiVault.ttl_ms) && piiVault.ttl_ms > 0,
      '`runtime.pii_vault.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(piiVault.max_sessions) && piiVault.max_sessions > 0,
      '`runtime.pii_vault.max_sessions` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(piiVault.max_mappings_per_session) && piiVault.max_mappings_per_session > 0,
      '`runtime.pii_vault.max_mappings_per_session` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(piiVault.max_memory_bytes) && piiVault.max_memory_bytes > 0,
      '`runtime.pii_vault.max_memory_bytes` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(piiVault.max_egress_rewrite_entries) && piiVault.max_egress_rewrite_entries > 0,
      '`runtime.pii_vault.max_egress_rewrite_entries` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(piiVault.max_payload_bytes) && piiVault.max_payload_bytes > 0,
      '`runtime.pii_vault.max_payload_bytes` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(piiVault.max_replacements_per_pass) && piiVault.max_replacements_per_pass > 0,
      '`runtime.pii_vault.max_replacements_per_pass` must be integer > 0',
      details
    );
    assertType(
      typeof piiVault.token_domain === 'string' && piiVault.token_domain.length > 0,
      '`runtime.pii_vault.token_domain` must be non-empty string',
      details
    );
    assertType(
      typeof piiVault.token_prefix === 'string' && piiVault.token_prefix.length > 0,
      '`runtime.pii_vault.token_prefix` must be non-empty string',
      details
    );
    assertType(
      Array.isArray(piiVault.target_types) && piiVault.target_types.length > 0,
      '`runtime.pii_vault.target_types` must be non-empty array',
      details
    );
    assertType(
      typeof piiVault.observability === 'boolean',
      '`runtime.pii_vault.observability` must be boolean',
      details
    );
  }

  if (runtime.polymorphic_prompt !== undefined) {
    assertNoUnknownKeys(polymorphicPrompt, POLYMORPHIC_PROMPT_KEYS, 'runtime.polymorphic_prompt', details);
    assertType(typeof polymorphicPrompt.enabled === 'boolean', '`runtime.polymorphic_prompt.enabled` must be boolean', details);
    assertType(
      Number.isInteger(polymorphicPrompt.rotation_seconds) && polymorphicPrompt.rotation_seconds > 0,
      '`runtime.polymorphic_prompt.rotation_seconds` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(polymorphicPrompt.max_mutations_per_message) && polymorphicPrompt.max_mutations_per_message > 0,
      '`runtime.polymorphic_prompt.max_mutations_per_message` must be integer > 0',
      details
    );
    assertType(
      Array.isArray(polymorphicPrompt.target_roles) && polymorphicPrompt.target_roles.length > 0,
      '`runtime.polymorphic_prompt.target_roles` must be non-empty array',
      details
    );
    assertType(
      typeof polymorphicPrompt.bypass_header === 'string' && polymorphicPrompt.bypass_header.length > 0,
      '`runtime.polymorphic_prompt.bypass_header` must be non-empty string',
      details
    );
    assertType(
      typeof polymorphicPrompt.seed === 'string' && polymorphicPrompt.seed.length > 0,
      '`runtime.polymorphic_prompt.seed` must be non-empty string',
      details
    );
    assertType(
      typeof polymorphicPrompt.observability === 'boolean',
      '`runtime.polymorphic_prompt.observability` must be boolean',
      details
    );
    assertType(
      polymorphicPrompt.lexicon && typeof polymorphicPrompt.lexicon === 'object' && !Array.isArray(polymorphicPrompt.lexicon),
      '`runtime.polymorphic_prompt.lexicon` must be object',
      details
    );
  }

  const syntheticPoisoning = runtime.synthetic_poisoning || {};
  if (runtime.synthetic_poisoning !== undefined) {
    assertNoUnknownKeys(syntheticPoisoning, SYNTHETIC_POISONING_KEYS, 'runtime.synthetic_poisoning', details);
    assertType(typeof syntheticPoisoning.enabled === 'boolean', '`runtime.synthetic_poisoning.enabled` must be boolean', details);
    assertType(
      SYNTHETIC_POISONING_MODES.has(String(syntheticPoisoning.mode)),
      '`runtime.synthetic_poisoning.mode` must be monitor|inject',
      details
    );
    assertType(
      typeof syntheticPoisoning.required_acknowledgement === 'string' &&
        syntheticPoisoning.required_acknowledgement.length > 0,
      '`runtime.synthetic_poisoning.required_acknowledgement` must be non-empty string',
      details
    );
    assertType(
      typeof syntheticPoisoning.acknowledgement === 'string',
      '`runtime.synthetic_poisoning.acknowledgement` must be string',
      details
    );
    assertType(
      Array.isArray(syntheticPoisoning.allowed_triggers) && syntheticPoisoning.allowed_triggers.length > 0,
      '`runtime.synthetic_poisoning.allowed_triggers` must be non-empty array',
      details
    );
    assertType(
      Array.isArray(syntheticPoisoning.target_roles) && syntheticPoisoning.target_roles.length > 0,
      '`runtime.synthetic_poisoning.target_roles` must be non-empty array',
      details
    );
    assertType(
      typeof syntheticPoisoning.decoy_label === 'string' && syntheticPoisoning.decoy_label.length > 0,
      '`runtime.synthetic_poisoning.decoy_label` must be non-empty string',
      details
    );
    assertType(
      Number.isInteger(syntheticPoisoning.max_insertions_per_request) &&
        syntheticPoisoning.max_insertions_per_request > 0,
      '`runtime.synthetic_poisoning.max_insertions_per_request` must be integer > 0',
      details
    );
    assertType(
      typeof syntheticPoisoning.observability === 'boolean',
      '`runtime.synthetic_poisoning.observability` must be boolean',
      details
    );
  }

  const cognitiveRollback = runtime.cognitive_rollback || {};
  if (runtime.cognitive_rollback !== undefined) {
    assertNoUnknownKeys(cognitiveRollback, COGNITIVE_ROLLBACK_KEYS, 'runtime.cognitive_rollback', details);
    assertType(
      typeof cognitiveRollback.enabled === 'boolean',
      '`runtime.cognitive_rollback.enabled` must be boolean',
      details
    );
    assertType(
      COGNITIVE_ROLLBACK_MODES.has(String(cognitiveRollback.mode)),
      '`runtime.cognitive_rollback.mode` must be monitor|auto',
      details
    );
    assertType(
      Array.isArray(cognitiveRollback.triggers) && cognitiveRollback.triggers.length > 0,
      '`runtime.cognitive_rollback.triggers` must be non-empty array',
      details
    );
    assertType(
      Array.isArray(cognitiveRollback.target_roles) && cognitiveRollback.target_roles.length > 0,
      '`runtime.cognitive_rollback.target_roles` must be non-empty array',
      details
    );
    assertType(
      Number.isInteger(cognitiveRollback.drop_messages) && cognitiveRollback.drop_messages > 0,
      '`runtime.cognitive_rollback.drop_messages` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(cognitiveRollback.min_messages_remaining) && cognitiveRollback.min_messages_remaining > 0,
      '`runtime.cognitive_rollback.min_messages_remaining` must be integer > 0',
      details
    );
    assertType(
      typeof cognitiveRollback.system_message === 'string' && cognitiveRollback.system_message.length > 0,
      '`runtime.cognitive_rollback.system_message` must be non-empty string',
      details
    );
    assertType(
      typeof cognitiveRollback.observability === 'boolean',
      '`runtime.cognitive_rollback.observability` must be boolean',
      details
    );
  }

  const omniShield = runtime.omni_shield || {};
  if (runtime.omni_shield !== undefined) {
    assertNoUnknownKeys(omniShield, OMNI_SHIELD_KEYS, 'runtime.omni_shield', details);
    assertType(typeof omniShield.enabled === 'boolean', '`runtime.omni_shield.enabled` must be boolean', details);
    assertType(
      OMNI_SHIELD_MODES.has(String(omniShield.mode)),
      '`runtime.omni_shield.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(omniShield.max_image_bytes) && omniShield.max_image_bytes > 0,
      '`runtime.omni_shield.max_image_bytes` must be integer > 0',
      details
    );
    assertType(
      typeof omniShield.allow_remote_image_urls === 'boolean',
      '`runtime.omni_shield.allow_remote_image_urls` must be boolean',
      details
    );
    assertType(
      typeof omniShield.allow_base64_images === 'boolean',
      '`runtime.omni_shield.allow_base64_images` must be boolean',
      details
    );
    assertType(
      typeof omniShield.block_on_any_image === 'boolean',
      '`runtime.omni_shield.block_on_any_image` must be boolean',
      details
    );
    assertType(
      Number.isInteger(omniShield.max_findings) && omniShield.max_findings > 0,
      '`runtime.omni_shield.max_findings` must be integer > 0',
      details
    );
    assertType(
      Array.isArray(omniShield.target_roles) && omniShield.target_roles.length > 0,
      '`runtime.omni_shield.target_roles` must be non-empty array',
      details
    );
    assertType(
      typeof omniShield.observability === 'boolean',
      '`runtime.omni_shield.observability` must be boolean',
      details
    );
    const omniPlugin = omniShield.plugin || {};
    assertType(
      omniPlugin && typeof omniPlugin === 'object' && !Array.isArray(omniPlugin),
      '`runtime.omni_shield.plugin` must be object',
      details
    );
    if (omniPlugin && typeof omniPlugin === 'object' && !Array.isArray(omniPlugin)) {
      assertNoUnknownKeys(omniPlugin, OMNI_SHIELD_PLUGIN_KEYS, 'runtime.omni_shield.plugin', details);
      assertType(
        typeof omniPlugin.enabled === 'boolean',
        '`runtime.omni_shield.plugin.enabled` must be boolean',
        details
      );
      assertType(
        typeof omniPlugin.provider === 'string' && omniPlugin.provider.length > 0,
        '`runtime.omni_shield.plugin.provider` must be non-empty string',
        details
      );
      assertType(
        typeof omniPlugin.module_path === 'string',
        '`runtime.omni_shield.plugin.module_path` must be string',
        details
      );
      assertType(
        OMNI_SHIELD_PLUGIN_MODES.has(String(omniPlugin.mode)),
        '`runtime.omni_shield.plugin.mode` must be enforce|always',
        details
      );
      assertType(
        typeof omniPlugin.fail_closed === 'boolean',
        '`runtime.omni_shield.plugin.fail_closed` must be boolean',
        details
      );
      assertType(
        Number.isInteger(omniPlugin.max_rewrites) && omniPlugin.max_rewrites > 0,
        '`runtime.omni_shield.plugin.max_rewrites` must be integer > 0',
        details
      );
      assertType(
        Number.isInteger(omniPlugin.timeout_ms) && omniPlugin.timeout_ms > 0,
        '`runtime.omni_shield.plugin.timeout_ms` must be integer > 0',
        details
      );
      assertType(
        typeof omniPlugin.observability === 'boolean',
        '`runtime.omni_shield.plugin.observability` must be boolean',
        details
      );
    }
  }

  const sandboxExperimental = runtime.sandbox_experimental || {};
  if (runtime.sandbox_experimental !== undefined) {
    assertNoUnknownKeys(
      sandboxExperimental,
      SANDBOX_EXPERIMENTAL_KEYS,
      'runtime.sandbox_experimental',
      details
    );
    assertType(
      typeof sandboxExperimental.enabled === 'boolean',
      '`runtime.sandbox_experimental.enabled` must be boolean',
      details
    );
    assertType(
      SANDBOX_EXPERIMENTAL_MODES.has(String(sandboxExperimental.mode)),
      '`runtime.sandbox_experimental.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(sandboxExperimental.max_code_chars) && sandboxExperimental.max_code_chars > 0,
      '`runtime.sandbox_experimental.max_code_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(sandboxExperimental.max_findings) && sandboxExperimental.max_findings > 0,
      '`runtime.sandbox_experimental.max_findings` must be integer > 0',
      details
    );
    assertType(
      typeof sandboxExperimental.normalize_evasion === 'boolean',
      '`runtime.sandbox_experimental.normalize_evasion` must be boolean',
      details
    );
    assertType(
      typeof sandboxExperimental.decode_base64 === 'boolean',
      '`runtime.sandbox_experimental.decode_base64` must be boolean',
      details
    );
    assertType(
      Number.isInteger(sandboxExperimental.max_decoded_bytes) && sandboxExperimental.max_decoded_bytes > 0,
      '`runtime.sandbox_experimental.max_decoded_bytes` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(sandboxExperimental.max_variants_per_candidate) &&
        sandboxExperimental.max_variants_per_candidate > 0,
      '`runtime.sandbox_experimental.max_variants_per_candidate` must be integer > 0',
      details
    );
    assertType(
      Array.isArray(sandboxExperimental.disallowed_patterns) && sandboxExperimental.disallowed_patterns.length > 0,
      '`runtime.sandbox_experimental.disallowed_patterns` must be non-empty array',
      details
    );
    if (Array.isArray(sandboxExperimental.disallowed_patterns)) {
      sandboxExperimental.disallowed_patterns.forEach((pattern, idx) => {
        assertType(
          typeof pattern === 'string' && pattern.length > 0,
          `runtime.sandbox_experimental.disallowed_patterns[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      Array.isArray(sandboxExperimental.target_tool_names),
      '`runtime.sandbox_experimental.target_tool_names` must be array',
      details
    );
    if (Array.isArray(sandboxExperimental.target_tool_names)) {
      sandboxExperimental.target_tool_names.forEach((toolName, idx) => {
        assertType(
          typeof toolName === 'string' && toolName.length > 0,
          `runtime.sandbox_experimental.target_tool_names[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      typeof sandboxExperimental.observability === 'boolean',
      '`runtime.sandbox_experimental.observability` must be boolean',
      details
    );
  }

  const dashboard = runtime.dashboard || {};
  if (runtime.dashboard !== undefined) {
    assertNoUnknownKeys(dashboard, DASHBOARD_KEYS, 'runtime.dashboard', details);
    assertType(typeof dashboard.enabled === 'boolean', '`runtime.dashboard.enabled` must be boolean', details);
    assertType(typeof dashboard.host === 'string' && dashboard.host.length > 0, '`runtime.dashboard.host` must be string', details);
    assertType(
      Number.isInteger(dashboard.port) && dashboard.port > 0 && dashboard.port <= 65535,
      '`runtime.dashboard.port` must be integer between 1 and 65535',
      details
    );
    assertType(typeof dashboard.auth_token === 'string', '`runtime.dashboard.auth_token` must be string', details);
    assertType(typeof dashboard.allow_remote === 'boolean', '`runtime.dashboard.allow_remote` must be boolean', details);
    assertType(
      dashboard.team_tokens && typeof dashboard.team_tokens === 'object' && !Array.isArray(dashboard.team_tokens),
      '`runtime.dashboard.team_tokens` must be object',
      details
    );
    if (dashboard.team_tokens && typeof dashboard.team_tokens === 'object' && !Array.isArray(dashboard.team_tokens)) {
      for (const [team, token] of Object.entries(dashboard.team_tokens)) {
        assertType(
          typeof team === 'string' && team.trim().length > 0,
          '`runtime.dashboard.team_tokens` keys must be non-empty strings',
          details
        );
        assertType(
          typeof token === 'string' && token.length > 0,
          `runtime.dashboard.team_tokens.${team} must be non-empty string`,
          details
        );
      }
    }
    assertType(
      typeof dashboard.team_header === 'string' && dashboard.team_header.length > 0,
      '`runtime.dashboard.team_header` must be non-empty string',
      details
    );
    if (
      dashboard.allow_remote === true
      && String(dashboard.auth_token || '').length === 0
      && Object.keys(dashboard.team_tokens || {}).length === 0
    ) {
      details.push(
        '`runtime.dashboard.auth_token` or `runtime.dashboard.team_tokens` must be configured when `runtime.dashboard.allow_remote=true`'
      );
    }
  }

  const postureScoring = runtime.posture_scoring || {};
  if (runtime.posture_scoring !== undefined) {
    assertNoUnknownKeys(postureScoring, POSTURE_SCORING_KEYS, 'runtime.posture_scoring', details);
    assertType(
      typeof postureScoring.enabled === 'boolean',
      '`runtime.posture_scoring.enabled` must be boolean',
      details
    );
    assertType(
      typeof postureScoring.include_counters === 'boolean',
      '`runtime.posture_scoring.include_counters` must be boolean',
      details
    );
    assertType(
      Number.isInteger(postureScoring.warn_threshold) &&
        postureScoring.warn_threshold >= 1 &&
        postureScoring.warn_threshold <= 100,
      '`runtime.posture_scoring.warn_threshold` must be integer between 1 and 100',
      details
    );
    assertType(
      Number.isInteger(postureScoring.critical_threshold) &&
        postureScoring.critical_threshold >= 1 &&
        postureScoring.critical_threshold <= 100,
      '`runtime.posture_scoring.critical_threshold` must be integer between 1 and 100',
      details
    );
    if (
      Number.isInteger(postureScoring.warn_threshold) &&
      Number.isInteger(postureScoring.critical_threshold) &&
      postureScoring.critical_threshold >= postureScoring.warn_threshold
    ) {
      details.push('`runtime.posture_scoring.critical_threshold` must be less than `runtime.posture_scoring.warn_threshold`');
    }
  }

  const websocket = runtime.websocket || {};
  if (runtime.websocket !== undefined) {
    assertNoUnknownKeys(websocket, WEBSOCKET_KEYS, 'runtime.websocket', details);
    assertType(typeof websocket.enabled === 'boolean', '`runtime.websocket.enabled` must be boolean', details);
    assertType(
      typeof websocket.mode === 'string' && WEBSOCKET_MODES.has(String(websocket.mode).toLowerCase()),
      '`runtime.websocket.mode` must be one of: monitor, enforce',
      details
    );
    assertType(
      Number.isInteger(websocket.connect_timeout_ms) && websocket.connect_timeout_ms > 0,
      '`runtime.websocket.connect_timeout_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(websocket.idle_timeout_ms) && websocket.idle_timeout_ms > 0,
      '`runtime.websocket.idle_timeout_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(websocket.max_connections) && websocket.max_connections > 0,
      '`runtime.websocket.max_connections` must be integer > 0',
      details
    );
  }

  const budget = runtime.budget || {};
  if (runtime.budget !== undefined) {
    assertNoUnknownKeys(budget, BUDGET_KEYS, 'runtime.budget', details);
    assertType(typeof budget.enabled === 'boolean', '`runtime.budget.enabled` must be boolean', details);
    assertType(
      BUDGET_ACTIONS.has(String(budget.action)),
      '`runtime.budget.action` must be block|warn',
      details
    );
    assertType(
      Number.isFinite(Number(budget.daily_limit_usd)) && Number(budget.daily_limit_usd) > 0,
      '`runtime.budget.daily_limit_usd` must be number > 0',
      details
    );
    assertType(
      typeof budget.store_file === 'string' && budget.store_file.length > 0,
      '`runtime.budget.store_file` must be non-empty string',
      details
    );
    assertType(
      BUDGET_RESET_TIMEZONES.has(String(budget.reset_timezone)),
      '`runtime.budget.reset_timezone` must be utc|local',
      details
    );
    assertType(
      Number.isInteger(budget.chars_per_token) && budget.chars_per_token > 0,
      '`runtime.budget.chars_per_token` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(budget.input_cost_per_1k_tokens)) && Number(budget.input_cost_per_1k_tokens) >= 0,
      '`runtime.budget.input_cost_per_1k_tokens` must be number >= 0',
      details
    );
    assertType(
      Number.isFinite(Number(budget.output_cost_per_1k_tokens)) && Number(budget.output_cost_per_1k_tokens) >= 0,
      '`runtime.budget.output_cost_per_1k_tokens` must be number >= 0',
      details
    );
    assertType(
      typeof budget.charge_replay_hits === 'boolean',
      '`runtime.budget.charge_replay_hits` must be boolean',
      details
    );
    assertType(
      Number.isInteger(budget.retention_days) && budget.retention_days > 0,
      '`runtime.budget.retention_days` must be integer > 0',
      details
    );
  }

  const loopBreaker = runtime.loop_breaker || {};
  if (runtime.loop_breaker !== undefined) {
    assertNoUnknownKeys(loopBreaker, LOOP_BREAKER_KEYS, 'runtime.loop_breaker', details);
    assertType(typeof loopBreaker.enabled === 'boolean', '`runtime.loop_breaker.enabled` must be boolean', details);
    assertType(
      LOOP_BREAKER_ACTIONS.has(String(loopBreaker.action)),
      '`runtime.loop_breaker.action` must be block|warn',
      details
    );
    assertType(
      Number.isInteger(loopBreaker.window_ms) && loopBreaker.window_ms > 0,
      '`runtime.loop_breaker.window_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(loopBreaker.repeat_threshold) && loopBreaker.repeat_threshold >= 2,
      '`runtime.loop_breaker.repeat_threshold` must be integer >= 2',
      details
    );
    assertType(
      Number.isInteger(loopBreaker.max_recent) && loopBreaker.max_recent >= Number(loopBreaker.repeat_threshold || 2),
      '`runtime.loop_breaker.max_recent` must be integer >= repeat_threshold',
      details
    );
    assertType(
      Number.isInteger(loopBreaker.max_keys) && loopBreaker.max_keys > 0,
      '`runtime.loop_breaker.max_keys` must be integer > 0',
      details
    );
    assertType(
      typeof loopBreaker.key_header === 'string' && loopBreaker.key_header.length > 0,
      '`runtime.loop_breaker.key_header` must be non-empty string',
      details
    );
  }

  const agenticThreatShield = runtime.agentic_threat_shield || {};
  if (runtime.agentic_threat_shield !== undefined) {
    assertNoUnknownKeys(agenticThreatShield, AGENTIC_THREAT_SHIELD_KEYS, 'runtime.agentic_threat_shield', details);
    assertType(
      typeof agenticThreatShield.enabled === 'boolean',
      '`runtime.agentic_threat_shield.enabled` must be boolean',
      details
    );
    assertType(
      AGENTIC_THREAT_SHIELD_MODES.has(String(agenticThreatShield.mode)),
      '`runtime.agentic_threat_shield.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(agenticThreatShield.max_tool_call_depth) && agenticThreatShield.max_tool_call_depth > 0,
      '`runtime.agentic_threat_shield.max_tool_call_depth` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(agenticThreatShield.max_agent_delegations) && agenticThreatShield.max_agent_delegations > 0,
      '`runtime.agentic_threat_shield.max_agent_delegations` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(agenticThreatShield.max_analysis_nodes) && agenticThreatShield.max_analysis_nodes > 0,
      '`runtime.agentic_threat_shield.max_analysis_nodes` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(agenticThreatShield.max_tool_calls_analyzed) && agenticThreatShield.max_tool_calls_analyzed > 0,
      '`runtime.agentic_threat_shield.max_tool_calls_analyzed` must be integer > 0',
      details
    );
    assertType(
      typeof agenticThreatShield.block_on_analysis_truncation === 'boolean',
      '`runtime.agentic_threat_shield.block_on_analysis_truncation` must be boolean',
      details
    );
    assertType(
      typeof agenticThreatShield.detect_cycles === 'boolean',
      '`runtime.agentic_threat_shield.detect_cycles` must be boolean',
      details
    );
    assertType(
      typeof agenticThreatShield.verify_identity_tokens === 'boolean',
      '`runtime.agentic_threat_shield.verify_identity_tokens` must be boolean',
      details
    );
    assertType(
      typeof agenticThreatShield.identity_token_header === 'string' && agenticThreatShield.identity_token_header.length > 0,
      '`runtime.agentic_threat_shield.identity_token_header` must be non-empty string',
      details
    );
    assertType(
      typeof agenticThreatShield.agent_id_header === 'string' && agenticThreatShield.agent_id_header.length > 0,
      '`runtime.agentic_threat_shield.agent_id_header` must be non-empty string',
      details
    );
    assertType(
      typeof agenticThreatShield.session_header === 'string' && agenticThreatShield.session_header.length > 0,
      '`runtime.agentic_threat_shield.session_header` must be non-empty string',
      details
    );
    assertType(
      Array.isArray(agenticThreatShield.fallback_headers) && agenticThreatShield.fallback_headers.length > 0,
      '`runtime.agentic_threat_shield.fallback_headers` must be non-empty array',
      details
    );
    if (Array.isArray(agenticThreatShield.fallback_headers)) {
      agenticThreatShield.fallback_headers.forEach((header, idx) => {
        assertType(
          typeof header === 'string' && header.length > 0,
          `runtime.agentic_threat_shield.fallback_headers[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      typeof agenticThreatShield.hmac_secret === 'string',
      '`runtime.agentic_threat_shield.hmac_secret` must be string',
      details
    );
    assertType(
      Number.isInteger(agenticThreatShield.ttl_ms) && agenticThreatShield.ttl_ms > 0,
      '`runtime.agentic_threat_shield.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(agenticThreatShield.max_sessions) && agenticThreatShield.max_sessions > 0,
      '`runtime.agentic_threat_shield.max_sessions` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(agenticThreatShield.max_graph_edges_per_session) && agenticThreatShield.max_graph_edges_per_session > 0,
      '`runtime.agentic_threat_shield.max_graph_edges_per_session` must be integer > 0',
      details
    );
    assertType(
      typeof agenticThreatShield.observability === 'boolean',
      '`runtime.agentic_threat_shield.observability` must be boolean',
      details
    );
  }

  const a2aCardVerifier = runtime.a2a_card_verifier || {};
  if (runtime.a2a_card_verifier !== undefined) {
    assertNoUnknownKeys(a2aCardVerifier, A2A_CARD_VERIFIER_KEYS, 'runtime.a2a_card_verifier', details);
    assertType(typeof a2aCardVerifier.enabled === 'boolean', '`runtime.a2a_card_verifier.enabled` must be boolean', details);
    assertType(
      A2A_CARD_VERIFIER_MODES.has(String(a2aCardVerifier.mode)),
      '`runtime.a2a_card_verifier.mode` must be monitor|block',
      details
    );
    assertType(
      typeof a2aCardVerifier.card_header === 'string' && a2aCardVerifier.card_header.length > 0,
      '`runtime.a2a_card_verifier.card_header` must be non-empty string',
      details
    );
    assertType(
      typeof a2aCardVerifier.agent_id_header === 'string' && a2aCardVerifier.agent_id_header.length > 0,
      '`runtime.a2a_card_verifier.agent_id_header` must be non-empty string',
      details
    );
    assertType(
      Number.isInteger(a2aCardVerifier.max_card_bytes) && a2aCardVerifier.max_card_bytes > 0,
      '`runtime.a2a_card_verifier.max_card_bytes` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(a2aCardVerifier.ttl_ms) && a2aCardVerifier.ttl_ms > 0,
      '`runtime.a2a_card_verifier.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(a2aCardVerifier.max_agents) && a2aCardVerifier.max_agents > 0,
      '`runtime.a2a_card_verifier.max_agents` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(a2aCardVerifier.max_capabilities) && a2aCardVerifier.max_capabilities > 0,
      '`runtime.a2a_card_verifier.max_capabilities` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(a2aCardVerifier.max_observed_per_agent) && a2aCardVerifier.max_observed_per_agent > 0,
      '`runtime.a2a_card_verifier.max_observed_per_agent` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(a2aCardVerifier.overclaim_tolerance) && a2aCardVerifier.overclaim_tolerance >= 0,
      '`runtime.a2a_card_verifier.overclaim_tolerance` must be integer >= 0',
      details
    );
    assertType(
      typeof a2aCardVerifier.block_on_invalid_schema === 'boolean',
      '`runtime.a2a_card_verifier.block_on_invalid_schema` must be boolean',
      details
    );
    assertType(
      typeof a2aCardVerifier.block_on_drift === 'boolean',
      '`runtime.a2a_card_verifier.block_on_drift` must be boolean',
      details
    );
    assertType(
      typeof a2aCardVerifier.block_on_overclaim === 'boolean',
      '`runtime.a2a_card_verifier.block_on_overclaim` must be boolean',
      details
    );
    assertType(
      typeof a2aCardVerifier.block_on_auth_mismatch === 'boolean',
      '`runtime.a2a_card_verifier.block_on_auth_mismatch` must be boolean',
      details
    );
    assertType(
      typeof a2aCardVerifier.observability === 'boolean',
      '`runtime.a2a_card_verifier.observability` must be boolean',
      details
    );
  }

  const consensusProtocol = runtime.consensus_protocol || {};
  if (runtime.consensus_protocol !== undefined) {
    assertNoUnknownKeys(consensusProtocol, CONSENSUS_PROTOCOL_KEYS, 'runtime.consensus_protocol', details);
    assertType(typeof consensusProtocol.enabled === 'boolean', '`runtime.consensus_protocol.enabled` must be boolean', details);
    assertType(
      CONSENSUS_PROTOCOL_MODES.has(String(consensusProtocol.mode)),
      '`runtime.consensus_protocol.mode` must be monitor|block',
      details
    );
    assertType(
      typeof consensusProtocol.policy_header === 'string' && consensusProtocol.policy_header.length > 0,
      '`runtime.consensus_protocol.policy_header` must be non-empty string',
      details
    );
    assertType(
      typeof consensusProtocol.action_field === 'string' && consensusProtocol.action_field.length > 0,
      '`runtime.consensus_protocol.action_field` must be non-empty string',
      details
    );
    assertType(
      Number.isInteger(consensusProtocol.max_votes) && consensusProtocol.max_votes > 0,
      '`runtime.consensus_protocol.max_votes` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(consensusProtocol.required_votes) && consensusProtocol.required_votes > 0,
      '`runtime.consensus_protocol.required_votes` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(consensusProtocol.total_agents) && consensusProtocol.total_agents > 0,
      '`runtime.consensus_protocol.total_agents` must be integer > 0',
      details
    );
    if (
      Number.isInteger(consensusProtocol.required_votes) &&
      Number.isInteger(consensusProtocol.total_agents) &&
      consensusProtocol.required_votes > consensusProtocol.total_agents
    ) {
      details.push('`runtime.consensus_protocol.required_votes` must be <= `runtime.consensus_protocol.total_agents`');
    }
    assertType(
      typeof consensusProtocol.block_on_no_quorum === 'boolean',
      '`runtime.consensus_protocol.block_on_no_quorum` must be boolean',
      details
    );
    assertType(
      typeof consensusProtocol.block_on_byzantine === 'boolean',
      '`runtime.consensus_protocol.block_on_byzantine` must be boolean',
      details
    );
    assertType(
      Array.isArray(consensusProtocol.high_risk_actions),
      '`runtime.consensus_protocol.high_risk_actions` must be array',
      details
    );
    if (Array.isArray(consensusProtocol.high_risk_actions)) {
      consensusProtocol.high_risk_actions.forEach((value, idx) => {
        assertType(
          typeof value === 'string' && value.length > 0,
          `runtime.consensus_protocol.high_risk_actions[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      typeof consensusProtocol.observability === 'boolean',
      '`runtime.consensus_protocol.observability` must be boolean',
      details
    );
  }

  const crossTenantIsolator = runtime.cross_tenant_isolator || {};
  if (runtime.cross_tenant_isolator !== undefined) {
    assertNoUnknownKeys(crossTenantIsolator, CROSS_TENANT_ISOLATOR_KEYS, 'runtime.cross_tenant_isolator', details);
    assertType(
      typeof crossTenantIsolator.enabled === 'boolean',
      '`runtime.cross_tenant_isolator.enabled` must be boolean',
      details
    );
    assertType(
      CROSS_TENANT_ISOLATOR_MODES.has(String(crossTenantIsolator.mode)),
      '`runtime.cross_tenant_isolator.mode` must be monitor|block',
      details
    );
    assertType(
      typeof crossTenantIsolator.tenant_header === 'string' && crossTenantIsolator.tenant_header.length > 0,
      '`runtime.cross_tenant_isolator.tenant_header` must be non-empty string',
      details
    );
    assertType(
      typeof crossTenantIsolator.session_header === 'string' && crossTenantIsolator.session_header.length > 0,
      '`runtime.cross_tenant_isolator.session_header` must be non-empty string',
      details
    );
    assertType(
      Array.isArray(crossTenantIsolator.fallback_headers),
      '`runtime.cross_tenant_isolator.fallback_headers` must be array',
      details
    );
    if (Array.isArray(crossTenantIsolator.fallback_headers)) {
      crossTenantIsolator.fallback_headers.forEach((value, idx) => {
        assertType(
          typeof value === 'string' && value.length > 0,
          `runtime.cross_tenant_isolator.fallback_headers[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      Number.isInteger(crossTenantIsolator.ttl_ms) && crossTenantIsolator.ttl_ms > 0,
      '`runtime.cross_tenant_isolator.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(crossTenantIsolator.max_sessions) && crossTenantIsolator.max_sessions > 0,
      '`runtime.cross_tenant_isolator.max_sessions` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(crossTenantIsolator.max_known_tenants) && crossTenantIsolator.max_known_tenants > 0,
      '`runtime.cross_tenant_isolator.max_known_tenants` must be integer > 0',
      details
    );
    assertType(
      typeof crossTenantIsolator.block_on_mismatch === 'boolean',
      '`runtime.cross_tenant_isolator.block_on_mismatch` must be boolean',
      details
    );
    assertType(
      typeof crossTenantIsolator.block_on_leak === 'boolean',
      '`runtime.cross_tenant_isolator.block_on_leak` must be boolean',
      details
    );
    assertType(
      typeof crossTenantIsolator.observability === 'boolean',
      '`runtime.cross_tenant_isolator.observability` must be boolean',
      details
    );
  }

  const coldStartAnalyzer = runtime.cold_start_analyzer || {};
  if (runtime.cold_start_analyzer !== undefined) {
    assertNoUnknownKeys(coldStartAnalyzer, COLD_START_ANALYZER_KEYS, 'runtime.cold_start_analyzer', details);
    assertType(
      typeof coldStartAnalyzer.enabled === 'boolean',
      '`runtime.cold_start_analyzer.enabled` must be boolean',
      details
    );
    assertType(
      COLD_START_ANALYZER_MODES.has(String(coldStartAnalyzer.mode)),
      '`runtime.cold_start_analyzer.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(coldStartAnalyzer.cold_start_window_ms) && coldStartAnalyzer.cold_start_window_ms > 0,
      '`runtime.cold_start_analyzer.cold_start_window_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(coldStartAnalyzer.warmup_request_threshold) && coldStartAnalyzer.warmup_request_threshold > 0,
      '`runtime.cold_start_analyzer.warmup_request_threshold` must be integer > 0',
      details
    );
    assertType(
      Array.isArray(coldStartAnalyzer.warmup_engines),
      '`runtime.cold_start_analyzer.warmup_engines` must be array',
      details
    );
    if (Array.isArray(coldStartAnalyzer.warmup_engines)) {
      coldStartAnalyzer.warmup_engines.forEach((value, idx) => {
        assertType(
          typeof value === 'string' && value.length > 0,
          `runtime.cold_start_analyzer.warmup_engines[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      typeof coldStartAnalyzer.block_during_cold_start === 'boolean',
      '`runtime.cold_start_analyzer.block_during_cold_start` must be boolean',
      details
    );
    assertType(
      typeof coldStartAnalyzer.observability === 'boolean',
      '`runtime.cold_start_analyzer.observability` must be boolean',
      details
    );
  }

  const serializationFirewall = runtime.serialization_firewall || {};
  if (runtime.serialization_firewall !== undefined) {
    assertNoUnknownKeys(serializationFirewall, SERIALIZATION_FIREWALL_KEYS, 'runtime.serialization_firewall', details);
    assertType(
      typeof serializationFirewall.enabled === 'boolean',
      '`runtime.serialization_firewall.enabled` must be boolean',
      details
    );
    assertType(
      SERIALIZATION_FIREWALL_MODES.has(String(serializationFirewall.mode)),
      '`runtime.serialization_firewall.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(serializationFirewall.max_scan_bytes) && serializationFirewall.max_scan_bytes > 0,
      '`runtime.serialization_firewall.max_scan_bytes` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(serializationFirewall.max_nesting_depth) && serializationFirewall.max_nesting_depth > 0,
      '`runtime.serialization_firewall.max_nesting_depth` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(serializationFirewall.max_object_nodes) && serializationFirewall.max_object_nodes > 0,
      '`runtime.serialization_firewall.max_object_nodes` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(serializationFirewall.metadata_ratio_threshold))
        && Number(serializationFirewall.metadata_ratio_threshold) >= 0,
      '`runtime.serialization_firewall.metadata_ratio_threshold` must be number >= 0',
      details
    );
    assertType(
      Array.isArray(serializationFirewall.allowed_formats),
      '`runtime.serialization_firewall.allowed_formats` must be array',
      details
    );
    if (Array.isArray(serializationFirewall.allowed_formats)) {
      serializationFirewall.allowed_formats.forEach((value, idx) => {
        assertType(
          typeof value === 'string' && value.length > 0,
          `runtime.serialization_firewall.allowed_formats[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      Array.isArray(serializationFirewall.expected_root_keys),
      '`runtime.serialization_firewall.expected_root_keys` must be array',
      details
    );
    if (Array.isArray(serializationFirewall.expected_root_keys)) {
      serializationFirewall.expected_root_keys.forEach((value, idx) => {
        assertType(
          typeof value === 'string' && value.length > 0,
          `runtime.serialization_firewall.expected_root_keys[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      typeof serializationFirewall.block_on_type_confusion === 'boolean',
      '`runtime.serialization_firewall.block_on_type_confusion` must be boolean',
      details
    );
    assertType(
      typeof serializationFirewall.block_on_depth_bomb === 'boolean',
      '`runtime.serialization_firewall.block_on_depth_bomb` must be boolean',
      details
    );
    assertType(
      typeof serializationFirewall.block_on_format_violation === 'boolean',
      '`runtime.serialization_firewall.block_on_format_violation` must be boolean',
      details
    );
    assertType(
      typeof serializationFirewall.block_on_metadata_anomaly === 'boolean',
      '`runtime.serialization_firewall.block_on_metadata_anomaly` must be boolean',
      details
    );
    assertType(
      typeof serializationFirewall.block_on_schema_mismatch === 'boolean',
      '`runtime.serialization_firewall.block_on_schema_mismatch` must be boolean',
      details
    );
    assertType(
      typeof serializationFirewall.observability === 'boolean',
      '`runtime.serialization_firewall.observability` must be boolean',
      details
    );
  }

  const contextIntegrityGuardian = runtime.context_integrity_guardian || {};
  if (runtime.context_integrity_guardian !== undefined) {
    assertNoUnknownKeys(contextIntegrityGuardian, CONTEXT_INTEGRITY_GUARDIAN_KEYS, 'runtime.context_integrity_guardian', details);
    assertType(
      typeof contextIntegrityGuardian.enabled === 'boolean',
      '`runtime.context_integrity_guardian.enabled` must be boolean',
      details
    );
    assertType(
      CONTEXT_INTEGRITY_GUARDIAN_MODES.has(String(contextIntegrityGuardian.mode)),
      '`runtime.context_integrity_guardian.mode` must be monitor|block',
      details
    );
    assertType(
      typeof contextIntegrityGuardian.session_header === 'string' && contextIntegrityGuardian.session_header.length > 0,
      '`runtime.context_integrity_guardian.session_header` must be non-empty string',
      details
    );
    assertType(
      Array.isArray(contextIntegrityGuardian.fallback_headers),
      '`runtime.context_integrity_guardian.fallback_headers` must be array',
      details
    );
    if (Array.isArray(contextIntegrityGuardian.fallback_headers)) {
      contextIntegrityGuardian.fallback_headers.forEach((value, idx) => {
        assertType(
          typeof value === 'string' && value.length > 0,
          `runtime.context_integrity_guardian.fallback_headers[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      Array.isArray(contextIntegrityGuardian.required_anchors),
      '`runtime.context_integrity_guardian.required_anchors` must be array',
      details
    );
    if (Array.isArray(contextIntegrityGuardian.required_anchors)) {
      contextIntegrityGuardian.required_anchors.forEach((value, idx) => {
        assertType(
          typeof value === 'string' && value.length > 0,
          `runtime.context_integrity_guardian.required_anchors[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      Number.isInteger(contextIntegrityGuardian.max_context_chars) && contextIntegrityGuardian.max_context_chars > 0,
      '`runtime.context_integrity_guardian.max_context_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(contextIntegrityGuardian.max_sessions) && contextIntegrityGuardian.max_sessions > 0,
      '`runtime.context_integrity_guardian.max_sessions` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(contextIntegrityGuardian.ttl_ms) && contextIntegrityGuardian.ttl_ms > 0,
      '`runtime.context_integrity_guardian.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(contextIntegrityGuardian.repetition_threshold))
        && Number(contextIntegrityGuardian.repetition_threshold) >= 0
        && Number(contextIntegrityGuardian.repetition_threshold) <= 1,
      '`runtime.context_integrity_guardian.repetition_threshold` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(contextIntegrityGuardian.token_budget_warn_ratio))
        && Number(contextIntegrityGuardian.token_budget_warn_ratio) >= 0
        && Number(contextIntegrityGuardian.token_budget_warn_ratio) <= 1,
      '`runtime.context_integrity_guardian.token_budget_warn_ratio` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(contextIntegrityGuardian.provider_token_limit) && contextIntegrityGuardian.provider_token_limit > 0,
      '`runtime.context_integrity_guardian.provider_token_limit` must be integer > 0',
      details
    );
    assertType(
      typeof contextIntegrityGuardian.block_on_anchor_loss === 'boolean',
      '`runtime.context_integrity_guardian.block_on_anchor_loss` must be boolean',
      details
    );
    assertType(
      typeof contextIntegrityGuardian.block_on_repetition === 'boolean',
      '`runtime.context_integrity_guardian.block_on_repetition` must be boolean',
      details
    );
    assertType(
      typeof contextIntegrityGuardian.observability === 'boolean',
      '`runtime.context_integrity_guardian.observability` must be boolean',
      details
    );
  }

  const contextCompressionGuard = runtime.context_compression_guard || {};
  if (runtime.context_compression_guard !== undefined) {
    assertNoUnknownKeys(contextCompressionGuard, CONTEXT_COMPRESSION_GUARD_KEYS, 'runtime.context_compression_guard', details);
    assertType(
      typeof contextCompressionGuard.enabled === 'boolean',
      '`runtime.context_compression_guard.enabled` must be boolean',
      details
    );
    assertType(
      CONTEXT_COMPRESSION_GUARD_MODES.has(String(contextCompressionGuard.mode)),
      '`runtime.context_compression_guard.mode` must be monitor|block',
      details
    );
    assertType(
      typeof contextCompressionGuard.session_header === 'string' && contextCompressionGuard.session_header.length > 0,
      '`runtime.context_compression_guard.session_header` must be non-empty string',
      details
    );
    assertType(
      Array.isArray(contextCompressionGuard.fallback_headers),
      '`runtime.context_compression_guard.fallback_headers` must be array',
      details
    );
    if (Array.isArray(contextCompressionGuard.fallback_headers)) {
      contextCompressionGuard.fallback_headers.forEach((value, idx) => {
        assertType(
          typeof value === 'string' && value.length > 0,
          `runtime.context_compression_guard.fallback_headers[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      Array.isArray(contextCompressionGuard.protected_anchors),
      '`runtime.context_compression_guard.protected_anchors` must be array',
      details
    );
    if (Array.isArray(contextCompressionGuard.protected_anchors)) {
      contextCompressionGuard.protected_anchors.forEach((value, idx) => {
        assertType(
          typeof value === 'string' && value.length > 0,
          `runtime.context_compression_guard.protected_anchors[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      Array.isArray(contextCompressionGuard.summary_fields),
      '`runtime.context_compression_guard.summary_fields` must be array',
      details
    );
    if (Array.isArray(contextCompressionGuard.summary_fields)) {
      contextCompressionGuard.summary_fields.forEach((value, idx) => {
        assertType(
          typeof value === 'string' && value.length > 0,
          `runtime.context_compression_guard.summary_fields[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      Number.isInteger(contextCompressionGuard.max_context_chars) && contextCompressionGuard.max_context_chars > 0,
      '`runtime.context_compression_guard.max_context_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(contextCompressionGuard.max_summary_chars) && contextCompressionGuard.max_summary_chars > 0,
      '`runtime.context_compression_guard.max_summary_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(contextCompressionGuard.max_sessions) && contextCompressionGuard.max_sessions > 0,
      '`runtime.context_compression_guard.max_sessions` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(contextCompressionGuard.ttl_ms) && contextCompressionGuard.ttl_ms > 0,
      '`runtime.context_compression_guard.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(contextCompressionGuard.anchor_loss_ratio))
        && Number(contextCompressionGuard.anchor_loss_ratio) >= 0
        && Number(contextCompressionGuard.anchor_loss_ratio) <= 1,
      '`runtime.context_compression_guard.anchor_loss_ratio` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(contextCompressionGuard.shrink_spike_ratio))
        && Number(contextCompressionGuard.shrink_spike_ratio) >= 0
        && Number(contextCompressionGuard.shrink_spike_ratio) <= 1,
      '`runtime.context_compression_guard.shrink_spike_ratio` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(contextCompressionGuard.token_budget_warn_ratio))
        && Number(contextCompressionGuard.token_budget_warn_ratio) >= 0
        && Number(contextCompressionGuard.token_budget_warn_ratio) <= 1,
      '`runtime.context_compression_guard.token_budget_warn_ratio` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(contextCompressionGuard.provider_token_limit) && contextCompressionGuard.provider_token_limit > 0,
      '`runtime.context_compression_guard.provider_token_limit` must be integer > 0',
      details
    );
    assertType(
      typeof contextCompressionGuard.block_on_anchor_loss === 'boolean',
      '`runtime.context_compression_guard.block_on_anchor_loss` must be boolean',
      details
    );
    assertType(
      typeof contextCompressionGuard.block_on_summary_injection === 'boolean',
      '`runtime.context_compression_guard.block_on_summary_injection` must be boolean',
      details
    );
    assertType(
      typeof contextCompressionGuard.observability === 'boolean',
      '`runtime.context_compression_guard.observability` must be boolean',
      details
    );
  }

  const toolSchemaValidator = runtime.tool_schema_validator || {};
  if (runtime.tool_schema_validator !== undefined) {
    assertNoUnknownKeys(toolSchemaValidator, TOOL_SCHEMA_VALIDATOR_KEYS, 'runtime.tool_schema_validator', details);
    assertType(
      typeof toolSchemaValidator.enabled === 'boolean',
      '`runtime.tool_schema_validator.enabled` must be boolean',
      details
    );
    assertType(
      TOOL_SCHEMA_VALIDATOR_MODES.has(String(toolSchemaValidator.mode)),
      '`runtime.tool_schema_validator.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(toolSchemaValidator.max_tools) && toolSchemaValidator.max_tools > 0,
      '`runtime.tool_schema_validator.max_tools` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(toolSchemaValidator.max_schema_bytes) && toolSchemaValidator.max_schema_bytes > 0,
      '`runtime.tool_schema_validator.max_schema_bytes` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(toolSchemaValidator.max_param_name_chars) && toolSchemaValidator.max_param_name_chars > 0,
      '`runtime.tool_schema_validator.max_param_name_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(toolSchemaValidator.ttl_ms) && toolSchemaValidator.ttl_ms > 0,
      '`runtime.tool_schema_validator.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(toolSchemaValidator.max_servers) && toolSchemaValidator.max_servers > 0,
      '`runtime.tool_schema_validator.max_servers` must be integer > 0',
      details
    );
    assertType(
      typeof toolSchemaValidator.block_on_dangerous_parameter === 'boolean',
      '`runtime.tool_schema_validator.block_on_dangerous_parameter` must be boolean',
      details
    );
    assertType(
      typeof toolSchemaValidator.block_on_schema_drift === 'boolean',
      '`runtime.tool_schema_validator.block_on_schema_drift` must be boolean',
      details
    );
    assertType(
      typeof toolSchemaValidator.block_on_capability_boundary === 'boolean',
      '`runtime.tool_schema_validator.block_on_capability_boundary` must be boolean',
      details
    );
    assertType(
      typeof toolSchemaValidator.detect_schema_drift === 'boolean',
      '`runtime.tool_schema_validator.detect_schema_drift` must be boolean',
      details
    );
    assertType(
      typeof toolSchemaValidator.sanitize_in_monitor === 'boolean',
      '`runtime.tool_schema_validator.sanitize_in_monitor` must be boolean',
      details
    );
    assertType(
      typeof toolSchemaValidator.observability === 'boolean',
      '`runtime.tool_schema_validator.observability` must be boolean',
      details
    );
  }

  const multimodalInjectionShield = runtime.multimodal_injection_shield || {};
  if (runtime.multimodal_injection_shield !== undefined) {
    assertNoUnknownKeys(
      multimodalInjectionShield,
      MULTIMODAL_INJECTION_SHIELD_KEYS,
      'runtime.multimodal_injection_shield',
      details
    );
    assertType(
      typeof multimodalInjectionShield.enabled === 'boolean',
      '`runtime.multimodal_injection_shield.enabled` must be boolean',
      details
    );
    assertType(
      MULTIMODAL_INJECTION_SHIELD_MODES.has(String(multimodalInjectionShield.mode)),
      '`runtime.multimodal_injection_shield.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(multimodalInjectionShield.max_scan_bytes) && multimodalInjectionShield.max_scan_bytes > 0,
      '`runtime.multimodal_injection_shield.max_scan_bytes` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(multimodalInjectionShield.max_findings) && multimodalInjectionShield.max_findings > 0,
      '`runtime.multimodal_injection_shield.max_findings` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(multimodalInjectionShield.base64_entropy_threshold))
        && Number(multimodalInjectionShield.base64_entropy_threshold) >= 0
        && Number(multimodalInjectionShield.base64_entropy_threshold) <= 1,
      '`runtime.multimodal_injection_shield.base64_entropy_threshold` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(multimodalInjectionShield.max_decoded_base64_bytes)
        && multimodalInjectionShield.max_decoded_base64_bytes > 0,
      '`runtime.multimodal_injection_shield.max_decoded_base64_bytes` must be integer > 0',
      details
    );
    assertType(
      typeof multimodalInjectionShield.block_on_mime_mismatch === 'boolean',
      '`runtime.multimodal_injection_shield.block_on_mime_mismatch` must be boolean',
      details
    );
    assertType(
      typeof multimodalInjectionShield.block_on_suspicious_metadata === 'boolean',
      '`runtime.multimodal_injection_shield.block_on_suspicious_metadata` must be boolean',
      details
    );
    assertType(
      typeof multimodalInjectionShield.block_on_base64_injection === 'boolean',
      '`runtime.multimodal_injection_shield.block_on_base64_injection` must be boolean',
      details
    );
    assertType(
      typeof multimodalInjectionShield.observability === 'boolean',
      '`runtime.multimodal_injection_shield.observability` must be boolean',
      details
    );
  }

  const supplyChainValidator = runtime.supply_chain_validator || {};
  if (runtime.supply_chain_validator !== undefined) {
    assertNoUnknownKeys(supplyChainValidator, SUPPLY_CHAIN_VALIDATOR_KEYS, 'runtime.supply_chain_validator', details);
    assertType(
      typeof supplyChainValidator.enabled === 'boolean',
      '`runtime.supply_chain_validator.enabled` must be boolean',
      details
    );
    assertType(
      SUPPLY_CHAIN_VALIDATOR_MODES.has(String(supplyChainValidator.mode)),
      '`runtime.supply_chain_validator.mode` must be monitor|block',
      details
    );
    assertType(
      typeof supplyChainValidator.project_root === 'string' && supplyChainValidator.project_root.length > 0,
      '`runtime.supply_chain_validator.project_root` must be non-empty string',
      details
    );
    assertType(
      Number.isInteger(supplyChainValidator.max_module_entries) && supplyChainValidator.max_module_entries > 0,
      '`runtime.supply_chain_validator.max_module_entries` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(supplyChainValidator.check_every_requests) && supplyChainValidator.check_every_requests > 0,
      '`runtime.supply_chain_validator.check_every_requests` must be integer > 0',
      details
    );
    assertType(
      typeof supplyChainValidator.block_on_lockfile_drift === 'boolean',
      '`runtime.supply_chain_validator.block_on_lockfile_drift` must be boolean',
      details
    );
    assertType(
      typeof supplyChainValidator.block_on_blocked_package === 'boolean',
      '`runtime.supply_chain_validator.block_on_blocked_package` must be boolean',
      details
    );
    assertType(
      typeof supplyChainValidator.require_lockfile === 'boolean',
      '`runtime.supply_chain_validator.require_lockfile` must be boolean',
      details
    );
    assertType(
      Array.isArray(supplyChainValidator.blocked_packages),
      '`runtime.supply_chain_validator.blocked_packages` must be array',
      details
    );
    if (Array.isArray(supplyChainValidator.blocked_packages)) {
      supplyChainValidator.blocked_packages.forEach((value, idx) => {
        assertType(
          typeof value === 'string' && value.length > 0,
          `runtime.supply_chain_validator.blocked_packages[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      Array.isArray(supplyChainValidator.lock_files),
      '`runtime.supply_chain_validator.lock_files` must be array',
      details
    );
    if (Array.isArray(supplyChainValidator.lock_files)) {
      supplyChainValidator.lock_files.forEach((value, idx) => {
        assertType(
          typeof value === 'string' && value.length > 0,
          `runtime.supply_chain_validator.lock_files[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      typeof supplyChainValidator.observability === 'boolean',
      '`runtime.supply_chain_validator.observability` must be boolean',
      details
    );
  }

  const sandboxEnforcer = runtime.sandbox_enforcer || {};
  if (runtime.sandbox_enforcer !== undefined) {
    assertNoUnknownKeys(sandboxEnforcer, SANDBOX_ENFORCER_KEYS, 'runtime.sandbox_enforcer', details);
    assertType(
      typeof sandboxEnforcer.enabled === 'boolean',
      '`runtime.sandbox_enforcer.enabled` must be boolean',
      details
    );
    assertType(
      SANDBOX_ENFORCER_MODES.has(String(sandboxEnforcer.mode)),
      '`runtime.sandbox_enforcer.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(sandboxEnforcer.max_argument_bytes) && sandboxEnforcer.max_argument_bytes > 0,
      '`runtime.sandbox_enforcer.max_argument_bytes` must be integer > 0',
      details
    );
    assertType(
      Array.isArray(sandboxEnforcer.allowed_paths),
      '`runtime.sandbox_enforcer.allowed_paths` must be array',
      details
    );
    if (Array.isArray(sandboxEnforcer.allowed_paths)) {
      sandboxEnforcer.allowed_paths.forEach((value, idx) => {
        assertType(
          typeof value === 'string' && value.length > 0,
          `runtime.sandbox_enforcer.allowed_paths[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      Array.isArray(sandboxEnforcer.allowed_domains),
      '`runtime.sandbox_enforcer.allowed_domains` must be array',
      details
    );
    if (Array.isArray(sandboxEnforcer.allowed_domains)) {
      sandboxEnforcer.allowed_domains.forEach((value, idx) => {
        assertType(
          typeof value === 'string' && value.length > 0,
          `runtime.sandbox_enforcer.allowed_domains[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      Array.isArray(sandboxEnforcer.blocked_ports),
      '`runtime.sandbox_enforcer.blocked_ports` must be array',
      details
    );
    if (Array.isArray(sandboxEnforcer.blocked_ports)) {
      sandboxEnforcer.blocked_ports.forEach((value, idx) => {
        assertType(
          Number.isInteger(value) && value > 0 && value <= 65535,
          `runtime.sandbox_enforcer.blocked_ports[${idx}] must be integer in range 1..65535`,
          details
        );
      });
    }
    assertType(
      typeof sandboxEnforcer.block_on_path_escape === 'boolean',
      '`runtime.sandbox_enforcer.block_on_path_escape` must be boolean',
      details
    );
    assertType(
      typeof sandboxEnforcer.block_on_network_escape === 'boolean',
      '`runtime.sandbox_enforcer.block_on_network_escape` must be boolean',
      details
    );
    assertType(
      typeof sandboxEnforcer.observability === 'boolean',
      '`runtime.sandbox_enforcer.observability` must be boolean',
      details
    );
  }

  const memoryIntegrityMonitor = runtime.memory_integrity_monitor || {};
  if (runtime.memory_integrity_monitor !== undefined) {
    assertNoUnknownKeys(memoryIntegrityMonitor, MEMORY_INTEGRITY_MONITOR_KEYS, 'runtime.memory_integrity_monitor', details);
    assertType(
      typeof memoryIntegrityMonitor.enabled === 'boolean',
      '`runtime.memory_integrity_monitor.enabled` must be boolean',
      details
    );
    assertType(
      MEMORY_INTEGRITY_MONITOR_MODES.has(String(memoryIntegrityMonitor.mode)),
      '`runtime.memory_integrity_monitor.mode` must be monitor|block',
      details
    );
    assertType(
      typeof memoryIntegrityMonitor.session_header === 'string' && memoryIntegrityMonitor.session_header.length > 0,
      '`runtime.memory_integrity_monitor.session_header` must be non-empty string',
      details
    );
    assertType(
      typeof memoryIntegrityMonitor.agent_header === 'string' && memoryIntegrityMonitor.agent_header.length > 0,
      '`runtime.memory_integrity_monitor.agent_header` must be non-empty string',
      details
    );
    assertType(
      typeof memoryIntegrityMonitor.chain_header === 'string' && memoryIntegrityMonitor.chain_header.length > 0,
      '`runtime.memory_integrity_monitor.chain_header` must be non-empty string',
      details
    );
    assertType(
      Number.isInteger(memoryIntegrityMonitor.max_memory_chars) && memoryIntegrityMonitor.max_memory_chars > 0,
      '`runtime.memory_integrity_monitor.max_memory_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(memoryIntegrityMonitor.ttl_ms) && memoryIntegrityMonitor.ttl_ms > 0,
      '`runtime.memory_integrity_monitor.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(memoryIntegrityMonitor.max_sessions) && memoryIntegrityMonitor.max_sessions > 0,
      '`runtime.memory_integrity_monitor.max_sessions` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(memoryIntegrityMonitor.max_growth_ratio))
        && Number(memoryIntegrityMonitor.max_growth_ratio) >= 1,
      '`runtime.memory_integrity_monitor.max_growth_ratio` must be number >= 1',
      details
    );
    assertType(
      typeof memoryIntegrityMonitor.block_on_chain_break === 'boolean',
      '`runtime.memory_integrity_monitor.block_on_chain_break` must be boolean',
      details
    );
    assertType(
      typeof memoryIntegrityMonitor.block_on_growth === 'boolean',
      '`runtime.memory_integrity_monitor.block_on_growth` must be boolean',
      details
    );
    assertType(
      typeof memoryIntegrityMonitor.block_on_owner_mismatch === 'boolean',
      '`runtime.memory_integrity_monitor.block_on_owner_mismatch` must be boolean',
      details
    );
    assertType(
      typeof memoryIntegrityMonitor.observability === 'boolean',
      '`runtime.memory_integrity_monitor.observability` must be boolean',
      details
    );
  }

  const mcpPoisoning = runtime.mcp_poisoning || {};
  if (runtime.mcp_poisoning !== undefined) {
    assertNoUnknownKeys(mcpPoisoning, MCP_POISONING_KEYS, 'runtime.mcp_poisoning', details);
    assertType(
      typeof mcpPoisoning.enabled === 'boolean',
      '`runtime.mcp_poisoning.enabled` must be boolean',
      details
    );
    assertType(
      MCP_POISONING_MODES.has(String(mcpPoisoning.mode)),
      '`runtime.mcp_poisoning.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isFinite(Number(mcpPoisoning.description_threshold))
        && Number(mcpPoisoning.description_threshold) >= 0
        && Number(mcpPoisoning.description_threshold) <= 1,
      '`runtime.mcp_poisoning.description_threshold` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(mcpPoisoning.max_description_scan_bytes) && mcpPoisoning.max_description_scan_bytes > 0,
      '`runtime.mcp_poisoning.max_description_scan_bytes` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(mcpPoisoning.max_argument_bytes) && mcpPoisoning.max_argument_bytes > 0,
      '`runtime.mcp_poisoning.max_argument_bytes` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(mcpPoisoning.max_tools) && mcpPoisoning.max_tools > 0,
      '`runtime.mcp_poisoning.max_tools` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(mcpPoisoning.max_drift_snapshot_bytes) && mcpPoisoning.max_drift_snapshot_bytes > 0,
      '`runtime.mcp_poisoning.max_drift_snapshot_bytes` must be integer > 0',
      details
    );
    assertType(
      typeof mcpPoisoning.block_on_config_drift === 'boolean',
      '`runtime.mcp_poisoning.block_on_config_drift` must be boolean',
      details
    );
    assertType(
      typeof mcpPoisoning.detect_config_drift === 'boolean',
      '`runtime.mcp_poisoning.detect_config_drift` must be boolean',
      details
    );
    assertType(
      Number.isInteger(mcpPoisoning.drift_ttl_ms) && mcpPoisoning.drift_ttl_ms > 0,
      '`runtime.mcp_poisoning.drift_ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(mcpPoisoning.max_server_entries) && mcpPoisoning.max_server_entries > 0,
      '`runtime.mcp_poisoning.max_server_entries` must be integer > 0',
      details
    );
    assertType(
      typeof mcpPoisoning.sanitize_arguments === 'boolean',
      '`runtime.mcp_poisoning.sanitize_arguments` must be boolean',
      details
    );
    assertType(
      typeof mcpPoisoning.strip_non_printable === 'boolean',
      '`runtime.mcp_poisoning.strip_non_printable` must be boolean',
      details
    );
    assertType(
      typeof mcpPoisoning.observability === 'boolean',
      '`runtime.mcp_poisoning.observability` must be boolean',
      details
    );
  }

  const mcpShadow = runtime.mcp_shadow || {};
  if (runtime.mcp_shadow !== undefined) {
    assertNoUnknownKeys(mcpShadow, MCP_SHADOW_KEYS, 'runtime.mcp_shadow', details);
    assertType(
      typeof mcpShadow.enabled === 'boolean',
      '`runtime.mcp_shadow.enabled` must be boolean',
      details
    );
    assertType(
      MCP_SHADOW_MODES.has(String(mcpShadow.mode)),
      '`runtime.mcp_shadow.mode` must be monitor|block',
      details
    );
    assertType(
      typeof mcpShadow.detect_schema_drift === 'boolean',
      '`runtime.mcp_shadow.detect_schema_drift` must be boolean',
      details
    );
    assertType(
      typeof mcpShadow.detect_late_registration === 'boolean',
      '`runtime.mcp_shadow.detect_late_registration` must be boolean',
      details
    );
    assertType(
      typeof mcpShadow.detect_name_collisions === 'boolean',
      '`runtime.mcp_shadow.detect_name_collisions` must be boolean',
      details
    );
    assertType(
      typeof mcpShadow.block_on_schema_drift === 'boolean',
      '`runtime.mcp_shadow.block_on_schema_drift` must be boolean',
      details
    );
    assertType(
      typeof mcpShadow.block_on_late_registration === 'boolean',
      '`runtime.mcp_shadow.block_on_late_registration` must be boolean',
      details
    );
    assertType(
      typeof mcpShadow.block_on_name_collision === 'boolean',
      '`runtime.mcp_shadow.block_on_name_collision` must be boolean',
      details
    );
    assertType(
      Number.isInteger(mcpShadow.max_tools) && mcpShadow.max_tools > 0,
      '`runtime.mcp_shadow.max_tools` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(mcpShadow.max_tool_snapshot_bytes) && mcpShadow.max_tool_snapshot_bytes > 0,
      '`runtime.mcp_shadow.max_tool_snapshot_bytes` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(mcpShadow.ttl_ms) && mcpShadow.ttl_ms > 0,
      '`runtime.mcp_shadow.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(mcpShadow.max_server_entries) && mcpShadow.max_server_entries > 0,
      '`runtime.mcp_shadow.max_server_entries` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(mcpShadow.max_findings) && mcpShadow.max_findings > 0,
      '`runtime.mcp_shadow.max_findings` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(mcpShadow.min_tool_name_length) && mcpShadow.min_tool_name_length > 0,
      '`runtime.mcp_shadow.min_tool_name_length` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(mcpShadow.name_similarity_distance) && mcpShadow.name_similarity_distance > 0,
      '`runtime.mcp_shadow.name_similarity_distance` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(mcpShadow.max_name_candidates) && mcpShadow.max_name_candidates > 0,
      '`runtime.mcp_shadow.max_name_candidates` must be integer > 0',
      details
    );
    assertType(
      typeof mcpShadow.observability === 'boolean',
      '`runtime.mcp_shadow.observability` must be boolean',
      details
    );
  }

  const mcpCertificatePinning = runtime.mcp_certificate_pinning || {};
  if (runtime.mcp_certificate_pinning !== undefined) {
    assertNoUnknownKeys(mcpCertificatePinning, MCP_CERTIFICATE_PINNING_KEYS, 'runtime.mcp_certificate_pinning', details);
    assertType(
      typeof mcpCertificatePinning.enabled === 'boolean',
      '`runtime.mcp_certificate_pinning.enabled` must be boolean',
      details
    );
    assertType(
      MCP_CERTIFICATE_PINNING_MODES.has(String(mcpCertificatePinning.mode)),
      '`runtime.mcp_certificate_pinning.mode` must be monitor|block',
      details
    );
    assertType(
      typeof mcpCertificatePinning.server_id_header === 'string' && mcpCertificatePinning.server_id_header.length > 0,
      '`runtime.mcp_certificate_pinning.server_id_header` must be non-empty string',
      details
    );
    assertType(
      typeof mcpCertificatePinning.fingerprint_header === 'string' && mcpCertificatePinning.fingerprint_header.length > 0,
      '`runtime.mcp_certificate_pinning.fingerprint_header` must be non-empty string',
      details
    );
    assertType(
      mcpCertificatePinning.pins && typeof mcpCertificatePinning.pins === 'object' && !Array.isArray(mcpCertificatePinning.pins),
      '`runtime.mcp_certificate_pinning.pins` must be object',
      details
    );
    if (mcpCertificatePinning.pins && typeof mcpCertificatePinning.pins === 'object' && !Array.isArray(mcpCertificatePinning.pins)) {
      for (const [serverId, pins] of Object.entries(mcpCertificatePinning.pins)) {
        assertType(
          typeof serverId === 'string' && serverId.length > 0,
          '`runtime.mcp_certificate_pinning.pins` keys must be non-empty server ids',
          details
        );
        const values = Array.isArray(pins) ? pins : [pins];
        values.forEach((pin, idx) => {
          const normalized = String(pin || '').trim();
          assertType(
            normalized.length > 0,
            `runtime.mcp_certificate_pinning.pins.${serverId}[${idx}] must be non-empty`,
            details
          );
        });
      }
    }
    assertType(
      typeof mcpCertificatePinning.allow_unpinned_servers === 'boolean',
      '`runtime.mcp_certificate_pinning.allow_unpinned_servers` must be boolean',
      details
    );
    assertType(
      typeof mcpCertificatePinning.require_fingerprint_for_pinned_servers === 'boolean',
      '`runtime.mcp_certificate_pinning.require_fingerprint_for_pinned_servers` must be boolean',
      details
    );
    assertType(
      typeof mcpCertificatePinning.detect_rotation === 'boolean',
      '`runtime.mcp_certificate_pinning.detect_rotation` must be boolean',
      details
    );
    assertType(
      typeof mcpCertificatePinning.block_on_mismatch === 'boolean',
      '`runtime.mcp_certificate_pinning.block_on_mismatch` must be boolean',
      details
    );
    assertType(
      typeof mcpCertificatePinning.block_on_rotation === 'boolean',
      '`runtime.mcp_certificate_pinning.block_on_rotation` must be boolean',
      details
    );
    assertType(
      Number.isInteger(mcpCertificatePinning.max_servers) && mcpCertificatePinning.max_servers > 0,
      '`runtime.mcp_certificate_pinning.max_servers` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(mcpCertificatePinning.ttl_ms) && mcpCertificatePinning.ttl_ms > 0,
      '`runtime.mcp_certificate_pinning.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      typeof mcpCertificatePinning.observability === 'boolean',
      '`runtime.mcp_certificate_pinning.observability` must be boolean',
      details
    );
  }

  const memoryPoisoning = runtime.memory_poisoning || {};
  if (runtime.memory_poisoning !== undefined) {
    assertNoUnknownKeys(memoryPoisoning, MEMORY_POISONING_KEYS, 'runtime.memory_poisoning', details);
    assertType(
      typeof memoryPoisoning.enabled === 'boolean',
      '`runtime.memory_poisoning.enabled` must be boolean',
      details
    );
    assertType(
      MEMORY_POISONING_MODES.has(String(memoryPoisoning.mode)),
      '`runtime.memory_poisoning.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(memoryPoisoning.max_content_chars) && memoryPoisoning.max_content_chars > 0,
      '`runtime.memory_poisoning.max_content_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(memoryPoisoning.ttl_ms) && memoryPoisoning.ttl_ms > 0,
      '`runtime.memory_poisoning.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(memoryPoisoning.max_sessions) && memoryPoisoning.max_sessions > 0,
      '`runtime.memory_poisoning.max_sessions` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(memoryPoisoning.max_writes_per_session) && memoryPoisoning.max_writes_per_session > 0,
      '`runtime.memory_poisoning.max_writes_per_session` must be integer > 0',
      details
    );
    assertType(
      typeof memoryPoisoning.detect_contradictions === 'boolean',
      '`runtime.memory_poisoning.detect_contradictions` must be boolean',
      details
    );
    assertType(
      typeof memoryPoisoning.block_on_poisoning === 'boolean',
      '`runtime.memory_poisoning.block_on_poisoning` must be boolean',
      details
    );
    assertType(
      typeof memoryPoisoning.block_on_contradiction === 'boolean',
      '`runtime.memory_poisoning.block_on_contradiction` must be boolean',
      details
    );
    assertType(
      typeof memoryPoisoning.quarantine_on_detect === 'boolean',
      '`runtime.memory_poisoning.quarantine_on_detect` must be boolean',
      details
    );
    assertType(
      Array.isArray(memoryPoisoning.policy_anchors),
      '`runtime.memory_poisoning.policy_anchors` must be array',
      details
    );
    if (Array.isArray(memoryPoisoning.policy_anchors)) {
      memoryPoisoning.policy_anchors.forEach((anchor, idx) => {
        assertType(
          typeof anchor === 'string' && anchor.length > 0,
          `runtime.memory_poisoning.policy_anchors[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      typeof memoryPoisoning.observability === 'boolean',
      '`runtime.memory_poisoning.observability` must be boolean',
      details
    );
  }

  const cascadeIsolator = runtime.cascade_isolator || {};
  if (runtime.cascade_isolator !== undefined) {
    assertNoUnknownKeys(cascadeIsolator, CASCADE_ISOLATOR_KEYS, 'runtime.cascade_isolator', details);
    assertType(
      typeof cascadeIsolator.enabled === 'boolean',
      '`runtime.cascade_isolator.enabled` must be boolean',
      details
    );
    assertType(
      CASCADE_ISOLATOR_MODES.has(String(cascadeIsolator.mode)),
      '`runtime.cascade_isolator.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(cascadeIsolator.ttl_ms) && cascadeIsolator.ttl_ms > 0,
      '`runtime.cascade_isolator.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(cascadeIsolator.max_sessions) && cascadeIsolator.max_sessions > 0,
      '`runtime.cascade_isolator.max_sessions` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(cascadeIsolator.max_nodes) && cascadeIsolator.max_nodes > 0,
      '`runtime.cascade_isolator.max_nodes` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(cascadeIsolator.max_edges) && cascadeIsolator.max_edges > 0,
      '`runtime.cascade_isolator.max_edges` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(cascadeIsolator.max_downstream_agents) && cascadeIsolator.max_downstream_agents > 0,
      '`runtime.cascade_isolator.max_downstream_agents` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(cascadeIsolator.max_influence_ratio)) &&
        Number(cascadeIsolator.max_influence_ratio) >= 0 &&
        Number(cascadeIsolator.max_influence_ratio) <= 1,
      '`runtime.cascade_isolator.max_influence_ratio` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(cascadeIsolator.anomaly_threshold)) &&
        Number(cascadeIsolator.anomaly_threshold) >= 0 &&
        Number(cascadeIsolator.anomaly_threshold) <= 1,
      '`runtime.cascade_isolator.anomaly_threshold` must be number between 0 and 1',
      details
    );
    assertType(
      typeof cascadeIsolator.block_on_threshold === 'boolean',
      '`runtime.cascade_isolator.block_on_threshold` must be boolean',
      details
    );
    assertType(
      typeof cascadeIsolator.observability === 'boolean',
      '`runtime.cascade_isolator.observability` must be boolean',
      details
    );
  }

  const agentIdentityFederation = runtime.agent_identity_federation || {};
  if (runtime.agent_identity_federation !== undefined) {
    assertNoUnknownKeys(
      agentIdentityFederation,
      AGENT_IDENTITY_FEDERATION_KEYS,
      'runtime.agent_identity_federation',
      details
    );
    assertType(
      typeof agentIdentityFederation.enabled === 'boolean',
      '`runtime.agent_identity_federation.enabled` must be boolean',
      details
    );
    assertType(
      AGENT_IDENTITY_FEDERATION_MODES.has(String(agentIdentityFederation.mode)),
      '`runtime.agent_identity_federation.mode` must be monitor|block',
      details
    );
    assertType(
      typeof agentIdentityFederation.token_header === 'string' && agentIdentityFederation.token_header.length > 0,
      '`runtime.agent_identity_federation.token_header` must be non-empty string',
      details
    );
    assertType(
      typeof agentIdentityFederation.agent_id_header === 'string' && agentIdentityFederation.agent_id_header.length > 0,
      '`runtime.agent_identity_federation.agent_id_header` must be non-empty string',
      details
    );
    assertType(
      typeof agentIdentityFederation.correlation_header === 'string' && agentIdentityFederation.correlation_header.length > 0,
      '`runtime.agent_identity_federation.correlation_header` must be non-empty string',
      details
    );
    assertType(
      typeof agentIdentityFederation.hmac_secret === 'string',
      '`runtime.agent_identity_federation.hmac_secret` must be string',
      details
    );
    assertType(
      Number.isInteger(agentIdentityFederation.ttl_ms) && agentIdentityFederation.ttl_ms > 0,
      '`runtime.agent_identity_federation.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(agentIdentityFederation.max_chain_depth) && agentIdentityFederation.max_chain_depth > 0,
      '`runtime.agent_identity_federation.max_chain_depth` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(agentIdentityFederation.max_replay_entries) && agentIdentityFederation.max_replay_entries > 0,
      '`runtime.agent_identity_federation.max_replay_entries` must be integer > 0',
      details
    );
    assertType(
      typeof agentIdentityFederation.block_on_invalid_token === 'boolean',
      '`runtime.agent_identity_federation.block_on_invalid_token` must be boolean',
      details
    );
    assertType(
      typeof agentIdentityFederation.block_on_capability_widen === 'boolean',
      '`runtime.agent_identity_federation.block_on_capability_widen` must be boolean',
      details
    );
    assertType(
      typeof agentIdentityFederation.block_on_replay === 'boolean',
      '`runtime.agent_identity_federation.block_on_replay` must be boolean',
      details
    );
    assertType(
      typeof agentIdentityFederation.observability === 'boolean',
      '`runtime.agent_identity_federation.observability` must be boolean',
      details
    );
  }

  const toolUseAnomaly = runtime.tool_use_anomaly || {};
  if (runtime.tool_use_anomaly !== undefined) {
    assertNoUnknownKeys(toolUseAnomaly, TOOL_USE_ANOMALY_KEYS, 'runtime.tool_use_anomaly', details);
    assertType(
      typeof toolUseAnomaly.enabled === 'boolean',
      '`runtime.tool_use_anomaly.enabled` must be boolean',
      details
    );
    assertType(
      TOOL_USE_ANOMALY_MODES.has(String(toolUseAnomaly.mode)),
      '`runtime.tool_use_anomaly.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(toolUseAnomaly.ttl_ms) && toolUseAnomaly.ttl_ms > 0,
      '`runtime.tool_use_anomaly.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(toolUseAnomaly.max_agents) && toolUseAnomaly.max_agents > 0,
      '`runtime.tool_use_anomaly.max_agents` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(toolUseAnomaly.max_tools_per_agent) && toolUseAnomaly.max_tools_per_agent > 0,
      '`runtime.tool_use_anomaly.max_tools_per_agent` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(toolUseAnomaly.warmup_events) && toolUseAnomaly.warmup_events > 0,
      '`runtime.tool_use_anomaly.warmup_events` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(toolUseAnomaly.z_score_threshold)) && Number(toolUseAnomaly.z_score_threshold) >= 0,
      '`runtime.tool_use_anomaly.z_score_threshold` must be number >= 0',
      details
    );
    assertType(
      Number.isInteger(toolUseAnomaly.sequence_threshold) && toolUseAnomaly.sequence_threshold > 0,
      '`runtime.tool_use_anomaly.sequence_threshold` must be integer > 0',
      details
    );
    assertType(
      typeof toolUseAnomaly.block_on_anomaly === 'boolean',
      '`runtime.tool_use_anomaly.block_on_anomaly` must be boolean',
      details
    );
    assertType(
      typeof toolUseAnomaly.observability === 'boolean',
      '`runtime.tool_use_anomaly.observability` must be boolean',
      details
    );
  }

  const behavioralFingerprint = runtime.behavioral_fingerprint || {};
  if (runtime.behavioral_fingerprint !== undefined) {
    assertNoUnknownKeys(behavioralFingerprint, BEHAVIORAL_FINGERPRINT_KEYS, 'runtime.behavioral_fingerprint', details);
    assertType(
      typeof behavioralFingerprint.enabled === 'boolean',
      '`runtime.behavioral_fingerprint.enabled` must be boolean',
      details
    );
    assertType(
      BEHAVIORAL_FINGERPRINT_MODES.has(String(behavioralFingerprint.mode)),
      '`runtime.behavioral_fingerprint.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(behavioralFingerprint.ttl_ms) && behavioralFingerprint.ttl_ms > 0,
      '`runtime.behavioral_fingerprint.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(behavioralFingerprint.max_agents) && behavioralFingerprint.max_agents > 0,
      '`runtime.behavioral_fingerprint.max_agents` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(behavioralFingerprint.max_styles_per_agent) && behavioralFingerprint.max_styles_per_agent > 0,
      '`runtime.behavioral_fingerprint.max_styles_per_agent` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(behavioralFingerprint.max_text_chars) && behavioralFingerprint.max_text_chars > 0,
      '`runtime.behavioral_fingerprint.max_text_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(behavioralFingerprint.max_impersonation_agents) && behavioralFingerprint.max_impersonation_agents > 0,
      '`runtime.behavioral_fingerprint.max_impersonation_agents` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(behavioralFingerprint.warmup_events) && behavioralFingerprint.warmup_events > 0,
      '`runtime.behavioral_fingerprint.warmup_events` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(behavioralFingerprint.z_score_threshold)) && Number(behavioralFingerprint.z_score_threshold) > 0,
      '`runtime.behavioral_fingerprint.z_score_threshold` must be number > 0',
      details
    );
    assertType(
      Number.isInteger(behavioralFingerprint.impersonation_min_hits) && behavioralFingerprint.impersonation_min_hits > 0,
      '`runtime.behavioral_fingerprint.impersonation_min_hits` must be integer > 0',
      details
    );
    assertType(
      typeof behavioralFingerprint.block_on_anomaly === 'boolean',
      '`runtime.behavioral_fingerprint.block_on_anomaly` must be boolean',
      details
    );
    assertType(
      typeof behavioralFingerprint.block_on_impersonation === 'boolean',
      '`runtime.behavioral_fingerprint.block_on_impersonation` must be boolean',
      details
    );
    assertType(
      typeof behavioralFingerprint.observability === 'boolean',
      '`runtime.behavioral_fingerprint.observability` must be boolean',
      details
    );
  }

  const threatIntelMesh = runtime.threat_intel_mesh || {};
  if (runtime.threat_intel_mesh !== undefined) {
    assertNoUnknownKeys(threatIntelMesh, THREAT_INTEL_MESH_KEYS, 'runtime.threat_intel_mesh', details);
    assertType(
      typeof threatIntelMesh.enabled === 'boolean',
      '`runtime.threat_intel_mesh.enabled` must be boolean',
      details
    );
    assertType(
      THREAT_INTEL_MESH_MODES.has(String(threatIntelMesh.mode)),
      '`runtime.threat_intel_mesh.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(threatIntelMesh.ttl_ms) && threatIntelMesh.ttl_ms > 0,
      '`runtime.threat_intel_mesh.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(threatIntelMesh.max_signatures) && threatIntelMesh.max_signatures > 0,
      '`runtime.threat_intel_mesh.max_signatures` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(threatIntelMesh.max_text_chars) && threatIntelMesh.max_text_chars > 0,
      '`runtime.threat_intel_mesh.max_text_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(threatIntelMesh.min_hits_to_block) && threatIntelMesh.min_hits_to_block > 0,
      '`runtime.threat_intel_mesh.min_hits_to_block` must be integer > 0',
      details
    );
    assertType(
      typeof threatIntelMesh.block_on_match === 'boolean',
      '`runtime.threat_intel_mesh.block_on_match` must be boolean',
      details
    );
    assertType(
      typeof threatIntelMesh.allow_anonymous_share === 'boolean',
      '`runtime.threat_intel_mesh.allow_anonymous_share` must be boolean',
      details
    );
    assertType(
      typeof threatIntelMesh.allow_unsigned_import === 'boolean',
      '`runtime.threat_intel_mesh.allow_unsigned_import` must be boolean',
      details
    );
    assertType(
      typeof threatIntelMesh.node_id === 'string' && threatIntelMesh.node_id.length > 0,
      '`runtime.threat_intel_mesh.node_id` must be non-empty string',
      details
    );
    assertType(
      typeof threatIntelMesh.shared_secret === 'string',
      '`runtime.threat_intel_mesh.shared_secret` must be string',
      details
    );
    assertType(
      Array.isArray(threatIntelMesh.peers),
      '`runtime.threat_intel_mesh.peers` must be array',
      details
    );
    if (Array.isArray(threatIntelMesh.peers)) {
      threatIntelMesh.peers.forEach((peer, idx) => {
        assertType(
          typeof peer === 'string' && peer.length > 0,
          `runtime.threat_intel_mesh.peers[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      typeof threatIntelMesh.sync_enabled === 'boolean',
      '`runtime.threat_intel_mesh.sync_enabled` must be boolean',
      details
    );
    assertType(
      Number.isInteger(threatIntelMesh.sync_interval_ms) && threatIntelMesh.sync_interval_ms > 0,
      '`runtime.threat_intel_mesh.sync_interval_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(threatIntelMesh.sync_timeout_ms) && threatIntelMesh.sync_timeout_ms > 0,
      '`runtime.threat_intel_mesh.sync_timeout_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(threatIntelMesh.max_peer_signatures) && threatIntelMesh.max_peer_signatures > 0,
      '`runtime.threat_intel_mesh.max_peer_signatures` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(threatIntelMesh.max_peers) && threatIntelMesh.max_peers > 0,
      '`runtime.threat_intel_mesh.max_peers` must be integer > 0',
      details
    );
    assertType(
      Array.isArray(threatIntelMesh.bootstrap_signatures),
      '`runtime.threat_intel_mesh.bootstrap_signatures` must be array',
      details
    );
    assertType(
      typeof threatIntelMesh.observability === 'boolean',
      '`runtime.threat_intel_mesh.observability` must be boolean',
      details
    );
  }

  const lfrl = runtime.lfrl || {};
  if (runtime.lfrl !== undefined) {
    assertNoUnknownKeys(lfrl, LFRL_KEYS, 'runtime.lfrl', details);
    assertType(
      typeof lfrl.enabled === 'boolean',
      '`runtime.lfrl.enabled` must be boolean',
      details
    );
    assertType(
      LFRL_MODES.has(String(lfrl.mode)),
      '`runtime.lfrl.mode` must be monitor|block',
      details
    );
    assertType(
      Array.isArray(lfrl.rules),
      '`runtime.lfrl.rules` must be array',
      details
    );
    if (Array.isArray(lfrl.rules)) {
      lfrl.rules.forEach((rule, idx) => {
        assertType(
          typeof rule === 'string' && rule.length > 0,
          `runtime.lfrl.rules[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      Number.isInteger(lfrl.max_rules) && lfrl.max_rules > 0,
      '`runtime.lfrl.max_rules` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(lfrl.max_events) && lfrl.max_events > 0,
      '`runtime.lfrl.max_events` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(lfrl.max_matches) && lfrl.max_matches > 0,
      '`runtime.lfrl.max_matches` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(lfrl.default_within_ms) && lfrl.default_within_ms > 0,
      '`runtime.lfrl.default_within_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(lfrl.ttl_ms) && lfrl.ttl_ms > 0,
      '`runtime.lfrl.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      typeof lfrl.block_on_rule_action === 'boolean',
      '`runtime.lfrl.block_on_rule_action` must be boolean',
      details
    );
    assertType(
      typeof lfrl.observability === 'boolean',
      '`runtime.lfrl.observability` must be boolean',
      details
    );
  }

  const selfHealingImmune = runtime.self_healing_immune || {};
  if (runtime.self_healing_immune !== undefined) {
    assertNoUnknownKeys(selfHealingImmune, SELF_HEALING_IMMUNE_KEYS, 'runtime.self_healing_immune', details);
    assertType(
      typeof selfHealingImmune.enabled === 'boolean',
      '`runtime.self_healing_immune.enabled` must be boolean',
      details
    );
    assertType(
      SELF_HEALING_IMMUNE_MODES.has(String(selfHealingImmune.mode)),
      '`runtime.self_healing_immune.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(selfHealingImmune.ttl_ms) && selfHealingImmune.ttl_ms > 0,
      '`runtime.self_healing_immune.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(selfHealingImmune.max_signatures) && selfHealingImmune.max_signatures > 0,
      '`runtime.self_healing_immune.max_signatures` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(selfHealingImmune.max_text_chars) && selfHealingImmune.max_text_chars > 0,
      '`runtime.self_healing_immune.max_text_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(selfHealingImmune.min_learn_hits) && selfHealingImmune.min_learn_hits > 0,
      '`runtime.self_healing_immune.min_learn_hits` must be integer > 0',
      details
    );
    assertType(
      typeof selfHealingImmune.block_on_learned_signature === 'boolean',
      '`runtime.self_healing_immune.block_on_learned_signature` must be boolean',
      details
    );
    assertType(
      typeof selfHealingImmune.auto_tune_enabled === 'boolean',
      '`runtime.self_healing_immune.auto_tune_enabled` must be boolean',
      details
    );
    assertType(
      Number.isInteger(selfHealingImmune.max_recommendations) && selfHealingImmune.max_recommendations > 0,
      '`runtime.self_healing_immune.max_recommendations` must be integer > 0',
      details
    );
    assertType(
      typeof selfHealingImmune.observability === 'boolean',
      '`runtime.self_healing_immune.observability` must be boolean',
      details
    );
  }

  const semanticFirewallDsl = runtime.semantic_firewall_dsl || {};
  if (runtime.semantic_firewall_dsl !== undefined) {
    assertNoUnknownKeys(semanticFirewallDsl, SEMANTIC_FIREWALL_DSL_KEYS, 'runtime.semantic_firewall_dsl', details);
    assertType(
      typeof semanticFirewallDsl.enabled === 'boolean',
      '`runtime.semantic_firewall_dsl.enabled` must be boolean',
      details
    );
    assertType(
      Array.isArray(semanticFirewallDsl.rules),
      '`runtime.semantic_firewall_dsl.rules` must be array',
      details
    );
    if (Array.isArray(semanticFirewallDsl.rules)) {
      semanticFirewallDsl.rules.forEach((rule, idx) => {
        assertType(
          typeof rule === 'string' && rule.length > 0,
          `runtime.semantic_firewall_dsl.rules[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      Number.isInteger(semanticFirewallDsl.max_rules) && semanticFirewallDsl.max_rules > 0,
      '`runtime.semantic_firewall_dsl.max_rules` must be integer > 0',
      details
    );
    assertType(
      typeof semanticFirewallDsl.observability === 'boolean',
      '`runtime.semantic_firewall_dsl.observability` must be boolean',
      details
    );
    if (semanticFirewallDsl.enabled === true && Array.isArray(semanticFirewallDsl.rules)) {
      try {
        compileRules(semanticFirewallDsl.rules, {
          maxRules: semanticFirewallDsl.max_rules,
        });
      } catch (error) {
        details.push(`runtime.semantic_firewall_dsl.rules invalid: ${error.message}`);
      }
    }
  }

  const stegoExfilDetector = runtime.stego_exfil_detector || {};
  if (runtime.stego_exfil_detector !== undefined) {
    assertNoUnknownKeys(stegoExfilDetector, STEGO_EXFIL_DETECTOR_KEYS, 'runtime.stego_exfil_detector', details);
    assertType(
      typeof stegoExfilDetector.enabled === 'boolean',
      '`runtime.stego_exfil_detector.enabled` must be boolean',
      details
    );
    assertType(
      STEGO_EXFIL_DETECTOR_MODES.has(String(stegoExfilDetector.mode)),
      '`runtime.stego_exfil_detector.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(stegoExfilDetector.max_scan_chars) && stegoExfilDetector.max_scan_chars > 0,
      '`runtime.stego_exfil_detector.max_scan_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(stegoExfilDetector.max_findings) && stegoExfilDetector.max_findings > 0,
      '`runtime.stego_exfil_detector.max_findings` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(stegoExfilDetector.zero_width_density_threshold))
        && Number(stegoExfilDetector.zero_width_density_threshold) >= 0
        && Number(stegoExfilDetector.zero_width_density_threshold) <= 1,
      '`runtime.stego_exfil_detector.zero_width_density_threshold` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(stegoExfilDetector.invisible_density_threshold))
        && Number(stegoExfilDetector.invisible_density_threshold) >= 0
        && Number(stegoExfilDetector.invisible_density_threshold) <= 1,
      '`runtime.stego_exfil_detector.invisible_density_threshold` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(stegoExfilDetector.whitespace_bits_threshold) && stegoExfilDetector.whitespace_bits_threshold > 0,
      '`runtime.stego_exfil_detector.whitespace_bits_threshold` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(stegoExfilDetector.segment_entropy_threshold)) && Number(stegoExfilDetector.segment_entropy_threshold) > 0,
      '`runtime.stego_exfil_detector.segment_entropy_threshold` must be number > 0',
      details
    );
    assertType(
      Number.isInteger(stegoExfilDetector.emoji_compound_threshold) && stegoExfilDetector.emoji_compound_threshold > 0,
      '`runtime.stego_exfil_detector.emoji_compound_threshold` must be integer > 0',
      details
    );
    assertType(
      typeof stegoExfilDetector.block_on_detect === 'boolean',
      '`runtime.stego_exfil_detector.block_on_detect` must be boolean',
      details
    );
    assertType(
      typeof stegoExfilDetector.observability === 'boolean',
      '`runtime.stego_exfil_detector.observability` must be boolean',
      details
    );
  }

  const reasoningTraceMonitor = runtime.reasoning_trace_monitor || {};
  if (runtime.reasoning_trace_monitor !== undefined) {
    assertNoUnknownKeys(reasoningTraceMonitor, REASONING_TRACE_MONITOR_KEYS, 'runtime.reasoning_trace_monitor', details);
    assertType(
      typeof reasoningTraceMonitor.enabled === 'boolean',
      '`runtime.reasoning_trace_monitor.enabled` must be boolean',
      details
    );
    assertType(
      REASONING_TRACE_MONITOR_MODES.has(String(reasoningTraceMonitor.mode)),
      '`runtime.reasoning_trace_monitor.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(reasoningTraceMonitor.max_scan_chars) && reasoningTraceMonitor.max_scan_chars > 0,
      '`runtime.reasoning_trace_monitor.max_scan_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(reasoningTraceMonitor.max_steps) && reasoningTraceMonitor.max_steps > 1,
      '`runtime.reasoning_trace_monitor.max_steps` must be integer > 1',
      details
    );
    assertType(
      Number.isInteger(reasoningTraceMonitor.min_step_chars) && reasoningTraceMonitor.min_step_chars > 0,
      '`runtime.reasoning_trace_monitor.min_step_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(reasoningTraceMonitor.coherence_threshold))
        && Number(reasoningTraceMonitor.coherence_threshold) >= 0
        && Number(reasoningTraceMonitor.coherence_threshold) <= 1,
      '`runtime.reasoning_trace_monitor.coherence_threshold` must be number between 0 and 1',
      details
    );
    assertType(
      typeof reasoningTraceMonitor.block_on_injection === 'boolean',
      '`runtime.reasoning_trace_monitor.block_on_injection` must be boolean',
      details
    );
    assertType(
      typeof reasoningTraceMonitor.block_on_incoherence === 'boolean',
      '`runtime.reasoning_trace_monitor.block_on_incoherence` must be boolean',
      details
    );
    assertType(
      typeof reasoningTraceMonitor.block_on_conclusion_mismatch === 'boolean',
      '`runtime.reasoning_trace_monitor.block_on_conclusion_mismatch` must be boolean',
      details
    );
    assertType(
      typeof reasoningTraceMonitor.observability === 'boolean',
      '`runtime.reasoning_trace_monitor.observability` must be boolean',
      details
    );
  }

  const hallucinationTripwire = runtime.hallucination_tripwire || {};
  if (runtime.hallucination_tripwire !== undefined) {
    assertNoUnknownKeys(hallucinationTripwire, HALLUCINATION_TRIPWIRE_KEYS, 'runtime.hallucination_tripwire', details);
    assertType(
      typeof hallucinationTripwire.enabled === 'boolean',
      '`runtime.hallucination_tripwire.enabled` must be boolean',
      details
    );
    assertType(
      HALLUCINATION_TRIPWIRE_MODES.has(String(hallucinationTripwire.mode)),
      '`runtime.hallucination_tripwire.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(hallucinationTripwire.max_scan_chars) && hallucinationTripwire.max_scan_chars > 0,
      '`runtime.hallucination_tripwire.max_scan_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(hallucinationTripwire.max_findings) && hallucinationTripwire.max_findings > 0,
      '`runtime.hallucination_tripwire.max_findings` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(hallucinationTripwire.warn_threshold))
        && Number(hallucinationTripwire.warn_threshold) >= 0
        && Number(hallucinationTripwire.warn_threshold) <= 1,
      '`runtime.hallucination_tripwire.warn_threshold` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(hallucinationTripwire.block_threshold))
        && Number(hallucinationTripwire.block_threshold) >= 0
        && Number(hallucinationTripwire.block_threshold) <= 1,
      '`runtime.hallucination_tripwire.block_threshold` must be number between 0 and 1',
      details
    );
    if (
      Number.isFinite(Number(hallucinationTripwire.warn_threshold)) &&
      Number.isFinite(Number(hallucinationTripwire.block_threshold)) &&
      Number(hallucinationTripwire.block_threshold) < Number(hallucinationTripwire.warn_threshold)
    ) {
      details.push('`runtime.hallucination_tripwire.block_threshold` must be >= `runtime.hallucination_tripwire.warn_threshold`');
    }
    assertType(
      typeof hallucinationTripwire.block_on_detect === 'boolean',
      '`runtime.hallucination_tripwire.block_on_detect` must be boolean',
      details
    );
    assertType(
      typeof hallucinationTripwire.observability === 'boolean',
      '`runtime.hallucination_tripwire.observability` must be boolean',
      details
    );
  }

  const semanticDriftCanary = runtime.semantic_drift_canary || {};
  if (runtime.semantic_drift_canary !== undefined) {
    assertNoUnknownKeys(semanticDriftCanary, SEMANTIC_DRIFT_CANARY_KEYS, 'runtime.semantic_drift_canary', details);
    assertType(
      typeof semanticDriftCanary.enabled === 'boolean',
      '`runtime.semantic_drift_canary.enabled` must be boolean',
      details
    );
    assertType(
      SEMANTIC_DRIFT_CANARY_MODES.has(String(semanticDriftCanary.mode)),
      '`runtime.semantic_drift_canary.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(semanticDriftCanary.sample_every_requests) && semanticDriftCanary.sample_every_requests > 0,
      '`runtime.semantic_drift_canary.sample_every_requests` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(semanticDriftCanary.max_providers) && semanticDriftCanary.max_providers > 0,
      '`runtime.semantic_drift_canary.max_providers` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(semanticDriftCanary.max_samples_per_provider) && semanticDriftCanary.max_samples_per_provider > 0,
      '`runtime.semantic_drift_canary.max_samples_per_provider` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(semanticDriftCanary.max_text_chars) && semanticDriftCanary.max_text_chars > 0,
      '`runtime.semantic_drift_canary.max_text_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(semanticDriftCanary.warn_distance_threshold))
        && Number(semanticDriftCanary.warn_distance_threshold) >= 0
        && Number(semanticDriftCanary.warn_distance_threshold) <= 1,
      '`runtime.semantic_drift_canary.warn_distance_threshold` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(semanticDriftCanary.block_distance_threshold))
        && Number(semanticDriftCanary.block_distance_threshold) >= 0
        && Number(semanticDriftCanary.block_distance_threshold) <= 1,
      '`runtime.semantic_drift_canary.block_distance_threshold` must be number between 0 and 1',
      details
    );
    assertType(
      typeof semanticDriftCanary.observability === 'boolean',
      '`runtime.semantic_drift_canary.observability` must be boolean',
      details
    );
  }

  const outputProvenance = runtime.output_provenance || {};
  if (runtime.output_provenance !== undefined) {
    assertNoUnknownKeys(outputProvenance, OUTPUT_PROVENANCE_KEYS, 'runtime.output_provenance', details);
    assertType(
      typeof outputProvenance.enabled === 'boolean',
      '`runtime.output_provenance.enabled` must be boolean',
      details
    );
    assertType(
      typeof outputProvenance.key_id === 'string' && outputProvenance.key_id.length > 0,
      '`runtime.output_provenance.key_id` must be non-empty string',
      details
    );
    assertType(
      typeof outputProvenance.secret === 'string',
      '`runtime.output_provenance.secret` must be string',
      details
    );
    assertType(
      typeof outputProvenance.expose_verify_endpoint === 'boolean',
      '`runtime.output_provenance.expose_verify_endpoint` must be boolean',
      details
    );
    assertType(
      Number.isInteger(outputProvenance.max_envelope_bytes) && outputProvenance.max_envelope_bytes > 0,
      '`runtime.output_provenance.max_envelope_bytes` must be integer > 0',
      details
    );
  }

  const tokenWatermark = runtime.token_watermark || {};
  if (runtime.token_watermark !== undefined) {
    assertNoUnknownKeys(tokenWatermark, TOKEN_WATERMARK_KEYS, 'runtime.token_watermark', details);
    assertType(
      typeof tokenWatermark.enabled === 'boolean',
      '`runtime.token_watermark.enabled` must be boolean',
      details
    );
    assertType(
      typeof tokenWatermark.key_id === 'string' && tokenWatermark.key_id.length > 0,
      '`runtime.token_watermark.key_id` must be non-empty string',
      details
    );
    assertType(
      typeof tokenWatermark.secret === 'string',
      '`runtime.token_watermark.secret` must be string',
      details
    );
    assertType(
      typeof tokenWatermark.expose_verify_endpoint === 'boolean',
      '`runtime.token_watermark.expose_verify_endpoint` must be boolean',
      details
    );
    assertType(
      Number.isInteger(tokenWatermark.max_envelope_bytes) && tokenWatermark.max_envelope_bytes > 0,
      '`runtime.token_watermark.max_envelope_bytes` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(tokenWatermark.max_token_chars) && tokenWatermark.max_token_chars > 0,
      '`runtime.token_watermark.max_token_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(tokenWatermark.max_tokens) && tokenWatermark.max_tokens > 0,
      '`runtime.token_watermark.max_tokens` must be integer > 0',
      details
    );
  }

  const computeAttestation = runtime.compute_attestation || {};
  if (runtime.compute_attestation !== undefined) {
    assertNoUnknownKeys(computeAttestation, COMPUTE_ATTESTATION_KEYS, 'runtime.compute_attestation', details);
    assertType(
      typeof computeAttestation.enabled === 'boolean',
      '`runtime.compute_attestation.enabled` must be boolean',
      details
    );
    assertType(
      typeof computeAttestation.key_id === 'string' && computeAttestation.key_id.length > 0,
      '`runtime.compute_attestation.key_id` must be non-empty string',
      details
    );
    assertType(
      typeof computeAttestation.secret === 'string',
      '`runtime.compute_attestation.secret` must be string',
      details
    );
    assertType(
      typeof computeAttestation.expose_verify_endpoint === 'boolean',
      '`runtime.compute_attestation.expose_verify_endpoint` must be boolean',
      details
    );
    assertType(
      Number.isInteger(computeAttestation.max_config_chars) && computeAttestation.max_config_chars > 0,
      '`runtime.compute_attestation.max_config_chars` must be integer > 0',
      details
    );
    assertType(
      typeof computeAttestation.include_environment === 'boolean',
      '`runtime.compute_attestation.include_environment` must be boolean',
      details
    );
  }

  const capabilityIntrospection = runtime.capability_introspection || {};
  if (runtime.capability_introspection !== undefined) {
    assertNoUnknownKeys(capabilityIntrospection, CAPABILITY_INTROSPECTION_KEYS, 'runtime.capability_introspection', details);
    assertType(
      typeof capabilityIntrospection.enabled === 'boolean',
      '`runtime.capability_introspection.enabled` must be boolean',
      details
    );
    assertType(
      Number.isInteger(capabilityIntrospection.max_engines) && capabilityIntrospection.max_engines > 0,
      '`runtime.capability_introspection.max_engines` must be integer > 0',
      details
    );
    assertType(
      typeof capabilityIntrospection.observability === 'boolean',
      '`runtime.capability_introspection.observability` must be boolean',
      details
    );
  }

  const policyGradientAnalyzer = runtime.policy_gradient_analyzer || {};
  if (runtime.policy_gradient_analyzer !== undefined) {
    assertNoUnknownKeys(policyGradientAnalyzer, POLICY_GRADIENT_ANALYZER_KEYS, 'runtime.policy_gradient_analyzer', details);
    assertType(
      typeof policyGradientAnalyzer.enabled === 'boolean',
      '`runtime.policy_gradient_analyzer.enabled` must be boolean',
      details
    );
    assertType(
      Number.isInteger(policyGradientAnalyzer.max_events) && policyGradientAnalyzer.max_events > 0,
      '`runtime.policy_gradient_analyzer.max_events` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(policyGradientAnalyzer.current_injection_threshold))
        && Number(policyGradientAnalyzer.current_injection_threshold) >= 0
        && Number(policyGradientAnalyzer.current_injection_threshold) <= 1,
      '`runtime.policy_gradient_analyzer.current_injection_threshold` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(policyGradientAnalyzer.proposed_injection_threshold))
        && Number(policyGradientAnalyzer.proposed_injection_threshold) >= 0
        && Number(policyGradientAnalyzer.proposed_injection_threshold) <= 1,
      '`runtime.policy_gradient_analyzer.proposed_injection_threshold` must be number between 0 and 1',
      details
    );
  }

  const budgetAutopilot = runtime.budget_autopilot || {};
  if (runtime.budget_autopilot !== undefined) {
    assertNoUnknownKeys(budgetAutopilot, BUDGET_AUTOPILOT_KEYS, 'runtime.budget_autopilot', details);
    assertType(
      typeof budgetAutopilot.enabled === 'boolean',
      '`runtime.budget_autopilot.enabled` must be boolean',
      details
    );
    assertType(
      BUDGET_AUTOPILOT_MODES.has(String(budgetAutopilot.mode)),
      '`runtime.budget_autopilot.mode` must be monitor|active',
      details
    );
    assertType(
      Number.isInteger(budgetAutopilot.ttl_ms) && budgetAutopilot.ttl_ms > 0,
      '`runtime.budget_autopilot.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(budgetAutopilot.max_providers) && budgetAutopilot.max_providers > 0,
      '`runtime.budget_autopilot.max_providers` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(budgetAutopilot.min_samples) && budgetAutopilot.min_samples > 0,
      '`runtime.budget_autopilot.min_samples` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(budgetAutopilot.cost_weight)) &&
        Number(budgetAutopilot.cost_weight) >= 0 &&
        Number(budgetAutopilot.cost_weight) <= 1,
      '`runtime.budget_autopilot.cost_weight` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(budgetAutopilot.latency_weight)) &&
        Number(budgetAutopilot.latency_weight) >= 0 &&
        Number(budgetAutopilot.latency_weight) <= 1,
      '`runtime.budget_autopilot.latency_weight` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(budgetAutopilot.warn_budget_ratio)) &&
        Number(budgetAutopilot.warn_budget_ratio) >= 0 &&
        Number(budgetAutopilot.warn_budget_ratio) <= 1,
      '`runtime.budget_autopilot.warn_budget_ratio` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(budgetAutopilot.sla_p95_ms)) && Number(budgetAutopilot.sla_p95_ms) > 0,
      '`runtime.budget_autopilot.sla_p95_ms` must be number > 0',
      details
    );
    assertType(
      Number.isFinite(Number(budgetAutopilot.horizon_hours)) && Number(budgetAutopilot.horizon_hours) > 0,
      '`runtime.budget_autopilot.horizon_hours` must be number > 0',
      details
    );
    assertType(
      typeof budgetAutopilot.observability === 'boolean',
      '`runtime.budget_autopilot.observability` must be boolean',
      details
    );
  }

  const costEfficiencyOptimizer = runtime.cost_efficiency_optimizer || {};
  if (runtime.cost_efficiency_optimizer !== undefined) {
    assertNoUnknownKeys(
      costEfficiencyOptimizer,
      COST_EFFICIENCY_OPTIMIZER_KEYS,
      'runtime.cost_efficiency_optimizer',
      details
    );
    assertType(
      typeof costEfficiencyOptimizer.enabled === 'boolean',
      '`runtime.cost_efficiency_optimizer.enabled` must be boolean',
      details
    );
    assertType(
      COST_EFFICIENCY_OPTIMIZER_MODES.has(String(costEfficiencyOptimizer.mode)),
      '`runtime.cost_efficiency_optimizer.mode` must be monitor|active',
      details
    );
    assertType(
      Number.isInteger(costEfficiencyOptimizer.ttl_ms) && costEfficiencyOptimizer.ttl_ms > 0,
      '`runtime.cost_efficiency_optimizer.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(costEfficiencyOptimizer.max_providers) && costEfficiencyOptimizer.max_providers > 0,
      '`runtime.cost_efficiency_optimizer.max_providers` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(costEfficiencyOptimizer.max_samples_per_provider)
        && costEfficiencyOptimizer.max_samples_per_provider > 0,
      '`runtime.cost_efficiency_optimizer.max_samples_per_provider` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(costEfficiencyOptimizer.max_prompt_chars) && costEfficiencyOptimizer.max_prompt_chars > 0,
      '`runtime.cost_efficiency_optimizer.max_prompt_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(costEfficiencyOptimizer.chars_per_token) && costEfficiencyOptimizer.chars_per_token > 0,
      '`runtime.cost_efficiency_optimizer.chars_per_token` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(costEfficiencyOptimizer.prompt_bloat_chars) && costEfficiencyOptimizer.prompt_bloat_chars > 0,
      '`runtime.cost_efficiency_optimizer.prompt_bloat_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(costEfficiencyOptimizer.repetition_warn_ratio))
        && Number(costEfficiencyOptimizer.repetition_warn_ratio) >= 0
        && Number(costEfficiencyOptimizer.repetition_warn_ratio) <= 1,
      '`runtime.cost_efficiency_optimizer.repetition_warn_ratio` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(costEfficiencyOptimizer.low_budget_usd)) && Number(costEfficiencyOptimizer.low_budget_usd) >= 0,
      '`runtime.cost_efficiency_optimizer.low_budget_usd` must be number >= 0',
      details
    );
    assertType(
      Number.isInteger(costEfficiencyOptimizer.memory_warn_bytes) && costEfficiencyOptimizer.memory_warn_bytes > 0,
      '`runtime.cost_efficiency_optimizer.memory_warn_bytes` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(costEfficiencyOptimizer.memory_critical_bytes) && costEfficiencyOptimizer.memory_critical_bytes > 0,
      '`runtime.cost_efficiency_optimizer.memory_critical_bytes` must be integer > 0',
      details
    );
    assertType(
      costEfficiencyOptimizer.memory_critical_bytes >= costEfficiencyOptimizer.memory_warn_bytes,
      '`runtime.cost_efficiency_optimizer.memory_critical_bytes` must be >= memory_warn_bytes',
      details
    );
    assertType(
      Number.isInteger(costEfficiencyOptimizer.memory_hard_cap_bytes) && costEfficiencyOptimizer.memory_hard_cap_bytes >= 0,
      '`runtime.cost_efficiency_optimizer.memory_hard_cap_bytes` must be integer >= 0',
      details
    );
    assertType(
      costEfficiencyOptimizer.memory_hard_cap_bytes === 0
        || costEfficiencyOptimizer.memory_hard_cap_bytes >= costEfficiencyOptimizer.memory_critical_bytes,
      '`runtime.cost_efficiency_optimizer.memory_hard_cap_bytes` must be 0 or >= memory_critical_bytes',
      details
    );
    assertType(
      typeof costEfficiencyOptimizer.shed_on_memory_pressure === 'boolean',
      '`runtime.cost_efficiency_optimizer.shed_on_memory_pressure` must be boolean',
      details
    );
    assertType(
      Number.isInteger(costEfficiencyOptimizer.max_shed_engines) && costEfficiencyOptimizer.max_shed_engines > 0,
      '`runtime.cost_efficiency_optimizer.max_shed_engines` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(costEfficiencyOptimizer.shed_cooldown_ms) && costEfficiencyOptimizer.shed_cooldown_ms > 0,
      '`runtime.cost_efficiency_optimizer.shed_cooldown_ms` must be integer > 0',
      details
    );
    assertType(
      Array.isArray(costEfficiencyOptimizer.shed_engine_order),
      '`runtime.cost_efficiency_optimizer.shed_engine_order` must be array',
      details
    );
    if (Array.isArray(costEfficiencyOptimizer.shed_engine_order)) {
      costEfficiencyOptimizer.shed_engine_order.forEach((value, idx) => {
        assertType(
          typeof value === 'string' && value.trim().length > 0,
          `runtime.cost_efficiency_optimizer.shed_engine_order[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      typeof costEfficiencyOptimizer.block_on_critical_memory === 'boolean',
      '`runtime.cost_efficiency_optimizer.block_on_critical_memory` must be boolean',
      details
    );
    assertType(
      typeof costEfficiencyOptimizer.block_on_budget_exhausted === 'boolean',
      '`runtime.cost_efficiency_optimizer.block_on_budget_exhausted` must be boolean',
      details
    );
    assertType(
      typeof costEfficiencyOptimizer.observability === 'boolean',
      '`runtime.cost_efficiency_optimizer.observability` must be boolean',
      details
    );
  }

  const zkConfigValidator = runtime.zk_config_validator || {};
  if (runtime.zk_config_validator !== undefined) {
    assertNoUnknownKeys(zkConfigValidator, ZK_CONFIG_VALIDATOR_KEYS, 'runtime.zk_config_validator', details);
    assertType(
      typeof zkConfigValidator.enabled === 'boolean',
      '`runtime.zk_config_validator.enabled` must be boolean',
      details
    );
    assertType(
      typeof zkConfigValidator.hmac_key === 'string',
      '`runtime.zk_config_validator.hmac_key` must be string',
      details
    );
    assertType(
      Number.isInteger(zkConfigValidator.max_findings) && zkConfigValidator.max_findings > 0,
      '`runtime.zk_config_validator.max_findings` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(zkConfigValidator.max_nodes) && zkConfigValidator.max_nodes > 0,
      '`runtime.zk_config_validator.max_nodes` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(zkConfigValidator.max_depth) && zkConfigValidator.max_depth > 0,
      '`runtime.zk_config_validator.max_depth` must be integer > 0',
      details
    );
    assertType(
      typeof zkConfigValidator.redaction_text === 'string',
      '`runtime.zk_config_validator.redaction_text` must be string',
      details
    );
    assertType(
      Number.isInteger(zkConfigValidator.score_penalty_secret) && zkConfigValidator.score_penalty_secret >= 0,
      '`runtime.zk_config_validator.score_penalty_secret` must be integer >= 0',
      details
    );
    assertType(
      Number.isInteger(zkConfigValidator.score_penalty_dead_key) && zkConfigValidator.score_penalty_dead_key >= 0,
      '`runtime.zk_config_validator.score_penalty_dead_key` must be integer >= 0',
      details
    );
    assertType(
      Number.isInteger(zkConfigValidator.score_penalty_over_config) && zkConfigValidator.score_penalty_over_config >= 0,
      '`runtime.zk_config_validator.score_penalty_over_config` must be integer >= 0',
      details
    );
    assertType(
      typeof zkConfigValidator.observability === 'boolean',
      '`runtime.zk_config_validator.observability` must be boolean',
      details
    );
  }

  const adversarialEvalHarness = runtime.adversarial_eval_harness || {};
  if (runtime.adversarial_eval_harness !== undefined) {
    assertNoUnknownKeys(
      adversarialEvalHarness,
      ADVERSARIAL_EVAL_HARNESS_KEYS,
      'runtime.adversarial_eval_harness',
      details
    );
    assertType(
      typeof adversarialEvalHarness.enabled === 'boolean',
      '`runtime.adversarial_eval_harness.enabled` must be boolean',
      details
    );
    assertType(
      Number.isInteger(adversarialEvalHarness.max_cases) && adversarialEvalHarness.max_cases > 0,
      '`runtime.adversarial_eval_harness.max_cases` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(adversarialEvalHarness.max_prompt_chars) && adversarialEvalHarness.max_prompt_chars > 0,
      '`runtime.adversarial_eval_harness.max_prompt_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(adversarialEvalHarness.max_runs) && adversarialEvalHarness.max_runs > 0,
      '`runtime.adversarial_eval_harness.max_runs` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(adversarialEvalHarness.schedule_every_requests) && adversarialEvalHarness.schedule_every_requests >= 0,
      '`runtime.adversarial_eval_harness.schedule_every_requests` must be integer >= 0',
      details
    );
    assertType(
      typeof adversarialEvalHarness.fail_open === 'boolean',
      '`runtime.adversarial_eval_harness.fail_open` must be boolean',
      details
    );
    assertType(
      Number.isFinite(Number(adversarialEvalHarness.regression_drop_threshold))
        && Number(adversarialEvalHarness.regression_drop_threshold) >= 0
        && Number(adversarialEvalHarness.regression_drop_threshold) <= 1,
      '`runtime.adversarial_eval_harness.regression_drop_threshold` must be number between 0 and 1',
      details
    );
    assertType(
      typeof adversarialEvalHarness.observability === 'boolean',
      '`runtime.adversarial_eval_harness.observability` must be boolean',
      details
    );
  }

  const anomalyTelemetry = runtime.anomaly_telemetry || {};
  if (runtime.anomaly_telemetry !== undefined) {
    assertNoUnknownKeys(anomalyTelemetry, ANOMALY_TELEMETRY_KEYS, 'runtime.anomaly_telemetry', details);
    assertType(
      typeof anomalyTelemetry.enabled === 'boolean',
      '`runtime.anomaly_telemetry.enabled` must be boolean',
      details
    );
    assertType(
      Number.isInteger(anomalyTelemetry.max_events) && anomalyTelemetry.max_events > 0,
      '`runtime.anomaly_telemetry.max_events` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(anomalyTelemetry.window_ms) && anomalyTelemetry.window_ms > 0,
      '`runtime.anomaly_telemetry.window_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(anomalyTelemetry.max_engine_buckets) && anomalyTelemetry.max_engine_buckets > 0,
      '`runtime.anomaly_telemetry.max_engine_buckets` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(anomalyTelemetry.max_timeline_events) && anomalyTelemetry.max_timeline_events > 0,
      '`runtime.anomaly_telemetry.max_timeline_events` must be integer > 0',
      details
    );
    assertType(
      typeof anomalyTelemetry.observability === 'boolean',
      '`runtime.anomaly_telemetry.observability` must be boolean',
      details
    );
  }

  const evidenceVault = runtime.evidence_vault || {};
  if (runtime.evidence_vault !== undefined) {
    assertNoUnknownKeys(evidenceVault, EVIDENCE_VAULT_KEYS, 'runtime.evidence_vault', details);
    assertType(
      typeof evidenceVault.enabled === 'boolean',
      '`runtime.evidence_vault.enabled` must be boolean',
      details
    );
    assertType(
      EVIDENCE_VAULT_MODES.has(String(evidenceVault.mode)),
      '`runtime.evidence_vault.mode` must be monitor|active',
      details
    );
    assertType(
      Number.isInteger(evidenceVault.max_entries) && evidenceVault.max_entries > 0,
      '`runtime.evidence_vault.max_entries` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(evidenceVault.retention_days) && evidenceVault.retention_days > 0,
      '`runtime.evidence_vault.retention_days` must be integer > 0',
      details
    );
    assertType(
      typeof evidenceVault.file_path === 'string',
      '`runtime.evidence_vault.file_path` must be string',
      details
    );
    assertType(
      typeof evidenceVault.observability === 'boolean',
      '`runtime.evidence_vault.observability` must be boolean',
      details
    );
  }

  const threatGraph = runtime.threat_graph || {};
  if (runtime.threat_graph !== undefined) {
    assertNoUnknownKeys(threatGraph, THREAT_GRAPH_KEYS, 'runtime.threat_graph', details);
    assertType(
      typeof threatGraph.enabled === 'boolean',
      '`runtime.threat_graph.enabled` must be boolean',
      details
    );
    assertType(
      Number.isInteger(threatGraph.max_events) && threatGraph.max_events > 0,
      '`runtime.threat_graph.max_events` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(threatGraph.window_ms) && threatGraph.window_ms > 0,
      '`runtime.threat_graph.window_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(threatGraph.risk_decay)) &&
        Number(threatGraph.risk_decay) >= 0 &&
        Number(threatGraph.risk_decay) <= 1,
      '`runtime.threat_graph.risk_decay` must be number between 0 and 1',
      details
    );
    assertType(
      typeof threatGraph.observability === 'boolean',
      '`runtime.threat_graph.observability` must be boolean',
      details
    );
  }

  const attackCorpusEvolver = runtime.attack_corpus_evolver || {};
  if (runtime.attack_corpus_evolver !== undefined) {
    assertNoUnknownKeys(
      attackCorpusEvolver,
      ATTACK_CORPUS_EVOLVER_KEYS,
      'runtime.attack_corpus_evolver',
      details
    );
    assertType(
      typeof attackCorpusEvolver.enabled === 'boolean',
      '`runtime.attack_corpus_evolver.enabled` must be boolean',
      details
    );
    assertType(
      Number.isInteger(attackCorpusEvolver.max_candidates) && attackCorpusEvolver.max_candidates > 0,
      '`runtime.attack_corpus_evolver.max_candidates` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(attackCorpusEvolver.max_prompt_chars) && attackCorpusEvolver.max_prompt_chars > 0,
      '`runtime.attack_corpus_evolver.max_prompt_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(attackCorpusEvolver.max_families) && attackCorpusEvolver.max_families > 0,
      '`runtime.attack_corpus_evolver.max_families` must be integer > 0',
      details
    );
    assertType(
      typeof attackCorpusEvolver.include_monitor_decisions === 'boolean',
      '`runtime.attack_corpus_evolver.include_monitor_decisions` must be boolean',
      details
    );
    assertType(
      typeof attackCorpusEvolver.observability === 'boolean',
      '`runtime.attack_corpus_evolver.observability` must be boolean',
      details
    );
  }

  const forensicDebugger = runtime.forensic_debugger || {};
  if (runtime.forensic_debugger !== undefined) {
    assertNoUnknownKeys(forensicDebugger, FORENSIC_DEBUGGER_KEYS, 'runtime.forensic_debugger', details);
    assertType(
      typeof forensicDebugger.enabled === 'boolean',
      '`runtime.forensic_debugger.enabled` must be boolean',
      details
    );
    assertType(
      Number.isInteger(forensicDebugger.max_snapshots) && forensicDebugger.max_snapshots > 0,
      '`runtime.forensic_debugger.max_snapshots` must be integer > 0',
      details
    );
    assertType(
      Array.isArray(forensicDebugger.redact_fields),
      '`runtime.forensic_debugger.redact_fields` must be array',
      details
    );
    if (Array.isArray(forensicDebugger.redact_fields)) {
      forensicDebugger.redact_fields.forEach((field, idx) => {
        assertType(
          typeof field === 'string' && field.length > 0,
          `runtime.forensic_debugger.redact_fields[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      typeof forensicDebugger.default_summary_only === 'boolean',
      '`runtime.forensic_debugger.default_summary_only` must be boolean',
      details
    );
    assertType(
      typeof forensicDebugger.observability === 'boolean',
      '`runtime.forensic_debugger.observability` must be boolean',
      details
    );
  }

  const promptRebuff = runtime.prompt_rebuff || {};
  if (runtime.prompt_rebuff !== undefined) {
    assertNoUnknownKeys(promptRebuff, PROMPT_REBUFF_KEYS, 'runtime.prompt_rebuff', details);
    assertType(
      typeof promptRebuff.enabled === 'boolean',
      '`runtime.prompt_rebuff.enabled` must be boolean',
      details
    );
    assertType(
      PROMPT_REBUFF_MODES.has(String(promptRebuff.mode)),
      '`runtime.prompt_rebuff.mode` must be monitor|block',
      details
    );
    assertType(
      PROMPT_REBUFF_SENSITIVITIES.has(String(promptRebuff.sensitivity)),
      '`runtime.prompt_rebuff.sensitivity` must be permissive|balanced|paranoid',
      details
    );
    assertType(
      Number.isFinite(Number(promptRebuff.heuristic_weight))
        && Number(promptRebuff.heuristic_weight) >= 0
        && Number(promptRebuff.heuristic_weight) <= 1,
      '`runtime.prompt_rebuff.heuristic_weight` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(promptRebuff.neural_weight))
        && Number(promptRebuff.neural_weight) >= 0
        && Number(promptRebuff.neural_weight) <= 1,
      '`runtime.prompt_rebuff.neural_weight` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(promptRebuff.canary_weight))
        && Number(promptRebuff.canary_weight) >= 0
        && Number(promptRebuff.canary_weight) <= 1,
      '`runtime.prompt_rebuff.canary_weight` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(promptRebuff.warn_threshold))
        && Number(promptRebuff.warn_threshold) >= 0
        && Number(promptRebuff.warn_threshold) <= 1,
      '`runtime.prompt_rebuff.warn_threshold` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(promptRebuff.block_threshold))
        && Number(promptRebuff.block_threshold) >= 0
        && Number(promptRebuff.block_threshold) <= 1,
      '`runtime.prompt_rebuff.block_threshold` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(promptRebuff.max_body_chars) && promptRebuff.max_body_chars > 0,
      '`runtime.prompt_rebuff.max_body_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(promptRebuff.max_response_chars) && promptRebuff.max_response_chars > 0,
      '`runtime.prompt_rebuff.max_response_chars` must be integer > 0',
      details
    );
    if (
      Number.isFinite(Number(promptRebuff.warn_threshold)) &&
      Number.isFinite(Number(promptRebuff.block_threshold)) &&
      Number(promptRebuff.block_threshold) < Number(promptRebuff.warn_threshold)
    ) {
      details.push('`runtime.prompt_rebuff.block_threshold` must be >= `runtime.prompt_rebuff.warn_threshold`');
    }
    assertType(
      typeof promptRebuff.session_header === 'string' && promptRebuff.session_header.length > 0,
      '`runtime.prompt_rebuff.session_header` must be non-empty string',
      details
    );
    assertType(
      Array.isArray(promptRebuff.fallback_headers) && promptRebuff.fallback_headers.length > 0,
      '`runtime.prompt_rebuff.fallback_headers` must be non-empty array',
      details
    );
    if (Array.isArray(promptRebuff.fallback_headers)) {
      promptRebuff.fallback_headers.forEach((header, idx) => {
        assertType(
          typeof header === 'string' && header.length > 0,
          `runtime.prompt_rebuff.fallback_headers[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      Number.isInteger(promptRebuff.ttl_ms) && promptRebuff.ttl_ms > 0,
      '`runtime.prompt_rebuff.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(promptRebuff.max_sessions) && promptRebuff.max_sessions > 0,
      '`runtime.prompt_rebuff.max_sessions` must be integer > 0',
      details
    );
    assertType(
      typeof promptRebuff.canary_tool_name === 'string' && promptRebuff.canary_tool_name.length > 0,
      '`runtime.prompt_rebuff.canary_tool_name` must be non-empty string',
      details
    );
    assertType(
      typeof promptRebuff.observability === 'boolean',
      '`runtime.prompt_rebuff.observability` must be boolean',
      details
    );
  }

  const outputClassifier = runtime.output_classifier || {};
  if (runtime.output_classifier !== undefined) {
    assertNoUnknownKeys(outputClassifier, OUTPUT_CLASSIFIER_KEYS, 'runtime.output_classifier', details);
    assertType(
      typeof outputClassifier.enabled === 'boolean',
      '`runtime.output_classifier.enabled` must be boolean',
      details
    );
    assertType(
      OUTPUT_CLASSIFIER_MODES.has(String(outputClassifier.mode)),
      '`runtime.output_classifier.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(outputClassifier.max_scan_chars) && outputClassifier.max_scan_chars > 0,
      '`runtime.output_classifier.max_scan_chars` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(outputClassifier.context_window_chars) &&
        outputClassifier.context_window_chars >= 16 &&
        outputClassifier.context_window_chars <= 4096,
      '`runtime.output_classifier.context_window_chars` must be integer between 16 and 4096',
      details
    );
    assertType(
      Number.isInteger(outputClassifier.max_matches_per_rule) &&
        outputClassifier.max_matches_per_rule >= 1 &&
        outputClassifier.max_matches_per_rule <= 32,
      '`runtime.output_classifier.max_matches_per_rule` must be integer between 1 and 32',
      details
    );
    assertType(
      Number.isFinite(Number(outputClassifier.contextual_dampening)) &&
        Number(outputClassifier.contextual_dampening) >= 0 &&
        Number(outputClassifier.contextual_dampening) <= 1,
      '`runtime.output_classifier.contextual_dampening` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(outputClassifier.contextual_escalation)) &&
        Number(outputClassifier.contextual_escalation) >= 0 &&
        Number(outputClassifier.contextual_escalation) <= 1,
      '`runtime.output_classifier.contextual_escalation` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(outputClassifier.ngram_boost)) &&
        Number(outputClassifier.ngram_boost) >= 0 &&
        Number(outputClassifier.ngram_boost) <= 1,
      '`runtime.output_classifier.ngram_boost` must be number between 0 and 1',
      details
    );
    assertType(
      outputClassifier.categories &&
        typeof outputClassifier.categories === 'object' &&
        !Array.isArray(outputClassifier.categories),
      '`runtime.output_classifier.categories` must be object',
      details
    );
    if (outputClassifier.categories && typeof outputClassifier.categories === 'object' && !Array.isArray(outputClassifier.categories)) {
      assertNoUnknownKeys(
        outputClassifier.categories,
        OUTPUT_CLASSIFIER_CATEGORIES_KEYS,
        'runtime.output_classifier.categories',
        details
      );
      for (const [category, categoryConfig] of Object.entries(outputClassifier.categories)) {
        const label = `runtime.output_classifier.categories.${category}`;
        assertType(
          categoryConfig && typeof categoryConfig === 'object' && !Array.isArray(categoryConfig),
          `${label} must be object`,
          details
        );
        if (!categoryConfig || typeof categoryConfig !== 'object' || Array.isArray(categoryConfig)) {
          continue;
        }
        assertNoUnknownKeys(categoryConfig, OUTPUT_CLASSIFIER_CATEGORY_KEYS, label, details);
        assertType(
          typeof categoryConfig.enabled === 'boolean',
          `${label}.enabled must be boolean`,
          details
        );
        assertType(
          Number.isFinite(Number(categoryConfig.warn_threshold)) &&
            Number(categoryConfig.warn_threshold) >= 0 &&
            Number(categoryConfig.warn_threshold) <= 1,
          `${label}.warn_threshold must be number between 0 and 1`,
          details
        );
        assertType(
          Number.isFinite(Number(categoryConfig.block_threshold)) &&
            Number(categoryConfig.block_threshold) >= 0 &&
            Number(categoryConfig.block_threshold) <= 1,
          `${label}.block_threshold must be number between 0 and 1`,
          details
        );
        if (
          Number.isFinite(Number(categoryConfig.warn_threshold)) &&
          Number.isFinite(Number(categoryConfig.block_threshold)) &&
          Number(categoryConfig.block_threshold) < Number(categoryConfig.warn_threshold)
        ) {
          details.push(`${label}.block_threshold must be >= warn_threshold`);
        }
      }
    }
  }

  const outputSchemaValidator = runtime.output_schema_validator || {};
  if (runtime.output_schema_validator !== undefined) {
    assertNoUnknownKeys(outputSchemaValidator, OUTPUT_SCHEMA_VALIDATOR_KEYS, 'runtime.output_schema_validator', details);
    assertType(
      typeof outputSchemaValidator.enabled === 'boolean',
      '`runtime.output_schema_validator.enabled` must be boolean',
      details
    );
    assertType(
      OUTPUT_SCHEMA_VALIDATOR_MODES.has(String(outputSchemaValidator.mode)),
      '`runtime.output_schema_validator.mode` must be monitor|block',
      details
    );
    assertType(
      typeof outputSchemaValidator.default_schema === 'string',
      '`runtime.output_schema_validator.default_schema` must be string',
      details
    );
    assertType(
      typeof outputSchemaValidator.schema_header === 'string' && outputSchemaValidator.schema_header.length > 0,
      '`runtime.output_schema_validator.schema_header` must be non-empty string',
      details
    );
    assertType(
      Number.isInteger(outputSchemaValidator.max_body_bytes) && outputSchemaValidator.max_body_bytes > 0,
      '`runtime.output_schema_validator.max_body_bytes` must be integer > 0',
      details
    );
    assertType(
      outputSchemaValidator.schemas &&
        typeof outputSchemaValidator.schemas === 'object' &&
        !Array.isArray(outputSchemaValidator.schemas),
      '`runtime.output_schema_validator.schemas` must be object',
      details
    );
    if (
      outputSchemaValidator.schemas &&
      typeof outputSchemaValidator.schemas === 'object' &&
      !Array.isArray(outputSchemaValidator.schemas)
    ) {
      for (const [name, schemaNode] of Object.entries(outputSchemaValidator.schemas)) {
        validateOutputSchemaNode(
          schemaNode,
          details,
          `runtime.output_schema_validator.schemas.${name}`
        );
      }
    }
  }

  const agentObservability = runtime.agent_observability || {};
  if (runtime.agent_observability !== undefined) {
    assertNoUnknownKeys(agentObservability, AGENT_OBSERVABILITY_KEYS, 'runtime.agent_observability', details);
    assertType(
      typeof agentObservability.enabled === 'boolean',
      '`runtime.agent_observability.enabled` must be boolean',
      details
    );
    assertType(
      Number.isInteger(agentObservability.max_events_per_request) &&
        agentObservability.max_events_per_request > 0 &&
        agentObservability.max_events_per_request <= 256,
      '`runtime.agent_observability.max_events_per_request` must be integer between 1 and 256',
      details
    );
    assertType(
      Number.isInteger(agentObservability.max_field_length) &&
        agentObservability.max_field_length >= 32 &&
        agentObservability.max_field_length <= 4096,
      '`runtime.agent_observability.max_field_length` must be integer between 32 and 4096',
      details
    );
  }

  const differentialPrivacy = runtime.differential_privacy || {};
  if (runtime.differential_privacy !== undefined) {
    assertNoUnknownKeys(differentialPrivacy, DIFFERENTIAL_PRIVACY_KEYS, 'runtime.differential_privacy', details);
    assertType(
      typeof differentialPrivacy.enabled === 'boolean',
      '`runtime.differential_privacy.enabled` must be boolean',
      details
    );
    assertType(
      Number.isFinite(Number(differentialPrivacy.epsilon_budget)) &&
        Number(differentialPrivacy.epsilon_budget) > 0,
      '`runtime.differential_privacy.epsilon_budget` must be number > 0',
      details
    );
    assertType(
      Number.isFinite(Number(differentialPrivacy.epsilon_per_call)) &&
        Number(differentialPrivacy.epsilon_per_call) > 0,
      '`runtime.differential_privacy.epsilon_per_call` must be number > 0',
      details
    );
    assertType(
      Number.isFinite(Number(differentialPrivacy.sensitivity)) &&
        Number(differentialPrivacy.sensitivity) > 0,
      '`runtime.differential_privacy.sensitivity` must be number > 0',
      details
    );
    assertType(
      Number.isInteger(differentialPrivacy.max_simulation_calls) &&
        differentialPrivacy.max_simulation_calls > 0,
      '`runtime.differential_privacy.max_simulation_calls` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(differentialPrivacy.max_vector_length) &&
        differentialPrivacy.max_vector_length > 0,
      '`runtime.differential_privacy.max_vector_length` must be integer > 0',
      details
    );
    assertType(
      typeof differentialPrivacy.persist_state === 'boolean',
      '`runtime.differential_privacy.persist_state` must be boolean',
      details
    );
    assertType(
      typeof differentialPrivacy.state_file === 'string',
      '`runtime.differential_privacy.state_file` must be string',
      details
    );
    assertType(
      typeof differentialPrivacy.state_hmac_key === 'string',
      '`runtime.differential_privacy.state_hmac_key` must be string',
      details
    );
    assertType(
      typeof differentialPrivacy.reset_on_tamper === 'boolean',
      '`runtime.differential_privacy.reset_on_tamper` must be boolean',
      details
    );
    assertType(
      differentialPrivacy.persist_state !== true || String(differentialPrivacy.state_file || '').trim().length > 0,
      '`runtime.differential_privacy.state_file` must be non-empty when persist_state=true',
      details
    );
  }

  const autoImmune = runtime.auto_immune || {};
  if (runtime.auto_immune !== undefined) {
    assertNoUnknownKeys(autoImmune, AUTO_IMMUNE_KEYS, 'runtime.auto_immune', details);
    assertType(typeof autoImmune.enabled === 'boolean', '`runtime.auto_immune.enabled` must be boolean', details);
    assertType(
      AUTO_IMMUNE_MODES.has(String(autoImmune.mode)),
      '`runtime.auto_immune.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(autoImmune.ttl_ms) && autoImmune.ttl_ms > 0,
      '`runtime.auto_immune.ttl_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(autoImmune.max_entries) && autoImmune.max_entries > 0,
      '`runtime.auto_immune.max_entries` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(autoImmune.max_scan_bytes) && autoImmune.max_scan_bytes > 0,
      '`runtime.auto_immune.max_scan_bytes` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(autoImmune.min_confidence_to_match))
        && Number(autoImmune.min_confidence_to_match) >= 0
        && Number(autoImmune.min_confidence_to_match) <= 1,
      '`runtime.auto_immune.min_confidence_to_match` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(autoImmune.learn_min_score))
        && Number(autoImmune.learn_min_score) >= 0
        && Number(autoImmune.learn_min_score) <= 1,
      '`runtime.auto_immune.learn_min_score` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(autoImmune.learn_increment))
        && Number(autoImmune.learn_increment) >= 0
        && Number(autoImmune.learn_increment) <= 1,
      '`runtime.auto_immune.learn_increment` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isFinite(Number(autoImmune.max_confidence))
        && Number(autoImmune.max_confidence) >= 0
        && Number(autoImmune.max_confidence) <= 1,
      '`runtime.auto_immune.max_confidence` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(autoImmune.decay_half_life_ms) && autoImmune.decay_half_life_ms > 0,
      '`runtime.auto_immune.decay_half_life_ms` must be integer > 0',
      details
    );
    assertType(
      typeof autoImmune.observability === 'boolean',
      '`runtime.auto_immune.observability` must be boolean',
      details
    );
  }

  const provenance = runtime.provenance || {};
  if (runtime.provenance !== undefined) {
    assertNoUnknownKeys(provenance, PROVENANCE_KEYS, 'runtime.provenance', details);
    assertType(typeof provenance.enabled === 'boolean', '`runtime.provenance.enabled` must be boolean', details);
    assertType(typeof provenance.key_id === 'string' && provenance.key_id.length > 0, '`runtime.provenance.key_id` must be non-empty string', details);
    assertType(
      typeof provenance.sign_stream_trailers === 'boolean',
      '`runtime.provenance.sign_stream_trailers` must be boolean',
      details
    );
    assertType(
      typeof provenance.expose_public_key_endpoint === 'boolean',
      '`runtime.provenance.expose_public_key_endpoint` must be boolean',
      details
    );
    assertType(
      Number.isInteger(provenance.max_signable_bytes) && provenance.max_signable_bytes > 0,
      '`runtime.provenance.max_signable_bytes` must be integer > 0',
      details
    );
  }

  const deception = runtime.deception || {};
  if (runtime.deception !== undefined) {
    assertNoUnknownKeys(deception, DECEPTION_KEYS, 'runtime.deception', details);
    assertType(typeof deception.enabled === 'boolean', '`runtime.deception.enabled` must be boolean', details);
    assertType(
      DECEPTION_MODES.has(String(deception.mode)),
      '`runtime.deception.mode` must be off|tarpit',
      details
    );
    assertType(typeof deception.on_injection === 'boolean', '`runtime.deception.on_injection` must be boolean', details);
    assertType(typeof deception.on_loop === 'boolean', '`runtime.deception.on_loop` must be boolean', details);
    assertType(
      Number.isFinite(Number(deception.min_injection_score)) &&
        Number(deception.min_injection_score) >= 0 &&
        Number(deception.min_injection_score) <= 1,
      '`runtime.deception.min_injection_score` must be between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(deception.sse_token_interval_ms) && deception.sse_token_interval_ms >= 0,
      '`runtime.deception.sse_token_interval_ms` must be integer >= 0',
      details
    );
    assertType(
      Number.isInteger(deception.sse_max_tokens) && deception.sse_max_tokens > 0,
      '`runtime.deception.sse_max_tokens` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(deception.non_stream_delay_ms) && deception.non_stream_delay_ms >= 0,
      '`runtime.deception.non_stream_delay_ms` must be integer >= 0',
      details
    );
  }

  const honeytoken = runtime.honeytoken || {};
  if (runtime.honeytoken !== undefined) {
    assertNoUnknownKeys(honeytoken, HONEYTOKEN_KEYS, 'runtime.honeytoken', details);
    assertType(typeof honeytoken.enabled === 'boolean', '`runtime.honeytoken.enabled` must be boolean', details);
    assertType(
      HONEYTOKEN_MODES.has(String(honeytoken.mode)),
      '`runtime.honeytoken.mode` must be zero_width|uuid_suffix',
      details
    );
    assertType(
      Number.isFinite(Number(honeytoken.injection_rate)) &&
        Number(honeytoken.injection_rate) >= 0 &&
        Number(honeytoken.injection_rate) <= 1,
      '`runtime.honeytoken.injection_rate` must be between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(honeytoken.max_insertions_per_request) && honeytoken.max_insertions_per_request > 0,
      '`runtime.honeytoken.max_insertions_per_request` must be integer > 0',
      details
    );
    assertType(
      Array.isArray(honeytoken.target_roles) && honeytoken.target_roles.length > 0,
      '`runtime.honeytoken.target_roles` must be non-empty array',
      details
    );
    if (Array.isArray(honeytoken.target_roles)) {
      honeytoken.target_roles.forEach((role, idx) => {
        assertType(
          typeof role === 'string' && role.length > 0,
          `runtime.honeytoken.target_roles[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      typeof honeytoken.token_prefix === 'string' && honeytoken.token_prefix.length > 0,
      '`runtime.honeytoken.token_prefix` must be non-empty string',
      details
    );
  }

  const latencyNormalization = runtime.latency_normalization || {};
  if (runtime.latency_normalization !== undefined) {
    assertNoUnknownKeys(latencyNormalization, LATENCY_NORMALIZATION_KEYS, 'runtime.latency_normalization', details);
    assertType(
      typeof latencyNormalization.enabled === 'boolean',
      '`runtime.latency_normalization.enabled` must be boolean',
      details
    );
    assertType(
      Number.isInteger(latencyNormalization.window_size) && latencyNormalization.window_size > 0,
      '`runtime.latency_normalization.window_size` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(latencyNormalization.min_samples) &&
        latencyNormalization.min_samples > 0 &&
        latencyNormalization.min_samples <= latencyNormalization.window_size,
      '`runtime.latency_normalization.min_samples` must be integer > 0 and <= window_size',
      details
    );
    assertType(
      Number.isInteger(latencyNormalization.max_delay_ms) && latencyNormalization.max_delay_ms > 0,
      '`runtime.latency_normalization.max_delay_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(latencyNormalization.max_baseline_sample_ms) && latencyNormalization.max_baseline_sample_ms > 0,
      '`runtime.latency_normalization.max_baseline_sample_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(latencyNormalization.trim_percentile)) &&
        Number(latencyNormalization.trim_percentile) >= 0 &&
        Number(latencyNormalization.trim_percentile) < 0.5,
      '`runtime.latency_normalization.trim_percentile` must be number in [0, 0.5)',
      details
    );
    assertType(
      Number.isInteger(latencyNormalization.max_concurrent_normalized) &&
        latencyNormalization.max_concurrent_normalized > 0,
      '`runtime.latency_normalization.max_concurrent_normalized` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(latencyNormalization.jitter_ms) && latencyNormalization.jitter_ms >= 0,
      '`runtime.latency_normalization.jitter_ms` must be integer >= 0',
      details
    );
    assertType(
      Array.isArray(latencyNormalization.statuses) && latencyNormalization.statuses.length > 0,
      '`runtime.latency_normalization.statuses` must be non-empty array',
      details
    );
    if (Array.isArray(latencyNormalization.statuses)) {
      latencyNormalization.statuses.forEach((status, idx) => {
        assertType(
          Number.isInteger(status) && status >= 100 && status <= 599,
          `runtime.latency_normalization.statuses[${idx}] must be HTTP status integer`,
          details
        );
      });
    }
  }

  const canaryTools = runtime.canary_tools || {};
  if (runtime.canary_tools !== undefined) {
    assertNoUnknownKeys(canaryTools, CANARY_TOOL_KEYS, 'runtime.canary_tools', details);
    assertType(typeof canaryTools.enabled === 'boolean', '`runtime.canary_tools.enabled` must be boolean', details);
    assertType(
      CANARY_TOOL_MODES.has(String(canaryTools.mode)),
      '`runtime.canary_tools.mode` must be monitor|block',
      details
    );
    assertType(
      typeof canaryTools.tool_name === 'string' && canaryTools.tool_name.length > 0,
      '`runtime.canary_tools.tool_name` must be non-empty string',
      details
    );
    assertType(
      typeof canaryTools.tool_description === 'string' && canaryTools.tool_description.length > 0,
      '`runtime.canary_tools.tool_description` must be non-empty string',
      details
    );
    assertType(
      Number.isInteger(canaryTools.max_injected_tools) && canaryTools.max_injected_tools > 0,
      '`runtime.canary_tools.max_injected_tools` must be integer > 0',
      details
    );
    assertType(
      Array.isArray(canaryTools.inject_on_providers) && canaryTools.inject_on_providers.length > 0,
      '`runtime.canary_tools.inject_on_providers` must be non-empty array',
      details
    );
    assertType(
      typeof canaryTools.require_tools_array === 'boolean',
      '`runtime.canary_tools.require_tools_array` must be boolean',
      details
    );
  }

  const parallax = runtime.parallax || {};
  if (runtime.parallax !== undefined) {
    assertNoUnknownKeys(parallax, PARALLAX_KEYS, 'runtime.parallax', details);
    assertType(typeof parallax.enabled === 'boolean', '`runtime.parallax.enabled` must be boolean', details);
    assertType(
      PARALLAX_MODES.has(String(parallax.mode)),
      '`runtime.parallax.mode` must be monitor|block',
      details
    );
    assertType(
      Array.isArray(parallax.high_risk_tools) && parallax.high_risk_tools.length > 0,
      '`runtime.parallax.high_risk_tools` must be non-empty array',
      details
    );
    if (Array.isArray(parallax.high_risk_tools)) {
      parallax.high_risk_tools.forEach((toolName, idx) => {
        assertType(
          typeof toolName === 'string' && toolName.length > 0,
          `runtime.parallax.high_risk_tools[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      ['openai', 'anthropic', 'google', 'ollama', 'custom'].includes(String(parallax.secondary_target)),
      '`runtime.parallax.secondary_target` must be openai|anthropic|google|ollama|custom',
      details
    );
    assertType(
      typeof parallax.secondary_group === 'string',
      '`runtime.parallax.secondary_group` must be string',
      details
    );
    assertType(
      typeof parallax.secondary_contract === 'string' && parallax.secondary_contract.length > 0,
      '`runtime.parallax.secondary_contract` must be non-empty string',
      details
    );
    assertType(
      typeof parallax.secondary_model === 'string',
      '`runtime.parallax.secondary_model` must be string',
      details
    );
    assertType(
      Number.isInteger(parallax.timeout_ms) && parallax.timeout_ms > 0,
      '`runtime.parallax.timeout_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(parallax.risk_threshold)) &&
        Number(parallax.risk_threshold) >= 0 &&
        Number(parallax.risk_threshold) <= 1,
      '`runtime.parallax.risk_threshold` must be number between 0 and 1',
      details
    );
  }

  const shadowOs = runtime.shadow_os || {};
  if (runtime.shadow_os !== undefined) {
    assertNoUnknownKeys(shadowOs, SHADOW_OS_KEYS, 'runtime.shadow_os', details);
    assertType(typeof shadowOs.enabled === 'boolean', '`runtime.shadow_os.enabled` must be boolean', details);
    assertType(
      SHADOW_OS_MODES.has(String(shadowOs.mode)),
      '`runtime.shadow_os.mode` must be monitor|block',
      details
    );
    assertType(
      Number.isInteger(shadowOs.window_ms) && shadowOs.window_ms > 0,
      '`runtime.shadow_os.window_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(shadowOs.max_sessions) && shadowOs.max_sessions > 0,
      '`runtime.shadow_os.max_sessions` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(shadowOs.max_history_per_session) && shadowOs.max_history_per_session > 0,
      '`runtime.shadow_os.max_history_per_session` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(shadowOs.repeat_threshold) && shadowOs.repeat_threshold >= 2,
      '`runtime.shadow_os.repeat_threshold` must be integer >= 2',
      details
    );
    assertType(
      typeof shadowOs.session_header === 'string' && shadowOs.session_header.length > 0,
      '`runtime.shadow_os.session_header` must be non-empty string',
      details
    );
    assertType(
      Array.isArray(shadowOs.fallback_headers) && shadowOs.fallback_headers.length > 0,
      '`runtime.shadow_os.fallback_headers` must be non-empty array',
      details
    );
    assertType(
      Array.isArray(shadowOs.high_risk_tools) && shadowOs.high_risk_tools.length > 0,
      '`runtime.shadow_os.high_risk_tools` must be non-empty array',
      details
    );
    assertType(
      Array.isArray(shadowOs.sequence_rules) && shadowOs.sequence_rules.length > 0,
      '`runtime.shadow_os.sequence_rules` must be non-empty array',
      details
    );
    if (Array.isArray(shadowOs.sequence_rules)) {
      shadowOs.sequence_rules.forEach((rule, idx) => {
        assertNoUnknownKeys(rule, SHADOW_OS_SEQUENCE_RULE_KEYS, `runtime.shadow_os.sequence_rules[${idx}]`, details);
        assertType(
          typeof rule.id === 'string' && rule.id.length > 0,
          `runtime.shadow_os.sequence_rules[${idx}].id must be non-empty string`,
          details
        );
        assertType(
          Array.isArray(rule.requires) && rule.requires.length > 0,
          `runtime.shadow_os.sequence_rules[${idx}].requires must be non-empty array`,
          details
        );
        assertType(
          typeof rule.order_required === 'boolean',
          `runtime.shadow_os.sequence_rules[${idx}].order_required must be boolean`,
          details
        );
      });
    }
    assertType(
      typeof shadowOs.observability === 'boolean',
      '`runtime.shadow_os.observability` must be boolean',
      details
    );
  }

  const epistemicAnchor = runtime.epistemic_anchor || {};
  if (runtime.epistemic_anchor !== undefined) {
    assertNoUnknownKeys(epistemicAnchor, EPISTEMIC_ANCHOR_KEYS, 'runtime.epistemic_anchor', details);
    assertType(
      typeof epistemicAnchor.enabled === 'boolean',
      '`runtime.epistemic_anchor.enabled` must be boolean',
      details
    );
    assertType(
      EPISTEMIC_ANCHOR_MODES.has(String(epistemicAnchor.mode)),
      '`runtime.epistemic_anchor.mode` must be monitor|block',
      details
    );
    assertType(
      typeof epistemicAnchor.required_acknowledgement === 'string' && epistemicAnchor.required_acknowledgement.length > 0,
      '`runtime.epistemic_anchor.required_acknowledgement` must be non-empty string',
      details
    );
    assertType(
      typeof epistemicAnchor.acknowledgement === 'string',
      '`runtime.epistemic_anchor.acknowledgement` must be string',
      details
    );
    assertType(
      typeof epistemicAnchor.key_header === 'string' && epistemicAnchor.key_header.length > 0,
      '`runtime.epistemic_anchor.key_header` must be non-empty string',
      details
    );
    assertType(
      Array.isArray(epistemicAnchor.fallback_key_headers) && epistemicAnchor.fallback_key_headers.length > 0,
      '`runtime.epistemic_anchor.fallback_key_headers` must be non-empty array',
      details
    );
    assertType(
      Number.isInteger(epistemicAnchor.sample_every_turns) && epistemicAnchor.sample_every_turns > 0,
      '`runtime.epistemic_anchor.sample_every_turns` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(epistemicAnchor.min_turns) && epistemicAnchor.min_turns > 0,
      '`runtime.epistemic_anchor.min_turns` must be integer > 0',
      details
    );
    assertType(
      Number.isFinite(Number(epistemicAnchor.threshold))
        && Number(epistemicAnchor.threshold) >= 0
        && Number(epistemicAnchor.threshold) <= 1,
      '`runtime.epistemic_anchor.threshold` must be number between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(epistemicAnchor.cooldown_ms) && epistemicAnchor.cooldown_ms > 0,
      '`runtime.epistemic_anchor.cooldown_ms` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(epistemicAnchor.max_sessions) && epistemicAnchor.max_sessions > 0,
      '`runtime.epistemic_anchor.max_sessions` must be integer > 0',
      details
    );
    assertType(
      Number.isInteger(epistemicAnchor.context_window_messages) && epistemicAnchor.context_window_messages > 0,
      '`runtime.epistemic_anchor.context_window_messages` must be integer > 0',
      details
    );
    assertType(
      typeof epistemicAnchor.model_id === 'string' && epistemicAnchor.model_id.length > 0,
      '`runtime.epistemic_anchor.model_id` must be non-empty string',
      details
    );
    assertType(
      typeof epistemicAnchor.cache_dir === 'string' && epistemicAnchor.cache_dir.length > 0,
      '`runtime.epistemic_anchor.cache_dir` must be non-empty string',
      details
    );
    assertType(
      Number.isInteger(epistemicAnchor.max_prompt_chars) && epistemicAnchor.max_prompt_chars > 0,
      '`runtime.epistemic_anchor.max_prompt_chars` must be integer > 0',
      details
    );
    assertType(
      typeof epistemicAnchor.observability === 'boolean',
      '`runtime.epistemic_anchor.observability` must be boolean',
      details
    );
  }

  const retry = runtime.upstream?.retry || {};
  const upstream = runtime.upstream || {};
  assertNoUnknownKeys(upstream, UPSTREAM_KEYS, 'runtime.upstream', details);
  assertNoUnknownKeys(retry, RETRY_KEYS, 'runtime.upstream.retry', details);
  assertType(typeof retry.enabled === 'boolean', '`runtime.upstream.retry.enabled` must be boolean', details);
  assertType(Number.isInteger(retry.max_attempts) && retry.max_attempts >= 0, '`runtime.upstream.retry.max_attempts` must be integer >= 0', details);

  const cb = runtime.upstream?.circuit_breaker || {};
  assertNoUnknownKeys(cb, CIRCUIT_BREAKER_KEYS, 'runtime.upstream.circuit_breaker', details);
  assertType(typeof cb.enabled === 'boolean', '`runtime.upstream.circuit_breaker.enabled` must be boolean', details);
  assertType(Number.isInteger(cb.open_seconds) && cb.open_seconds > 0, '`runtime.upstream.circuit_breaker.open_seconds` must be integer > 0', details);

  const customTargets = runtime.upstream?.custom_targets;
  if (customTargets !== undefined) {
    assertNoUnknownKeys(customTargets, CUSTOM_TARGET_KEYS, 'runtime.upstream.custom_targets', details);
    assertType(typeof customTargets.enabled === 'boolean', '`runtime.upstream.custom_targets.enabled` must be boolean', details);
    assertType(Array.isArray(customTargets.allowlist), '`runtime.upstream.custom_targets.allowlist` must be an array', details);
    assertType(
      typeof customTargets.block_private_networks === 'boolean',
      '`runtime.upstream.custom_targets.block_private_networks` must be boolean',
      details
    );
    if (customTargets.enabled && Array.isArray(customTargets.allowlist) && customTargets.allowlist.length === 0) {
      details.push('`runtime.upstream.custom_targets.allowlist` must not be empty when custom targets are enabled');
    }
  }

  const resilienceMesh = runtime.upstream?.resilience_mesh;
  if (resilienceMesh !== undefined) {
    assertNoUnknownKeys(resilienceMesh, RESILIENCE_MESH_KEYS, 'runtime.upstream.resilience_mesh', details);
    assertType(
      typeof resilienceMesh.enabled === 'boolean',
      '`runtime.upstream.resilience_mesh.enabled` must be boolean',
      details
    );
    assertType(
      typeof resilienceMesh.contract === 'string',
      '`runtime.upstream.resilience_mesh.contract` must be string',
      details
    );
    assertType(
      typeof resilienceMesh.default_group === 'string',
      '`runtime.upstream.resilience_mesh.default_group` must be string',
      details
    );
    assertType(
      Number.isInteger(resilienceMesh.max_failover_hops) && resilienceMesh.max_failover_hops >= 0,
      '`runtime.upstream.resilience_mesh.max_failover_hops` must be integer >= 0',
      details
    );
    assertType(
      typeof resilienceMesh.allow_post_with_idempotency_key === 'boolean',
      '`runtime.upstream.resilience_mesh.allow_post_with_idempotency_key` must be boolean',
      details
    );
    assertType(
      Array.isArray(resilienceMesh.failover_on_status),
      '`runtime.upstream.resilience_mesh.failover_on_status` must be an array',
      details
    );
    if (Array.isArray(resilienceMesh.failover_on_status)) {
      resilienceMesh.failover_on_status.forEach((status, idx) => {
        assertType(
          Number.isInteger(status) && status >= 100 && status <= 599,
          `runtime.upstream.resilience_mesh.failover_on_status[${idx}] must be HTTP status integer`,
          details
        );
      });
    }
    assertType(
      Array.isArray(resilienceMesh.failover_on_error_types),
      '`runtime.upstream.resilience_mesh.failover_on_error_types` must be an array',
      details
    );
    if (Array.isArray(resilienceMesh.failover_on_error_types)) {
      resilienceMesh.failover_on_error_types.forEach((item, idx) => {
        const normalized = String(item).toLowerCase();
        assertType(
          ['timeout', 'transport', 'circuit_open'].includes(normalized),
          `runtime.upstream.resilience_mesh.failover_on_error_types[${idx}] must be timeout|transport|circuit_open`,
          details
        );
      });
    }
    assertType(
      resilienceMesh.groups && typeof resilienceMesh.groups === 'object' && !Array.isArray(resilienceMesh.groups),
      '`runtime.upstream.resilience_mesh.groups` must be an object',
      details
    );
    if (resilienceMesh.groups && typeof resilienceMesh.groups === 'object' && !Array.isArray(resilienceMesh.groups)) {
      Object.entries(resilienceMesh.groups).forEach(([groupName, groupConfig]) => {
        assertType(
          groupConfig && typeof groupConfig === 'object' && !Array.isArray(groupConfig),
          `runtime.upstream.resilience_mesh.groups.${groupName} must be object`,
          details
        );
        if (!groupConfig || typeof groupConfig !== 'object' || Array.isArray(groupConfig)) {
          return;
        }
        assertNoUnknownKeys(
          groupConfig,
          RESILIENCE_GROUP_KEYS,
          `runtime.upstream.resilience_mesh.groups.${groupName}`,
          details
        );
        assertType(
          typeof groupConfig.enabled === 'boolean',
          `runtime.upstream.resilience_mesh.groups.${groupName}.enabled must be boolean`,
          details
        );
        assertType(
          typeof groupConfig.contract === 'string',
          `runtime.upstream.resilience_mesh.groups.${groupName}.contract must be string`,
          details
        );
        assertType(
          Array.isArray(groupConfig.targets),
          `runtime.upstream.resilience_mesh.groups.${groupName}.targets must be array`,
          details
        );
      });
    }
    assertType(
      resilienceMesh.targets && typeof resilienceMesh.targets === 'object' && !Array.isArray(resilienceMesh.targets),
      '`runtime.upstream.resilience_mesh.targets` must be an object',
      details
    );
    if (resilienceMesh.targets && typeof resilienceMesh.targets === 'object' && !Array.isArray(resilienceMesh.targets)) {
      Object.entries(resilienceMesh.targets).forEach(([targetName, targetConfig]) => {
        assertType(
          targetConfig && typeof targetConfig === 'object' && !Array.isArray(targetConfig),
          `runtime.upstream.resilience_mesh.targets.${targetName} must be object`,
          details
        );
        if (!targetConfig || typeof targetConfig !== 'object' || Array.isArray(targetConfig)) {
          return;
        }
        assertNoUnknownKeys(
          targetConfig,
          RESILIENCE_TARGET_KEYS,
          `runtime.upstream.resilience_mesh.targets.${targetName}`,
          details
        );
        assertType(
          typeof targetConfig.enabled === 'boolean',
          `runtime.upstream.resilience_mesh.targets.${targetName}.enabled must be boolean`,
          details
        );
        assertType(
          typeof targetConfig.provider === 'string',
          `runtime.upstream.resilience_mesh.targets.${targetName}.provider must be string`,
          details
        );
        assertType(
          ['openai', 'anthropic', 'google', 'ollama', 'custom'].includes(String(targetConfig.provider).toLowerCase()),
          `runtime.upstream.resilience_mesh.targets.${targetName}.provider must be openai|anthropic|google|ollama|custom`,
          details
        );
        assertType(
          typeof targetConfig.contract === 'string',
          `runtime.upstream.resilience_mesh.targets.${targetName}.contract must be string`,
          details
        );
        if (targetConfig.base_url !== undefined) {
          assertType(
            typeof targetConfig.base_url === 'string' && targetConfig.base_url.length > 0,
            `runtime.upstream.resilience_mesh.targets.${targetName}.base_url must be non-empty string`,
            details
          );
        }
        if (targetConfig.custom_url !== undefined) {
          assertType(
            typeof targetConfig.custom_url === 'string' && targetConfig.custom_url.length > 0,
            `runtime.upstream.resilience_mesh.targets.${targetName}.custom_url must be non-empty string`,
            details
          );
        }
        if (targetConfig.headers !== undefined) {
          assertType(
            targetConfig.headers && typeof targetConfig.headers === 'object' && !Array.isArray(targetConfig.headers),
            `runtime.upstream.resilience_mesh.targets.${targetName}.headers must be object`,
            details
          );
        }
      });
    }
  }

  const canary = runtime.upstream?.canary;
  if (canary !== undefined) {
    assertNoUnknownKeys(canary, CANARY_KEYS, 'runtime.upstream.canary', details);
    assertType(typeof canary.enabled === 'boolean', '`runtime.upstream.canary.enabled` must be boolean', details);
    assertType(typeof canary.key_header === 'string', '`runtime.upstream.canary.key_header` must be string', details);
    assertType(
      Array.isArray(canary.fallback_key_headers),
      '`runtime.upstream.canary.fallback_key_headers` must be array',
      details
    );
    assertType(Array.isArray(canary.splits), '`runtime.upstream.canary.splits` must be array', details);
    if (Array.isArray(canary.splits)) {
      canary.splits.forEach((split, idx) => {
        assertType(split && typeof split === 'object' && !Array.isArray(split), `runtime.upstream.canary.splits[${idx}] must be object`, details);
        if (!split || typeof split !== 'object' || Array.isArray(split)) {
          return;
        }
        assertNoUnknownKeys(split, CANARY_SPLIT_KEYS, `runtime.upstream.canary.splits[${idx}]`, details);
        assertType(typeof split.name === 'string', `runtime.upstream.canary.splits[${idx}].name must be string`, details);
        assertType(typeof split.match_target === 'string', `runtime.upstream.canary.splits[${idx}].match_target must be string`, details);
        assertType(typeof split.group_a === 'string', `runtime.upstream.canary.splits[${idx}].group_a must be string`, details);
        assertType(typeof split.group_b === 'string', `runtime.upstream.canary.splits[${idx}].group_b must be string`, details);
        assertType(
          Number.isFinite(Number(split.weight_a)) && Number(split.weight_a) >= 0,
          `runtime.upstream.canary.splits[${idx}].weight_a must be number >= 0`,
          details
        );
        assertType(
          Number.isFinite(Number(split.weight_b)) && Number(split.weight_b) >= 0,
          `runtime.upstream.canary.splits[${idx}].weight_b must be number >= 0`,
          details
        );
        assertType(typeof split.sticky === 'boolean', `runtime.upstream.canary.splits[${idx}].sticky must be boolean`, details);
      });
    }
  }

  const ghostMode = runtime.upstream?.ghost_mode;
  if (ghostMode !== undefined) {
    assertNoUnknownKeys(ghostMode, GHOST_MODE_KEYS, 'runtime.upstream.ghost_mode', details);
    assertType(
      ghostMode.enabled === undefined || typeof ghostMode.enabled === 'boolean',
      '`runtime.upstream.ghost_mode.enabled` must be boolean',
      details
    );
    assertType(
      ghostMode.strip_headers === undefined || Array.isArray(ghostMode.strip_headers),
      '`runtime.upstream.ghost_mode.strip_headers` must be array',
      details
    );
    if (Array.isArray(ghostMode.strip_headers)) {
      ghostMode.strip_headers.forEach((value, idx) => {
        assertType(
          typeof value === 'string' && value.length > 0,
          `runtime.upstream.ghost_mode.strip_headers[${idx}] must be non-empty string`,
          details
        );
      });
    }
    assertType(
      ghostMode.override_user_agent === undefined || typeof ghostMode.override_user_agent === 'boolean',
      '`runtime.upstream.ghost_mode.override_user_agent` must be boolean',
      details
    );
    assertType(
      ghostMode.user_agent_value === undefined || (typeof ghostMode.user_agent_value === 'string' && ghostMode.user_agent_value.length > 0),
      '`runtime.upstream.ghost_mode.user_agent_value` must be non-empty string',
      details
    );
  }

  const authVault = runtime.upstream?.auth_vault;
  if (authVault !== undefined) {
    assertNoUnknownKeys(authVault, AUTH_VAULT_KEYS, 'runtime.upstream.auth_vault', details);
    assertType(
      authVault.enabled === undefined || typeof authVault.enabled === 'boolean',
      '`runtime.upstream.auth_vault.enabled` must be boolean',
      details
    );
    assertType(
      authVault.mode === undefined || AUTH_VAULT_MODES.has(String(authVault.mode)),
      '`runtime.upstream.auth_vault.mode` must be replace_dummy|enforce',
      details
    );
    assertType(
      authVault.dummy_key === undefined || (typeof authVault.dummy_key === 'string' && authVault.dummy_key.length > 0),
      '`runtime.upstream.auth_vault.dummy_key` must be non-empty string',
      details
    );
    if (authVault.providers !== undefined) {
      assertType(
        authVault.providers && typeof authVault.providers === 'object' && !Array.isArray(authVault.providers),
        '`runtime.upstream.auth_vault.providers` must be object',
        details
      );
    }
    if (authVault.providers && typeof authVault.providers === 'object' && !Array.isArray(authVault.providers)) {
      for (const [providerName, providerConfig] of Object.entries(authVault.providers)) {
        if (!AUTH_VAULT_PROVIDERS.has(providerName)) {
          details.push(
            `runtime.upstream.auth_vault.providers.${providerName} is not supported (allowed: openai, anthropic, google)`
          );
          continue;
        }
        assertType(
          providerConfig && typeof providerConfig === 'object' && !Array.isArray(providerConfig),
          `runtime.upstream.auth_vault.providers.${providerName} must be object`,
          details
        );
        if (!providerConfig || typeof providerConfig !== 'object' || Array.isArray(providerConfig)) {
          continue;
        }
        assertNoUnknownKeys(
          providerConfig,
          AUTH_VAULT_PROVIDER_KEYS,
          `runtime.upstream.auth_vault.providers.${providerName}`,
          details
        );
        assertType(
          providerConfig.enabled === undefined || typeof providerConfig.enabled === 'boolean',
          `runtime.upstream.auth_vault.providers.${providerName}.enabled must be boolean`,
          details
        );
        assertType(
          providerConfig.api_key === undefined || typeof providerConfig.api_key === 'string',
          `runtime.upstream.auth_vault.providers.${providerName}.api_key must be string`,
          details
        );
        assertType(
          providerConfig.env_var === undefined || typeof providerConfig.env_var === 'string',
          `runtime.upstream.auth_vault.providers.${providerName}.env_var must be string`,
          details
        );
      }
    }
  }

  validateRules(config.rules, details);

  const pii = config.pii || {};
  if (pii !== undefined) {
    assertNoUnknownKeys(pii, PII_KEYS, 'pii', details);
    assertType(typeof pii.enabled === 'boolean', '`pii.enabled` must be boolean', details);
    assertType(typeof pii.provider_mode === 'string', '`pii.provider_mode` must be string', details);
    if (typeof pii.provider_mode === 'string' && !VALID_PII_PROVIDER_MODES.has(String(pii.provider_mode).toLowerCase())) {
      details.push('`pii.provider_mode` must be one of: local, rapidapi, hybrid');
    }
    assertType(
      Number.isFinite(Number(pii.max_scan_bytes)) && Number(pii.max_scan_bytes) > 0,
      '`pii.max_scan_bytes` must be > 0',
      details
    );
    assertType(
      pii.regex_safety_cap_bytes === undefined ||
        (Number.isFinite(Number(pii.regex_safety_cap_bytes)) && Number(pii.regex_safety_cap_bytes) > 0),
      '`pii.regex_safety_cap_bytes` must be > 0',
      details
    );
    if (pii.redaction !== undefined) {
      const redaction = pii.redaction || {};
      assertNoUnknownKeys(redaction, PII_REDACTION_KEYS, 'pii.redaction', details);
      assertType(
        PII_REDACTION_MODES.has(String(redaction.mode)),
        '`pii.redaction.mode` must be placeholder|format_preserving',
        details
      );
      assertType(
        typeof redaction.salt === 'string' && redaction.salt.length > 0,
        '`pii.redaction.salt` must be non-empty string',
        details
      );
    }
    assertNoUnknownKeys(pii.severity_actions, PII_SEVERITY_KEYS, 'pii.severity_actions', details);

    const rapidapi = pii.rapidapi || {};
    const semantic = pii.semantic || {};
    if (pii.rapidapi !== undefined) {
      assertNoUnknownKeys(rapidapi, RAPIDAPI_KEYS, 'pii.rapidapi', details);
      assertType(rapidapi.endpoint === undefined || typeof rapidapi.endpoint === 'string', '`pii.rapidapi.endpoint` must be string', details);
      assertType(rapidapi.host === undefined || typeof rapidapi.host === 'string', '`pii.rapidapi.host` must be string', details);
      assertType(
        rapidapi.timeout_ms === undefined || (Number.isInteger(rapidapi.timeout_ms) && rapidapi.timeout_ms > 0),
        '`pii.rapidapi.timeout_ms` must be integer > 0',
        details
      );
      assertType(
        rapidapi.request_body_field === undefined || typeof rapidapi.request_body_field === 'string',
        '`pii.rapidapi.request_body_field` must be string',
        details
      );
      assertType(
        rapidapi.fallback_to_local === undefined || typeof rapidapi.fallback_to_local === 'boolean',
        '`pii.rapidapi.fallback_to_local` must be boolean',
        details
      );
      assertType(
        rapidapi.allow_non_rapidapi_host === undefined || typeof rapidapi.allow_non_rapidapi_host === 'boolean',
        '`pii.rapidapi.allow_non_rapidapi_host` must be boolean',
        details
      );
      assertType(rapidapi.api_key === undefined || typeof rapidapi.api_key === 'string', '`pii.rapidapi.api_key` must be string', details);
      assertType(
        rapidapi.cache_max_entries === undefined ||
          (Number.isInteger(rapidapi.cache_max_entries) && rapidapi.cache_max_entries > 0),
        '`pii.rapidapi.cache_max_entries` must be integer > 0',
        details
      );
      assertType(
        rapidapi.cache_ttl_ms === undefined ||
          (Number.isInteger(rapidapi.cache_ttl_ms) && rapidapi.cache_ttl_ms >= 0),
        '`pii.rapidapi.cache_ttl_ms` must be integer >= 0',
        details
      );
      assertType(
        rapidapi.max_timeout_ms === undefined ||
          (Number.isInteger(rapidapi.max_timeout_ms) && rapidapi.max_timeout_ms > 0),
        '`pii.rapidapi.max_timeout_ms` must be integer > 0',
        details
      );
      assertType(
        rapidapi.extra_body === undefined ||
          (rapidapi.extra_body && typeof rapidapi.extra_body === 'object' && !Array.isArray(rapidapi.extra_body)),
        '`pii.rapidapi.extra_body` must be object',
        details
      );
    }
    if (pii.semantic !== undefined) {
      assertNoUnknownKeys(semantic, PII_SEMANTIC_KEYS, 'pii.semantic', details);
      assertType(typeof semantic.enabled === 'boolean', '`pii.semantic.enabled` must be boolean', details);
      assertType(typeof semantic.model_id === 'string', '`pii.semantic.model_id` must be string', details);
      assertType(typeof semantic.cache_dir === 'string', '`pii.semantic.cache_dir` must be string', details);
      assertType(
        Number.isFinite(Number(semantic.score_threshold)) &&
          Number(semantic.score_threshold) >= 0 &&
          Number(semantic.score_threshold) <= 1,
        '`pii.semantic.score_threshold` must be between 0 and 1',
        details
      );
      assertType(
        Number.isInteger(semantic.max_scan_bytes) && semantic.max_scan_bytes > 0,
        '`pii.semantic.max_scan_bytes` must be integer > 0',
        details
      );
    }
    if (pii.egress !== undefined) {
      const egress = pii.egress || {};
      assertNoUnknownKeys(egress, PII_EGRESS_KEYS, 'pii.egress', details);
      assertType(typeof egress.enabled === 'boolean', '`pii.egress.enabled` must be boolean', details);
      assertType(
        Number.isInteger(egress.max_scan_bytes) && egress.max_scan_bytes > 0,
        '`pii.egress.max_scan_bytes` must be integer > 0',
        details
      );
      assertType(typeof egress.stream_enabled === 'boolean', '`pii.egress.stream_enabled` must be boolean', details);
      assertType(
        Number.isInteger(egress.sse_line_max_bytes) && egress.sse_line_max_bytes > 0,
        '`pii.egress.sse_line_max_bytes` must be integer > 0',
        details
      );
      assertType(
        egress.stream_block_mode === undefined || ['redact', 'terminate'].includes(String(egress.stream_block_mode)),
        '`pii.egress.stream_block_mode` must be redact|terminate',
        details
      );

      if (egress.entropy !== undefined) {
        assertType(
          egress.entropy && typeof egress.entropy === 'object' && !Array.isArray(egress.entropy),
          '`pii.egress.entropy` must be object',
          details
        );
        if (egress.entropy && typeof egress.entropy === 'object' && !Array.isArray(egress.entropy)) {
          assertNoUnknownKeys(egress.entropy, PII_EGRESS_ENTROPY_KEYS, 'pii.egress.entropy', details);
          assertType(typeof egress.entropy.enabled === 'boolean', '`pii.egress.entropy.enabled` must be boolean', details);
          assertType(
            PII_EGRESS_ENTROPY_MODES.has(String(egress.entropy.mode)),
            '`pii.egress.entropy.mode` must be monitor|block',
            details
          );
          assertType(
            Number.isFinite(Number(egress.entropy.threshold)) &&
              Number(egress.entropy.threshold) >= 0 &&
              Number(egress.entropy.threshold) <= 8,
            '`pii.egress.entropy.threshold` must be number between 0 and 8',
            details
          );
          assertType(
            Number.isInteger(egress.entropy.min_token_length) && egress.entropy.min_token_length > 0,
            '`pii.egress.entropy.min_token_length` must be integer > 0',
            details
          );
          assertType(
            Number.isInteger(egress.entropy.max_scan_bytes) && egress.entropy.max_scan_bytes > 0,
            '`pii.egress.entropy.max_scan_bytes` must be integer > 0',
            details
          );
          assertType(
            Number.isInteger(egress.entropy.max_findings) && egress.entropy.max_findings > 0,
            '`pii.egress.entropy.max_findings` must be integer > 0',
            details
          );
          assertType(
            Number.isFinite(Number(egress.entropy.min_unique_ratio)) &&
              Number(egress.entropy.min_unique_ratio) >= 0 &&
              Number(egress.entropy.min_unique_ratio) <= 1,
            '`pii.egress.entropy.min_unique_ratio` must be number between 0 and 1',
            details
          );
          assertType(
            typeof egress.entropy.detect_base64 === 'boolean',
            '`pii.egress.entropy.detect_base64` must be boolean',
            details
          );
          assertType(
            typeof egress.entropy.detect_hex === 'boolean',
            '`pii.egress.entropy.detect_hex` must be boolean',
            details
          );
          assertType(
            typeof egress.entropy.detect_generic === 'boolean',
            '`pii.egress.entropy.detect_generic` must be boolean',
            details
          );
          assertType(
            typeof egress.entropy.redact_replacement === 'string' &&
              egress.entropy.redact_replacement.length > 0,
            '`pii.egress.entropy.redact_replacement` must be non-empty string',
            details
          );
        }
      }
    }
  }

  const injection = config.injection || {};
  if (config.injection !== undefined) {
    assertNoUnknownKeys(injection, INJECTION_KEYS, 'injection', details);
    assertType(typeof injection.enabled === 'boolean', '`injection.enabled` must be boolean', details);
    assertType(
      Number.isFinite(Number(injection.threshold)) &&
        Number(injection.threshold) >= 0 &&
        Number(injection.threshold) <= 1,
      '`injection.threshold` must be between 0 and 1',
      details
    );
    assertType(
      Number.isInteger(injection.max_scan_bytes) && injection.max_scan_bytes > 0,
      '`injection.max_scan_bytes` must be integer > 0',
      details
    );
    assertType(
      INJECTION_ACTIONS.has(String(injection.action)),
      '`injection.action` must be one of: allow, block, warn',
      details
    );
    if (injection.neural !== undefined) {
      const neural = injection.neural || {};
      assertNoUnknownKeys(neural, INJECTION_NEURAL_KEYS, 'injection.neural', details);
      assertType(typeof neural.enabled === 'boolean', '`injection.neural.enabled` must be boolean', details);
      assertType(typeof neural.model_id === 'string', '`injection.neural.model_id` must be string', details);
      assertType(typeof neural.cache_dir === 'string', '`injection.neural.cache_dir` must be string', details);
      assertType(
        Number.isInteger(neural.max_scan_bytes) && neural.max_scan_bytes > 0,
        '`injection.neural.max_scan_bytes` must be integer > 0',
        details
      );
      assertType(
        Number.isInteger(neural.timeout_ms) && neural.timeout_ms > 0,
        '`injection.neural.timeout_ms` must be integer > 0',
        details
      );
      assertType(
        Number.isFinite(Number(neural.weight)) && Number(neural.weight) >= 0 && Number(neural.weight) <= 2,
        '`injection.neural.weight` must be between 0 and 2',
        details
      );
      assertType(
        INJECTION_NEURAL_MODES.has(String(neural.mode)),
        '`injection.neural.mode` must be max|blend',
        details
      );
    }
  }

  assertType(Array.isArray(config.whitelist?.domains), '`whitelist.domains` must be an array', details);
  assertNoUnknownKeys(config.whitelist, WHITELIST_KEYS, 'whitelist', details);
  assertNoUnknownKeys(config.logging, LOGGING_KEYS, 'logging', details);
  if (config.logging?.audit_stdout !== undefined) {
    assertType(typeof config.logging.audit_stdout === 'boolean', '`logging.audit_stdout` must be boolean', details);
  }

  if (details.length > 0) {
    throw new ConfigValidationError('Configuration validation failed', details);
  }

  return applyDefaults(config);
}

module.exports = {
  ConfigValidationError,
  validateConfigShape,
  applyDefaults,
};
