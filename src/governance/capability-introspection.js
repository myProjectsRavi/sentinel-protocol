const crypto = require('crypto');

function hashJson(value) {
  return crypto
    .createHash('sha256')
    .update(JSON.stringify(value || {}), 'utf8')
    .digest('hex');
}

function safeMode(instance, fallback = 'monitor') {
  if (!instance || typeof instance !== 'object') {
    return fallback;
  }
  if (typeof instance.mode === 'string' && instance.mode) {
    return instance.mode;
  }
  return fallback;
}

function enabled(instance) {
  if (!instance) {
    return false;
  }
  if (typeof instance.isEnabled === 'function') {
    return instance.isEnabled() === true;
  }
  return instance.enabled === true;
}

class CapabilityIntrospection {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.maxEngines = Number.isInteger(Number(config.max_engines)) && Number(config.max_engines) > 0
      ? Number(config.max_engines)
      : 256;
    this.observability = config.observability !== false;
  }

  isEnabled() {
    return this.enabled === true;
  }

  snapshot(server) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
      };
    }

    const descriptors = [
      ['agentic_threat_shield', server.agenticThreatShield],
      ['a2a_card_verifier', server.a2aCardVerifier],
      ['consensus_protocol', server.consensusProtocol],
      ['cross_tenant_isolator', server.crossTenantIsolator],
      ['cold_start_analyzer', server.coldStartAnalyzer],
      ['mcp_poisoning', server.mcpPoisoningDetector],
      ['mcp_shadow', server.mcpShadowDetector],
      ['memory_poisoning', server.memoryPoisoningSentinel],
      ['cascade_isolator', server.cascadeIsolator],
      ['agent_identity_federation', server.agentIdentityFederation],
      ['tool_use_anomaly', server.toolUseAnomalyDetector],
      ['behavioral_fingerprint', server.behavioralFingerprint],
      ['serialization_firewall', server.serializationFirewall],
      ['context_integrity_guardian', server.contextIntegrityGuardian],
      ['context_compression_guard', server.contextCompressionGuard],
      ['tool_schema_validator', server.toolSchemaValidator],
      ['multimodal_injection_shield', server.multimodalInjectionShield],
      ['supply_chain_validator', server.supplyChainValidator],
      ['sandbox_enforcer', server.sandboxEnforcer],
      ['memory_integrity_monitor', server.memoryIntegrityMonitor],
      ['threat_intel_mesh', server.threatIntelMesh],
      ['lfrl', server.lfrlEngine],
      ['self_healing_immune', server.selfHealingImmune],
      ['output_classifier', server.outputClassifier],
      ['stego_exfil_detector', server.stegoExfilDetector],
      ['reasoning_trace_monitor', server.reasoningTraceMonitor],
      ['hallucination_tripwire', server.hallucinationTripwire],
      ['semantic_drift_canary', server.semanticDriftCanary],
      ['output_provenance', server.outputProvenanceSigner],
      ['compute_attestation', server.computeAttestation],
      ['provenance', server.provenanceSigner],
      ['loop_breaker', server.loopBreaker],
      ['omni_shield', server.omniShield],
      ['sandbox_experimental', server.experimentalSandbox],
      ['shadow_os', server.shadowOS],
      ['epistemic_anchor', server.epistemicAnchor],
      ['auto_immune', server.autoImmune],
    ];

    const engines = [];
    for (const [name, instance] of descriptors) {
      if (engines.length >= this.maxEngines) {
        break;
      }
      engines.push({
        name,
        enabled: enabled(instance),
        mode: safeMode(instance),
      });
    }

    const configDigest = hashJson({
      mode: server.config?.mode,
      runtime: server.config?.runtime,
      pii: server.config?.pii,
      injection: server.config?.injection,
      rules: server.config?.rules,
    });

    const snapshot = {
      enabled: true,
      generated_at: new Date().toISOString(),
      service_version: String(server.config?.version || '1'),
      effective_mode: typeof server.computeEffectiveMode === 'function' ? server.computeEffectiveMode() : 'monitor',
      engines,
      config_hash: configDigest,
      tool_matrix: {
        canary_tools_enabled: enabled(server.canaryToolTrap),
        mcp_shadow_enabled: enabled(server.mcpShadowDetector),
        mcp_poisoning_enabled: enabled(server.mcpPoisoningDetector),
        mcp_certificate_pinning_enabled: enabled(server.mcpCertificatePinning),
        lfrl_enabled: enabled(server.lfrlEngine),
        threat_intel_mesh_enabled: enabled(server.threatIntelMesh),
      },
    };

    return snapshot;
  }

  exportAgentCard(server, agentId = 'sentinel-agent') {
    const snapshot = this.snapshot(server);
    if (snapshot.enabled !== true) {
      return {
        enabled: false,
      };
    }

    const capabilities = snapshot.engines
      .filter((engine) => engine.enabled)
      .map((engine) => engine.name)
      .sort();

    return {
      id: String(agentId || 'sentinel-agent'),
      generated_at: snapshot.generated_at,
      auth: {
        schemes: ['api_key', 'oauth2'],
      },
      capabilities,
      metadata: {
        config_hash: snapshot.config_hash,
        effective_mode: snapshot.effective_mode,
      },
    };
  }
}

module.exports = {
  CapabilityIntrospection,
};
