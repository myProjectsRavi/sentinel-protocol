const fs = require('fs');
const path = require('path');

describe('server pipeline stage orchestration', () => {
  test('critical request modules are routed through runOrchestratedStage checkpoints', () => {
    const serverSource = fs.readFileSync(path.join(__dirname, '../../src/server.js'), 'utf8');
    const bufferedEgressSource = fs.readFileSync(
      path.join(__dirname, '../../src/stages/egress/buffered-egress-stage.js'),
      'utf8'
    );
    const requiredStageSource = {
      auto_immune: serverSource,
      swarm: serverSource,
      omni_shield: serverSource,
      injection_policy: serverSource,
      loop: serverSource,
      agentic_threat_shield: serverSource,
      intent: serverSource,
      sandbox: serverSource,
      pii: serverSource,
      optimizer: serverSource,
      polymorphic_prompt: serverSource,
      honeytoken_inject: serverSource,
      canary_tool_inject: serverSource,
      budget_estimate: serverSource,
      vcr_lookup: serverSource,
      semantic_cache_lookup: serverSource,
      upstream_forward: serverSource,
      stream_egress: serverSource,
      buffered_egress_scan: bufferedEgressSource,
      canary_tool_detect: bufferedEgressSource,
      parallax: bufferedEgressSource,
      semantic_cache_store: bufferedEgressSource,
      pii_vault_egress: bufferedEgressSource,
      budget_record: bufferedEgressSource,
    };

    for (const [stage, source] of Object.entries(requiredStageSource)) {
      expect(source).toContain(`runOrchestratedStage(`);
      expect(source).toContain(`'${stage}'`);
    }
  });

  test('phase A engines are wired into live policy stages', () => {
    const serverSource = fs.readFileSync(path.join(__dirname, '../../src/server.js'), 'utf8');
    const policySource = fs.readFileSync(
      path.join(__dirname, '../../src/stages/policy/pii-injection-stage.js'),
      'utf8'
    );
    const agenticSource = fs.readFileSync(
      path.join(__dirname, '../../src/stages/policy/agentic-stage.js'),
      'utf8'
    );

    const constructorWiring = [
      'this.serializationFirewall = new SerializationFirewall',
      'this.contextIntegrityGuardian = new ContextIntegrityGuardian',
      'this.toolSchemaValidator = new ToolSchemaValidator',
      'this.multimodalInjectionShield = new MultiModalInjectionShield',
      'this.supplyChainValidator = new SupplyChainValidator',
      'this.sandboxEnforcer = new SandboxEnforcer',
      'this.memoryIntegrityMonitor = new MemoryIntegrityMonitor',
    ];
    for (const marker of constructorWiring) {
      expect(serverSource).toContain(marker);
    }

    const ingressPolicyWiring = [
      'server.serializationFirewall?.isEnabled()',
      'server.contextIntegrityGuardian?.isEnabled()',
      'server.toolSchemaValidator?.isEnabled()',
      'server.multimodalInjectionShield?.isEnabled()',
      'server.supplyChainValidator?.isEnabled()',
      "'x-sentinel-serialization-firewall'",
      "'x-sentinel-context-integrity'",
      "'x-sentinel-tool-schema'",
      "'x-sentinel-multimodal-shield'",
      "'x-sentinel-supply-chain'",
    ];
    for (const marker of ingressPolicyWiring) {
      expect(policySource).toContain(marker);
    }

    const agenticPolicyWiring = [
      'server.memoryIntegrityMonitor?.isEnabled()',
      'server.sandboxEnforcer?.isEnabled()',
      "'x-sentinel-memory-integrity'",
      "'x-sentinel-sandbox-enforcer'",
    ];
    for (const marker of agenticPolicyWiring) {
      expect(agenticSource).toContain(marker);
    }
  });
});
