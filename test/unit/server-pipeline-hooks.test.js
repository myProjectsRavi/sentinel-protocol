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
});
