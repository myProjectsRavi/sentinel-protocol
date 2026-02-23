const { CapabilityIntrospection } = require('../../src/governance/capability-introspection');

describe('CapabilityIntrospection', () => {
  test('exports deterministic snapshot and agent card', () => {
    const introspection = new CapabilityIntrospection({ enabled: true });
    const server = {
      config: {
        version: 1,
        mode: 'monitor',
        runtime: {},
      },
      computeEffectiveMode: () => 'monitor',
      agenticThreatShield: { enabled: true, mode: 'monitor' },
      a2aCardVerifier: { enabled: true, mode: 'monitor' },
      consensusProtocol: { enabled: false, mode: 'monitor' },
      crossTenantIsolator: { enabled: false, mode: 'monitor' },
      coldStartAnalyzer: { enabled: false, mode: 'monitor' },
      mcpPoisoningDetector: { enabled: false, mode: 'monitor' },
      mcpShadowDetector: { enabled: false, mode: 'monitor' },
      memoryPoisoningSentinel: { enabled: false, mode: 'monitor' },
      cascadeIsolator: { enabled: false, mode: 'monitor' },
      agentIdentityFederation: { enabled: false, mode: 'monitor' },
      toolUseAnomalyDetector: { enabled: false, mode: 'monitor' },
      outputClassifier: { enabled: true, mode: 'monitor' },
      stegoExfilDetector: { enabled: true, mode: 'monitor' },
      reasoningTraceMonitor: { enabled: true, mode: 'monitor' },
      hallucinationTripwire: { enabled: true, mode: 'monitor' },
      semanticDriftCanary: { enabled: false, mode: 'monitor' },
      outputProvenanceSigner: { enabled: true, mode: 'monitor' },
      computeAttestation: { enabled: true, mode: 'monitor' },
      provenanceSigner: { enabled: true, mode: 'monitor' },
      loopBreaker: { enabled: true, mode: 'block' },
      omniShield: { enabled: false, mode: 'monitor' },
      experimentalSandbox: { enabled: false, mode: 'monitor' },
      shadowOS: { enabled: false, mode: 'monitor' },
      epistemicAnchor: { enabled: false, mode: 'monitor' },
      autoImmune: { enabled: false, mode: 'monitor' },
      canaryToolTrap: { enabled: false, mode: 'monitor' },
    };

    const snapshot = introspection.snapshot(server);
    const card = introspection.exportAgentCard(server, 'sentinel-agent');

    expect(snapshot.enabled).toBe(true);
    expect(snapshot.engines.length).toBeGreaterThan(0);
    expect(card.id).toBe('sentinel-agent');
    expect(Array.isArray(card.capabilities)).toBe(true);
  });
});
