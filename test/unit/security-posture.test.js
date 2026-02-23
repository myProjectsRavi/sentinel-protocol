const { computeSecurityPosture } = require('../../src/governance/security-posture');

function createConfig(overrides = {}) {
  const base = {
    mode: 'enforce',
    injection: {
      enabled: true,
      action: 'block',
    },
    pii: {
      enabled: true,
      egress: {
        enabled: true,
        stream_enabled: true,
        stream_block_mode: 'terminate',
        entropy: {
          enabled: true,
          mode: 'block',
        },
      },
    },
    runtime: {
      prompt_rebuff: { enabled: true, mode: 'block' },
      mcp_poisoning: { enabled: true, mode: 'block' },
      auto_immune: { enabled: true, mode: 'block' },
      websocket: { enabled: true, mode: 'enforce' },
      provenance: { enabled: true, mode: 'enforce' },
      pii_vault: { enabled: true, mode: 'active' },
      upstream: { ghost_mode: { enabled: true, mode: 'active' } },
      honeytoken: { enabled: true, mode: 'active' },
      loop_breaker: { enabled: true, action: 'block' },
      agentic_threat_shield: { enabled: true, mode: 'block' },
      intent_throttle: { enabled: true, mode: 'block' },
      intent_drift: { enabled: true, mode: 'block' },
      canary_tools: { enabled: true, mode: 'block' },
      sandbox_experimental: { enabled: true, mode: 'block' },
      posture_scoring: { enabled: true, include_counters: true, warn_threshold: 70, critical_threshold: 50 },
    },
  };

  return {
    ...base,
    ...overrides,
    runtime: {
      ...base.runtime,
      ...(overrides.runtime || {}),
    },
    pii: {
      ...base.pii,
      ...(overrides.pii || {}),
      egress: {
        ...base.pii.egress,
        ...((overrides.pii || {}).egress || {}),
      },
    },
    injection: {
      ...base.injection,
      ...(overrides.injection || {}),
    },
  };
}

describe('security posture', () => {
  test('returns deterministic score for identical config and counter inputs', () => {
    const config = createConfig();
    const counters = {
      requests_total: 100,
      upstream_errors: 5,
      blocked_total: 8,
    };
    const first = computeSecurityPosture({ config, counters });
    const second = computeSecurityPosture({ config, counters });
    expect(first).toEqual(second);
  });

  test('penalizes disabled enforce-capable controls', () => {
    const baseline = computeSecurityPosture({
      config: createConfig(),
      counters: { requests_total: 100, upstream_errors: 2, blocked_total: 5 },
    });
    const weakened = computeSecurityPosture({
      config: createConfig({
        injection: { enabled: false, action: 'block' },
        runtime: {
          prompt_rebuff: { enabled: false, mode: 'block' },
          agentic_threat_shield: { enabled: false, mode: 'block' },
        },
      }),
      counters: { requests_total: 100, upstream_errors: 2, blocked_total: 5 },
    });

    expect(weakened.overall).toBeLessThan(baseline.overall);
    expect(weakened.categories.ingress).toBeLessThan(baseline.categories.ingress);
    expect(weakened.categories.agentic).toBeLessThan(baseline.categories.agentic);
  });

  test('computes category breakdown ingress/egress/privacy/agentic', () => {
    const posture = computeSecurityPosture({
      config: createConfig(),
      counters: {},
    });

    expect(posture.categories).toEqual({
      ingress: expect.any(Number),
      egress: expect.any(Number),
      privacy: expect.any(Number),
      agentic: expect.any(Number),
    });
  });

  test('handles missing audit data without throw', () => {
    expect(() =>
      computeSecurityPosture({
        config: createConfig(),
        counters: {},
        auditSummary: undefined,
      })
    ).not.toThrow();
  });
});
