const { CrossTenantIsolator } = require('../../src/security/cross-tenant-isolator');

describe('CrossTenantIsolator', () => {
  test('detects session tenant mismatch', () => {
    const isolator = new CrossTenantIsolator({
      enabled: true,
      mode: 'block',
      block_on_mismatch: true,
    });

    isolator.evaluateIngress({
      headers: {
        'x-sentinel-session-id': 's1',
        'x-sentinel-tenant-id': 'tenant-a',
      },
      effectiveMode: 'enforce',
    });

    const decision = isolator.evaluateIngress({
      headers: {
        'x-sentinel-session-id': 's1',
        'x-sentinel-tenant-id': 'tenant-b',
      },
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.shouldBlock).toBe(true);
  });

  test('detects cross-tenant egress leak', () => {
    const isolator = new CrossTenantIsolator({
      enabled: true,
      mode: 'block',
      block_on_leak: true,
    });

    isolator.evaluateIngress({
      headers: {
        'x-sentinel-session-id': 's1',
        'x-sentinel-tenant-id': 'tenant-a',
      },
    });
    isolator.evaluateIngress({
      headers: {
        'x-sentinel-session-id': 's2',
        'x-sentinel-tenant-id': 'tenant-b',
      },
    });

    const decision = isolator.evaluateEgress({
      tenantId: 'tenant-a',
      text: 'report for tenant-b includes confidential fields',
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.shouldBlock).toBe(true);
  });
});
