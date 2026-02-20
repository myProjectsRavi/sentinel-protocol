const { isLocalAddress, estimateSavings } = require('../../src/monitor/dashboard-server');

describe('dashboard server', () => {
  test('local address classifier works for loopback variants', () => {
    expect(isLocalAddress('127.0.0.1')).toBe(true);
    expect(isLocalAddress('::1')).toBe(true);
    expect(isLocalAddress('::ffff:127.0.0.1')).toBe(true);
    expect(isLocalAddress('10.0.0.2')).toBe(false);
  });

  test('savings estimator remains deterministic', () => {
    const value = estimateSavings({
      semantic_cache_hits: 10,
      blocked_total: 20,
    });
    expect(value).toBe(0.029);
  });

});
