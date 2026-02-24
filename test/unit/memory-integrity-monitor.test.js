const { MemoryIntegrityMonitor } = require('../../src/security/memory-integrity-monitor');

describe('MemoryIntegrityMonitor', () => {
  test('blocks on external chain break in enforce mode', () => {
    const monitor = new MemoryIntegrityMonitor({
      enabled: true,
      mode: 'block',
      block_on_chain_break: true,
    });

    const first = monitor.evaluate({
      headers: {
        'x-sentinel-session-id': 'sess-a',
        'x-sentinel-agent-id': 'agent-a',
      },
      bodyJson: {
        memory: 'baseline memory',
      },
      effectiveMode: 'enforce',
    });

    expect(first.detected).toBe(false);

    const second = monitor.evaluate({
      headers: {
        'x-sentinel-session-id': 'sess-a',
        'x-sentinel-agent-id': 'agent-a',
        'x-sentinel-memory-chain': 'unexpected-chain',
      },
      bodyJson: {
        memory: 'next memory',
      },
      effectiveMode: 'enforce',
    });

    expect(second.detected).toBe(true);
    expect(second.findings.some((item) => item.code === 'memory_integrity_chain_break')).toBe(true);
    expect(second.shouldBlock).toBe(true);
  });

  test('blocks on abnormal memory growth in enforce mode', () => {
    const monitor = new MemoryIntegrityMonitor({
      enabled: true,
      mode: 'block',
      block_on_growth: true,
      max_growth_ratio: 1.5,
    });

    monitor.evaluate({
      headers: {
        'x-sentinel-session-id': 'sess-growth',
        'x-sentinel-agent-id': 'agent-a',
      },
      bodyJson: {
        memory: 'short',
      },
      effectiveMode: 'enforce',
    });

    const second = monitor.evaluate({
      headers: {
        'x-sentinel-session-id': 'sess-growth',
        'x-sentinel-agent-id': 'agent-a',
      },
      bodyJson: {
        memory: 'long memory '.repeat(200),
      },
      effectiveMode: 'enforce',
    });

    expect(second.detected).toBe(true);
    expect(second.findings.some((item) => item.code === 'memory_integrity_growth_spike')).toBe(true);
    expect(second.shouldBlock).toBe(true);
  });

  test('detects owner mismatch without blocking in monitor mode', () => {
    const monitor = new MemoryIntegrityMonitor({
      enabled: true,
      mode: 'monitor',
      block_on_owner_mismatch: true,
    });

    monitor.evaluate({
      headers: {
        'x-sentinel-session-id': 'sess-owner',
        'x-sentinel-agent-id': 'agent-a',
      },
      bodyJson: {
        memory: 'owner a',
      },
      effectiveMode: 'enforce',
    });

    const second = monitor.evaluate({
      headers: {
        'x-sentinel-session-id': 'sess-owner',
        'x-sentinel-agent-id': 'agent-b',
      },
      bodyJson: {
        memory: 'owner b',
      },
      effectiveMode: 'enforce',
    });

    expect(second.detected).toBe(true);
    expect(second.findings.some((item) => item.code === 'memory_integrity_owner_mismatch')).toBe(true);
    expect(second.shouldBlock).toBe(false);
  });
});

