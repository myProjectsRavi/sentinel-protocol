const {
  MCPCertificatePinning,
  normalizeFingerprint,
} = require('../../src/security/mcp-certificate-pinning');

describe('MCPCertificatePinning', () => {
  test('normalizes sha256 hex fingerprints', () => {
    const input = 'sha256:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99';
    const normalized = normalizeFingerprint(input);
    expect(normalized).toBe('aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899');
  });

  test('allows unpinned server when configured', () => {
    const engine = new MCPCertificatePinning({
      enabled: true,
      mode: 'monitor',
      allow_unpinned_servers: true,
    });

    const decision = engine.inspect({
      headers: {
        'x-sentinel-mcp-server-id': 'mcp-a',
        'x-sentinel-mcp-cert-sha256': 'a'.repeat(64),
      },
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(false);
    expect(decision.shouldBlock).toBe(false);
  });

  test('detects mismatch against pinned fingerprint and blocks when configured', () => {
    const engine = new MCPCertificatePinning({
      enabled: true,
      mode: 'block',
      pins: {
        'mcp-prod': ['b'.repeat(64)],
      },
      block_on_mismatch: true,
    });

    const decision = engine.inspect({
      headers: {
        'x-sentinel-mcp-server-id': 'mcp-prod',
        'x-sentinel-mcp-cert-sha256': 'a'.repeat(64),
      },
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.reason).toBe('mcp_certificate_pin_mismatch');
    expect(decision.shouldBlock).toBe(true);
  });

  test('detects certificate rotation between requests', () => {
    const engine = new MCPCertificatePinning({
      enabled: true,
      mode: 'monitor',
      detect_rotation: true,
    });

    const first = engine.inspect({
      headers: {
        'x-sentinel-mcp-server-id': 'mcp-rot',
        'x-sentinel-mcp-cert-sha256': '1'.repeat(64),
      },
      effectiveMode: 'monitor',
    });
    expect(first.detected).toBe(false);

    const second = engine.inspect({
      headers: {
        'x-sentinel-mcp-server-id': 'mcp-rot',
        'x-sentinel-mcp-cert-sha256': '2'.repeat(64),
      },
      effectiveMode: 'monitor',
    });

    expect(second.detected).toBe(true);
    expect(second.findings.some((item) => item.code === 'mcp_certificate_rotation_detected')).toBe(true);
    expect(second.shouldBlock).toBe(false);
  });

  test('flags missing fingerprint when server has configured pins', () => {
    const engine = new MCPCertificatePinning({
      enabled: true,
      mode: 'monitor',
      pins: {
        'mcp-pin-required': ['c'.repeat(64)],
      },
      require_fingerprint_for_pinned_servers: true,
    });

    const decision = engine.inspect({
      headers: {
        'x-sentinel-mcp-server-id': 'mcp-pin-required',
      },
      effectiveMode: 'monitor',
    });

    expect(decision.detected).toBe(true);
    expect(decision.reason).toBe('mcp_certificate_missing');
    expect(decision.shouldBlock).toBe(false);
  });
});
