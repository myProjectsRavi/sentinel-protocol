const { SerializationFirewall } = require('../../src/security/serialization-firewall');

describe('SerializationFirewall', () => {
  test('allows clean JSON payload', () => {
    const firewall = new SerializationFirewall({
      enabled: true,
      mode: 'block',
      metadata_ratio_threshold: 8,
    });
    const decision = firewall.evaluate({
      headers: {
        'content-type': 'application/json',
      },
      rawBody: Buffer.from('{"ok":true}', 'utf8'),
      bodyText: '{"ok":true}',
      bodyJson: { ok: true },
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(false);
    expect(decision.shouldBlock).toBe(false);
    expect(decision.reason).toBe('clean');
  });

  test('blocks gadget-like type confusion payload in enforce mode', () => {
    const firewall = new SerializationFirewall({
      enabled: true,
      mode: 'block',
      block_on_type_confusion: true,
    });
    const decision = firewall.evaluate({
      headers: {
        'content-type': 'application/json',
      },
      bodyText: '__reduce__: os.system',
      bodyJson: { __reduce__: 'os.system' },
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.findings.some((item) => item.code === 'serialization_type_confusion_gadget')).toBe(true);
    expect(decision.shouldBlock).toBe(true);
  });

  test('supports metadata ratio thresholds above 1.0', () => {
    const firewall = new SerializationFirewall({
      enabled: true,
      mode: 'block',
      metadata_ratio_threshold: 2.5,
      block_on_metadata_anomaly: true,
    });
    const decision = firewall.evaluate({
      headers: {
        'content-type': 'application/json',
      },
      bodyText: '@@@@@@@@@@@@#######$$$%%%^&*()',
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.findings.some((item) => item.code === 'serialization_metadata_anomaly')).toBe(true);
    expect(decision.shouldBlock).toBe(true);
  });

  test('detects disallowed formats without blocking by default', () => {
    const firewall = new SerializationFirewall({
      enabled: true,
      mode: 'block',
      allowed_formats: ['json'],
      block_on_format_violation: false,
    });
    const decision = firewall.evaluate({
      headers: {
        'content-type': 'application/x-protobuf',
      },
      rawBody: Buffer.from([0x0a, 0x01, 0x01]),
      bodyText: '',
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.findings.some((item) => item.code === 'serialization_format_disallowed')).toBe(true);
    expect(decision.shouldBlock).toBe(false);
  });
});
