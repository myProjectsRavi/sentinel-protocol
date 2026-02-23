const { StegoExfilDetector } = require('../../src/egress/stego-exfil-detector');

describe('StegoExfilDetector', () => {
  test('detects high-density zero width payload and blocks in enforce mode', () => {
    const detector = new StegoExfilDetector({
      enabled: true,
      mode: 'block',
      block_on_detect: true,
      zero_width_density_threshold: 0.01,
    });

    const payload = `hello${'\u200b'.repeat(120)}world`;
    const decision = detector.analyzeText(payload, { effectiveMode: 'enforce' });
    expect(decision.detected).toBe(true);
    expect(decision.shouldBlock).toBe(true);
    expect(decision.findings.some((item) => item.code === 'stego_zero_width_density')).toBe(true);
  });

  test('ignores non-textual content in buffer mode', () => {
    const detector = new StegoExfilDetector({ enabled: true });
    const decision = detector.analyzeBuffer({
      bodyBuffer: Buffer.from([0x00, 0xff, 0x01]),
      contentType: 'application/octet-stream',
      effectiveMode: 'monitor',
    });
    expect(decision.detected).toBe(false);
  });
});
