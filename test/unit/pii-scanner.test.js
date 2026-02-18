const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.SENTINEL_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-home-pii-'));

const { PIIScanner } = require('../../src/engines/pii-scanner');

describe('PII scanner', () => {
  test('catalog includes at least 80 patterns', () => {
    const scanner = new PIIScanner();
    expect(scanner.patterns.length).toBeGreaterThanOrEqual(80);
  });

  test('detects and redacts critical API keys', () => {
    const scanner = new PIIScanner();
    const input = 'openai key: sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef';
    const result = scanner.scan(input);

    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.some((item) => item.id === 'openai_api_key')).toBe(true);
    expect(result.redactedText).toContain('[REDACTED_OPENAI_API_KEY]');
  });

  test('enforces regex safety cap for oversized input', () => {
    const scanner = new PIIScanner({
      maxScanBytes: 200000,
      regexSafetyCapBytes: 1024,
    });

    const oversized = `${'a'.repeat(1500)} openai key: sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef`;
    const result = scanner.scan(oversized);
    expect(result.scanTruncated).toBe(true);
  });

  test('supports format-preserving redaction mode', () => {
    const scanner = new PIIScanner({
      redactionMode: 'format_preserving',
      redactionSalt: 'unit-test-salt',
    });
    const input = 'Contact me at ravi@gmail.com or +1 (555) 123-9876';
    const result = scanner.scan(input);

    expect(result.findings.some((f) => f.id === 'email_address')).toBe(true);
    expect(result.redactedText).not.toContain('ravi@gmail.com');
    expect(result.redactedText).toMatch(/user_[a-z]{8}@example\.com/);
    expect(result.redactedText).toMatch(/\+1 \(\d{3}\) \d{3}-\d{4}/);
  });
});
