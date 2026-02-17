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
});
