const { PIIScanner } = require('../../src/engines/pii-scanner');
const { scanBufferedResponse } = require('../../src/egress/response-scanner');

function scanner() {
  return new PIIScanner({
    maxScanBytes: 262144,
    regexSafetyCapBytes: 51200,
  });
}

describe('scanBufferedResponse', () => {
  test('redacts medium severity findings for textual responses', () => {
    const body = Buffer.from(JSON.stringify({ output: 'contact john@example.com' }), 'utf8');
    const result = scanBufferedResponse({
      bodyBuffer: body,
      contentType: 'application/json',
      scanner: scanner(),
      maxScanBytes: 65536,
      severityActions: { critical: 'block', high: 'block', medium: 'redact', low: 'log' },
      effectiveMode: 'enforce',
    });

    expect(result.detected).toBe(true);
    expect(result.redacted).toBe(true);
    expect(result.blocked).toBe(false);
    expect(result.bodyBuffer.toString('utf8')).toContain('[REDACTED_EMAIL_ADDRESS]');
    expect(result.bodyBuffer.toString('utf8')).not.toContain('john@example.com');
  });

  test('blocks critical findings in enforce mode', () => {
    const body = Buffer.from(
      JSON.stringify({ output: 'openai key sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefgh' }),
      'utf8'
    );
    const result = scanBufferedResponse({
      bodyBuffer: body,
      contentType: 'application/json',
      scanner: scanner(),
      maxScanBytes: 65536,
      severityActions: { critical: 'block', high: 'block', medium: 'redact', low: 'log' },
      effectiveMode: 'enforce',
    });

    expect(result.detected).toBe(true);
    expect(result.blocked).toBe(true);
    expect(result.redacted).toBe(false);
  });
});
