const { Readable } = require('stream');

const { PIIScanner } = require('../../src/engines/pii-scanner');
const { SSERedactionTransform } = require('../../src/egress/sse-redaction-transform');

async function collect(stream) {
  const chunks = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8'));
  }
  return Buffer.concat(chunks).toString('utf8');
}

describe('SSERedactionTransform', () => {
  test('redacts pii in SSE data lines across chunk boundaries', async () => {
    const scanner = new PIIScanner({
      maxScanBytes: 262144,
      regexSafetyCapBytes: 51200,
    });
    const transform = new SSERedactionTransform({
      scanner,
      maxScanBytes: 65536,
      maxLineBytes: 16384,
      severityActions: { critical: 'block', high: 'block', medium: 'redact', low: 'log' },
      effectiveMode: 'enforce',
    });

    const source = Readable.from([
      Buffer.from('event: token\n', 'utf8'),
      Buffer.from('data: contact john@examp', 'utf8'),
      Buffer.from('le.com\n\n', 'utf8'),
    ]);

    const out = await collect(source.pipe(transform));
    expect(out).toContain('event: token');
    expect(out).toContain('[REDACTED_EMAIL_ADDRESS]');
    expect(out).not.toContain('john@example.com');
  });

  test('supports terminate mode for block-severity findings', async () => {
    const scanner = new PIIScanner({
      maxScanBytes: 262144,
      regexSafetyCapBytes: 51200,
    });
    const detections = [];
    const transform = new SSERedactionTransform({
      scanner,
      maxScanBytes: 65536,
      maxLineBytes: 16384,
      severityActions: { critical: 'block', high: 'block', medium: 'redact', low: 'log' },
      effectiveMode: 'enforce',
      streamBlockMode: 'terminate',
      onDetection: (event) => detections.push(event),
    });

    const source = Readable.from([
      Buffer.from('data: openai key sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefgh\n\n', 'utf8'),
    ]);

    const out = await collect(source.pipe(transform));
    expect(out).not.toContain('sk-proj-');
    expect(out.trim()).toBe('');
    expect(detections.length).toBeGreaterThan(0);
    expect(detections[0].action).toBe('block');
  });
});
