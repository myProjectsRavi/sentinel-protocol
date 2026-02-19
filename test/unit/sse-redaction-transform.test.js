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
    expect(detections[0].projectedRedaction).toContain('[REDACTED_OPENAI_API_KEY]');
  });

  test('detects entropy in monitor mode and keeps stream flowing', async () => {
    const scanner = new PIIScanner({
      maxScanBytes: 262144,
      regexSafetyCapBytes: 51200,
    });
    const entropyEvents = [];
    const transform = new SSERedactionTransform({
      scanner,
      maxScanBytes: 65536,
      maxLineBytes: 16384,
      severityActions: { critical: 'block', high: 'block', medium: 'redact', low: 'log' },
      effectiveMode: 'enforce',
      entropyConfig: {
        enabled: true,
        mode: 'monitor',
        threshold: 4.3,
        min_token_length: 24,
      },
      onEntropy: (event) => entropyEvents.push(event),
    });

    const source = Readable.from([
      Buffer.from('data: QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3ODkwQUJDREVGR0hJSktM\n\n', 'utf8'),
    ]);

    const out = await collect(source.pipe(transform));
    expect(out).toContain('QUJDREVGR0hJSktM');
    expect(entropyEvents.length).toBeGreaterThan(0);
    expect(entropyEvents[0].action).toBe('monitor');
  });

  test('terminates stream in enforce mode when entropy block is enabled', async () => {
    const scanner = new PIIScanner({
      maxScanBytes: 262144,
      regexSafetyCapBytes: 51200,
    });
    const entropyEvents = [];
    const transform = new SSERedactionTransform({
      scanner,
      maxScanBytes: 65536,
      maxLineBytes: 16384,
      severityActions: { critical: 'block', high: 'block', medium: 'redact', low: 'log' },
      effectiveMode: 'enforce',
      streamBlockMode: 'terminate',
      entropyConfig: {
        enabled: true,
        mode: 'block',
        threshold: 4.3,
        min_token_length: 24,
      },
      onEntropy: (event) => entropyEvents.push(event),
    });

    const source = Readable.from([
      Buffer.from('data: U2VudGluZWxQcm90b2NvbEV4ZmlsVGVzdERhdGFCbG9iMDEyMzQ1Njc4OUFCQ0RFRg==\n\n', 'utf8'),
    ]);

    const out = await collect(source.pipe(transform));
    expect(out.trim()).toBe('');
    expect(entropyEvents.length).toBeGreaterThan(0);
    expect(entropyEvents[0].action).toBe('block');
  });
});
