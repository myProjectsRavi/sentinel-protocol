const { DeceptionEngine } = require('../../src/engines/deception-engine');

describe('DeceptionEngine', () => {
  test('engages for high-confidence injection in enforce mode', () => {
    const engine = new DeceptionEngine({
      enabled: true,
      mode: 'tarpit',
      min_injection_score: 0.8,
    });

    const result = engine.shouldEngage({
      trigger: 'injection',
      injectionScore: 0.9,
      effectiveMode: 'enforce',
    });

    expect(result.engage).toBe(true);
  });

  test('does not engage in monitor mode', () => {
    const engine = new DeceptionEngine({
      enabled: true,
      mode: 'tarpit',
    });

    const result = engine.shouldEngage({
      trigger: 'loop',
      effectiveMode: 'monitor',
    });

    expect(result.engage).toBe(false);
  });

  test('creates valid buffered payload', () => {
    const engine = new DeceptionEngine({
      enabled: true,
      mode: 'tarpit',
    });

    const payload = engine.createBufferedPayload({
      trigger: 'injection',
      provider: 'openai',
    });
    const parsed = JSON.parse(payload.toString('utf8'));

    expect(parsed.object).toBe('chat.completion');
    expect(parsed.model).toBe('sentinel-phantom-1');
    expect(parsed.sentinel_deception.trigger).toBe('injection');
  });

  test('streams SSE chunks and done marker', async () => {
    const engine = new DeceptionEngine({
      enabled: true,
      mode: 'tarpit',
      sse_max_tokens: 2,
      sse_token_interval_ms: 1,
    });

    const writes = [];
    const res = {
      destroyed: false,
      writableEnded: false,
      write(chunk) {
        writes.push(Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk));
      },
      end() {
        this.writableEnded = true;
      },
    };

    const result = await engine.streamToSSE(res, { trigger: 'loop' });
    expect(result.streamedBytes).toBeGreaterThan(0);
    expect(writes.some((line) => line.includes('data: '))).toBe(true);
    expect(writes[writes.length - 1]).toContain('[DONE]');
  });
});
