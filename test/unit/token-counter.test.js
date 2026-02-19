const {
  countTokensFromText,
  countTokensFromBuffer,
  extractUsageFromResponseBody,
  estimateUsageFromBuffers,
  estimateUsageFromStream,
  computeCostUsd,
} = require('../../src/accounting/token-counter');

describe('token counter', () => {
  test('counts tokens from text/buffer using deterministic ratio', () => {
    expect(countTokensFromText('')).toBe(0);
    expect(countTokensFromText('hello', 4)).toBeGreaterThanOrEqual(1);
    expect(countTokensFromBuffer(Buffer.from('hello world'), 4)).toBeGreaterThanOrEqual(1);
  });

  test('extracts provider usage when response includes usage object', () => {
    const body = Buffer.from(JSON.stringify({
      id: 'abc',
      usage: {
        prompt_tokens: 12,
        completion_tokens: 8,
        total_tokens: 20,
      },
    }));
    const usage = extractUsageFromResponseBody(body);
    expect(usage).toEqual({
      inputTokens: 12,
      outputTokens: 8,
      totalTokens: 20,
      source: 'upstream_usage',
    });
  });

  test('falls back to estimated usage and computes usd', () => {
    const usage = estimateUsageFromBuffers({
      requestBodyBuffer: Buffer.from('request'),
      responseBodyBuffer: Buffer.from('response'),
      charsPerToken: 4,
    });
    expect(usage.totalTokens).toBe(usage.inputTokens + usage.outputTokens);

    const streamUsage = estimateUsageFromStream({
      requestBodyBuffer: Buffer.from('req'),
      streamedBytes: 120,
      charsPerToken: 4,
    });
    expect(streamUsage.outputTokens).toBeGreaterThan(0);

    const cost = computeCostUsd({
      inputTokens: 1000,
      outputTokens: 1000,
      inputCostPer1k: 0.001,
      outputCostPer1k: 0.002,
    });
    expect(cost).toBeCloseTo(0.003, 6);
  });
});
