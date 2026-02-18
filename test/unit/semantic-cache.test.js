const { SemanticCache } = require('../../src/cache/semantic-cache');

describe('SemanticCache', () => {
  test('stores and returns semantically similar responses when enabled', async () => {
    const cache = new SemanticCache({
      enabled: true,
      similarity_threshold: 0.8,
      max_entries: 10,
      ttl_ms: 60000,
      max_prompt_chars: 1000,
    });

    cache.embedFn = async (text) => {
      const input = String(text || '').toLowerCase();
      if (input.includes('france') && input.includes('capital')) return [1, 0];
      if (input.includes('france')) return [0.9, 0.1];
      return [0, 1];
    };

    const request = {
      provider: 'openai',
      method: 'POST',
      pathWithQuery: '/v1/chat/completions',
      wantsStream: false,
      bodyJson: {
        model: 'gpt-test',
        messages: [{ role: 'user', content: 'What is the capital of France?' }],
      },
    };

    const storeResult = await cache.store({
      ...request,
      responseStatus: 200,
      responseHeaders: { 'content-type': 'application/json' },
      responseBodyBuffer: Buffer.from(JSON.stringify({ answer: 'Paris' })),
    });
    expect(storeResult.stored).toBe(true);

    const lookup = await cache.lookup({
      ...request,
      bodyJson: {
        model: 'gpt-test',
        messages: [{ role: 'user', content: 'Tell me France capital city' }],
      },
    });

    expect(lookup.hit).toBe(true);
    expect(lookup.response.status).toBe(200);
    expect(lookup.response.bodyBuffer.toString('utf8')).toContain('Paris');
  });

  test('is disabled by default', async () => {
    const cache = new SemanticCache({});
    const result = await cache.lookup({
      provider: 'openai',
      method: 'POST',
      pathWithQuery: '/v1/chat/completions',
      wantsStream: false,
      bodyJson: { messages: [{ role: 'user', content: 'hello' }] },
    });
    expect(result.hit).toBe(false);
    expect(result.reason).toBe('disabled');
  });
});
