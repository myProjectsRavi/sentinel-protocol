const { SemanticCache } = require('../../src/cache/semantic-cache');

describe('SemanticCache', () => {
  test('stores and returns semantically similar responses when enabled', async () => {
    const scanWorkerPool = {
      enabled: true,
      embed: async ({ text }) => {
        const input = String(text || '').toLowerCase();
        if (input.includes('france') && input.includes('capital')) return { vector: [1, 0] };
        if (input.includes('france')) return { vector: [0.9, 0.1] };
        return { vector: [0, 1] };
      },
    };
    const cache = new SemanticCache({
      enabled: true,
      similarity_threshold: 0.8,
      max_entries: 10,
      ttl_ms: 60000,
      max_prompt_chars: 1000,
      max_entry_bytes: 1024,
      max_ram_mb: 1,
    }, { scanWorkerPool });

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

  test('rejects oversized responses by max_entry_bytes', async () => {
    const scanWorkerPool = {
      enabled: true,
      embed: async () => ({ vector: [1, 0, 0] }),
    };
    const cache = new SemanticCache({
      enabled: true,
      max_entry_bytes: 32,
    }, { scanWorkerPool });

    const storeResult = await cache.store({
      provider: 'openai',
      method: 'POST',
      pathWithQuery: '/v1/chat/completions',
      wantsStream: false,
      bodyJson: {
        model: 'gpt-test',
        messages: [{ role: 'user', content: 'hello' }],
      },
      responseStatus: 200,
      responseHeaders: { 'content-type': 'application/json' },
      responseBodyBuffer: Buffer.from(JSON.stringify({ very_large: 'x'.repeat(200) })),
    });

    expect(storeResult.stored).toBe(false);
    expect(storeResult.reason).toBe('entry_too_large');
  });

  test('requires worker pool when cache is enabled', async () => {
    const cache = new SemanticCache({
      enabled: true,
    });

    const result = await cache.lookup({
      provider: 'openai',
      method: 'POST',
      pathWithQuery: '/v1/chat/completions',
      wantsStream: false,
      bodyJson: { messages: [{ role: 'user', content: 'hello' }] },
    });

    expect(result.hit).toBe(false);
    expect(result.reason).toBe('worker_pool_unavailable');
  });

  test('enters runtime backoff after consecutive embed failures', async () => {
    const scanWorkerPool = {
      enabled: true,
      embed: jest.fn(async () => ({ vector: [1, 0] })),
    };
    const cache = new SemanticCache({
      enabled: true,
      similarity_threshold: 0.8,
      max_consecutive_errors: 2,
      failure_cooldown_ms: 60000,
    }, { scanWorkerPool });

    const request = {
      provider: 'openai',
      method: 'POST',
      pathWithQuery: '/v1/chat/completions',
      wantsStream: false,
      bodyJson: { messages: [{ role: 'user', content: 'hello world' }] },
    };

    const seedStore = await cache.store({
      ...request,
      responseStatus: 200,
      responseHeaders: { 'content-type': 'application/json' },
      responseBodyBuffer: Buffer.from(JSON.stringify({ answer: 'ok' })),
    });
    expect(seedStore.stored).toBe(true);

    scanWorkerPool.embed.mockImplementation(async () => {
      throw new Error('embed worker unavailable');
    });

    const first = await cache.lookup(request);
    expect(first.hit).toBe(false);
    expect(first.reason).toBe('embed_error');

    const second = await cache.lookup(request);
    expect(second.hit).toBe(false);
    expect(second.reason).toBe('embed_error');

    const third = await cache.lookup(request);
    expect(third.hit).toBe(false);
    expect(third.reason).toBe('runtime_backoff');
    // One embed for seed store, then two failing embed attempts.
    expect(scanWorkerPool.embed).toHaveBeenCalledTimes(3);
  });
});
