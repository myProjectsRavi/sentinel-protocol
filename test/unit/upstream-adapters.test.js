const { selectUpstreamAdapter } = require('../../src/upstream/adapters');

describe('upstream adapters', () => {
  test('returns identity adapter for passthrough contract', () => {
    const selection = selectUpstreamAdapter({
      desiredContract: 'passthrough',
      candidateContract: 'passthrough',
      provider: 'openai',
      candidate: {},
    });

    expect(selection.ok).toBe(true);
    expect(selection.adapter.name).toBe('identity');
    expect(selection.adapter.supportsStreaming).toBe(true);
  });

  test('adapts openai chat request to anthropic messages request', () => {
    const selection = selectUpstreamAdapter({
      desiredContract: 'openai_chat_v1',
      candidateContract: 'anthropic_messages_v1',
      provider: 'anthropic',
      candidate: {
        staticHeaders: {},
      },
    });

    expect(selection.ok).toBe(true);
    const prepared = selection.adapter.prepareRequest({
      method: 'POST',
      pathWithQuery: '/v1/chat/completions',
      bodyJson: {
        model: 'gpt-4o-mini',
        max_tokens: 256,
        messages: [
          { role: 'system', content: 'You are helpful' },
          { role: 'user', content: 'hello' },
        ],
      },
      bodyBuffer: Buffer.alloc(0),
      reqHeaders: {},
      wantsStream: false,
      candidate: {},
    });

    expect(prepared.pathWithQuery).toBe('/v1/messages');
    const payload = JSON.parse(prepared.bodyBuffer.toString('utf8'));
    expect(payload.model).toBe('gpt-4o-mini');
    expect(payload.messages).toEqual([{ role: 'user', content: 'hello' }]);
    expect(payload.system).toContain('You are helpful');
    expect(prepared.headerOverrides['anthropic-version']).toBeDefined();
  });

  test('transforms anthropic response into openai chat completion shape', () => {
    const selection = selectUpstreamAdapter({
      desiredContract: 'openai_chat_v1',
      candidateContract: 'anthropic_messages_v1',
      provider: 'anthropic',
      candidate: {},
    });

    const transformed = selection.adapter.transformBufferedResponse({
      status: 200,
      responseHeaders: { 'content-type': 'application/json' },
      bodyBuffer: Buffer.from(JSON.stringify({
        id: 'msg_123',
        model: 'claude-3-5-sonnet-latest',
        content: [{ type: 'text', text: 'Paris' }],
        stop_reason: 'end_turn',
        usage: {
          input_tokens: 11,
          output_tokens: 7,
        },
      })),
      candidate: {},
    });

    const payload = JSON.parse(transformed.bodyBuffer.toString('utf8'));
    expect(payload.object).toBe('chat.completion');
    expect(payload.choices[0].message.content).toBe('Paris');
    expect(payload.usage.prompt_tokens).toBe(11);
    expect(payload.usage.completion_tokens).toBe(7);
  });

  test('returns unsupported for unknown conversion', () => {
    const selection = selectUpstreamAdapter({
      desiredContract: 'google_generative_v1',
      candidateContract: 'anthropic_messages_v1',
      provider: 'anthropic',
      candidate: {},
    });

    expect(selection.ok).toBe(false);
    expect(selection.reason).toMatch(/No adapter/);
  });

  test('adapts openai chat request to ollama chat and back', () => {
    const selection = selectUpstreamAdapter({
      desiredContract: 'openai_chat_v1',
      candidateContract: 'ollama_chat_v1',
      provider: 'ollama',
      candidate: {},
    });

    expect(selection.ok).toBe(true);
    const prepared = selection.adapter.prepareRequest({
      method: 'POST',
      pathWithQuery: '/v1/chat/completions',
      bodyJson: {
        model: 'llama3.1',
        max_tokens: 128,
        temperature: 0.2,
        messages: [
          { role: 'system', content: 'You are concise.' },
          { role: 'user', content: 'Hello' },
        ],
      },
      bodyBuffer: Buffer.alloc(0),
      reqHeaders: {},
      wantsStream: false,
      candidate: {},
    });

    expect(prepared.pathWithQuery).toBe('/api/chat');
    const payload = JSON.parse(prepared.bodyBuffer.toString('utf8'));
    expect(payload.model).toBe('llama3.1');
    expect(payload.stream).toBe(false);
    expect(payload.messages).toHaveLength(2);
    expect(payload.options.num_predict).toBe(128);

    const transformed = selection.adapter.transformBufferedResponse({
      status: 200,
      responseHeaders: { 'content-type': 'application/json' },
      bodyBuffer: Buffer.from(
        JSON.stringify({
          model: 'llama3.1',
          created_at: '2026-02-19T00:00:00.000Z',
          message: {
            role: 'assistant',
            content: 'Hello from local model',
          },
          done_reason: 'stop',
          prompt_eval_count: 22,
          eval_count: 9,
        })
      ),
      candidate: {},
    });

    const out = JSON.parse(transformed.bodyBuffer.toString('utf8'));
    expect(out.object).toBe('chat.completion');
    expect(out.choices[0].message.content).toBe('Hello from local model');
    expect(out.usage.prompt_tokens).toBe(22);
    expect(out.usage.completion_tokens).toBe(9);
  });
});
