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
});
