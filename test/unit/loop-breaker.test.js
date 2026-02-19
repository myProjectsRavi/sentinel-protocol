const { LoopBreaker } = require('../../src/engines/loop-breaker');

describe('LoopBreaker', () => {
  test('detects repeated identical payload hashes within the window', () => {
    const breaker = new LoopBreaker({
      enabled: true,
      action: 'block',
      window_ms: 30000,
      repeat_threshold: 4,
      max_recent: 5,
      max_keys: 100,
      key_header: 'x-sentinel-agent-id',
    });

    const baseInput = {
      headers: {
        'x-sentinel-agent-id': 'agent-1',
      },
      provider: 'openai',
      method: 'POST',
      path: '/v1/chat/completions',
      bodyJson: {
        messages: [{ role: 'user', content: 'same prompt' }],
      },
    };

    expect(breaker.evaluate({ ...baseInput, now: 1000 }).detected).toBe(false);
    expect(breaker.evaluate({ ...baseInput, now: 2000 }).detected).toBe(false);
    expect(breaker.evaluate({ ...baseInput, now: 3000 }).detected).toBe(false);

    const fourth = breaker.evaluate({ ...baseInput, now: 4000 });
    expect(fourth.detected).toBe(true);
    expect(fourth.shouldBlock).toBe(true);
    expect(fourth.streak).toBe(4);
  });

  test('does not detect loop when payload changes', () => {
    const breaker = new LoopBreaker({
      enabled: true,
      repeat_threshold: 3,
      max_recent: 5,
      window_ms: 30000,
    });

    const first = breaker.evaluate({
      headers: { 'x-sentinel-agent-id': 'agent-2' },
      provider: 'openai',
      path: '/v1/chat/completions',
      method: 'POST',
      bodyText: 'alpha',
      now: 1000,
    });
    const second = breaker.evaluate({
      headers: { 'x-sentinel-agent-id': 'agent-2' },
      provider: 'openai',
      path: '/v1/chat/completions',
      method: 'POST',
      bodyText: 'beta',
      now: 2000,
    });
    const third = breaker.evaluate({
      headers: { 'x-sentinel-agent-id': 'agent-2' },
      provider: 'openai',
      path: '/v1/chat/completions',
      method: 'POST',
      bodyText: 'alpha',
      now: 3000,
    });

    expect(first.detected).toBe(false);
    expect(second.detected).toBe(false);
    expect(third.detected).toBe(false);
  });

  test('warn action detects but does not hard-block', () => {
    const breaker = new LoopBreaker({
      enabled: true,
      action: 'warn',
      repeat_threshold: 2,
      max_recent: 5,
      window_ms: 30000,
    });

    breaker.evaluate({
      headers: { 'x-sentinel-agent-id': 'agent-3' },
      provider: 'openai',
      path: '/v1/chat/completions',
      method: 'POST',
      bodyText: 'same',
      now: 1000,
    });
    const second = breaker.evaluate({
      headers: { 'x-sentinel-agent-id': 'agent-3' },
      provider: 'openai',
      path: '/v1/chat/completions',
      method: 'POST',
      bodyText: 'same',
      now: 1500,
    });

    expect(second.detected).toBe(true);
    expect(second.shouldBlock).toBe(false);
  });

  test('ignores volatile metadata when fingerprinting conversation state', () => {
    const breaker = new LoopBreaker({
      enabled: true,
      action: 'block',
      repeat_threshold: 3,
      max_recent: 5,
      window_ms: 30000,
    });

    const makeBody = (traceId, timestamp) => ({
      trace_id: traceId,
      timestamp,
      messages: [
        { role: 'system', content: 'You are a planner.' },
        { role: 'user', content: 'Generate next tool call.' },
      ],
    });

    const first = breaker.evaluate({
      headers: { 'x-sentinel-agent-id': 'agent-loop' },
      provider: 'openai',
      path: '/v1/chat/completions',
      method: 'POST',
      bodyJson: makeBody('trace-1', 1000),
      now: 1000,
    });
    const second = breaker.evaluate({
      headers: { 'x-sentinel-agent-id': 'agent-loop' },
      provider: 'openai',
      path: '/v1/chat/completions',
      method: 'POST',
      bodyJson: makeBody('trace-2', 2000),
      now: 2000,
    });
    const third = breaker.evaluate({
      headers: { 'x-sentinel-agent-id': 'agent-loop' },
      provider: 'openai',
      path: '/v1/chat/completions',
      method: 'POST',
      bodyJson: makeBody('trace-3', 3000),
      now: 3000,
    });

    expect(first.detected).toBe(false);
    expect(second.detected).toBe(false);
    expect(third.detected).toBe(true);
    expect(third.shouldBlock).toBe(true);
  });
});
