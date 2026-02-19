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
});
