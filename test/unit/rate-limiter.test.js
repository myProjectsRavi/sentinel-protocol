const { InMemoryRateLimiter } = require('../../src/engines/rate-limiter');

describe('InMemoryRateLimiter', () => {
  test('enforces token bucket and returns retry metadata', () => {
    let now = 1_000;
    const limiter = new InMemoryRateLimiter({
      default_window_ms: 60_000,
      default_limit: 2,
      default_burst: 2,
      clock: () => now,
    });

    const first = limiter.consume({ key: 'agent-a', provider: 'openai' });
    const second = limiter.consume({ key: 'agent-a', provider: 'openai' });
    const third = limiter.consume({ key: 'agent-a', provider: 'openai' });

    expect(first.allowed).toBe(true);
    expect(first.remaining).toBe(1);
    expect(second.allowed).toBe(true);
    expect(second.remaining).toBe(0);
    expect(third.allowed).toBe(false);
    expect(third.retryAfterMs).toBeGreaterThan(0);

    now += 31_000;
    const afterRefill = limiter.consume({ key: 'agent-a', provider: 'openai' });
    expect(afterRefill.allowed).toBe(true);
  });

  test('honors burst above base limit', () => {
    const limiter = new InMemoryRateLimiter({
      default_window_ms: 60_000,
      default_limit: 1,
      default_burst: 3,
    });

    expect(limiter.consume({ key: 'agent-b', provider: 'openai' }).allowed).toBe(true);
    expect(limiter.consume({ key: 'agent-b', provider: 'openai' }).allowed).toBe(true);
    expect(limiter.consume({ key: 'agent-b', provider: 'openai' }).allowed).toBe(true);
    expect(limiter.consume({ key: 'agent-b', provider: 'openai' }).allowed).toBe(false);
  });

  test('tracks rate limits independently per scope', () => {
    const limiter = new InMemoryRateLimiter({
      default_window_ms: 60_000,
      default_limit: 1,
      default_burst: 1,
    });

    expect(limiter.consume({ key: 'agent-c', provider: 'openai', scope: 'rule-a' }).allowed).toBe(true);
    expect(limiter.consume({ key: 'agent-c', provider: 'openai', scope: 'rule-a' }).allowed).toBe(false);

    // Same key/provider but different scope should not share quota.
    expect(limiter.consume({ key: 'agent-c', provider: 'openai', scope: 'rule-b' }).allowed).toBe(true);
  });

  test('prunes stale buckets based on ttl', () => {
    let now = 1_000;
    const limiter = new InMemoryRateLimiter({
      default_window_ms: 60_000,
      default_limit: 10,
      default_burst: 10,
      stale_bucket_ttl_ms: 2_000,
      prune_interval: 1,
      clock: () => now,
    });

    limiter.consume({ key: 'stale-key', provider: 'openai' });
    expect(limiter.snapshot().bucket_count).toBe(1);

    now += 2_500;
    limiter.consume({ key: 'fresh-key', provider: 'openai' });
    expect(limiter.snapshot().bucket_count).toBe(1);
  });

  test('hashes oversized identity keys deterministically', () => {
    const limiter = new InMemoryRateLimiter({
      default_window_ms: 60_000,
      default_limit: 10,
      default_burst: 10,
      max_key_length: 24,
    });

    const longKey = `agent:${'x'.repeat(200)}`;
    const first = limiter.consume({ key: longKey, provider: 'openai', scope: 'policy' });
    const second = limiter.consume({ key: longKey, provider: 'openai', scope: 'policy' });

    expect(first.key).toContain('sha256:');
    expect(first.key).toBe(second.key);
    expect(first.remaining).toBe(9);
    expect(second.remaining).toBe(8);
  });
});
