const { LatencyNormalizer } = require('../../src/runtime/latency-normalizer');

describe('LatencyNormalizer', () => {
  test('is disabled by default', () => {
    const normalizer = new LatencyNormalizer();
    const plan = normalizer.planDelay({
      elapsedMs: 10,
      statusCode: 403,
    });
    expect(plan.apply).toBe(false);
    expect(plan.reason).toBe('disabled');
  });

  test('requires enough success samples before delay', () => {
    const normalizer = new LatencyNormalizer({
      enabled: true,
      window_size: 5,
      min_samples: 3,
      statuses: [403],
    });
    normalizer.recordSuccess(100);
    normalizer.recordSuccess(120);
    const plan = normalizer.planDelay({
      elapsedMs: 20,
      statusCode: 403,
    });
    expect(plan.apply).toBe(false);
    expect(plan.reason).toBe('insufficient_samples');
  });

  test('computes bounded delay with jitter for eligible blocked status', () => {
    const normalizer = new LatencyNormalizer(
      {
        enabled: true,
        window_size: 5,
        min_samples: 3,
        max_delay_ms: 200,
        jitter_ms: 0,
        statuses: [403],
      },
      {
        random: () => 0.5,
      }
    );
    normalizer.recordSuccess(100);
    normalizer.recordSuccess(110);
    normalizer.recordSuccess(90);

    const plan = normalizer.planDelay({
      elapsedMs: 10,
      statusCode: 403,
    });
    expect(plan.apply).toBe(true);
    expect(plan.delayMs).toBeGreaterThan(0);
    expect(plan.delayMs).toBeLessThanOrEqual(200);
  });

  test('does not delay non-eligible status', () => {
    const normalizer = new LatencyNormalizer({
      enabled: true,
      statuses: [403],
      min_samples: 1,
    });
    normalizer.recordSuccess(100);
    const plan = normalizer.planDelay({
      elapsedMs: 1,
      statusCode: 500,
    });
    expect(plan.apply).toBe(false);
    expect(plan.reason).toBe('status_not_eligible');
  });
});
