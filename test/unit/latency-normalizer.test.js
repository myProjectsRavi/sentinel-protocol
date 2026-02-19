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

  test('clips baseline outliers and trims extremes for target latency', () => {
    const normalizer = new LatencyNormalizer({
      enabled: true,
      window_size: 10,
      min_samples: 3,
      max_baseline_sample_ms: 5000,
      trim_percentile: 0.2,
      jitter_ms: 0,
      statuses: [403],
    });

    normalizer.recordSuccess(100);
    normalizer.recordSuccess(120);
    normalizer.recordSuccess(130);
    normalizer.recordSuccess(60000); // clipped to 5000 and then trimmed as high outlier
    normalizer.recordSuccess(90);

    const target = normalizer.targetLatencyMs();
    expect(target).toBeGreaterThanOrEqual(100);
    expect(target).toBeLessThan(1000);
  });

  test('respects max concurrent normalization slots', () => {
    const normalizer = new LatencyNormalizer({
      enabled: true,
      min_samples: 1,
      max_concurrent_normalized: 1,
      jitter_ms: 0,
      statuses: [403],
    });
    normalizer.recordSuccess(100);
    const plan = normalizer.planDelay({
      elapsedMs: 1,
      statusCode: 403,
    });
    expect(plan.apply).toBe(true);
    expect(normalizer.tryAcquire()).toBe(true);
    const saturated = normalizer.planDelay({
      elapsedMs: 1,
      statusCode: 403,
    });
    expect(saturated.apply).toBe(false);
    expect(saturated.reason).toBe('normalization_capacity_reached');
    normalizer.release();
  });
});
