const { CircuitBreakerManager } = require('../../src/resilience/circuit-breaker');

describe('circuit breaker manager', () => {
  const config = {
    enabled: true,
    window_size: 10,
    min_failures_to_evaluate: 2,
    failure_rate_threshold: 0.5,
    consecutive_timeout_threshold: 3,
    open_seconds: 1,
    half_open_success_threshold: 2,
  };

  test('opens after repeated upstream failures', () => {
    const manager = new CircuitBreakerManager(config);
    manager.recordUpstreamFailure('openai', 'status');
    manager.recordUpstreamFailure('openai', 'status');

    const gate = manager.canRequest('openai');
    expect(gate.allowed).toBe(false);
    expect(gate.state).toBe('open');
  });

  test('moves to half-open then closes on consecutive successes', () => {
    const manager = new CircuitBreakerManager(config);
    manager.recordUpstreamFailure('openai', 'status');
    manager.recordUpstreamFailure('openai', 'status');

    const state = manager.getProviderState('openai');
    state.openUntil = Date.now() - 1;

    const firstProbe = manager.canRequest('openai');
    expect(firstProbe.allowed).toBe(true);
    expect(firstProbe.state).toBe('half-open');

    manager.recordUpstreamSuccess('openai');

    const secondProbe = manager.canRequest('openai');
    expect(secondProbe.allowed).toBe(true);
    manager.recordUpstreamSuccess('openai');

    expect(manager.getProviderState('openai').state).toBe('closed');
  });
});
