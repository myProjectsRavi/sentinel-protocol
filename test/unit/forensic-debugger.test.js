const { ForensicDebugger } = require('../../src/governance/forensic-debugger');

describe('ForensicDebugger', () => {
  test('replay reproduces original deterministic decisions', () => {
    const debuggerEngine = new ForensicDebugger({
      enabled: true,
      max_snapshots: 100,
    });
    const snapshot = debuggerEngine.capture({
      request: {
        method: 'POST',
        path: '/v1/chat/completions',
        body: { prompt: 'hello' },
      },
      decision: {
        blocked: false,
        injection_score: 0.2,
      },
      configVersion: 1,
      summaryOnly: false,
    });
    const evaluator = {
      name: 'deterministic_policy',
      run({ decision }) {
        return {
          blocked: Number(decision.injection_score || 0) >= 0.8,
          injection_score: Number(decision.injection_score || 0),
        };
      },
    };
    const replay = debuggerEngine.replay(snapshot, [evaluator], {});
    expect(replay.results[0].result).toEqual({
      blocked: false,
      injection_score: 0.2,
    });
  });

  test('what-if threshold override changes only expected decisions', () => {
    const debuggerEngine = new ForensicDebugger({
      enabled: true,
    });
    const snapshot = debuggerEngine.capture({
      request: { method: 'POST', path: '/v1/chat/completions', body: { prompt: 'x' } },
      decision: { injection_score: 0.6 },
      configVersion: 1,
    });
    const evaluator = {
      name: 'threshold_eval',
      run({ decision, overrides }) {
        const threshold = Number(overrides.injection_threshold ?? 0.8);
        return {
          blocked: Number(decision.injection_score || 0) >= threshold,
          threshold,
        };
      },
    };
    const base = debuggerEngine.replay(snapshot, [evaluator], {});
    const whatIf = debuggerEngine.replay(snapshot, [evaluator], { injection_threshold: 0.5 });
    expect(base.results[0].result.blocked).toBe(false);
    expect(whatIf.results[0].result.blocked).toBe(true);
  });

  test('diff report includes engine-level deltas with stable keys', () => {
    const debuggerEngine = new ForensicDebugger({
      enabled: true,
    });
    const diff = debuggerEngine.diff(
      { blocked: false, threshold: 0.8 },
      { blocked: true, threshold: 0.5 }
    );
    expect(diff.changed).toBe(true);
    expect(diff.deltas.map((item) => item.key)).toEqual(['blocked', 'threshold']);
  });

  test('export redacts configured sensitive fields', () => {
    const debuggerEngine = new ForensicDebugger({
      enabled: true,
      redact_fields: ['headers.authorization', 'body.password'],
    });
    const snapshot = debuggerEngine.capture({
      request: {
        headers: { authorization: 'Bearer secret' },
        body: { password: 'p@ssw0rd' },
      },
      decision: { blocked: false },
      configVersion: 1,
      summaryOnly: false,
    });
    expect(snapshot.request.headers.authorization).toBe('[REDACTED]');
    expect(snapshot.request.body.password).toBe('[REDACTED]');
  });
});
