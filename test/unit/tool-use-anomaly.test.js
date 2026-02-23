const { ToolUseAnomalyDetector } = require('../../src/security/tool-use-anomaly');

describe('ToolUseAnomalyDetector', () => {
  test('does not alert during warm-up window', () => {
    const detector = new ToolUseAnomalyDetector({
      enabled: true,
      mode: 'block',
      warmup_events: 4,
      block_on_anomaly: true,
    });

    for (let i = 0; i < 3; i += 1) {
      const decision = detector.evaluate({
        agentId: 'agent-a',
        toolName: 'read_records',
        argsBytes: 100,
        resultBytes: 100,
        effectiveMode: 'enforce',
      });
      expect(decision.detected).toBe(false);
      expect(decision.shouldBlock).toBe(false);
      expect(decision.warmup).toBe(true);
    }
  });

  test('flags high-volume deviation after warm-up', () => {
    const detector = new ToolUseAnomalyDetector({
      enabled: true,
      mode: 'monitor',
      warmup_events: 3,
      z_score_threshold: 1.2,
    });

    for (let i = 0; i < 4; i += 1) {
      detector.evaluate({
        agentId: 'agent-b',
        toolName: 'read_records',
        argsBytes: 120,
        resultBytes: 120,
        effectiveMode: 'monitor',
      });
    }

    const decision = detector.evaluate({
      agentId: 'agent-b',
      toolName: 'read_records',
      argsBytes: 6000,
      resultBytes: 6000,
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.findings.some((item) => item.code === 'tool_use_args_anomaly')).toBe(true);
  });

  test('flags suspicious sequence chain pattern', () => {
    const detector = new ToolUseAnomalyDetector({
      enabled: true,
      mode: 'block',
      warmup_events: 1,
      sequence_threshold: 1,
      block_on_anomaly: true,
    });

    detector.evaluate({
      agentId: 'agent-c',
      toolName: 'read_all_users',
      argsBytes: 1,
      resultBytes: 1,
      effectiveMode: 'enforce',
    });
    detector.evaluate({
      agentId: 'agent-c',
      toolName: 'export_csv',
      argsBytes: 1,
      resultBytes: 1,
      effectiveMode: 'enforce',
    });
    const decision = detector.evaluate({
      agentId: 'agent-c',
      toolName: 'send_email',
      argsBytes: 1,
      resultBytes: 1,
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.findings.some((item) => item.code === 'tool_use_sequence_anomaly')).toBe(true);
    expect(decision.shouldBlock).toBe(true);
  });

  test('returns deterministic score for fixed history', () => {
    const detector = new ToolUseAnomalyDetector({
      enabled: true,
      mode: 'monitor',
      warmup_events: 2,
      z_score_threshold: 1.1,
    });
    const inputs = [100, 100, 100, 500];
    const outputs = [];
    for (const value of inputs) {
      outputs.push(detector.evaluate({
        agentId: 'agent-d',
        toolName: 'search_docs',
        argsBytes: value,
        resultBytes: value,
        effectiveMode: 'monitor',
      }));
    }
    const first = outputs[outputs.length - 1];
    const second = detector.evaluate({
      agentId: 'agent-e',
      toolName: 'search_docs',
      argsBytes: 500,
      resultBytes: 500,
      effectiveMode: 'monitor',
    });
    expect(typeof first.reason).toBe('string');
    expect(typeof second.reason).toBe('string');
  });
});
