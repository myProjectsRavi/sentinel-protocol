const { CascadeIsolator } = require('../../src/security/cascade-isolator');

describe('CascadeIsolator', () => {
  test('builds trust graph and computes downstream reach', () => {
    const isolator = new CascadeIsolator({
      enabled: true,
      mode: 'monitor',
      max_downstream_agents: 50,
      max_influence_ratio: 1,
      anomaly_threshold: 1,
    });

    const decision = isolator.evaluate({
      sessionId: 'graph-1',
      agentId: 'agent-a',
      bodyJson: {
        agent_delegations: [
          { from: 'agent-a', to: 'agent-b' },
          { from: 'agent-b', to: 'agent-c' },
        ],
      },
      effectiveMode: 'monitor',
    });

    expect(decision.impact.downstream_agents).toBe(2);
    expect(decision.impact.session_nodes).toBeGreaterThanOrEqual(3);
  });

  test('blocks propagation when blast radius threshold exceeded', () => {
    const isolator = new CascadeIsolator({
      enabled: true,
      mode: 'block',
      max_downstream_agents: 1,
      max_influence_ratio: 0.4,
      anomaly_threshold: 0.3,
      block_on_threshold: true,
    });

    const decision = isolator.evaluate({
      sessionId: 'graph-2',
      agentId: 'agent-a',
      bodyJson: {
        agent_delegations: [
          { from: 'agent-a', to: 'agent-b' },
          { from: 'agent-a', to: 'agent-c' },
        ],
      },
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.shouldBlock).toBe(true);
  });

  test('returns monitor warning when configured monitor mode', () => {
    const isolator = new CascadeIsolator({
      enabled: true,
      mode: 'monitor',
      max_downstream_agents: 2,
      max_influence_ratio: 1,
      anomaly_threshold: 0.95,
      block_on_threshold: true,
    });

    const decision = isolator.evaluate({
      sessionId: 'graph-3',
      agentId: 'agent-a',
      bodyJson: {
        delegate_to: 'agent-b',
      },
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(false);

    const second = isolator.evaluate({
      sessionId: 'graph-3',
      agentId: 'agent-a',
      bodyJson: {
        delegate_to: 'agent-c',
      },
      effectiveMode: 'enforce',
    });
    expect(second.detected).toBe(true);
    expect(second.shouldBlock).toBe(false);
  });

  test('respects max_nodes and max_edges caps', () => {
    const isolator = new CascadeIsolator({
      enabled: true,
      mode: 'monitor',
      max_nodes: 8,
      max_edges: 8,
    });

    const decision = isolator.evaluate({
      sessionId: 'graph-4',
      agentId: 'agent-a',
      bodyJson: {
        agent_delegations: Array.from({ length: 10 }).map((_, idx) => ({
          from: `agent-${idx}`,
          to: `agent-${idx + 1}`,
        })),
      },
      effectiveMode: 'monitor',
    });

    expect(decision.findings.some((finding) => finding.code === 'cascade_graph_truncated')).toBe(true);
  });
});
