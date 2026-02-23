const { ThreatPropagationGraph } = require('../../src/governance/threat-propagation-graph');

describe('ThreatPropagationGraph', () => {
  test('builds graph edges from correlated detection events', () => {
    const now = Date.now();
    const graph = new ThreatPropagationGraph({
      enabled: true,
      max_events: 1000,
      window_ms: 24 * 3600 * 1000,
    });
    graph.ingest({
      timestamp: new Date(now).toISOString(),
      correlation_id: 'corr-1',
      agent_id: 'agent-a',
      tool_name: 'tool-b',
      decision: 'blocked_policy',
    });
    graph.ingest({
      timestamp: new Date(now + 1000).toISOString(),
      correlation_id: 'corr-1',
      agent_id: 'agent-a',
      tool_name: 'tool-c',
      decision: 'forwarded',
    });
    const exported = graph.export('json');
    expect(exported.graph.edges.length).toBe(2);
  });

  test('computes propagation score deterministically', () => {
    const now = Date.now();
    const build = () => {
      const graph = new ThreatPropagationGraph({
        enabled: true,
        max_events: 1000,
        window_ms: 24 * 3600 * 1000,
      });
      graph.ingest({
        timestamp: new Date(now).toISOString(),
        agent_id: 'agent-a',
        target: 'tool-b',
        decision: 'blocked_policy',
      });
      graph.ingest({
        timestamp: new Date(now + 1000).toISOString(),
        agent_id: 'tool-b',
        target: 'provider-c',
        decision: 'blocked_policy',
      });
      return graph.export('json').scores;
    };
    expect(build()).toEqual(build());
  });

  test('exports stable Mermaid and DOT output', () => {
    const now = Date.now();
    const graph = new ThreatPropagationGraph({
      enabled: true,
      max_events: 1000,
    });
    graph.ingest({
      timestamp: new Date(now).toISOString(),
      source: 'agent-a',
      target: 'tool-b',
      decision: 'blocked_policy',
    });
    const mermaid = graph.export('mermaid');
    const dot = graph.export('dot');
    expect(mermaid).toContain('graph TD');
    expect(dot).toContain('digraph ThreatGraph');
  });

  test('enforces max event cap without crash', () => {
    const graph = new ThreatPropagationGraph({
      enabled: true,
      max_events: 3,
      window_ms: 24 * 3600 * 1000,
    });
    for (let i = 0; i < 10; i += 1) {
      graph.ingest({
        timestamp: `2026-01-01T00:00:0${i % 10}.000Z`,
        source: `agent-${i}`,
        target: `tool-${i}`,
        decision: 'forwarded',
      });
    }
    expect(graph.events.length).toBeLessThanOrEqual(3);
  });
});
