const {
  clampPositiveInt,
  clampProbability,
} = require('../utils/primitives');

function toObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return value;
}

class ThreatPropagationGraph {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.maxEvents = clampPositiveInt(config.max_events, 20000, 128, 2_000_000);
    this.windowMs = clampPositiveInt(config.window_ms, 24 * 3600 * 1000, 1000, 30 * 24 * 3600 * 1000);
    this.riskDecay = clampProbability(config.risk_decay, 0.8);
    this.observability = config.observability !== false;
    this.events = [];
  }

  isEnabled() {
    return this.enabled === true;
  }

  ingest(event = {}) {
    if (!this.isEnabled()) {
      return;
    }
    const safe = toObject(event);
    const nowMs = Date.now();
    this.events.push({
      ts: Number(Date.parse(String(safe.timestamp || ''))) || nowMs,
      correlation_id: String(safe.correlation_id || ''),
      source: String(safe.agent_id || safe.source || safe.provider || 'unknown_source'),
      target: String(safe.target || safe.tool_name || safe.path || 'unknown_target'),
      reason: String((safe.reasons && safe.reasons[0]) || safe.reason || 'observed'),
      blocked: safe.decision ? String(safe.decision).startsWith('blocked') : false,
    });
    this.prune(nowMs);
  }

  prune(nowMs = Date.now()) {
    const cutoff = nowMs - this.windowMs;
    this.events = this.events.filter((item) => Number(item.ts || 0) >= cutoff);
    if (this.events.length > this.maxEvents) {
      this.events = this.events.slice(this.events.length - this.maxEvents);
    }
  }

  buildGraph() {
    const nodes = new Map();
    const edges = new Map();
    for (const event of this.events) {
      const source = event.source || 'unknown_source';
      const target = event.target || 'unknown_target';
      nodes.set(source, (nodes.get(source) || 0) + 1);
      nodes.set(target, (nodes.get(target) || 0) + 1);
      const key = `${source}->${target}`;
      const existing = edges.get(key) || {
        source,
        target,
        count: 0,
        blocked: 0,
      };
      existing.count += 1;
      if (event.blocked) {
        existing.blocked += 1;
      }
      edges.set(key, existing);
    }
    return {
      nodes: Array.from(nodes.entries()).map(([id, count]) => ({ id, count })),
      edges: Array.from(edges.values()),
    };
  }

  computeScores() {
    const graph = this.buildGraph();
    const scores = {};
    for (const node of graph.nodes) {
      scores[node.id] = 0;
    }
    for (const edge of graph.edges) {
      const base = edge.count + (edge.blocked * 2);
      scores[edge.target] = (scores[edge.target] || 0) + base;
      scores[edge.source] = (scores[edge.source] || 0) + (base * this.riskDecay);
    }
    const normalized = Object.entries(scores)
      .map(([node, score]) => ({
        node,
        score: Number(score.toFixed(4)),
      }))
      .sort((a, b) => b.score - a.score);
    return {
      graph,
      scores: normalized,
    };
  }

  export(format = 'json') {
    const normalized = String(format || 'json').toLowerCase();
    const computed = this.computeScores();
    if (normalized === 'mermaid') {
      const lines = ['graph TD'];
      for (const edge of computed.graph.edges) {
        lines.push(`  ${JSON.stringify(edge.source)} -->|${edge.count}| ${JSON.stringify(edge.target)}`);
      }
      return lines.join('\n');
    }
    if (normalized === 'dot') {
      const lines = ['digraph ThreatGraph {'];
      for (const edge of computed.graph.edges) {
        lines.push(`  "${edge.source}" -> "${edge.target}" [label="${edge.count}"];`);
      }
      lines.push('}');
      return lines.join('\n');
    }
    return computed;
  }
}

module.exports = {
  ThreatPropagationGraph,
};
