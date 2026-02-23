const {
  clampPositiveInt,
  clampProbability,
  normalizeMode,
  normalizeSessionValue,
} = require('../utils/primitives');

function toObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return value;
}

class CascadeIsolator {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.ttlMs = clampPositiveInt(config.ttl_ms, 6 * 3600 * 1000, 1000, 7 * 24 * 3600 * 1000);
    this.maxSessions = clampPositiveInt(config.max_sessions, 5000, 8, 100000);
    this.maxNodes = clampPositiveInt(config.max_nodes, 512, 8, 100000);
    this.maxEdges = clampPositiveInt(config.max_edges, 2048, 8, 500000);
    this.maxDownstreamAgents = clampPositiveInt(config.max_downstream_agents, 16, 1, 10000);
    this.maxInfluenceRatio = clampProbability(config.max_influence_ratio, 0.6);
    this.anomalyThreshold = clampProbability(config.anomaly_threshold, 0.75);
    this.blockOnThreshold = config.block_on_threshold === true;
    this.observability = config.observability !== false;
    this.sessions = new Map();
  }

  isEnabled() {
    return this.enabled === true;
  }

  prune(nowMs) {
    const cutoff = nowMs - this.ttlMs;
    for (const [sessionId, entry] of this.sessions.entries()) {
      if (Number(entry?.updatedAt || 0) < cutoff) {
        this.sessions.delete(sessionId);
      }
    }
    while (this.sessions.size > this.maxSessions) {
      const oldest = this.sessions.keys().next().value;
      if (!oldest) {
        break;
      }
      this.sessions.delete(oldest);
    }
  }

  getSession(sessionId, nowMs) {
    const sid = normalizeSessionValue(sessionId || 'anonymous', 256) || 'anonymous';
    const existing = this.sessions.get(sid);
    if (existing) {
      existing.updatedAt = nowMs;
      return existing;
    }
    const entry = {
      updatedAt: nowMs,
      adjacency: new Map(),
      nodeSet: new Set(),
      edgeCount: 0,
      truncated: false,
    };
    this.sessions.set(sid, entry);
    return entry;
  }

  addEdge(entry, from, to) {
    if (!from || !to || from === to) {
      return;
    }
    if (entry.nodeSet.size >= this.maxNodes && (!entry.nodeSet.has(from) || !entry.nodeSet.has(to))) {
      entry.truncated = true;
      return;
    }
    entry.nodeSet.add(from);
    entry.nodeSet.add(to);
    if (!entry.adjacency.has(from)) {
      entry.adjacency.set(from, new Set());
    }
    const set = entry.adjacency.get(from);
    if (!set.has(to)) {
      if (entry.edgeCount >= this.maxEdges) {
        entry.truncated = true;
        return;
      }
      set.add(to);
      entry.edgeCount += 1;
    }
  }

  extractEdges(bodyJson, defaultFrom) {
    const out = [];
    const payload = toObject(bodyJson);
    const delegations = Array.isArray(payload.agent_delegations) ? payload.agent_delegations : [];
    for (const item of delegations.slice(0, 128)) {
      const edge = toObject(item);
      const from = String(edge.from || defaultFrom || '').trim();
      const to = String(edge.to || edge.agent || '').trim();
      if (from && to) {
        out.push([from, to]);
      }
    }
    if (out.length === 0 && payload.delegate_to) {
      const to = String(payload.delegate_to).trim();
      if (defaultFrom && to) {
        out.push([defaultFrom, to]);
      }
    }
    return out;
  }

  countDownstream(entry, source) {
    const visited = new Set();
    const stack = [source];
    while (stack.length > 0) {
      const node = stack.pop();
      const next = entry.adjacency.get(node);
      if (!next) {
        continue;
      }
      for (const child of next) {
        if (visited.has(child)) {
          continue;
        }
        visited.add(child);
        stack.push(child);
      }
    }
    return visited.size;
  }

  evaluate({
    sessionId,
    agentId,
    bodyJson = {},
    effectiveMode = 'monitor',
  } = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        detected: false,
        shouldBlock: false,
        reason: 'clean',
        findings: [],
      };
    }

    const nowMs = Date.now();
    this.prune(nowMs);
    const source = normalizeSessionValue(agentId || 'agent:unknown', 128) || 'agent:unknown';
    const session = this.getSession(sessionId, nowMs);
    const edges = this.extractEdges(bodyJson, source);
    for (const [from, to] of edges) {
      this.addEdge(session, from, to);
    }

    const findings = [];
    let downstream = 0;
    let influenceRatio = 0;
    if (session.nodeSet.size > 0) {
      downstream = this.countDownstream(session, source);
      influenceRatio = session.nodeSet.size <= 1 ? 0 : downstream / Math.max(1, session.nodeSet.size - 1);
      if (downstream > this.maxDownstreamAgents) {
        findings.push({
          code: 'cascade_downstream_limit',
          message: `downstream influence ${downstream} exceeds cap ${this.maxDownstreamAgents}`,
          blockEligible: this.blockOnThreshold,
        });
      }
      if (influenceRatio > this.maxInfluenceRatio) {
        findings.push({
          code: 'cascade_influence_ratio',
          message: `influence ratio ${influenceRatio.toFixed(3)} exceeds cap ${this.maxInfluenceRatio}`,
          blockEligible: this.blockOnThreshold,
        });
      }
      const anomalyScore = Math.min(1, (influenceRatio * 0.6) + (downstream / Math.max(1, this.maxDownstreamAgents)) * 0.4);
      if (anomalyScore >= this.anomalyThreshold) {
        findings.push({
          code: 'cascade_anomaly_threshold',
          message: `anomaly score ${anomalyScore.toFixed(3)} reached threshold ${this.anomalyThreshold}`,
          score: Number(anomalyScore.toFixed(4)),
          blockEligible: this.blockOnThreshold,
        });
      }
    }

    if (session.truncated) {
      findings.push({
        code: 'cascade_graph_truncated',
        message: 'graph bounds reached; analysis truncated',
        blockEligible: false,
      });
    }

    const detected = findings.length > 0;
    const blockEligible = findings.some((item) => item.blockEligible === true);
    const shouldBlock =
      detected &&
      blockEligible &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce';

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      reason: detected ? String(findings[0].code || 'cascade_detected') : 'clean',
      findings,
      impact: {
        session_nodes: session.nodeSet.size,
        session_edges: session.edgeCount,
        downstream_agents: downstream,
        influence_ratio: Number(influenceRatio.toFixed(4)),
      },
    };
  }
}

module.exports = {
  CascadeIsolator,
};
