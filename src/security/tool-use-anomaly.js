const {
  clampPositiveInt,
  normalizeMode,
  normalizeSessionValue,
} = require('../utils/primitives');

class ToolUseAnomalyDetector {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.ttlMs = clampPositiveInt(config.ttl_ms, 6 * 3600 * 1000, 1000, 7 * 24 * 3600 * 1000);
    this.maxAgents = clampPositiveInt(config.max_agents, 5000, 8, 200000);
    this.maxToolsPerAgent = clampPositiveInt(config.max_tools_per_agent, 256, 1, 10000);
    this.warmupEvents = clampPositiveInt(config.warmup_events, 20, 1, 5000);
    this.zScoreThreshold = Number.isFinite(Number(config.z_score_threshold))
      ? Number(config.z_score_threshold)
      : 3;
    this.sequenceThreshold = clampPositiveInt(config.sequence_threshold, 2, 1, 100);
    this.blockOnAnomaly = config.block_on_anomaly === true;
    this.observability = config.observability !== false;
    this.agents = new Map();
  }

  isEnabled() {
    return this.enabled === true;
  }

  prune(nowMs) {
    const cutoff = nowMs - this.ttlMs;
    for (const [agentId, entry] of this.agents.entries()) {
      if (Number(entry?.updatedAt || 0) < cutoff) {
        this.agents.delete(agentId);
      }
    }
    while (this.agents.size > this.maxAgents) {
      const oldest = this.agents.keys().next().value;
      if (!oldest) {
        break;
      }
      this.agents.delete(oldest);
    }
  }

  getAgentState(agentId, nowMs) {
    const key = normalizeSessionValue(agentId || 'agent:unknown', 128) || 'agent:unknown';
    const existing = this.agents.get(key);
    if (existing) {
      existing.updatedAt = nowMs;
      return [key, existing];
    }
    const created = {
      updatedAt: nowMs,
      totalEvents: 0,
      tools: new Map(),
      recentSequence: [],
      flaggedSequences: 0,
    };
    this.agents.set(key, created);
    return [key, created];
  }

  zScore(value, mean, variance) {
    if (!Number.isFinite(value) || !Number.isFinite(mean) || !Number.isFinite(variance)) {
      return 0;
    }
    if (variance <= 0) {
      if (mean > 0 && value > mean) {
        return (value / mean) - 1;
      }
      return 0;
    }
    const std = Math.sqrt(variance);
    if (std <= 0) {
      return 0;
    }
    return (value - mean) / std;
  }

  updateStats(stat, value) {
    const v = Number(value || 0);
    stat.count += 1;
    const delta = v - stat.mean;
    stat.mean += delta / stat.count;
    const delta2 = v - stat.mean;
    stat.m2 += delta * delta2;
  }

  variance(stat) {
    return stat.count > 1 ? stat.m2 / (stat.count - 1) : 0;
  }

  evaluate({
    agentId,
    toolName,
    argsBytes = 0,
    resultBytes = 0,
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
    const name = normalizeSessionValue(toolName || '', 128);
    if (!name) {
      return {
        enabled: true,
        detected: false,
        shouldBlock: false,
        reason: 'clean',
        findings: [],
      };
    }

    const nowMs = Date.now();
    this.prune(nowMs);
    const [key, agent] = this.getAgentState(agentId, nowMs);

    if (!agent.tools.has(name)) {
      if (agent.tools.size >= this.maxToolsPerAgent) {
        return {
          enabled: true,
          detected: false,
          shouldBlock: false,
          reason: 'tool_cap_reached',
          findings: [],
          warmup: agent.totalEvents < this.warmupEvents,
        };
      }
      agent.tools.set(name, {
        args: { count: 0, mean: 0, m2: 0 },
        result: { count: 0, mean: 0, m2: 0 },
        calls: 0,
      });
    }

    const stats = agent.tools.get(name);
    const findings = [];
    const argsZ = this.zScore(Number(argsBytes || 0), stats.args.mean, this.variance(stats.args));
    const resultZ = this.zScore(Number(resultBytes || 0), stats.result.mean, this.variance(stats.result));
    const warmup = agent.totalEvents < this.warmupEvents;
    if (!warmup) {
      if (argsZ >= this.zScoreThreshold) {
        findings.push({
          code: 'tool_use_args_anomaly',
          score: Number(argsZ.toFixed(4)),
          blockEligible: this.blockOnAnomaly,
        });
      }
      if (resultZ >= this.zScoreThreshold) {
        findings.push({
          code: 'tool_use_result_anomaly',
          score: Number(resultZ.toFixed(4)),
          blockEligible: this.blockOnAnomaly,
        });
      }
    }

    agent.recentSequence.push(name);
    if (agent.recentSequence.length > 6) {
      agent.recentSequence = agent.recentSequence.slice(agent.recentSequence.length - 6);
    }
    const sequence = agent.recentSequence.join('>');
    if (!warmup && /read.*>export.*>send|query.*>export.*>email/i.test(sequence)) {
      agent.flaggedSequences += 1;
      if (agent.flaggedSequences >= this.sequenceThreshold) {
        findings.push({
          code: 'tool_use_sequence_anomaly',
          blockEligible: this.blockOnAnomaly,
        });
      }
    }

    this.updateStats(stats.args, Number(argsBytes || 0));
    this.updateStats(stats.result, Number(resultBytes || 0));
    stats.calls += 1;
    agent.totalEvents += 1;
    this.agents.set(key, agent);

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
      reason: detected ? String(findings[0].code || 'tool_use_anomaly') : 'clean',
      findings,
      warmup,
      stats: {
        agent_id: key,
        total_events: agent.totalEvents,
        tool_calls: stats.calls,
      },
    };
  }
}

module.exports = {
  ToolUseAnomalyDetector,
};
