const {
  clampPositiveInt,
  normalizeMode,
} = require('../utils/primitives');

function toObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return value;
}

function normalizeAction(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .slice(0, 128);
}

function parseNofM(raw, defaults) {
  const value = String(raw || '').trim();
  if (!value) {
    return defaults;
  }
  const match = value.match(/^(\d+)\s*[\/:]\s*(\d+)$/);
  if (!match) {
    return defaults;
  }
  const required = Number(match[1]);
  const total = Number(match[2]);
  if (!Number.isInteger(required) || !Number.isInteger(total) || required <= 0 || total <= 0 || required > total) {
    return defaults;
  }
  return {
    required,
    total,
  };
}

class ConsensusProtocol {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.policyHeader = String(config.policy_header || 'x-sentinel-consensus-policy').toLowerCase();
    this.actionField = String(config.action_field || 'action');
    this.maxVotes = clampPositiveInt(config.max_votes, 32, 1, 1000);
    this.requiredVotes = clampPositiveInt(config.required_votes, 2, 1, 64);
    this.totalAgents = clampPositiveInt(config.total_agents, 3, 1, 256);
    this.blockOnNoQuorum = config.block_on_no_quorum === true;
    this.blockOnByzantine = config.block_on_byzantine === true;
    this.observability = config.observability !== false;
    this.highRiskActions = Array.isArray(config.high_risk_actions)
      ? config.high_risk_actions.map((item) => normalizeAction(item)).filter(Boolean).slice(0, 256)
      : ['wire_funds', 'grant_admin', 'delete_data', 'drop_database', 'execute_shell'];
  }

  isEnabled() {
    return this.enabled === true;
  }

  evaluate({
    headers = {},
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

    const payload = toObject(bodyJson);
    const action = normalizeAction(payload[this.actionField] || payload.action || payload.tool_name || payload.operation);
    if (!action || !this.highRiskActions.includes(action)) {
      return {
        enabled: true,
        mode: this.mode,
        detected: false,
        shouldBlock: false,
        reason: 'clean',
        findings: [],
        action,
      };
    }

    const headerPolicy = headers[this.policyHeader];
    const quorum = parseNofM(headerPolicy, {
      required: this.requiredVotes,
      total: this.totalAgents,
    });

    const votesRaw = Array.isArray(payload.agent_votes) ? payload.agent_votes : [];
    const votes = votesRaw.slice(0, this.maxVotes);
    const findings = [];

    if (votesRaw.length > votes.length) {
      findings.push({
        code: 'consensus_votes_truncated',
        blockEligible: false,
      });
    }

    const voteCounts = new Map();
    const voterSet = new Set();
    for (const vote of votes) {
      const safeVote = toObject(vote);
      const voter = String(safeVote.agent_id || safeVote.agent || '').trim().slice(0, 128);
      const decision = String(safeVote.decision || '').trim().toLowerCase().slice(0, 64);
      if (!voter || !decision) {
        continue;
      }
      if (voterSet.has(voter)) {
        findings.push({
          code: 'consensus_duplicate_voter',
          voter,
          blockEligible: this.blockOnByzantine,
        });
        continue;
      }
      voterSet.add(voter);
      voteCounts.set(decision, (voteCounts.get(decision) || 0) + 1);
    }

    let winningDecision = '';
    let winningVotes = 0;
    for (const [decision, count] of voteCounts.entries()) {
      if (count > winningVotes) {
        winningDecision = decision;
        winningVotes = count;
      }
    }

    if (winningVotes < quorum.required) {
      findings.push({
        code: 'consensus_quorum_not_met',
        required_votes: quorum.required,
        received_votes: winningVotes,
        total_expected: quorum.total,
        blockEligible: this.blockOnNoQuorum,
      });
    }

    if (voteCounts.size > 1) {
      findings.push({
        code: 'consensus_dissent_detected',
        variants: voteCounts.size,
        blockEligible: this.blockOnByzantine,
      });
    }

    const detected = findings.length > 0;
    const shouldBlock =
      detected &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce' &&
      findings.some((item) => item.blockEligible === true);

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      reason: detected ? String(findings[0].code || 'consensus_violation') : 'clean',
      findings,
      action,
      winning_decision: winningDecision,
      winning_votes: winningVotes,
      quorum_required: quorum.required,
      quorum_total: quorum.total,
      vote_breakdown: Object.fromEntries(voteCounts),
    };
  }
}

module.exports = {
  ConsensusProtocol,
};
