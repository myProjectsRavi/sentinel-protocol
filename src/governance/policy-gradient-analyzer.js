const { clampPositiveInt } = require('../utils/primitives');

function toNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

class PolicyGradientAnalyzer {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.maxEvents = clampPositiveInt(config.max_events, 250000, 1, 5000000);
    this.defaultCurrentInjectionThreshold = toNumber(config.current_injection_threshold, 0.5);
    this.defaultProposedInjectionThreshold = toNumber(config.proposed_injection_threshold, 0.35);
  }

  isEnabled() {
    return this.enabled === true;
  }

  inferScore(event = {}) {
    if (Number.isFinite(Number(event.injection_score))) {
      return Number(event.injection_score);
    }
    if (Number.isFinite(Number(event.prompt_rebuff_score))) {
      return Number(event.prompt_rebuff_score);
    }
    const reasons = Array.isArray(event.reasons) ? event.reasons : [];
    if (reasons.some((item) => String(item).includes('injection'))) {
      return 0.9;
    }
    return 0;
  }

  classifyDecision(event = {}) {
    const decision = String(event.decision || '').toLowerCase();
    return {
      blocked: decision.startsWith('blocked_'),
      forwarded: decision.startsWith('forwarded'),
      upstreamError: decision === 'upstream_error' || decision === 'stream_error',
    };
  }

  analyze({
    events = [],
    current = {},
    proposed = {},
  } = {}) {
    const currentThreshold = toNumber(
      current.injection_threshold,
      this.defaultCurrentInjectionThreshold
    );
    const proposedThreshold = toNumber(
      proposed.injection_threshold,
      this.defaultProposedInjectionThreshold
    );

    const boundedEvents = Array.isArray(events)
      ? events.slice(Math.max(0, events.length - this.maxEvents))
      : [];

    let currentBlocked = 0;
    let proposedBlocked = 0;
    let wouldFlipToBlocked = 0;
    let wouldFlipToAllowed = 0;
    let evaluated = 0;

    for (const event of boundedEvents) {
      const parsed = event && typeof event === 'object' && !Array.isArray(event) ? event : {};
      const score = this.inferScore(parsed);
      const classification = this.classifyDecision(parsed);
      const currentDecisionBlocked = score >= currentThreshold;
      const proposedDecisionBlocked = score >= proposedThreshold;

      if (classification.upstreamError) {
        continue;
      }

      evaluated += 1;
      if (currentDecisionBlocked) {
        currentBlocked += 1;
      }
      if (proposedDecisionBlocked) {
        proposedBlocked += 1;
      }
      if (!currentDecisionBlocked && proposedDecisionBlocked) {
        wouldFlipToBlocked += 1;
      }
      if (currentDecisionBlocked && !proposedDecisionBlocked) {
        wouldFlipToAllowed += 1;
      }
    }

    const deltaBlocked = proposedBlocked - currentBlocked;
    const securityDelta = evaluated > 0 ? deltaBlocked / evaluated : 0;
    const disruptionDelta = evaluated > 0 ? (wouldFlipToBlocked + wouldFlipToAllowed) / evaluated : 0;
    const recommendation =
      securityDelta >= 0
        ? disruptionDelta <= 0.2
          ? 'safe_to_trial'
          : 'requires_canary_rollout'
        : 'security_regression_risk';

    return {
      evaluated_events: evaluated,
      current_threshold: Number(currentThreshold.toFixed(4)),
      proposed_threshold: Number(proposedThreshold.toFixed(4)),
      current_blocked: currentBlocked,
      proposed_blocked: proposedBlocked,
      delta_blocked: deltaBlocked,
      flips_to_blocked: wouldFlipToBlocked,
      flips_to_allowed: wouldFlipToAllowed,
      security_delta: Number(securityDelta.toFixed(6)),
      disruption_delta: Number(disruptionDelta.toFixed(6)),
      recommendation,
    };
  }
}

module.exports = {
  PolicyGradientAnalyzer,
};
