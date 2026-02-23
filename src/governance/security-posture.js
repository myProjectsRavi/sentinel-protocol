const { clampPositiveInt, normalizeMode } = require('../utils/primitives');

const ALLOWED_MODES = ['monitor', 'warn', 'enforce', 'block', 'active', 'allow', 'auto', 'inject', 'terminate'];

function normalizePostureMode(value, fallback = 'monitor') {
  return normalizeMode(value, fallback, ALLOWED_MODES);
}

function scoreControl(enabled, mode, options = {}) {
  const safeWeight = Number(options.weight || 0);
  if (!enabled) {
    return 0;
  }
  const enforceModes = new Set(options.enforceModes || ['enforce', 'block', 'active']);
  const normalizedMode = normalizePostureMode(mode, options.defaultMode || 'monitor');
  if (enforceModes.has(normalizedMode)) {
    return safeWeight;
  }
  return safeWeight * Number(options.monitorMultiplier ?? 0.6);
}

function percent(part, total) {
  if (!Number.isFinite(total) || total <= 0) {
    return 0;
  }
  return Math.max(0, Math.min(100, Number(((part / total) * 100).toFixed(2))));
}

function computeCategoryScore(items) {
  let earned = 0;
  let max = 0;
  for (const item of items) {
    const weight = Number(item.weight || 0);
    max += weight;
    earned += scoreControl(item.enabled, item.mode, {
      weight,
      enforceModes: item.enforceModes,
      monitorMultiplier: item.monitorMultiplier,
      defaultMode: item.defaultMode,
    });
  }
  return {
    earned: Number(earned.toFixed(2)),
    max: Number(max.toFixed(2)),
    score: percent(earned, max),
  };
}

function computeCounterPenalty(counters = {}) {
  const requests = Number(counters.requests_total || 0);
  if (!Number.isFinite(requests) || requests <= 0) {
    return {
      total_penalty: 0,
      upstream_error_rate: 0,
      block_rate: 0,
    };
  }
  const upstreamErrors = Number(counters.upstream_errors || 0);
  const blocked = Number(counters.blocked_total || 0);
  const upstreamErrorRate = upstreamErrors / requests;
  const blockRate = blocked / requests;

  let penalty = 0;
  if (upstreamErrorRate > 0.4) {
    penalty += 10;
  } else if (upstreamErrorRate > 0.2) {
    penalty += 5;
  }
  if (blockRate > 0.85) {
    penalty += 5;
  }

  return {
    total_penalty: penalty,
    upstream_error_rate: Number(upstreamErrorRate.toFixed(4)),
    block_rate: Number(blockRate.toFixed(4)),
  };
}

function normalizeScoringOptions(options = {}) {
  return {
    warnThreshold: clampPositiveInt(options.warnThreshold, 70, 1, 100),
    criticalThreshold: clampPositiveInt(options.criticalThreshold, 50, 1, 100),
    includeCounters: options.includeCounters !== false,
  };
}

function computeSecurityPosture({ config = {}, counters = {}, auditSummary = {}, options = {} } = {}) {
  const scoring = normalizeScoringOptions(options);
  const runtime = config.runtime || {};
  const pii = config.pii || {};
  const injection = config.injection || {};

  const ingress = computeCategoryScore([
    { weight: 22, enabled: injection.enabled === true, mode: injection.action, enforceModes: ['block'] },
    { weight: 22, enabled: pii.enabled !== false, mode: config.mode, enforceModes: ['enforce'] },
    {
      weight: 18,
      enabled: runtime.prompt_rebuff?.enabled === true,
      mode: runtime.prompt_rebuff?.mode,
      enforceModes: ['block'],
    },
    {
      weight: 20,
      enabled: runtime.mcp_poisoning?.enabled === true,
      mode: runtime.mcp_poisoning?.mode,
      enforceModes: ['block'],
    },
    {
      weight: 18,
      enabled: runtime.auto_immune?.enabled === true,
      mode: runtime.auto_immune?.mode,
      enforceModes: ['block'],
    },
  ]);

  const egress = computeCategoryScore([
    {
      weight: 30,
      enabled: pii?.egress?.enabled !== false,
      mode: pii?.egress?.mode || config.mode,
      enforceModes: ['enforce', 'block'],
    },
    {
      weight: 20,
      enabled: pii?.egress?.stream_enabled !== false,
      mode: pii?.egress?.stream_block_mode === 'terminate' ? 'block' : 'monitor',
      enforceModes: ['block'],
    },
    {
      weight: 18,
      enabled: pii?.egress?.entropy?.enabled === true,
      mode: pii?.egress?.entropy?.mode || 'monitor',
      enforceModes: ['block'],
    },
    {
      weight: 16,
      enabled: runtime.websocket?.enabled !== false,
      mode: runtime.websocket?.mode || 'monitor',
      enforceModes: ['enforce'],
    },
    {
      weight: 16,
      enabled: runtime.provenance?.enabled === true,
      mode: runtime.provenance?.mode || 'monitor',
      enforceModes: ['enforce', 'block', 'active'],
    },
  ]);

  const privacy = computeCategoryScore([
    { weight: 34, enabled: pii.enabled !== false, mode: config.mode, enforceModes: ['enforce'] },
    {
      weight: 26,
      enabled: runtime.pii_vault?.enabled === true,
      mode: runtime.pii_vault?.mode || 'monitor',
      enforceModes: ['active'],
    },
    {
      weight: 20,
      enabled: runtime.upstream?.ghost_mode?.enabled === true,
      mode: runtime.upstream?.ghost_mode?.mode || 'monitor',
      enforceModes: ['enforce', 'active'],
    },
    {
      weight: 20,
      enabled: runtime.honeytoken?.enabled === true,
      mode: runtime.honeytoken?.mode || 'monitor',
      enforceModes: ['enforce', 'active'],
    },
  ]);

  const agentic = computeCategoryScore([
    {
      weight: 20,
      enabled: runtime.loop_breaker?.enabled === true,
      mode: runtime.loop_breaker?.action || 'warn',
      enforceModes: ['block'],
    },
    {
      weight: 20,
      enabled: runtime.agentic_threat_shield?.enabled === true,
      mode: runtime.agentic_threat_shield?.mode || 'monitor',
      enforceModes: ['block'],
    },
    {
      weight: 15,
      enabled: runtime.intent_throttle?.enabled === true,
      mode: runtime.intent_throttle?.mode || 'monitor',
      enforceModes: ['block'],
    },
    {
      weight: 15,
      enabled: runtime.intent_drift?.enabled === true,
      mode: runtime.intent_drift?.mode || 'monitor',
      enforceModes: ['block'],
    },
    {
      weight: 15,
      enabled: runtime.canary_tools?.enabled === true,
      mode: runtime.canary_tools?.mode || 'monitor',
      enforceModes: ['block'],
    },
    {
      weight: 15,
      enabled: runtime.sandbox_experimental?.enabled === true,
      mode: runtime.sandbox_experimental?.mode || 'monitor',
      enforceModes: ['block'],
    },
  ]);

  const categories = {
    ingress: ingress.score,
    egress: egress.score,
    privacy: privacy.score,
    agentic: agentic.score,
  };

  const baseOverall = Number(
    ((categories.ingress + categories.egress + categories.privacy + categories.agentic) / 4).toFixed(2)
  );
  const counterPenalty = scoring.includeCounters ? computeCounterPenalty(counters) : computeCounterPenalty({});
  const overall = Math.max(0, Number((baseOverall - counterPenalty.total_penalty).toFixed(2)));
  const posture = overall < scoring.criticalThreshold ? 'critical' : overall < scoring.warnThreshold ? 'warn' : 'strong';

  return {
    posture,
    overall,
    categories,
    scoring: {
      warn_threshold: scoring.warnThreshold,
      critical_threshold: scoring.criticalThreshold,
      include_counters: scoring.includeCounters,
    },
    adjustments: counterPenalty,
    audit: {
      total_events: Number(auditSummary.total_events || 0),
      blocked_events: Number(auditSummary.blocked_events || 0),
      upstream_errors: Number(auditSummary.upstream_errors || 0),
    },
  };
}

module.exports = {
  computeSecurityPosture,
};
