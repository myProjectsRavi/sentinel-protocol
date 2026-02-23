const {
  clampPositiveInt,
  normalizeMode,
} = require('../utils/primitives');

class ColdStartAnalyzer {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.coldStartWindowMs = clampPositiveInt(
      config.cold_start_window_ms,
      10 * 60 * 1000,
      1000,
      24 * 60 * 60 * 1000
    );
    this.warmupRequestThreshold = clampPositiveInt(
      config.warmup_request_threshold,
      200,
      1,
      1000000
    );
    this.blockDuringColdStart = config.block_during_cold_start === true;
    this.observability = config.observability !== false;
    this.warmupEngines = Array.isArray(config.warmup_engines)
      ? config.warmup_engines.map((item) => String(item || '').trim()).filter(Boolean).slice(0, 64)
      : [
          'semantic_cache',
          'intent_drift',
          'intent_throttle',
          'agent_observability',
        ];

    this.startedAtMs = Date.now();
    this.requestCount = 0;
  }

  isEnabled() {
    return this.enabled === true;
  }

  evaluate({
    effectiveMode = 'monitor',
    engineStates = {},
  } = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        detected: false,
        shouldBlock: false,
        reason: 'warm',
        findings: [],
      };
    }

    this.requestCount += 1;
    const nowMs = Date.now();
    const elapsedMs = Math.max(0, nowMs - this.startedAtMs);

    const requestsProgress = Math.min(1, this.requestCount / this.warmupRequestThreshold);
    const timeProgress = Math.min(1, elapsedMs / this.coldStartWindowMs);
    const progress = Number(Math.max(requestsProgress, timeProgress).toFixed(4));
    const inColdStart = progress < 1;

    const warmedEngines = [];
    const pendingEngines = [];
    const safeStates =
      engineStates && typeof engineStates === 'object' && !Array.isArray(engineStates)
        ? engineStates
        : {};
    for (const name of this.warmupEngines) {
      if (safeStates[name] === true) {
        warmedEngines.push(name);
      } else {
        pendingEngines.push(name);
      }
    }

    const findings = [];
    if (inColdStart) {
      findings.push({
        code: 'cold_start_active',
        message: `cold start active (${Math.round(progress * 100)}% warm)`,
        blockEligible: this.blockDuringColdStart,
      });
    }
    if (pendingEngines.length > 0 && inColdStart) {
      findings.push({
        code: 'cold_start_engine_warmup_pending',
        message: `warmup pending: ${pendingEngines.join(',')}`,
        blockEligible: false,
      });
    }

    const detected = findings.length > 0;
    const shouldBlock =
      detected &&
      this.blockDuringColdStart &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce';

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      reason: detected ? findings[0].code : 'warm',
      findings,
      progress,
      elapsed_ms: elapsedMs,
      requests_seen: this.requestCount,
      requests_target: this.warmupRequestThreshold,
      window_ms: this.coldStartWindowMs,
      warmed_engines: warmedEngines,
      pending_engines: pendingEngines,
    };
  }
}

module.exports = {
  ColdStartAnalyzer,
};
