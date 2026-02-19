const { responseHeaderDiagnostics } = require('../shared');

async function runAutoImmuneStage({
  server,
  res,
  bodyText,
  effectiveMode,
  provider,
  breakerKey,
  correlationId,
  requestStart,
  rawBody,
  warnings,
  finalizeRequestTelemetry,
}) {
  const autoImmuneDecision = server.autoImmune.check({
    text: bodyText,
    effectiveMode,
  });

  if (autoImmuneDecision?.enabled && server.autoImmune.observability) {
    res.setHeader(
      'x-sentinel-auto-immune',
      autoImmuneDecision.matched ? 'match' : autoImmuneDecision.reason || 'miss'
    );
    if (Number.isFinite(Number(autoImmuneDecision.confidence))) {
      res.setHeader('x-sentinel-auto-immune-confidence', String(autoImmuneDecision.confidence));
    }
  }

  if (autoImmuneDecision?.matched) {
    server.stats.auto_immune_matches += 1;
    warnings.push('auto_immune:match');
    server.stats.warnings_total += 1;

    if (autoImmuneDecision.shouldBlock) {
      server.stats.blocked_total += 1;
      server.stats.policy_blocked += 1;
      server.stats.auto_immune_blocked += 1;
      const diagnostics = {
        errorSource: 'sentinel',
        upstreamError: false,
        provider,
        retryCount: 0,
        circuitState: server.circuitBreakers.getProviderState(breakerKey).state,
        correlationId,
      };
      responseHeaderDiagnostics(res, diagnostics);
      await server.maybeNormalizeBlockedLatency({
        res,
        statusCode: 403,
        requestStart,
      });
      server.auditLogger.write({
        timestamp: new Date().toISOString(),
        correlation_id: correlationId,
        config_version: server.config.version,
        mode: effectiveMode,
        decision: 'blocked_auto_immune',
        reasons: ['auto_immune_hit'],
        pii_types: [],
        redactions: 0,
        duration_ms: Date.now() - requestStart,
        request_bytes: rawBody.length,
        response_status: 403,
        response_bytes: 0,
        provider,
        auto_immune_fingerprint: autoImmuneDecision.fingerprint,
        auto_immune_confidence: autoImmuneDecision.confidence,
        auto_immune_threshold: autoImmuneDecision.threshold,
      });
      server.writeStatus();
      finalizeRequestTelemetry({
        decision: 'blocked_policy',
        status: 403,
        providerName: provider,
      });
      res.status(403).json({
        error: 'AUTO_IMMUNE_BLOCKED',
        reason: 'auto_immune_hit',
        confidence: autoImmuneDecision.confidence,
        threshold: autoImmuneDecision.threshold,
        correlation_id: correlationId,
      });
      return {
        handled: true,
        autoImmuneDecision,
      };
    }
  }

  return {
    handled: false,
    autoImmuneDecision,
  };
}

module.exports = {
  runAutoImmuneStage,
};
