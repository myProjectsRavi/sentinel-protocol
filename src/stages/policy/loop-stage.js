const { responseHeaderDiagnostics } = require('../shared');

async function runLoopStage({
  server,
  req,
  res,
  provider,
  method,
  parsedPath,
  bodyText,
  bodyJson,
  effectiveMode,
  wantsStream,
  injectionScore,
  correlationId,
  requestStart,
  rawBody,
  piiTypes,
  redactedCount,
  warnings,
  routePlan,
  breakerKey,
  finalizeRequestTelemetry,
}) {
  const loopDecision = server.loopBreaker.evaluate({
    headers: req.headers || {},
    provider,
    method,
    path: parsedPath.pathname,
    bodyText,
    bodyJson,
  });
  if (loopDecision.detected) {
    server.stats.loop_detected += 1;
    if (effectiveMode === 'enforce' && loopDecision.shouldBlock) {
      const deceived = await server.maybeServeDeceptionResponse({
        res,
        trigger: 'loop',
        provider,
        effectiveMode,
        wantsStream,
        injectionScore,
        correlationId,
        requestStart,
        requestBytes: rawBody.length,
        piiTypes,
        redactedCount,
        warnings,
        routePlan,
        finalizeRequestTelemetry,
      });
      if (deceived) {
        return {
          handled: true,
          loopDecision,
        };
      }
      server.stats.blocked_total += 1;
      server.stats.loop_blocked += 1;
      const diagnostics = {
        errorSource: 'sentinel',
        upstreamError: false,
        provider,
        retryCount: 0,
        circuitState: server.circuitBreakers.getProviderState(breakerKey).state,
        correlationId,
      };
      responseHeaderDiagnostics(res, diagnostics);
      res.setHeader('x-sentinel-loop-breaker', 'blocked');
      await server.maybeNormalizeBlockedLatency({
        res,
        statusCode: 429,
        requestStart,
      });
      server.auditLogger.write({
        timestamp: new Date().toISOString(),
        correlation_id: correlationId,
        config_version: server.config.version,
        mode: effectiveMode,
        decision: 'blocked_loop',
        reasons: ['agent_loop_detected'],
        pii_types: [],
        redactions: 0,
        duration_ms: Date.now() - requestStart,
        request_bytes: rawBody.length,
        response_status: 429,
        response_bytes: 0,
        provider,
        loop_streak: loopDecision.streak,
        loop_threshold: loopDecision.repeatThreshold,
        loop_key: loopDecision.key,
        loop_hash_prefix: loopDecision.hash_prefix,
      });
      server.writeStatus();
      finalizeRequestTelemetry({
        decision: 'blocked_policy',
        status: 429,
        providerName: provider,
      });
      res.status(429).json({
        error: 'AGENT_LOOP_DETECTED',
        reason: 'agent_loop_detected',
        streak: loopDecision.streak,
        threshold: loopDecision.repeatThreshold,
        correlation_id: correlationId,
      });
      return {
        handled: true,
        loopDecision,
      };
    }
    warnings.push(`loop_detected:${loopDecision.streak}`);
    res.setHeader('x-sentinel-loop-breaker', 'warn');
    server.stats.warnings_total += 1;
  }

  return {
    handled: false,
    loopDecision,
  };
}

module.exports = {
  runLoopStage,
};
