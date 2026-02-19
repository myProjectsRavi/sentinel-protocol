const { responseHeaderDiagnostics } = require('../shared');

async function runParallaxStage({
  server,
  req,
  res,
  effectiveMode,
  correlationId,
  parallaxInputBodyJson,
  bodyJson,
  outboundBody,
  upstream,
  warnings,
  requestStart,
  durationMs,
  bodyBuffer,
  routePlan,
  routedProvider,
  routedTarget,
  routedBreakerKey,
  piiTypes,
  redactedCount,
  finalizeRequestTelemetry,
  cognitiveRollbackDecision,
}) {
  let parallaxDecision = null;

  if (server.parallaxValidator.isEnabled()) {
    parallaxDecision = await server.parallaxValidator.evaluate({
      req,
      correlationId,
      requestBodyJson: parallaxInputBodyJson || bodyJson,
      responseBody: outboundBody,
      responseContentType: upstream.responseHeaders?.['content-type'],
    });
    if (parallaxDecision.evaluated) {
      server.stats.parallax_evaluated += 1;
    }
    if (parallaxDecision.error) {
      warnings.push(`parallax_error:${parallaxDecision.error}`);
      server.stats.warnings_total += 1;
    } else if (parallaxDecision.evaluated && parallaxDecision.veto) {
      server.stats.parallax_vetoed += 1;
      warnings.push('parallax_veto');
      server.stats.warnings_total += 1;
      res.setHeader('x-sentinel-parallax', 'veto');
      res.setHeader('x-sentinel-parallax-risk', String(parallaxDecision.risk));
      res.setHeader('x-sentinel-parallax-provider', String(parallaxDecision.secondaryProvider || 'unknown'));

      const rollbackCandidate = server.cognitiveRollback.suggest({
        bodyJson: parallaxInputBodyJson || bodyJson,
        trigger: 'parallax_veto',
      });
      if (rollbackCandidate.applicable) {
        cognitiveRollbackDecision = rollbackCandidate;
        server.stats.cognitive_rollback_suggested += 1;
        warnings.push('cognitive_rollback_suggested');
        server.stats.warnings_total += 1;
        if (server.cognitiveRollback.observability) {
          res.setHeader(
            'x-sentinel-cognitive-rollback',
            server.cognitiveRollback.shouldAuto() ? 'auto' : 'suggested'
          );
          res.setHeader('x-sentinel-cognitive-rollback-trigger', 'parallax_veto');
          res.setHeader(
            'x-sentinel-cognitive-rollback-dropped',
            String(rollbackCandidate.droppedMessages || 0)
          );
        }
      }

      if (effectiveMode === 'enforce' && server.parallaxValidator.mode === 'block') {
        if (rollbackCandidate.applicable && server.cognitiveRollback.shouldAuto()) {
          server.stats.cognitive_rollback_auto += 1;
          const diagnostics = {
            errorSource: 'sentinel',
            upstreamError: false,
            provider: routedProvider,
            retryCount: upstream.diagnostics.retryCount || 0,
            circuitState: server.circuitBreakers.getProviderState(routedBreakerKey).state,
            correlationId,
          };
          responseHeaderDiagnostics(res, diagnostics);
          server.auditLogger.write({
            timestamp: new Date().toISOString(),
            correlation_id: correlationId,
            config_version: server.config.version,
            mode: effectiveMode,
            decision: 'cognitive_rollback_required',
            reasons: ['parallax_veto'],
            pii_types: piiTypes,
            redactions: redactedCount,
            duration_ms: durationMs,
            request_bytes: bodyBuffer.length,
            response_status: 409,
            response_bytes: 0,
            provider: routedProvider,
            upstream_target: routedTarget,
            parallax_risk: parallaxDecision.risk,
            parallax_reason: parallaxDecision.reason,
            parallax_secondary_provider: parallaxDecision.secondaryProvider,
            parallax_high_risk_tools: parallaxDecision.highRiskTools,
            cognitive_rollback_trigger: 'parallax_veto',
            cognitive_rollback_dropped_messages: rollbackCandidate.droppedMessages,
            route_source: routePlan.routeSource,
            route_group: routePlan.selectedGroup || undefined,
            route_contract: routePlan.desiredContract,
            requested_target: routePlan.requestedTarget,
          });
          server.writeStatus();
          finalizeRequestTelemetry({
            decision: 'blocked_policy',
            status: 409,
            providerName: routedProvider,
          });
          res.status(409).json({
            error: 'COGNITIVE_ROLLBACK_REQUIRED',
            reason: 'parallax_veto',
            rollback: {
              mode: server.cognitiveRollback.mode,
              trigger: 'parallax_veto',
              dropped_messages: rollbackCandidate.droppedMessages,
              messages: rollbackCandidate.bodyJson.messages,
            },
            correlation_id: correlationId,
          });
          return {
            handled: true,
            parallaxDecision,
            cognitiveRollbackDecision,
          };
        }

        server.stats.blocked_total += 1;
        const diagnostics = {
          errorSource: 'sentinel',
          upstreamError: false,
          provider: routedProvider,
          retryCount: upstream.diagnostics.retryCount || 0,
          circuitState: server.circuitBreakers.getProviderState(routedBreakerKey).state,
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
          decision: 'blocked_parallax',
          reasons: ['parallax_veto'],
          pii_types: piiTypes,
          redactions: redactedCount,
          duration_ms: durationMs,
          request_bytes: bodyBuffer.length,
          response_status: 403,
          response_bytes: 0,
          provider: routedProvider,
          upstream_target: routedTarget,
          parallax_risk: parallaxDecision.risk,
          parallax_reason: parallaxDecision.reason,
          parallax_secondary_provider: parallaxDecision.secondaryProvider,
          parallax_high_risk_tools: parallaxDecision.highRiskTools,
          route_source: routePlan.routeSource,
          route_group: routePlan.selectedGroup || undefined,
          route_contract: routePlan.desiredContract,
          requested_target: routePlan.requestedTarget,
        });
        server.writeStatus();
        finalizeRequestTelemetry({
          decision: 'blocked_policy',
          status: 403,
          providerName: routedProvider,
        });
        res.status(403).json({
          error: 'PARALLAX_VETO',
          reason: 'parallax_veto',
          risk: parallaxDecision.risk,
          secondary_provider: parallaxDecision.secondaryProvider,
          high_risk_tools: parallaxDecision.highRiskTools,
          correlation_id: correlationId,
        });
        return {
          handled: true,
          parallaxDecision,
          cognitiveRollbackDecision,
        };
      }
    } else if (parallaxDecision.evaluated) {
      res.setHeader('x-sentinel-parallax', 'allow');
      if (Number.isFinite(Number(parallaxDecision.risk))) {
        res.setHeader('x-sentinel-parallax-risk', String(parallaxDecision.risk));
      }
      if (parallaxDecision.secondaryProvider) {
        res.setHeader('x-sentinel-parallax-provider', String(parallaxDecision.secondaryProvider));
      }
    }
  }

  return {
    handled: false,
    parallaxDecision,
    cognitiveRollbackDecision,
  };
}

module.exports = {
  runParallaxStage,
};
