const { responseHeaderDiagnostics } = require('../shared');

async function runSwarmStage({
  server,
  req,
  res,
  method,
  pathWithQuery,
  rawBody,
  effectiveMode,
  provider,
  breakerKey,
  correlationId,
  requestStart,
  warnings,
  finalizeRequestTelemetry,
}) {
  const swarmInboundDecision = server.swarmProtocol.verifyInboundEnvelope({
    headers: req.headers || {},
    method,
    pathWithQuery,
    bodyBuffer: rawBody,
  });

  if (swarmInboundDecision.present) {
    res.setHeader('x-sentinel-swarm-verified', String(swarmInboundDecision.verified));
    res.setHeader('x-sentinel-swarm-reason', String(swarmInboundDecision.reason || 'unknown'));
    res.setHeader(
      'x-sentinel-swarm-allowed-skew-ms',
      String(swarmInboundDecision.allowedClockSkewMs || server.swarmProtocol.allowedClockSkewMs || 0)
    );
    if (Number.isFinite(Number(swarmInboundDecision.ageMs))) {
      res.setHeader('x-sentinel-swarm-clock-skew-ms', String(Number(swarmInboundDecision.ageMs)));
    }
    if (swarmInboundDecision.nodeId) {
      res.setHeader('x-sentinel-swarm-node-id', swarmInboundDecision.nodeId);
    }
  }

  server.recordSwarmObservation(swarmInboundDecision);

  if (swarmInboundDecision.verified) {
    server.stats.swarm_inbound_verified += 1;
  } else if (swarmInboundDecision.present || swarmInboundDecision.required) {
    server.stats.swarm_inbound_rejected += 1;
    if (swarmInboundDecision.reason === 'replay_nonce') {
      server.stats.swarm_replay_rejected += 1;
    } else if (swarmInboundDecision.reason === 'timestamp_skew') {
      server.stats.swarm_timestamp_skew_rejected += 1;
    } else if (swarmInboundDecision.reason === 'unknown_node') {
      server.stats.swarm_unknown_node_rejected += 1;
    }

    if (effectiveMode === 'enforce' && swarmInboundDecision.shouldBlock) {
      const diagnostics = {
        errorSource: 'sentinel',
        upstreamError: false,
        provider,
        retryCount: 0,
        circuitState: server.circuitBreakers.getProviderState(breakerKey).state,
        correlationId,
      };
      responseHeaderDiagnostics(res, diagnostics);
      const statusCode = swarmInboundDecision.reason === 'replay_nonce' ? 409 : 401;
      await server.maybeNormalizeBlockedLatency({
        res,
        statusCode,
        requestStart,
      });
      server.stats.blocked_total += 1;
      server.stats.policy_blocked += 1;
      server.auditLogger.write({
        timestamp: new Date().toISOString(),
        correlation_id: correlationId,
        config_version: server.config.version,
        mode: effectiveMode,
        decision: 'blocked_swarm',
        reasons: [String(swarmInboundDecision.reason || 'swarm_verification_failed')],
        pii_types: [],
        redactions: 0,
        duration_ms: Date.now() - requestStart,
        request_bytes: rawBody.length,
        response_status: statusCode,
        response_bytes: 0,
        provider,
        swarm_node_id: swarmInboundDecision.nodeId,
        swarm_key_id: swarmInboundDecision.keyId,
        swarm_nonce: swarmInboundDecision.nonce,
        swarm_clock_skew_ms: Number.isFinite(Number(swarmInboundDecision.ageMs))
          ? Number(swarmInboundDecision.ageMs)
          : undefined,
        swarm_allowed_clock_skew_ms: Number(
          swarmInboundDecision.allowedClockSkewMs || server.swarmProtocol.allowedClockSkewMs || 0
        ),
      });
      server.writeStatus();
      finalizeRequestTelemetry({
        decision: 'blocked_policy',
        status: statusCode,
        providerName: provider,
      });
      res.status(statusCode).json({
        error: 'SWARM_VERIFICATION_FAILED',
        reason: swarmInboundDecision.reason,
        swarm_node_id: swarmInboundDecision.nodeId,
        correlation_id: correlationId,
      });
      return {
        handled: true,
        swarmInboundDecision,
      };
    }

    warnings.push(`swarm:${swarmInboundDecision.reason}`);
    server.stats.warnings_total += 1;
  }

  return {
    handled: false,
    swarmInboundDecision,
  };
}

module.exports = {
  runSwarmStage,
};
