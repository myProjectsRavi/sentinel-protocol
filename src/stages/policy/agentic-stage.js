const { responseHeaderDiagnostics } = require('../shared');

async function runAgenticStage({
  server,
  req,
  res,
  bodyJson,
  effectiveMode,
  provider,
  breakerKey,
  correlationId,
  requestStart,
  rawBody,
  warnings,
  finalizeRequestTelemetry,
  agentObservabilityContext,
}) {
  let decision;
  try {
    decision = server.agenticThreatShield.evaluate({
      headers: req.headers || {},
      bodyJson,
      correlationId,
      effectiveMode,
    });
  } catch (error) {
    server.stats.agentic_threat_errors += 1;
    warnings.push('agentic:error');
    server.stats.warnings_total += 1;
    decision = {
      enabled: true,
      detected: false,
      shouldBlock: false,
      reasons: [],
      violations: [],
      error: String(error.message || error),
    };
  }

  if (server.agentObservability?.isEnabled?.() && agentObservabilityContext) {
    const toolCallCount = Number(decision?.toolCallCount || 0);
    const delegationCount = Number(decision?.totalDelegations || decision?.delegationCount || 0);
    if (toolCallCount > 0) {
      server.agentObservability.emitLifecycle(
        agentObservabilityContext,
        'agent.tool_call',
        {
          tool_call_count: toolCallCount,
          max_depth: Number(decision?.maxDepth || 0),
          cycle_detected: decision?.cycleDetected === true,
        }
      );
    }
    if (delegationCount > 0) {
      server.agentObservability.emitLifecycle(
        agentObservabilityContext,
        'agent.delegate',
        {
          delegation_count: delegationCount,
          max_depth: Number(decision?.maxDepth || 0),
        }
      );
    }
  }

  if (decision?.enabled && server.agenticThreatShield.observability) {
    res.setHeader(
      'x-sentinel-agentic-shield',
      decision.detected ? 'detected' : 'clean'
    );
    res.setHeader('x-sentinel-agentic-mode', String(server.agenticThreatShield.mode || 'monitor'));
    if (Number.isFinite(Number(decision.maxDepth))) {
      res.setHeader('x-sentinel-agentic-depth', String(decision.maxDepth));
    }
    if (Number.isFinite(Number(decision.totalDelegations))) {
      res.setHeader('x-sentinel-agentic-delegations', String(decision.totalDelegations));
    }
    if (decision.cycleDetected) {
      res.setHeader('x-sentinel-agentic-cycle', 'true');
    }
    if (decision.analysisTruncated) {
      res.setHeader('x-sentinel-agentic-analysis', String(decision.analysisTruncatedReason || 'truncated'));
    }
    if (decision.identity?.required) {
      res.setHeader(
        'x-sentinel-agentic-identity',
        decision.identity.verified ? 'verified' : String(decision.identity.reason || 'invalid')
      );
    }
  }

  if (decision?.detected) {
    server.stats.agentic_threat_detected += 1;
    if (decision.analysisTruncated) {
      server.stats.agentic_analysis_truncated += 1;
    }
    if (decision.identity?.reason === 'identity_token_invalid') {
      server.stats.agentic_identity_invalid += 1;
    }
    const reason = decision.reasons?.[0] || 'agentic_threat_detected';
    warnings.push(`agentic:${reason}`);
    server.stats.warnings_total += 1;

    if (decision.shouldBlock) {
      server.stats.blocked_total += 1;
      server.stats.policy_blocked += 1;
      server.stats.agentic_threat_blocked += 1;
      res.setHeader('x-sentinel-blocked-by', 'agentic_threat_shield');
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
        decision: 'blocked_agentic_threat',
        reasons: decision.reasons,
        pii_types: [],
        redactions: 0,
        duration_ms: Date.now() - requestStart,
        request_bytes: rawBody.length,
        response_status: 403,
        response_bytes: 0,
        provider,
        agentic_max_depth: decision.maxDepth,
        agentic_tool_call_count: decision.toolCallCount,
        agentic_delegation_count: decision.delegationCount,
        agentic_total_delegations: decision.totalDelegations,
        agentic_cycle_detected: decision.cycleDetected,
        agentic_identity_reason: decision.identity?.reason,
        agentic_violations: decision.violations || [],
      });
      server.writeStatus();
      finalizeRequestTelemetry({
        decision: 'blocked_policy',
        status: 403,
        providerName: provider,
      });
      res.status(403).json({
        error: 'AGENTIC_THREAT_DETECTED',
        reason: decision.reasons?.[0] || 'agentic_threat_detected',
        violations: decision.violations || [],
        correlation_id: correlationId,
      });
      return {
        handled: true,
        agenticDecision: decision,
      };
    }
  }

  return {
    handled: false,
    agenticDecision: decision,
  };
}

module.exports = {
  runAgenticStage,
};
