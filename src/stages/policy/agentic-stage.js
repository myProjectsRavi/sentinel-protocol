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
  const headers = req?.headers || {};
  const sessionId = String(headers['x-sentinel-session-id'] || correlationId || 'anonymous');
  const agentId = String(headers['x-sentinel-agent-id'] || 'agent:unknown');
  let decision;
  try {
    decision = server.agenticThreatShield.evaluate({
      headers,
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

  const auxiliaryDecisions = [];
  if (server.memoryPoisoningSentinel?.isEnabled()) {
    const memoryDecision = server.memoryPoisoningSentinel.evaluate({
      sessionId,
      bodyJson,
      effectiveMode,
    });
    auxiliaryDecisions.push({
      name: 'memory_poisoning',
      decision: memoryDecision,
      warningPrefix: 'memory_poisoning',
      statsDetected: 'memory_poisoning_detected',
      statsBlocked: 'memory_poisoning_blocked',
    });
  }
  if (server.cascadeIsolator?.isEnabled()) {
    const cascadeDecision = server.cascadeIsolator.evaluate({
      sessionId,
      agentId,
      bodyJson,
      effectiveMode,
    });
    auxiliaryDecisions.push({
      name: 'cascade_isolator',
      decision: cascadeDecision,
      warningPrefix: 'cascade',
      statsDetected: 'cascade_detected',
      statsBlocked: 'cascade_blocked',
    });
  }
  if (server.agentIdentityFederation?.isEnabled()) {
    const identityDecision = server.agentIdentityFederation.evaluate({
      headers,
      effectiveMode,
    });
    auxiliaryDecisions.push({
      name: 'agent_identity_federation',
      decision: identityDecision,
      warningPrefix: 'agent_identity',
      statsDetected: 'agent_identity_detected',
      statsBlocked: 'agent_identity_blocked',
    });
  }
  if (server.toolUseAnomalyDetector?.isEnabled()) {
    const toolNames = [];
    if (bodyJson?.tool && typeof bodyJson.tool === 'object' && bodyJson.tool.name) {
      toolNames.push(String(bodyJson.tool.name));
    }
    if (typeof bodyJson?.tool_name === 'string') {
      toolNames.push(String(bodyJson.tool_name));
    }
    if (Array.isArray(bodyJson?.tools)) {
      for (const tool of bodyJson.tools.slice(0, 8)) {
        const name = tool?.function?.name;
        if (name) {
          toolNames.push(String(name));
        }
      }
    }
    let anomalyDecision = {
      enabled: server.toolUseAnomalyDetector.isEnabled(),
      detected: false,
      shouldBlock: false,
      reason: 'clean',
      findings: [],
    };
    for (const toolName of toolNames) {
      const current = server.toolUseAnomalyDetector.evaluate({
        agentId,
        toolName,
        argsBytes: Buffer.byteLength(JSON.stringify(bodyJson?.arguments || bodyJson?.tool_arguments || {}), 'utf8'),
        resultBytes: 0,
        effectiveMode,
      });
      if (current.detected) {
        anomalyDecision = current;
        break;
      }
      anomalyDecision = current;
    }
    auxiliaryDecisions.push({
      name: 'tool_use_anomaly',
      decision: anomalyDecision,
      warningPrefix: 'tool_use_anomaly',
      statsDetected: 'tool_use_anomaly_detected',
      statsBlocked: 'tool_use_anomaly_blocked',
    });
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
  }

  for (const entry of auxiliaryDecisions) {
    const aux = entry.decision;
    if (!aux?.enabled || !aux.detected) {
      continue;
    }
    server.stats[entry.statsDetected] += 1;
    warnings.push(`${entry.warningPrefix}:${aux.reason || 'detected'}`);
    server.stats.warnings_total += 1;
  }

  const blockingDecision = decision?.shouldBlock
    ? {
        blockedBy: 'agentic_threat_shield',
        error: 'AGENTIC_THREAT_DETECTED',
        reason: decision.reasons?.[0] || 'agentic_threat_detected',
        detail: {
          agentic_violations: decision.violations || [],
          agentic_identity_reason: decision.identity?.reason,
        },
      }
    : (() => {
        const aux = auxiliaryDecisions.find((item) => item.decision?.shouldBlock);
        if (!aux) {
          return null;
        }
        return {
          blockedBy: aux.name,
          error: `${String(aux.name || 'policy').toUpperCase()}_DETECTED`,
          reason: aux.decision.reason || `${aux.name}_detected`,
          detail: {
            findings: aux.decision.findings || [],
          },
          statsBlocked: aux.statsBlocked,
        };
      })();

  if (blockingDecision) {
    server.stats.blocked_total += 1;
    server.stats.policy_blocked += 1;
    server.stats.agentic_threat_blocked += blockingDecision.blockedBy === 'agentic_threat_shield' ? 1 : 0;
    if (blockingDecision.statsBlocked) {
      server.stats[blockingDecision.statsBlocked] += 1;
    }
    res.setHeader('x-sentinel-blocked-by', blockingDecision.blockedBy);
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
      decision: `blocked_${blockingDecision.blockedBy}`,
      reasons: [blockingDecision.reason],
      pii_types: [],
      redactions: 0,
      duration_ms: Date.now() - requestStart,
      request_bytes: rawBody.length,
      response_status: 403,
      response_bytes: 0,
      provider,
      agentic_max_depth: decision?.maxDepth,
      agentic_tool_call_count: decision?.toolCallCount,
      agentic_delegation_count: decision?.delegationCount,
      agentic_total_delegations: decision?.totalDelegations,
      agentic_cycle_detected: decision?.cycleDetected,
      agentic_identity_reason: decision?.identity?.reason,
      agentic_violations: decision?.violations || [],
      ...blockingDecision.detail,
    });
    server.writeStatus();
    finalizeRequestTelemetry({
      decision: 'blocked_policy',
      status: 403,
      providerName: provider,
    });
    res.status(403).json({
      error: blockingDecision.error,
      reason: blockingDecision.reason,
      correlation_id: correlationId,
    });
    return {
      handled: true,
      agenticDecision: decision,
    };
  }

  return {
    handled: false,
    agenticDecision: decision,
  };
}

module.exports = {
  runAgenticStage,
};
