const { responseHeaderDiagnostics } = require('../shared');

async function runSandboxStage({
  server,
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
}) {
  let sandboxDecision = null;

  if (server.experimentalSandbox.isEnabled()) {
    try {
      sandboxDecision = server.experimentalSandbox.inspect({
        bodyJson,
        effectiveMode,
      });
    } catch (error) {
      sandboxDecision = {
        enabled: true,
        detected: false,
        shouldBlock: false,
        findings: [],
        reason: 'sandbox_error',
        error: String(error.message || error),
      };
    }

    if (sandboxDecision?.detected) {
      server.stats.sandbox_detected += 1;
      warnings.push('sandbox_experimental:detected');
      server.stats.warnings_total += 1;
      if (server.experimentalSandbox.observability) {
        res.setHeader('x-sentinel-sandbox', sandboxDecision.shouldBlock ? 'block' : 'monitor');
        res.setHeader(
          'x-sentinel-sandbox-findings',
          String(Array.isArray(sandboxDecision.findings) ? sandboxDecision.findings.length : 0)
        );
      }
    } else if (sandboxDecision?.reason === 'sandbox_error') {
      server.stats.sandbox_errors += 1;
      warnings.push('sandbox_experimental:error');
      server.stats.warnings_total += 1;
    }

    if (sandboxDecision?.shouldBlock) {
      server.stats.blocked_total += 1;
      server.stats.policy_blocked += 1;
      server.stats.sandbox_blocked += 1;

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
        decision: 'blocked_sandbox_experimental',
        reasons: ['sandbox_experimental_policy'],
        pii_types: [],
        redactions: 0,
        duration_ms: Date.now() - requestStart,
        request_bytes: rawBody.length,
        response_status: 403,
        response_bytes: 0,
        provider,
        sandbox_findings: sandboxDecision.findings || [],
      });
      server.writeStatus();
      finalizeRequestTelemetry({
        decision: 'blocked_policy',
        status: 403,
        providerName: provider,
      });
      res.status(403).json({
        error: 'SANDBOX_EXPERIMENTAL_BLOCKED',
        reason: 'sandbox_experimental_policy',
        findings: (sandboxDecision.findings || []).slice(0, 10),
        correlation_id: correlationId,
      });
      return {
        handled: true,
        sandboxDecision,
      };
    }
  }

  return {
    handled: false,
    sandboxDecision,
  };
}

module.exports = {
  runSandboxStage,
};
