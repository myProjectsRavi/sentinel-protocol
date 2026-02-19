const { responseHeaderDiagnostics } = require('../shared');

async function runOmniShieldStage({
  server,
  res,
  bodyJson,
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
  let omniShieldDecision = server.omniShield.inspect({
    bodyJson,
    effectiveMode,
  });
  let omniShieldSanitizeDecision = null;

  if (omniShieldDecision.detected) {
    server.stats.omni_shield_detected += 1;
    warnings.push('omni_shield:image_payload_detected');
    server.stats.warnings_total += 1;
    if (server.omniShield.observability) {
      res.setHeader('x-sentinel-omni-shield', omniShieldDecision.shouldBlock ? 'block' : 'monitor');
      res.setHeader(
        'x-sentinel-omni-shield-findings',
        String(Array.isArray(omniShieldDecision.findings) ? omniShieldDecision.findings.length : 0)
      );
    }
  }

  if (omniShieldDecision.detected && server.omniShield.plugin?.enabled === true) {
    omniShieldSanitizeDecision = await server.omniShield.sanitizePayload({
      bodyJson,
      findings: omniShieldDecision.findings,
      effectiveMode,
    });
    if (server.omniShield.plugin?.observability) {
      res.setHeader('x-sentinel-omni-shield-plugin', String(omniShieldSanitizeDecision.reason || 'ok'));
      if (Number.isFinite(Number(omniShieldSanitizeDecision.rewrites))) {
        res.setHeader(
          'x-sentinel-omni-shield-plugin-rewrites',
          String(Number(omniShieldSanitizeDecision.rewrites || 0))
        );
      }
    }
    if (omniShieldSanitizeDecision.error) {
      server.stats.omni_shield_plugin_errors += 1;
      warnings.push('omni_shield:plugin_error');
      server.stats.warnings_total += 1;
    }
    if (omniShieldSanitizeDecision.applied && omniShieldSanitizeDecision.bodyJson) {
      bodyJson = omniShieldSanitizeDecision.bodyJson;
      bodyText = JSON.stringify(bodyJson);
      server.stats.omni_shield_sanitized += Number(omniShieldSanitizeDecision.rewrites || 0);
      warnings.push(`omni_shield:sanitized:${Number(omniShieldSanitizeDecision.rewrites || 0)}`);
      server.stats.warnings_total += 1;
      omniShieldDecision = server.omniShield.inspect({
        bodyJson,
        effectiveMode,
      });
    }
    if (omniShieldSanitizeDecision.shouldBlock) {
      server.stats.blocked_total += 1;
      server.stats.omni_shield_blocked += 1;
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
        decision: 'blocked_omni_shield_plugin',
        reasons: [String(omniShieldSanitizeDecision.reason || 'plugin_fail_closed')],
        pii_types: [],
        redactions: 0,
        duration_ms: Date.now() - requestStart,
        request_bytes: rawBody.length,
        response_status: 403,
        response_bytes: 0,
        provider,
        omni_shield_plugin_error: omniShieldSanitizeDecision.error,
        omni_shield_plugin_rewrites: omniShieldSanitizeDecision.rewrites,
        omni_shield_plugin_unsupported: omniShieldSanitizeDecision.unsupported,
      });
      server.writeStatus();
      finalizeRequestTelemetry({
        decision: 'blocked_policy',
        status: 403,
        providerName: provider,
      });
      res.status(403).json({
        error: 'OMNI_SHIELD_PLUGIN_BLOCKED',
        reason: omniShieldSanitizeDecision.reason,
        correlation_id: correlationId,
      });
      return {
        handled: true,
        bodyJson,
        bodyText,
        omniShieldDecision,
        omniShieldSanitizeDecision,
      };
    }
  }

  if (omniShieldDecision.shouldBlock) {
    server.stats.blocked_total += 1;
    server.stats.omni_shield_blocked += 1;
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
      decision: 'blocked_omni_shield',
      reasons: ['omni_shield_image_policy'],
      pii_types: [],
      redactions: 0,
      duration_ms: Date.now() - requestStart,
      request_bytes: rawBody.length,
      response_status: 403,
      response_bytes: 0,
      provider,
      omni_shield_findings: omniShieldDecision.violating_findings || omniShieldDecision.findings || [],
      omni_shield_plugin_applied: Boolean(omniShieldSanitizeDecision?.applied),
      omni_shield_plugin_rewrites: omniShieldSanitizeDecision?.rewrites || 0,
    });
    server.writeStatus();
    finalizeRequestTelemetry({
      decision: 'blocked_policy',
      status: 403,
      providerName: provider,
    });
    res.status(403).json({
      error: 'OMNI_SHIELD_BLOCKED',
      reason: 'omni_shield_image_policy',
      findings: (omniShieldDecision.violating_findings || omniShieldDecision.findings || []).map((item) => ({
        kind: item.kind,
        reason: item.reason,
        role: item.role,
        message_index: item.message_index,
        part_index: item.part_index,
        media_type: item.media_type || null,
        bytes: item.bytes,
      })),
      correlation_id: correlationId,
    });
    return {
      handled: true,
      bodyJson,
      bodyText,
      omniShieldDecision,
      omniShieldSanitizeDecision,
    };
  }

  return {
    handled: false,
    bodyJson,
    bodyText,
    omniShieldDecision,
    omniShieldSanitizeDecision,
  };
}

module.exports = {
  runOmniShieldStage,
};
