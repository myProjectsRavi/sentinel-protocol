const { scanBufferedResponse } = require('../../egress/response-scanner');
const { runParallaxStage } = require('../policy/parallax-stage');
const {
  responseHeaderDiagnostics,
  formatBudgetUsd,
  setBudgetHeaders,
} = require('../shared');

function buildBufferedDiagnostics({
  server,
  correlationId,
  routedProvider,
  routedBreakerKey,
  upstream,
}) {
  return {
    errorSource: 'sentinel',
    upstreamError: false,
    provider: routedProvider,
    retryCount: upstream.diagnostics.retryCount || 0,
    circuitState: server.circuitBreakers.getProviderState(routedBreakerKey).state,
    correlationId,
  };
}

async function runBufferedEgressAndFinalizeStage({
  server,
  req,
  res,
  upstream,
  egressConfig,
  effectiveMode,
  correlationId,
  routedProvider,
  routedTarget,
  routedBreakerKey,
  routePlan,
  warnings,
  bodyBuffer,
  requestStart,
  durationMs,
  runOrchestratedStage,
  replayedFromVcr,
  replayedFromSemanticCache,
  vcrRequestMeta,
  piiVaultSessionKey,
  parallaxInputBodyJson,
  bodyJson,
  method,
  pathWithQuery,
  wantsStream,
  bodyText,
  cacheProviderKey,
  injectionScore,
  piiTypes,
  redactedCount,
  honeytokenDecision,
  canaryToolDecision,
  canaryTriggered,
  parallaxDecision,
  cognitiveRollbackDecision,
  omniShieldDecision,
  intentDriftDecision,
  sandboxDecision,
  finalizeRequestTelemetry,
}) {
  let outboundBody = upstream.body;
  let currentCanaryTriggered = canaryTriggered;
  let currentParallaxDecision = parallaxDecision;
  let currentCognitiveRollbackDecision = cognitiveRollbackDecision;

  if (
    !replayedFromVcr &&
    server.vcrStore.enabled &&
    server.vcrStore.mode === 'record' &&
    Buffer.isBuffer(upstream.body)
  ) {
    server.vcrStore.record(vcrRequestMeta, {
      status: upstream.status,
      headers: upstream.responseHeaders || {},
      bodyBuffer: upstream.body,
    });
    server.stats.vcr_records += 1;
    res.setHeader('x-sentinel-vcr', 'recorded');
  }

  if (egressConfig.enabled) {
    const bufferedEgressScanExecution = await runOrchestratedStage(
      'buffered_egress_scan',
      async () =>
        scanBufferedResponse({
          bodyBuffer: outboundBody,
          contentType: upstream.responseHeaders?.['content-type'],
          scanner: server.piiScanner,
          maxScanBytes: egressConfig.maxScanBytes,
          severityActions: server.config.pii?.severity_actions || {},
          effectiveMode,
          entropyConfig: egressConfig.entropy,
        }),
      routedProvider
    );
    if (bufferedEgressScanExecution.handled) {
      return { handled: true };
    }
    const egressResult = bufferedEgressScanExecution.result;

    if (egressResult.detected) {
      server.stats.egress_detected += 1;
      warnings.push(`egress_pii:${egressResult.severity}`);
      if (egressResult.redacted) {
        server.stats.egress_redacted += 1;
        outboundBody = egressResult.bodyBuffer;
        res.setHeader('x-sentinel-egress-action', 'redact');
      }
      if (egressResult.redactionSkipped) {
        warnings.push('egress_redaction_skipped_truncated');
        server.stats.warnings_total += 1;
      }

      if (egressResult.blocked) {
        server.stats.blocked_total += 1;
        server.stats.egress_blocked += 1;
        const diagnostics = buildBufferedDiagnostics({
          server,
          correlationId,
          routedProvider,
          routedBreakerKey,
          upstream,
        });
        responseHeaderDiagnostics(res, diagnostics);
        res.setHeader('x-sentinel-egress-action', 'block');
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
          decision: 'blocked_egress',
          reasons: ['egress_pii_detected'],
          pii_types: egressResult.piiTypes,
          redactions: 0,
          duration_ms: durationMs,
          request_bytes: bodyBuffer.length,
          response_status: 403,
          response_bytes: 0,
          provider: routedProvider,
          upstream_target: routedTarget,
          failover_used: upstream.route?.failoverUsed === true,
          route_source: routePlan.routeSource,
          route_group: routePlan.selectedGroup || undefined,
          route_contract: routePlan.desiredContract,
          requested_target: routePlan.requestedTarget,
        });
        server.writeStatus();
        finalizeRequestTelemetry({
          decision: 'blocked_egress',
          status: 403,
          providerName: routedProvider,
        });
        res.status(403).json({
          error: 'EGRESS_PII_DETECTED',
          reason: 'egress_pii_detected',
          pii_types: egressResult.piiTypes,
          correlation_id: correlationId,
        });
        return { handled: true };
      }
    }

    if (egressResult.entropy?.detected) {
      server.stats.egress_entropy_detected += 1;
      warnings.push(`egress_entropy:${egressResult.entropy.action}`);
      const entropyFindings = Array.isArray(egressResult.entropy.findings)
        ? egressResult.entropy.findings
        : [];
      res.setHeader('x-sentinel-egress-entropy', egressResult.entropy.action || 'monitor');
      res.setHeader('x-sentinel-egress-entropy-findings', String(entropyFindings.length));
      if (egressResult.entropy.truncated) {
        warnings.push('egress_entropy_scan_truncated');
        server.stats.warnings_total += 1;
      }
      if (egressResult.entropy.blocked) {
        server.stats.blocked_total += 1;
        server.stats.egress_entropy_blocked += 1;
        const diagnostics = buildBufferedDiagnostics({
          server,
          correlationId,
          routedProvider,
          routedBreakerKey,
          upstream,
        });
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
          decision: 'blocked_egress_entropy',
          reasons: ['egress_entropy_detected'],
          pii_types: piiTypes,
          egress_entropy_findings: entropyFindings,
          redactions: 0,
          duration_ms: durationMs,
          request_bytes: bodyBuffer.length,
          response_status: 403,
          response_bytes: 0,
          provider: routedProvider,
          upstream_target: routedTarget,
          failover_used: upstream.route?.failoverUsed === true,
          route_source: routePlan.routeSource,
          route_group: routePlan.selectedGroup || undefined,
          route_contract: routePlan.desiredContract,
          requested_target: routePlan.requestedTarget,
        });
        server.writeStatus();
        finalizeRequestTelemetry({
          decision: 'blocked_egress',
          status: 403,
          providerName: routedProvider,
        });
        res.status(403).json({
          error: 'EGRESS_ENTROPY_DETECTED',
          reason: 'egress_entropy_detected',
          findings: entropyFindings.map((item) => ({
            kind: item.kind,
            entropy: item.entropy,
            token_hash: item.token_hash,
            length: item.length,
          })),
          correlation_id: correlationId,
        });
        return { handled: true };
      }
    }
  }

  currentCanaryTriggered = null;
  if (server.canaryToolTrap.isEnabled()) {
    const canaryDetectStageExecution = await runOrchestratedStage(
      'canary_tool_detect',
      async () =>
        server.canaryToolTrap.detectTriggered(
          outboundBody,
          upstream.responseHeaders?.['content-type']
        ),
      routedProvider
    );
    if (canaryDetectStageExecution.handled) {
      return { handled: true };
    }
    currentCanaryTriggered = canaryDetectStageExecution.result;
    if (currentCanaryTriggered.triggered) {
      server.stats.canary_tool_triggered += 1;
      warnings.push('canary_tool_triggered');
      server.stats.warnings_total += 1;
      res.setHeader('x-sentinel-canary-tool-triggered', 'true');
      res.setHeader('x-sentinel-canary-tool-name', currentCanaryTriggered.toolName);

      const rollbackCandidate = server.cognitiveRollback.suggest({
        bodyJson: parallaxInputBodyJson || bodyJson,
        trigger: 'canary_tool_triggered',
      });
      if (rollbackCandidate.applicable) {
        currentCognitiveRollbackDecision = rollbackCandidate;
        server.stats.cognitive_rollback_suggested += 1;
        warnings.push('cognitive_rollback_suggested');
        server.stats.warnings_total += 1;
        if (server.cognitiveRollback.observability) {
          res.setHeader(
            'x-sentinel-cognitive-rollback',
            server.cognitiveRollback.shouldAuto() ? 'auto' : 'suggested'
          );
          res.setHeader('x-sentinel-cognitive-rollback-trigger', 'canary_tool_triggered');
          res.setHeader(
            'x-sentinel-cognitive-rollback-dropped',
            String(rollbackCandidate.droppedMessages || 0)
          );
        }
      }

      if (effectiveMode === 'enforce' && server.canaryToolTrap.mode === 'block') {
        if (rollbackCandidate.applicable && server.cognitiveRollback.shouldAuto()) {
          server.stats.cognitive_rollback_auto += 1;
          const diagnostics = buildBufferedDiagnostics({
            server,
            correlationId,
            routedProvider,
            routedBreakerKey,
            upstream,
          });
          responseHeaderDiagnostics(res, diagnostics);
          server.auditLogger.write({
            timestamp: new Date().toISOString(),
            correlation_id: correlationId,
            config_version: server.config.version,
            mode: effectiveMode,
            decision: 'cognitive_rollback_required',
            reasons: ['canary_tool_triggered'],
            pii_types: piiTypes,
            redactions: redactedCount,
            duration_ms: durationMs,
            request_bytes: bodyBuffer.length,
            response_status: 409,
            response_bytes: 0,
            provider: routedProvider,
            upstream_target: routedTarget,
            canary_tool_name: currentCanaryTriggered.toolName,
            cognitive_rollback_trigger: 'canary_tool_triggered',
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
            reason: 'canary_tool_triggered',
            rollback: {
              mode: server.cognitiveRollback.mode,
              trigger: 'canary_tool_triggered',
              dropped_messages: rollbackCandidate.droppedMessages,
              messages: rollbackCandidate.bodyJson.messages,
            },
            correlation_id: correlationId,
          });
          return { handled: true };
        }

        server.stats.blocked_total += 1;
        const diagnostics = buildBufferedDiagnostics({
          server,
          correlationId,
          routedProvider,
          routedBreakerKey,
          upstream,
        });
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
          decision: 'blocked_canary_tool',
          reasons: ['canary_tool_triggered'],
          pii_types: piiTypes,
          redactions: redactedCount,
          duration_ms: durationMs,
          request_bytes: bodyBuffer.length,
          response_status: 403,
          response_bytes: 0,
          provider: routedProvider,
          upstream_target: routedTarget,
          canary_tool_name: currentCanaryTriggered.toolName,
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
          error: 'CANARY_TOOL_TRIGGERED',
          reason: 'canary_tool_triggered',
          tool_name: currentCanaryTriggered.toolName,
          correlation_id: correlationId,
        });
        return { handled: true };
      }
    }
  }

  const parallaxStageExecution = await runOrchestratedStage(
    'parallax',
    async () =>
      runParallaxStage({
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
        cognitiveRollbackDecision: currentCognitiveRollbackDecision,
      }),
    routedProvider
  );
  if (parallaxStageExecution.handled) {
    return { handled: true };
  }
  const parallaxStageResult = parallaxStageExecution.result;
  currentParallaxDecision = parallaxStageResult.parallaxDecision;
  currentCognitiveRollbackDecision = parallaxStageResult.cognitiveRollbackDecision;
  if (parallaxStageResult.handled) {
    return { handled: true };
  }

  if (warnings.length > 0) {
    res.setHeader('x-sentinel-warning', warnings.join(','));
  }

  if (!replayedFromVcr && !replayedFromSemanticCache && server.semanticCache.isEnabled()) {
    const cacheSafeForStore =
      upstream.status >= 200 &&
      upstream.status < 300 &&
      injectionScore === 0 &&
      piiTypes.length === 0 &&
      redactedCount === 0 &&
      !warnings.some((item) => {
        const warning = String(item);
        return (
          warning.startsWith('policy:') ||
          warning.startsWith('pii:') ||
          warning.startsWith('injection:') ||
          warning.startsWith('egress_pii:') ||
          warning.includes('fallback') ||
          warning.includes('error')
        );
      });
    if (cacheSafeForStore) {
      try {
        const semanticStoreStageExecution = await runOrchestratedStage(
          'semantic_cache_store',
          async () =>
            server.semanticCache.store({
              provider: cacheProviderKey,
              method,
              pathWithQuery,
              wantsStream,
              bodyJson,
              bodyText,
              responseStatus: upstream.status,
              responseHeaders: upstream.responseHeaders || {},
              responseBodyBuffer: outboundBody,
            }),
          routedProvider
        );
        if (semanticStoreStageExecution.handled) {
          return { handled: true };
        }
        const stored = semanticStoreStageExecution.result;
        if (stored.stored) {
          server.stats.semantic_cache_stores += 1;
          res.setHeader('x-sentinel-semantic-cache', 'store');
        }
      } catch {
        warnings.push('semantic_cache_store_error');
        server.stats.warnings_total += 1;
      }
    }
  }

  let responseBodyForClient = outboundBody;
  const piiVaultEgressStageExecution = await runOrchestratedStage(
    'pii_vault_egress',
    async () =>
      server.piiVault.applyEgressBuffer({
        bodyBuffer: outboundBody,
        contentType: upstream.responseHeaders?.['content-type'],
        sessionKey: piiVaultSessionKey,
      }),
    routedProvider
  );
  if (piiVaultEgressStageExecution.handled) {
    return { handled: true };
  }
  const vaultEgress = piiVaultEgressStageExecution.result;
  if (vaultEgress.changed) {
    responseBodyForClient = vaultEgress.bodyBuffer;
    server.stats.pii_vault_detokenized += Number(vaultEgress.replacements || 0);
    warnings.push(`pii_vault:detokenized:${vaultEgress.replacements || 0}`);
    server.stats.warnings_total += 1;
    if (server.piiVault.observability) {
      res.setHeader('x-sentinel-pii-vault-egress', 'detokenize');
      res.setHeader(
        'x-sentinel-pii-vault-egress-replacements',
        String(vaultEgress.replacements || 0)
      );
    }
  }

  let budgetCharge = null;
  try {
    const budgetRecordStageExecution = await runOrchestratedStage(
      'budget_record',
      async () =>
        server.budgetStore.recordBuffered({
          provider: routedProvider,
          requestBodyBuffer: bodyBuffer,
          responseBodyBuffer: responseBodyForClient,
          replayedFromVcr,
          replayedFromSemanticCache,
          correlationId,
        }),
      routedProvider
    );
    if (budgetRecordStageExecution.handled) {
      return { handled: true };
    }
    budgetCharge = budgetRecordStageExecution.result;
    if (budgetCharge.charged) {
      server.stats.budget_charged_usd = Number(
        (server.stats.budget_charged_usd + Number(budgetCharge.chargedUsd || 0)).toFixed(6)
      );
      res.setHeader(
        'x-sentinel-budget-charged-usd',
        formatBudgetUsd(budgetCharge.chargedUsd)
      );
    }
    if (budgetCharge.enabled === true) {
      setBudgetHeaders(res, budgetCharge);
    }
  } catch {
    warnings.push('budget_record_error');
    server.stats.warnings_total += 1;
  }

  server.auditLogger.write({
    timestamp: new Date().toISOString(),
    correlation_id: correlationId,
    config_version: server.config.version,
    mode: effectiveMode,
    decision: 'forwarded',
    reasons: warnings,
    pii_types: piiTypes,
    redactions: redactedCount,
    duration_ms: durationMs,
    request_bytes: bodyBuffer.length,
    response_status: upstream.status,
    response_bytes: responseBodyForClient.length,
    provider: routedProvider,
    upstream_target: routedTarget,
    failover_used: upstream.route?.failoverUsed === true,
    budget_charged_usd: budgetCharge?.chargedUsd,
    budget_spent_usd: budgetCharge?.spentUsd,
    budget_remaining_usd: budgetCharge?.remainingUsd,
    route_source: routePlan.routeSource,
    route_group: routePlan.selectedGroup || undefined,
    route_contract: routePlan.desiredContract,
    requested_target: routePlan.requestedTarget,
    honeytoken_applied: Boolean(honeytokenDecision),
    honeytoken_mode: honeytokenDecision?.mode,
    honeytoken_token_hash: honeytokenDecision?.token_hash,
    canary_tool_injected: Boolean(canaryToolDecision),
    canary_tool_name: canaryToolDecision?.tool_name || currentCanaryTriggered?.toolName,
    canary_tool_triggered: Boolean(currentCanaryTriggered?.triggered),
    parallax_evaluated: Boolean(currentParallaxDecision?.evaluated),
    parallax_veto: Boolean(currentParallaxDecision?.veto),
    parallax_risk: currentParallaxDecision?.risk,
    parallax_secondary_provider: currentParallaxDecision?.secondaryProvider,
    parallax_high_risk_tools: currentParallaxDecision?.highRiskTools,
    cognitive_rollback_suggested: Boolean(currentCognitiveRollbackDecision?.applicable),
    cognitive_rollback_mode: currentCognitiveRollbackDecision?.mode,
    cognitive_rollback_trigger: currentCognitiveRollbackDecision?.trigger,
    cognitive_rollback_dropped_messages: currentCognitiveRollbackDecision?.droppedMessages,
    omni_shield_detected: Boolean(omniShieldDecision?.detected),
    omni_shield_findings: omniShieldDecision?.findings,
    intent_drift_evaluated: Boolean(intentDriftDecision?.evaluated),
    intent_drift_reason: intentDriftDecision?.reason,
    intent_drift_drifted: Boolean(intentDriftDecision?.drifted),
    intent_drift_distance: intentDriftDecision?.distance,
    intent_drift_threshold: intentDriftDecision?.threshold,
    intent_drift_turn_count: intentDriftDecision?.turnCount,
    sandbox_detected: Boolean(sandboxDecision?.detected),
    sandbox_findings: sandboxDecision?.findings,
    pii_vault_detokenized: vaultEgress.replacements || 0,
  });

  if (upstream.status < 400) {
    server.latencyNormalizer.recordSuccess(Date.now() - requestStart);
  }
  finalizeRequestTelemetry({
    decision: 'forwarded',
    status: upstream.status,
    providerName: routedProvider,
  });
  res.status(upstream.status).send(responseBodyForClient);

  return { handled: true };
}

module.exports = {
  runBufferedEgressAndFinalizeStage,
};
