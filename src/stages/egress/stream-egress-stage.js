const logger = require('../../utils/logger');
const { SSERedactionTransform } = require('../../egress/sse-redaction-transform');
const { ProvenanceSigner } = require('../../security/provenance-signer');
const { StringDecoder } = require('string_decoder');

function terminateStream({ upstreamBodyStream, streamOut, res, code }) {
  setImmediate(() => {
    const error = new Error(code);
    if (typeof upstreamBodyStream?.destroy === 'function') {
      upstreamBodyStream.destroy(error);
    }
    if (streamOut !== upstreamBodyStream && typeof streamOut?.destroy === 'function') {
      streamOut.destroy(error);
    }
    if (!res.destroyed) {
      res.destroy(error);
    }
  });
}

function buildStreamEgressAuditFields({
  streamEgressTypes,
  streamProjectedRedaction,
  streamBlockedSeverity,
  streamEntropyFindings,
  streamEntropyMode,
  streamEntropyProjectedRedaction,
  outputClassifierCategories,
  outputClassifierBlocked,
  stegoDetected,
  stegoBlocked,
  stegoFindings,
  reasoningDetected,
  reasoningBlocked,
  reasoningFindings,
  hallucinationDetected,
  hallucinationBlocked,
  hallucinationFindings,
  crossTenantDetected,
  crossTenantBlocked,
  crossTenantFindings,
  semanticDriftDetected,
  semanticDriftBlocked,
  semanticDriftFindings,
}) {
  return {
    egress_pii_types: Array.from(streamEgressTypes).sort(),
    egress_projected_redaction: streamProjectedRedaction || undefined,
    egress_block_severity: streamBlockedSeverity || undefined,
    egress_entropy_findings: streamEntropyFindings,
    egress_entropy_mode: streamEntropyMode || undefined,
    egress_entropy_projected_redaction: streamEntropyProjectedRedaction || undefined,
    output_classifier_categories: Array.from(outputClassifierCategories || []).sort(),
    output_classifier_blocked: outputClassifierBlocked === true ? true : undefined,
    stego_detected: stegoDetected === true ? true : undefined,
    stego_blocked: stegoBlocked === true ? true : undefined,
    stego_findings: stegoFindings || [],
    reasoning_trace_detected: reasoningDetected === true ? true : undefined,
    reasoning_trace_blocked: reasoningBlocked === true ? true : undefined,
    reasoning_trace_findings: reasoningFindings || [],
    hallucination_detected: hallucinationDetected === true ? true : undefined,
    hallucination_blocked: hallucinationBlocked === true ? true : undefined,
    hallucination_findings: hallucinationFindings || [],
    cross_tenant_egress_detected: crossTenantDetected === true ? true : undefined,
    cross_tenant_egress_blocked: crossTenantBlocked === true ? true : undefined,
    cross_tenant_egress_findings: crossTenantFindings || [],
    semantic_drift_detected: semanticDriftDetected === true ? true : undefined,
    semantic_drift_blocked: semanticDriftBlocked === true ? true : undefined,
    semantic_drift_findings: semanticDriftFindings || [],
  };
}

async function runStreamEgressStage({
  server,
  req,
  res,
  upstream,
  egressConfig,
  effectiveMode,
  correlationId,
  routedProvider,
  piiVaultSessionKey,
  warnings,
  bodyBuffer,
  requestStart,
  start,
  replayedFromVcr,
  replayedFromSemanticCache,
  routePlan,
  honeytokenDecision,
  canaryToolDecision,
  canaryTriggered,
  parallaxDecision,
  cognitiveRollbackDecision,
  omniShieldDecision,
  intentDriftDecision,
  sandboxDecision,
  redactedCount,
  piiTypes,
  routedTarget,
  finalizeRequestTelemetry,
}) {
  if (!upstream.isStream) {
    return {
      handled: false,
    };
  }

  res.status(upstream.status);
  let streamedBytes = 0;
  let streamOut = upstream.bodyStream;
  let streamTerminatedForPII = false;
  let streamTerminatedForEntropy = false;
  const streamEgressTypes = new Set();
  let streamProjectedRedaction = null;
  let streamBlockedSeverity = null;
  let streamVaultReplacements = 0;
  const streamEntropyFindings = [];
  let streamEntropyProjectedRedaction = null;
  let streamEntropyMode = null;
  let streamTerminatedForClassifier = false;
  let streamOutputClassifierDetected = false;
  const streamOutputClassifierCategories = new Set();
  const classifierDecoder = new StringDecoder('utf8');
  let classifierWindow = '';
  let streamStegoDetected = false;
  let streamStegoBlocked = false;
  let streamReasoningDetected = false;
  let streamReasoningBlocked = false;
  let streamHallucinationDetected = false;
  let streamHallucinationBlocked = false;
  let streamCrossTenantDetected = false;
  let streamCrossTenantBlocked = false;
  let streamSemanticDriftDetected = false;
  let streamSemanticDriftBlocked = false;
  const streamStegoFindings = [];
  const streamReasoningFindings = [];
  const streamHallucinationFindings = [];
  const streamCrossTenantFindings = [];
  const streamSemanticDriftFindings = [];
  const upstreamContentType = String(upstream.responseHeaders?.['content-type'] || '').toLowerCase();
  const streamProof = server.provenanceSigner.createStreamContext({
    statusCode: upstream.status,
    provider: routedProvider,
    correlationId,
  });
  const proofContext =
    streamProof &&
    typeof streamProof.update === 'function' &&
    typeof streamProof.finalize === 'function'
      ? streamProof
      : null;
  const canAddProofTrailers =
    Boolean(proofContext) &&
    server.provenanceSigner.signStreamTrailers === true &&
    typeof res.addTrailers === 'function';
  if (canAddProofTrailers) {
    res.setHeader(
      'trailer',
      'x-sentinel-signature-v, x-sentinel-signature-alg, x-sentinel-signature-key-id, x-sentinel-signature-input, x-sentinel-payload-sha256, x-sentinel-signature'
    );
    res.setHeader('x-sentinel-signature-status', 'stream-trailer');
  } else if (server.provenanceSigner.isEnabled()) {
    res.setHeader('x-sentinel-signature-status', 'stream-unsigned');
  }
  if (server.computeAttestation?.isEnabled?.() && !res.getHeader('x-sentinel-attestation')) {
    const attestation = server.computeAttestation.create({
      configHash: server.getRuntimeConfigHash(),
      policyHash: server.getRuntimeConfigHash(),
      correlationId,
      provider: routedProvider,
    });
    if (attestation?.envelope) {
      res.setHeader('x-sentinel-attestation', attestation.envelope);
      server.stats.compute_attestation_signed += 1;
    }
  }

  if (egressConfig.enabled && egressConfig.streamEnabled && upstreamContentType.includes('text/event-stream')) {
    const streamRedactor = new SSERedactionTransform({
      scanner: server.piiScanner,
      maxScanBytes: egressConfig.maxScanBytes,
      maxLineBytes: egressConfig.sseLineMaxBytes,
      severityActions: server.config.pii?.severity_actions || {},
      effectiveMode,
      streamBlockMode: egressConfig.streamBlockMode,
      entropyConfig: egressConfig.entropy,
      onDetection: ({ action, severity, findings, projectedRedaction }) => {
        server.stats.egress_detected += 1;
        streamBlockedSeverity = severity || streamBlockedSeverity;
        for (const finding of findings || []) {
          if (finding?.id) {
            streamEgressTypes.add(String(finding.id));
          }
        }
        if (typeof projectedRedaction === 'string' && projectedRedaction.length > 0 && !streamProjectedRedaction) {
          streamProjectedRedaction = projectedRedaction.slice(0, 512);
        }
        if (action === 'redact') {
          server.stats.egress_stream_redacted += 1;
        }
        if (action === 'block' && egressConfig.streamBlockMode === 'terminate' && !streamTerminatedForPII) {
          streamTerminatedForPII = true;
          server.stats.blocked_total += 1;
          server.stats.egress_blocked += 1;
          if (!res.headersSent) {
            res.setHeader('x-sentinel-egress-action', 'stream_terminate');
          }
          warnings.push('egress_stream_blocked');
          server.stats.warnings_total += 1;
          terminateStream({
            upstreamBodyStream: upstream.bodyStream,
            streamOut,
            res,
            code: 'EGRESS_STREAM_BLOCKED',
          });
        }
      },
      onEntropy: ({ action, findings, threshold, projectedRedaction, truncated }) => {
        server.stats.egress_entropy_detected += 1;
        streamEntropyMode = action;
        if (!res.headersSent) {
          res.setHeader('x-sentinel-egress-entropy', String(action || 'monitor'));
        }
        if (truncated === true) {
          warnings.push('egress_entropy_scan_truncated');
          server.stats.warnings_total += 1;
        }
        for (const finding of findings || []) {
          streamEntropyFindings.push({
            kind: finding.kind,
            entropy: finding.entropy,
            token_hash: finding.token_hash,
            threshold,
          });
        }
        if (
          typeof projectedRedaction === 'string' &&
          projectedRedaction.length > 0 &&
          !streamEntropyProjectedRedaction
        ) {
          streamEntropyProjectedRedaction = projectedRedaction.slice(0, 512);
        }
        if (action === 'redact') {
          server.stats.egress_entropy_redacted += 1;
        }
        if (action === 'block' && egressConfig.streamBlockMode === 'terminate' && !streamTerminatedForEntropy) {
          streamTerminatedForEntropy = true;
          server.stats.blocked_total += 1;
          server.stats.egress_entropy_blocked += 1;
          if (!res.headersSent) {
            res.setHeader('x-sentinel-egress-entropy', 'stream_terminate');
          }
          warnings.push('egress_entropy_stream_blocked');
          server.stats.warnings_total += 1;
          terminateStream({
            upstreamBodyStream: upstream.bodyStream,
            streamOut,
            res,
            code: 'EGRESS_STREAM_BLOCKED',
          });
        }
      },
    });
    streamOut = streamOut.pipe(streamRedactor);
    res.setHeader('x-sentinel-egress-stream', egressConfig.streamBlockMode === 'terminate' ? 'terminate' : 'redact');
  }

  const vaultStream = server.piiVault.createEgressStreamTransform({
    sessionKey: piiVaultSessionKey,
    contentType: upstreamContentType,
    onMetrics: ({ replacements }) => {
      streamVaultReplacements = Number(replacements || 0);
      if (streamVaultReplacements > 0) {
        server.stats.pii_vault_detokenized += streamVaultReplacements;
      }
    },
  });
  if (vaultStream) {
    streamOut = streamOut.pipe(vaultStream);
    if (server.piiVault.observability && !res.headersSent) {
      res.setHeader('x-sentinel-pii-vault-egress', 'detokenize_stream');
    }
  }

  const evaluateOutputClassifierChunk = (decodedChunk) => {
    if (!server.outputClassifier?.isEnabled?.() || !decodedChunk || streamTerminatedForClassifier) {
      return;
    }
    classifierWindow += decodedChunk;
    const maxChars = Number(server.outputClassifier?.config?.maxScanChars || 8192);
    if (classifierWindow.length > maxChars) {
      classifierWindow = classifierWindow.slice(-maxChars);
    }

    const decision = server.outputClassifier.classifyText(classifierWindow, {
      effectiveMode,
    });
    if (!decision?.enabled || decision.warnedBy?.length === 0) {
      return;
    }

    if (!streamOutputClassifierDetected) {
      streamOutputClassifierDetected = true;
      server.stats.output_classifier_detected += 1;
      warnings.push('output_classifier:stream_detected');
      server.stats.warnings_total += 1;
    }
    for (const category of decision.warnedBy) {
      if (!streamOutputClassifierCategories.has(category)) {
        streamOutputClassifierCategories.add(category);
        const counterKey = `output_classifier_${String(category)}_detected`;
        if (Object.prototype.hasOwnProperty.call(server.stats, counterKey)) {
          server.stats[counterKey] += 1;
        }
      }
    }

    if (!res.headersSent) {
      res.setHeader('x-sentinel-output-classifier', decision.shouldBlock ? 'block' : 'warn');
      res.setHeader(
        'x-sentinel-output-classifier-categories',
        Array.from(streamOutputClassifierCategories).sort().join(',')
      );
    }

    if (decision.shouldBlock && !streamTerminatedForClassifier) {
      streamTerminatedForClassifier = true;
      server.stats.blocked_total += 1;
      server.stats.output_classifier_blocked += 1;
      warnings.push('output_classifier_stream_blocked');
      server.stats.warnings_total += 1;
      if (!res.headersSent) {
        res.setHeader('x-sentinel-blocked-by', 'output_classifier');
        res.setHeader('x-sentinel-egress-action', 'stream_terminate');
      }
      terminateStream({
        upstreamBodyStream: upstream.bodyStream,
        streamOut,
        res,
        code: 'EGRESS_STREAM_BLOCKED',
      });
    }
  };

  const evaluateAdditionalEgressChunk = () => {
    if (!classifierWindow) {
      return;
    }
    if (!streamStegoBlocked && server.stegoExfilDetector?.isEnabled?.()) {
      const stego = server.stegoExfilDetector.analyzeText(classifierWindow, { effectiveMode });
      if (stego.detected) {
        streamStegoDetected = true;
        for (const finding of stego.findings || []) {
          if (streamStegoFindings.length < 16) {
            streamStegoFindings.push(finding);
          }
        }
        if (!warnings.includes('stego:stream_detected')) {
          warnings.push('stego:stream_detected');
          server.stats.warnings_total += 1;
        }
        server.stats.stego_exfil_detected += 1;
        if (!res.headersSent) {
          res.setHeader('x-sentinel-stego', stego.shouldBlock ? 'block' : 'warn');
        }
        if (stego.shouldBlock) {
          streamStegoBlocked = true;
          server.stats.stego_exfil_blocked += 1;
          server.stats.blocked_total += 1;
          warnings.push('stego_stream_blocked');
          server.stats.warnings_total += 1;
          terminateStream({
            upstreamBodyStream: upstream.bodyStream,
            streamOut,
            res,
            code: 'EGRESS_STREAM_BLOCKED',
          });
          return;
        }
      }
    }

    if (!streamReasoningBlocked && server.reasoningTraceMonitor?.isEnabled?.()) {
      const reasoning = server.reasoningTraceMonitor.analyzeText(classifierWindow, { effectiveMode });
      if (reasoning.detected) {
        streamReasoningDetected = true;
        for (const finding of reasoning.findings || []) {
          if (streamReasoningFindings.length < 16) {
            streamReasoningFindings.push(finding);
          }
        }
        if (!warnings.includes('reasoning:stream_detected')) {
          warnings.push('reasoning:stream_detected');
          server.stats.warnings_total += 1;
        }
        server.stats.reasoning_trace_detected += 1;
        if (!res.headersSent) {
          res.setHeader('x-sentinel-reasoning-trace', reasoning.shouldBlock ? 'block' : 'warn');
        }
        if (reasoning.shouldBlock) {
          streamReasoningBlocked = true;
          server.stats.reasoning_trace_blocked += 1;
          server.stats.blocked_total += 1;
          warnings.push('reasoning_stream_blocked');
          server.stats.warnings_total += 1;
          terminateStream({
            upstreamBodyStream: upstream.bodyStream,
            streamOut,
            res,
            code: 'EGRESS_STREAM_BLOCKED',
          });
          return;
        }
      }
    }

    if (!streamHallucinationBlocked && server.hallucinationTripwire?.isEnabled?.()) {
      const hallucination = server.hallucinationTripwire.analyzeText(classifierWindow, { effectiveMode });
      if (hallucination.detected) {
        streamHallucinationDetected = true;
        for (const finding of hallucination.findings || []) {
          if (streamHallucinationFindings.length < 16) {
            streamHallucinationFindings.push(finding);
          }
        }
        if (!warnings.includes('hallucination:stream_detected')) {
          warnings.push('hallucination:stream_detected');
          server.stats.warnings_total += 1;
        }
        server.stats.hallucination_tripwire_detected += 1;
        if (!res.headersSent) {
          res.setHeader('x-sentinel-hallucination', hallucination.shouldBlock ? 'block' : 'warn');
          res.setHeader('x-sentinel-hallucination-score', String(hallucination.score || 0));
        }
        if (hallucination.shouldBlock) {
          streamHallucinationBlocked = true;
          server.stats.hallucination_tripwire_blocked += 1;
          server.stats.blocked_total += 1;
          warnings.push('hallucination_stream_blocked');
          server.stats.warnings_total += 1;
          terminateStream({
            upstreamBodyStream: upstream.bodyStream,
            streamOut,
            res,
            code: 'EGRESS_STREAM_BLOCKED',
          });
          return;
        }
      }
    }

    if (!streamCrossTenantBlocked && server.crossTenantIsolator?.isEnabled?.()) {
      const tenantDecision = server.crossTenantIsolator.evaluateEgress({
        tenantId: req?.__sentinelTenantId || req?.headers?.['x-sentinel-tenant-id'] || '',
        text: classifierWindow,
        effectiveMode,
      });
      if (tenantDecision.detected) {
        streamCrossTenantDetected = true;
        server.stats.cross_tenant_detected += 1;
        server.stats.cross_tenant_leaks += 1;
        for (const finding of tenantDecision.findings || []) {
          if (streamCrossTenantFindings.length < 16) {
            streamCrossTenantFindings.push(finding);
          }
        }
        if (!warnings.includes('cross_tenant:stream_detected')) {
          warnings.push('cross_tenant:stream_detected');
          server.stats.warnings_total += 1;
        }
        if (!res.headersSent) {
          res.setHeader('x-sentinel-cross-tenant-egress', tenantDecision.shouldBlock ? 'block' : 'warn');
        }
        if (tenantDecision.shouldBlock) {
          streamCrossTenantBlocked = true;
          server.stats.cross_tenant_blocked += 1;
          server.stats.blocked_total += 1;
          warnings.push('cross_tenant_stream_blocked');
          server.stats.warnings_total += 1;
          terminateStream({
            upstreamBodyStream: upstream.bodyStream,
            streamOut,
            res,
            code: 'EGRESS_STREAM_BLOCKED',
          });
          return;
        }
      }
    }
  };

  streamOut.on('data', (chunk) => {
    streamedBytes += chunk.length;
    if (proofContext) {
      proofContext.update(chunk);
    }
    const decoded = classifierDecoder.write(chunk);
    if (decoded) {
      evaluateOutputClassifierChunk(decoded);
      evaluateAdditionalEgressChunk();
    }
  });

  let streamBudgetFinalizePromise = null;
  const finalizeStreamBudget = async () => {
    if (streamBudgetFinalizePromise) {
      return streamBudgetFinalizePromise;
    }

    streamBudgetFinalizePromise = (async () => {
      try {
        const budgetCharge = await server.budgetStore.recordStream({
          provider: routedProvider,
          requestBodyBuffer: bodyBuffer,
          streamedBytes,
          replayedFromVcr,
          replayedFromSemanticCache,
          correlationId,
        });
        if (budgetCharge?.charged) {
          server.stats.budget_charged_usd = Number(
            (server.stats.budget_charged_usd + Number(budgetCharge.chargedUsd || 0)).toFixed(6)
          );
        }
        return budgetCharge;
      } catch {
        warnings.push('budget_record_error');
        server.stats.warnings_total += 1;
        return null;
      }
    })();

    return streamBudgetFinalizePromise;
  };

  const buildStreamAuditPayload = ({ decision, reasons, responseStatus, responseBytes, budgetCharge }) => ({
    timestamp: new Date().toISOString(),
    correlation_id: correlationId,
    config_version: server.config.version,
    mode: effectiveMode,
    decision,
    reasons,
    pii_types: piiTypes,
    redactions: redactedCount,
    pii_vault_detokenized: streamVaultReplacements,
    duration_ms: Date.now() - start,
    request_bytes: bodyBuffer.length,
    response_status: responseStatus,
    response_bytes: responseBytes,
    provider: routedProvider,
    upstream_target: routedTarget,
    failover_used: upstream.route?.failoverUsed === true,
    route_source: routePlan.routeSource,
    route_group: routePlan.selectedGroup || undefined,
    route_contract: routePlan.desiredContract,
    requested_target: routePlan.requestedTarget,
    honeytoken_applied: Boolean(honeytokenDecision),
    honeytoken_mode: honeytokenDecision?.mode,
    honeytoken_token_hash: honeytokenDecision?.token_hash,
    canary_tool_injected: Boolean(canaryToolDecision),
    canary_tool_name: canaryToolDecision?.tool_name || canaryTriggered?.toolName,
    canary_tool_triggered: Boolean(canaryTriggered?.triggered),
    parallax_evaluated: Boolean(parallaxDecision?.evaluated),
    parallax_veto: Boolean(parallaxDecision?.veto),
    parallax_risk: parallaxDecision?.risk,
    parallax_secondary_provider: parallaxDecision?.secondaryProvider,
    parallax_high_risk_tools: parallaxDecision?.highRiskTools,
    cognitive_rollback_suggested: Boolean(cognitiveRollbackDecision?.applicable),
    cognitive_rollback_mode: cognitiveRollbackDecision?.mode,
    cognitive_rollback_trigger: cognitiveRollbackDecision?.trigger,
    cognitive_rollback_dropped_messages: cognitiveRollbackDecision?.droppedMessages,
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
    budget_charged_usd: budgetCharge?.chargedUsd,
    budget_spent_usd: budgetCharge?.spentUsd,
    budget_remaining_usd: budgetCharge?.remainingUsd,
  });

  streamOut.on('end', async () => {
    const trailing = classifierDecoder.end();
    if (trailing) {
      evaluateOutputClassifierChunk(trailing);
      evaluateAdditionalEgressChunk();
    }
    if (server.semanticDriftCanary?.isEnabled?.()) {
      const semanticDrift = server.semanticDriftCanary.observe({
        provider: routedProvider,
        responseText: classifierWindow,
        latencyMs: Date.now() - requestStart,
        effectiveMode,
        forceSample: true,
      });
      if (semanticDrift.detected) {
        streamSemanticDriftDetected = true;
        for (const finding of semanticDrift.findings || []) {
          if (streamSemanticDriftFindings.length < 16) {
            streamSemanticDriftFindings.push(finding);
          }
        }
        warnings.push('semantic_drift:stream_detected');
        server.stats.warnings_total += 1;
        server.stats.semantic_drift_detected += 1;
        if (semanticDrift.shouldBlock) {
          streamSemanticDriftBlocked = true;
          server.stats.semantic_drift_blocked += 1;
        }
      }
    }
    if (canAddProofTrailers) {
      const proof = proofContext.finalize();
      if (proof) {
        res.addTrailers(ProvenanceSigner.proofHeaders(proof));
        if (server.outputProvenanceSigner?.isEnabled?.()) {
          const envelope = server.outputProvenanceSigner.createEnvelope({
            outputSha256: proof.payloadSha256,
            statusCode: upstream.status,
            provider: routedProvider,
            correlationId,
            modelId: String(res.getHeader('x-sentinel-model-id') || ''),
            configHash: server.getRuntimeConfigHash(),
          });
          if (envelope?.envelope) {
            res.addTrailers({
              'x-sentinel-provenance': envelope.envelope,
            });
            server.stats.output_provenance_signed += 1;
          }
        }
      }
    }
    server.latencyNormalizer.recordSuccess(Date.now() - requestStart);
    const budgetCharge = await finalizeStreamBudget();

    server.auditLogger.write({
      ...buildStreamAuditPayload({
        decision: 'forwarded_stream',
        reasons: warnings,
        responseStatus: upstream.status,
        responseBytes: streamedBytes,
        budgetCharge,
      }),
      ...buildStreamEgressAuditFields({
        streamEgressTypes,
        streamProjectedRedaction,
        streamBlockedSeverity,
        streamEntropyFindings,
        streamEntropyMode,
        streamEntropyProjectedRedaction,
        outputClassifierCategories: streamOutputClassifierCategories,
        outputClassifierBlocked: streamTerminatedForClassifier,
        stegoDetected: streamStegoDetected,
        stegoBlocked: streamStegoBlocked,
        stegoFindings: streamStegoFindings,
        reasoningDetected: streamReasoningDetected,
        reasoningBlocked: streamReasoningBlocked,
        reasoningFindings: streamReasoningFindings,
        hallucinationDetected: streamHallucinationDetected,
        hallucinationBlocked: streamHallucinationBlocked,
        hallucinationFindings: streamHallucinationFindings,
        crossTenantDetected: streamCrossTenantDetected,
        crossTenantBlocked: streamCrossTenantBlocked,
        crossTenantFindings: streamCrossTenantFindings,
        semanticDriftDetected: streamSemanticDriftDetected,
        semanticDriftBlocked: streamSemanticDriftBlocked,
        semanticDriftFindings: streamSemanticDriftFindings,
      }),
    });
    server.writeStatus();
    finalizeRequestTelemetry({
      decision: 'forwarded_stream',
      status: upstream.status,
      providerName: routedProvider,
    });
  });

  streamOut.on('error', (error) => {
    void (async () => {
      const budgetCharge = await finalizeStreamBudget();
      if (
        (streamTerminatedForPII || streamTerminatedForEntropy || streamTerminatedForClassifier) &&
        String(error.message || '') === 'EGRESS_STREAM_BLOCKED'
      ) {
        const blockReason = streamTerminatedForClassifier
          ? 'output_classifier_stream_blocked'
          : streamStegoBlocked
            ? 'stego_stream_blocked'
            : streamReasoningBlocked
              ? 'reasoning_stream_blocked'
              : streamHallucinationBlocked
                ? 'hallucination_stream_blocked'
                : streamCrossTenantBlocked
                  ? 'cross_tenant_stream_blocked'
          : streamTerminatedForEntropy
            ? 'egress_entropy_stream_blocked'
            : 'egress_stream_blocked';
        server.auditLogger.write({
          ...buildStreamAuditPayload({
            decision: 'blocked_egress_stream',
            reasons: [blockReason],
            responseStatus: 499,
            responseBytes: streamedBytes,
            budgetCharge,
          }),
          ...buildStreamEgressAuditFields({
            streamEgressTypes,
            streamProjectedRedaction,
            streamBlockedSeverity,
            streamEntropyFindings,
            streamEntropyMode,
            streamEntropyProjectedRedaction,
            outputClassifierCategories: streamOutputClassifierCategories,
            outputClassifierBlocked: streamTerminatedForClassifier,
            stegoDetected: streamStegoDetected,
            stegoBlocked: streamStegoBlocked,
            stegoFindings: streamStegoFindings,
            reasoningDetected: streamReasoningDetected,
            reasoningBlocked: streamReasoningBlocked,
            reasoningFindings: streamReasoningFindings,
            hallucinationDetected: streamHallucinationDetected,
            hallucinationBlocked: streamHallucinationBlocked,
            hallucinationFindings: streamHallucinationFindings,
            crossTenantDetected: streamCrossTenantDetected,
            crossTenantBlocked: streamCrossTenantBlocked,
            crossTenantFindings: streamCrossTenantFindings,
            semanticDriftDetected: streamSemanticDriftDetected,
            semanticDriftBlocked: streamSemanticDriftBlocked,
            semanticDriftFindings: streamSemanticDriftFindings,
          }),
        });
        server.writeStatus();
        finalizeRequestTelemetry({
          decision: 'blocked_egress',
          status: 499,
          providerName: routedProvider,
        });
        return;
      }
      server.stats.upstream_errors += 1;
      server.auditLogger.write(
        buildStreamAuditPayload({
          decision: 'stream_error',
          reasons: [error.message || 'stream_error'],
          responseStatus: upstream.status,
          responseBytes: streamedBytes,
          budgetCharge,
        })
      );
      server.writeStatus();
      finalizeRequestTelemetry({
        decision: 'stream_error',
        status: upstream.status,
        providerName: routedProvider,
        error,
      });
      if (!res.destroyed) {
        res.destroy(error);
      }
    })().catch((handlerError) => {
      logger.warn('stream error handler failed', {
        correlationId,
        error: handlerError.message,
      });
    });
  });

  streamOut.pipe(res);

  return {
    handled: true,
  };
}

module.exports = {
  runStreamEgressStage,
};
