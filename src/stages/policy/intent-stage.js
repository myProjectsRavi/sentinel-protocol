const { responseHeaderDiagnostics } = require('../shared');

async function runIntentStage({
  server,
  req,
  res,
  bodyJson,
  bodyText,
  provider,
  breakerKey,
  effectiveMode,
  correlationId,
  requestStart,
  rawBody,
  warnings,
  finalizeRequestTelemetry,
}) {
  let intentThrottleDecision = null;
  let intentDriftDecision = null;
  let epistemicAnchorDecision = null;
  let syntheticPoisonDecision = null;

  if (server.intentThrottle.isEnabled()) {
    try {
      intentThrottleDecision = await server.intentThrottle.evaluate({
        headers: req.headers || {},
        bodyJson,
        bodyText,
      });
    } catch (error) {
      intentThrottleDecision = {
        enabled: true,
        matched: false,
        shouldBlock: false,
        reason: 'embedding_error',
        error: String(error.message || error),
      };
    }

    if (intentThrottleDecision?.matched) {
      server.stats.intent_throttle_matches += 1;
      res.setHeader('x-sentinel-intent-throttle', String(intentThrottleDecision.reason || 'intent_match'));
      if (intentThrottleDecision.cluster) {
        res.setHeader('x-sentinel-intent-cluster', String(intentThrottleDecision.cluster).slice(0, 64));
      }
      if (Number.isFinite(Number(intentThrottleDecision.similarity))) {
        res.setHeader('x-sentinel-intent-similarity', String(intentThrottleDecision.similarity));
      }

      if (effectiveMode === 'enforce' && intentThrottleDecision.shouldBlock) {
        syntheticPoisonDecision = server.syntheticPoisoner.inject({
          bodyJson,
          trigger: intentThrottleDecision.reason,
        });
        if (syntheticPoisonDecision.applied) {
          bodyJson = syntheticPoisonDecision.bodyJson;
          bodyText = syntheticPoisonDecision.bodyText;
          server.stats.synthetic_poisoning_injected += 1;
          warnings.push('synthetic_poisoning:injected');
          server.stats.warnings_total += 1;
          if (server.syntheticPoisoner.observability) {
            res.setHeader('x-sentinel-synthetic-poisoning', 'injected');
            res.setHeader(
              'x-sentinel-synthetic-trigger',
              String(syntheticPoisonDecision.meta?.trigger || intentThrottleDecision.reason || '')
            );
          }
        } else {
          if (server.syntheticPoisoner.isEnabled() && server.syntheticPoisoner.observability) {
            res.setHeader(
              'x-sentinel-synthetic-poisoning',
              String(syntheticPoisonDecision.reason || 'not_applied')
            );
          }
          server.stats.blocked_total += 1;
          server.stats.intent_throttle_blocked += 1;

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
            statusCode: 429,
            requestStart,
          });
          server.auditLogger.write({
            timestamp: new Date().toISOString(),
            correlation_id: correlationId,
            config_version: server.config.version,
            mode: effectiveMode,
            decision: 'blocked_intent_throttle',
            reasons: [String(intentThrottleDecision.reason || 'intent_velocity_exceeded')],
            pii_types: [],
            redactions: 0,
            duration_ms: Date.now() - requestStart,
            request_bytes: rawBody.length,
            response_status: 429,
            response_bytes: 0,
            provider,
            intent_cluster: intentThrottleDecision.cluster,
            intent_similarity: intentThrottleDecision.similarity,
            intent_threshold: intentThrottleDecision.threshold,
            intent_count: intentThrottleDecision.count,
            intent_max_events_per_window: intentThrottleDecision.maxEventsPerWindow,
            intent_window_ms: intentThrottleDecision.windowMs,
            intent_cooldown_ms: intentThrottleDecision.cooldownMs,
            intent_blocked_until: intentThrottleDecision.blockedUntil,
            synthetic_poison_reason: syntheticPoisonDecision?.reason,
          });
          server.writeStatus();
          finalizeRequestTelemetry({
            decision: 'blocked_policy',
            status: 429,
            providerName: provider,
          });
          res.status(429).json({
            error: 'INTENT_THROTTLED',
            reason: intentThrottleDecision.reason,
            cluster: intentThrottleDecision.cluster,
            similarity: intentThrottleDecision.similarity,
            count: intentThrottleDecision.count,
            threshold: intentThrottleDecision.threshold,
            max_events_per_window: intentThrottleDecision.maxEventsPerWindow,
            window_ms: intentThrottleDecision.windowMs,
            cooldown_ms: intentThrottleDecision.cooldownMs,
            blocked_until: intentThrottleDecision.blockedUntil || 0,
            correlation_id: correlationId,
          });
          return {
            handled: true,
            bodyJson,
            bodyText,
            intentThrottleDecision,
            intentDriftDecision,
            epistemicAnchorDecision,
            syntheticPoisonDecision,
          };
        }
      }

      warnings.push(`intent_throttle:${intentThrottleDecision.cluster || intentThrottleDecision.reason}`);
      server.stats.warnings_total += 1;
    } else if (
      intentThrottleDecision?.reason === 'embedding_error' ||
      intentThrottleDecision?.reason === 'embedder_unavailable'
    ) {
      server.stats.intent_throttle_errors += 1;
      warnings.push(`intent_throttle:${intentThrottleDecision.reason}`);
      server.stats.warnings_total += 1;
    }
  }

  if (server.intentDrift.isEnabled()) {
    try {
      intentDriftDecision = await server.intentDrift.evaluate({
        headers: req.headers || {},
        bodyJson,
        correlationId,
        effectiveMode,
      });
    } catch (error) {
      intentDriftDecision = {
        enabled: true,
        evaluated: false,
        drifted: false,
        shouldBlock: false,
        reason: 'embedding_error',
        error: String(error.message || error),
      };
    }

    if (intentDriftDecision?.evaluated) {
      server.stats.intent_drift_evaluated += 1;
    }
    if (intentDriftDecision?.enabled && server.intentDrift.observability) {
      res.setHeader('x-sentinel-intent-drift', String(intentDriftDecision.reason || 'not_evaluated'));
      const distanceForHeader = Number.isFinite(Number(intentDriftDecision.adjustedDistance))
        ? intentDriftDecision.adjustedDistance
        : intentDriftDecision.distance;
      if (Number.isFinite(Number(distanceForHeader))) {
        res.setHeader('x-sentinel-intent-drift-distance', String(distanceForHeader));
      }
      if (Number.isFinite(Number(intentDriftDecision.adjustedDistance))) {
        res.setHeader('x-sentinel-intent-drift-adjusted-distance', String(intentDriftDecision.adjustedDistance));
      }
      if (Number.isFinite(Number(intentDriftDecision.riskDelta))) {
        res.setHeader('x-sentinel-intent-drift-risk-delta', String(intentDriftDecision.riskDelta));
      }
      if (Number.isFinite(Number(intentDriftDecision.threshold))) {
        res.setHeader('x-sentinel-intent-drift-threshold', String(intentDriftDecision.threshold));
      }
      if (Number.isFinite(Number(intentDriftDecision.turnCount))) {
        res.setHeader('x-sentinel-intent-drift-turn', String(intentDriftDecision.turnCount));
      }
    }

    if (intentDriftDecision?.drifted) {
      server.stats.intent_drift_detected += 1;
      warnings.push(`intent_drift:${intentDriftDecision.reason || 'drift_threshold_exceeded'}`);
      server.stats.warnings_total += 1;

      if (effectiveMode === 'enforce' && intentDriftDecision.shouldBlock) {
        server.stats.blocked_total += 1;
        server.stats.policy_blocked += 1;
        server.stats.intent_drift_blocked += 1;
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
          statusCode: 409,
          requestStart,
        });
        server.auditLogger.write({
          timestamp: new Date().toISOString(),
          correlation_id: correlationId,
          config_version: server.config.version,
          mode: effectiveMode,
          decision: 'blocked_intent_drift',
          reasons: [String(intentDriftDecision.reason || 'drift_threshold_exceeded')],
          pii_types: [],
          redactions: 0,
          duration_ms: Date.now() - requestStart,
          request_bytes: rawBody.length,
          response_status: 409,
          response_bytes: 0,
          provider,
          intent_drift_distance: intentDriftDecision.distance,
          intent_drift_adjusted_distance: intentDriftDecision.adjustedDistance,
          intent_drift_risk_delta: intentDriftDecision.riskDelta,
          intent_drift_similarity: intentDriftDecision.similarity,
          intent_drift_threshold: intentDriftDecision.threshold,
          intent_drift_turn_count: intentDriftDecision.turnCount,
          intent_drift_anchor_hash: intentDriftDecision.anchorHash,
          intent_drift_blocked_until: intentDriftDecision.blockedUntil,
        });
        server.writeStatus();
        finalizeRequestTelemetry({
          decision: 'blocked_policy',
          status: 409,
          providerName: provider,
        });
        res.status(409).json({
          error: 'INTENT_DRIFT_DETECTED',
          reason: intentDriftDecision.reason,
          distance: intentDriftDecision.distance,
          adjusted_distance: intentDriftDecision.adjustedDistance,
          risk_delta: intentDriftDecision.riskDelta,
          threshold: intentDriftDecision.threshold,
          similarity: intentDriftDecision.similarity,
          turn_count: intentDriftDecision.turnCount,
          blocked_until: intentDriftDecision.blockedUntil || 0,
          correlation_id: correlationId,
        });
        return {
          handled: true,
          bodyJson,
          bodyText,
          intentThrottleDecision,
          intentDriftDecision,
          epistemicAnchorDecision,
          syntheticPoisonDecision,
        };
      }
    } else if (
      intentDriftDecision?.reason === 'embedding_error' ||
      intentDriftDecision?.reason === 'embedder_unavailable' ||
      intentDriftDecision?.reason === 'anchor_embedding_failed' ||
      intentDriftDecision?.reason === 'current_embedding_failed'
    ) {
      server.stats.intent_drift_errors += 1;
      warnings.push(`intent_drift:${intentDriftDecision.reason}`);
      server.stats.warnings_total += 1;
    }
  }

  if (server.epistemicAnchor.enabled === true) {
    try {
      epistemicAnchorDecision = await server.epistemicAnchor.evaluate({
        headers: req.headers || {},
        bodyJson,
        correlationId,
        effectiveMode,
      });
    } catch (error) {
      epistemicAnchorDecision = {
        enabled: true,
        evaluated: false,
        drifted: false,
        shouldBlock: false,
        reason: 'embedding_error',
        error: String(error.message || error),
      };
    }

    if (epistemicAnchorDecision?.evaluated) {
      server.stats.epistemic_anchor_evaluated += 1;
      if (server.epistemicAnchor.observability) {
        res.setHeader('x-sentinel-epistemic-anchor', String(epistemicAnchorDecision.reason || 'evaluated'));
        if (Number.isFinite(Number(epistemicAnchorDecision.distance))) {
          res.setHeader('x-sentinel-epistemic-anchor-distance', String(epistemicAnchorDecision.distance));
        }
        if (Number.isFinite(Number(epistemicAnchorDecision.threshold))) {
          res.setHeader('x-sentinel-epistemic-anchor-threshold', String(epistemicAnchorDecision.threshold));
        }
      }
    }

    if (epistemicAnchorDecision?.drifted) {
      server.stats.epistemic_anchor_detected += 1;
      warnings.push(`epistemic_anchor:${epistemicAnchorDecision.reason || 'anchor_divergence'}`);
      server.stats.warnings_total += 1;
      if (effectiveMode === 'enforce' && epistemicAnchorDecision.shouldBlock) {
        server.stats.blocked_total += 1;
        server.stats.policy_blocked += 1;
        server.stats.epistemic_anchor_blocked += 1;
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
          statusCode: 409,
          requestStart,
        });
        server.auditLogger.write({
          timestamp: new Date().toISOString(),
          correlation_id: correlationId,
          config_version: server.config.version,
          mode: effectiveMode,
          decision: 'blocked_epistemic_anchor',
          reasons: [String(epistemicAnchorDecision.reason || 'anchor_divergence')],
          pii_types: [],
          redactions: 0,
          duration_ms: Date.now() - requestStart,
          request_bytes: rawBody.length,
          response_status: 409,
          response_bytes: 0,
          provider,
          epistemic_anchor_distance: epistemicAnchorDecision.distance,
          epistemic_anchor_threshold: epistemicAnchorDecision.threshold,
          epistemic_anchor_similarity: epistemicAnchorDecision.similarity,
          epistemic_anchor_anchor_hash: epistemicAnchorDecision.anchorHash,
          epistemic_anchor_turn_count: epistemicAnchorDecision.turnCount,
        });
        server.writeStatus();
        finalizeRequestTelemetry({
          decision: 'blocked_policy',
          status: 409,
          providerName: provider,
        });
        res.status(409).json({
          error: 'EPISTEMIC_ANCHOR_DIVERGENCE',
          reason: epistemicAnchorDecision.reason,
          distance: epistemicAnchorDecision.distance,
          threshold: epistemicAnchorDecision.threshold,
          correlation_id: correlationId,
        });
        return {
          handled: true,
          bodyJson,
          bodyText,
          intentThrottleDecision,
          intentDriftDecision,
          epistemicAnchorDecision,
          syntheticPoisonDecision,
        };
      }
    } else if (
      epistemicAnchorDecision?.reason === 'embedding_error' ||
      epistemicAnchorDecision?.reason === 'anchor_embedding_failed' ||
      epistemicAnchorDecision?.reason === 'current_embedding_failed'
    ) {
      server.stats.epistemic_anchor_errors += 1;
      warnings.push(`epistemic_anchor:${epistemicAnchorDecision.reason}`);
      server.stats.warnings_total += 1;
    }
  }

  return {
    handled: false,
    bodyJson,
    bodyText,
    intentThrottleDecision,
    intentDriftDecision,
    epistemicAnchorDecision,
    syntheticPoisonDecision,
  };
}

module.exports = {
  runIntentStage,
};
