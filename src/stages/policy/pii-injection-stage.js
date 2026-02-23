const {
  safeJsonParse,
  flattenFindings,
  highestSeverity,
  responseHeaderDiagnostics,
} = require('../shared');
const { mergeInjectionResults } = require('../../engines/injection-merge');

function applyRateLimitHeaders(res, rateLimit) {
  if (!rateLimit || typeof rateLimit !== 'object') {
    return;
  }

  if (Number.isFinite(Number(rateLimit.limit))) {
    res.setHeader('x-sentinel-rate-limit-limit', String(Math.max(0, Math.floor(Number(rateLimit.limit)))));
  }
  if (Number.isFinite(Number(rateLimit.remaining))) {
    res.setHeader('x-sentinel-rate-limit-remaining', String(Math.max(0, Math.floor(Number(rateLimit.remaining)))));
  }
  if (Number.isFinite(Number(rateLimit.windowMs))) {
    res.setHeader('x-sentinel-rate-limit-window-ms', String(Math.max(0, Math.floor(Number(rateLimit.windowMs)))));
  }
  if (Number.isFinite(Number(rateLimit.burst))) {
    res.setHeader('x-sentinel-rate-limit-burst', String(Math.max(0, Math.floor(Number(rateLimit.burst)))));
  }
  if (Number.isFinite(Number(rateLimit.retryAfterMs))) {
    const retryMs = Math.max(0, Math.ceil(Number(rateLimit.retryAfterMs)));
    res.setHeader('x-sentinel-rate-limit-retry-ms', String(retryMs));
    if (retryMs > 0) {
      res.setHeader('retry-after', String(Math.ceil(retryMs / 1000)));
    }
  }
  if (typeof rateLimit.scope === 'string' && rateLimit.scope.length > 0) {
    res.setHeader('x-sentinel-rate-limit-scope', rateLimit.scope);
  }
  if (typeof rateLimit.keySource === 'string' && rateLimit.keySource.length > 0) {
    res.setHeader('x-sentinel-rate-limit-key-source', rateLimit.keySource);
  }
}

function extractClientIp(req) {
  if (!req || typeof req !== 'object') {
    return '';
  }
  if (typeof req.ip === 'string' && req.ip.trim()) {
    return req.ip.trim();
  }
  if (typeof req.socket?.remoteAddress === 'string' && req.socket.remoteAddress.trim()) {
    return req.socket.remoteAddress.trim();
  }
  if (typeof req.connection?.remoteAddress === 'string' && req.connection.remoteAddress.trim()) {
    return req.connection.remoteAddress.trim();
  }
  return '';
}

function isMcpLikeRequest({ req, parsedPath, bodyJson }) {
  const headers = req?.headers || {};
  if (typeof headers['x-sentinel-mcp-server-id'] === 'string' && headers['x-sentinel-mcp-server-id'].trim()) {
    return true;
  }
  const pathname = String(parsedPath?.pathname || '').toLowerCase();
  if (pathname.startsWith('/mcp')) {
    return true;
  }
  if (!bodyJson || typeof bodyJson !== 'object' || Array.isArray(bodyJson)) {
    return false;
  }
  if (Array.isArray(bodyJson.tools) && bodyJson.tools.length > 0) {
    return true;
  }
  if (bodyJson.tool_arguments && typeof bodyJson.tool_arguments === 'object' && !Array.isArray(bodyJson.tool_arguments)) {
    return true;
  }
  if (bodyJson.arguments && typeof bodyJson.arguments === 'object' && !Array.isArray(bodyJson.arguments)) {
    return true;
  }
  return false;
}

async function runInjectionAndPolicyStage({
  server,
  req,
  res,
  method,
  parsedPath,
  baseUrl,
  rawBody,
  bodyText,
  bodyJson,
  provider,
  breakerKey,
  correlationId,
  effectiveMode,
  requestStart,
  wantsStream,
  routePlan,
  warnings,
  finalizeRequestTelemetry,
  precomputedLocalScan,
  precomputedInjection,
}) {
  const canUseScanWorkers =
    server.scanWorkerPool?.enabled === true &&
    server.config.pii?.enabled !== false &&
    server.config.pii?.semantic?.enabled !== true &&
    bodyText.length > 0;

  if (canUseScanWorkers) {
    try {
      const workerScan = await server.scanWorkerPool.scan({
        text: bodyText,
        pii: {
          maxScanBytes: server.config.pii.max_scan_bytes,
          regexSafetyCapBytes: server.config.pii.regex_safety_cap_bytes,
          redactionMode: server.config.pii?.redaction?.mode,
          redactionSalt: server.config.pii?.redaction?.salt,
        },
        injection: {
          enabled: server.config.injection?.enabled !== false,
          maxScanBytes: server.config.injection?.max_scan_bytes,
        },
      });
      precomputedLocalScan = workerScan.piiResult || null;
      precomputedInjection = workerScan.injectionResult || null;
    } catch {
      server.stats.scan_worker_fallbacks += 1;
      warnings.push('scan_worker_fallback_main_thread');
      server.stats.warnings_total += 1;
    }
  }

  let injectionResult = precomputedInjection;
  if (server.neuralInjectionClassifier.enabled && bodyText.length > 0) {
    const baseInjection = injectionResult || server.policyEngine.scanInjection(bodyText);
    const neuralResult = await server.neuralInjectionClassifier.classify(bodyText, {
      maxScanBytes: server.config.injection?.neural?.max_scan_bytes,
      timeoutMs: server.config.injection?.neural?.timeout_ms,
    });
    if (neuralResult.error) {
      warnings.push('injection_neural_error');
      server.stats.warnings_total += 1;
    }
    injectionResult = mergeInjectionResults(baseInjection, neuralResult, server.config.injection?.neural || {});
  }
  const injectionScore = Number(injectionResult?.score || 0);

  let rebuffDecision = null;
  if (server.promptRebuff?.isEnabled()) {
    try {
      rebuffDecision = server.promptRebuff.evaluate({
        headers: req.headers || {},
        correlationId,
        bodyText,
        injectionResult,
        effectiveMode,
      });
    } catch (error) {
      rebuffDecision = {
        enabled: true,
        detected: false,
        shouldBlock: false,
        score: 0,
        reason: 'prompt_rebuff_error',
        error: String(error.message || error),
      };
      server.stats.prompt_rebuff_errors += 1;
      warnings.push('prompt_rebuff:error');
      server.stats.warnings_total += 1;
    }

    if (rebuffDecision?.enabled && server.promptRebuff.observability) {
      res.setHeader('x-sentinel-prompt-rebuff', String(rebuffDecision.reason || 'clean'));
      if (Number.isFinite(Number(rebuffDecision.score))) {
        res.setHeader('x-sentinel-prompt-rebuff-score', String(rebuffDecision.score));
      }
    }

    if (rebuffDecision?.detected) {
      server.stats.prompt_rebuff_detected += 1;
      warnings.push(`prompt_rebuff:${rebuffDecision.reason || 'detected'}`);
      server.stats.warnings_total += 1;
    }

    if (rebuffDecision?.shouldBlock) {
      server.stats.blocked_total += 1;
      server.stats.policy_blocked += 1;
      server.stats.prompt_rebuff_blocked += 1;
      res.setHeader('x-sentinel-blocked-by', 'prompt_rebuff');
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
        decision: 'blocked_prompt_rebuff',
        reasons: [String(rebuffDecision.reason || 'prompt_rebuff_high_confidence')],
        pii_types: [],
        redactions: 0,
        duration_ms: Date.now() - requestStart,
        request_bytes: rawBody.length,
        response_status: 403,
        response_bytes: 0,
        provider,
        prompt_rebuff_score: rebuffDecision.score,
        prompt_rebuff_heuristic_score: rebuffDecision.heuristicScore,
        prompt_rebuff_neural_score: rebuffDecision.neuralScore,
        prompt_rebuff_canary_signal: rebuffDecision.canarySignal?.value,
      });
      server.writeStatus();
      finalizeRequestTelemetry({
        decision: 'blocked_policy',
        status: 403,
        providerName: provider,
      });
      res.status(403).json({
        error: 'PROMPT_REBUFF_BLOCKED',
        reason: rebuffDecision.reason,
        score: rebuffDecision.score,
        correlation_id: correlationId,
      });
      return {
        handled: true,
        bodyText,
        bodyJson,
        precomputedLocalScan,
        precomputedInjection,
        injectionScore,
        shadowDecision: null,
      };
    }
  }

  let mcpPoisoningDecision = null;
  if (server.mcpPoisoningDetector?.isEnabled() && isMcpLikeRequest({ req, parsedPath, bodyJson })) {
    try {
      mcpPoisoningDecision = server.mcpPoisoningDetector.inspect({
        bodyJson,
        toolArgs: bodyJson?.tool_arguments || bodyJson?.arguments || {},
        serverId: req.headers?.['x-sentinel-mcp-server-id'] || provider,
        serverConfig: {
          provider,
          path: parsedPath.pathname,
          target: req.headers?.['x-sentinel-target'],
        },
        effectiveMode,
      });
    } catch (error) {
      mcpPoisoningDecision = {
        enabled: true,
        detected: false,
        shouldBlock: false,
        findings: [],
        reason: 'mcp_poisoning_error',
        error: String(error.message || error),
      };
      warnings.push('mcp_poisoning:error');
      server.stats.warnings_total += 1;
    }

    if (mcpPoisoningDecision?.enabled && server.mcpPoisoningDetector.observability) {
      res.setHeader(
        'x-sentinel-mcp-poisoning',
        mcpPoisoningDecision.detected ? String(mcpPoisoningDecision.reason || 'detected') : 'clean'
      );
      if (mcpPoisoningDecision?.drift?.drifted) {
        res.setHeader('x-sentinel-mcp-config-drift', 'true');
      }
    }

    if (mcpPoisoningDecision?.detected) {
      server.stats.mcp_poisoning_detected += 1;
      if (mcpPoisoningDecision?.drift?.drifted) {
        server.stats.mcp_config_drift += 1;
      }
      warnings.push(`mcp_poisoning:${mcpPoisoningDecision.reason || 'detected'}`);
      server.stats.warnings_total += 1;
    }

    const sanitizedArgs = mcpPoisoningDecision?.sanitizedArguments;
    if (
      sanitizedArgs &&
      bodyJson &&
      typeof bodyJson === 'object' &&
      !Array.isArray(bodyJson)
    ) {
      let nextBodyJson = bodyJson;
      if (bodyJson.tool_arguments && typeof bodyJson.tool_arguments === 'object' && !Array.isArray(bodyJson.tool_arguments)) {
        nextBodyJson = {
          ...bodyJson,
          tool_arguments: sanitizedArgs,
        };
      } else if (bodyJson.arguments && typeof bodyJson.arguments === 'object' && !Array.isArray(bodyJson.arguments)) {
        nextBodyJson = {
          ...bodyJson,
          arguments: sanitizedArgs,
        };
      }
      if (nextBodyJson !== bodyJson) {
        bodyJson = nextBodyJson;
        bodyText = JSON.stringify(bodyJson);
      }
    }

    if (mcpPoisoningDecision?.shouldBlock) {
      server.stats.blocked_total += 1;
      server.stats.policy_blocked += 1;
      server.stats.mcp_poisoning_blocked += 1;
      res.setHeader('x-sentinel-blocked-by', 'mcp_poisoning');
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
        decision: 'blocked_mcp_poisoning',
        reasons: [String(mcpPoisoningDecision.reason || 'mcp_poisoning_detected')],
        pii_types: [],
        redactions: 0,
        duration_ms: Date.now() - requestStart,
        request_bytes: rawBody.length,
        response_status: 403,
        response_bytes: 0,
        provider,
        mcp_poisoning_findings: (mcpPoisoningDecision.findings || []).map((finding) => finding.code),
        mcp_config_drift: mcpPoisoningDecision?.drift?.drifted === true,
      });
      server.writeStatus();
      finalizeRequestTelemetry({
        decision: 'blocked_policy',
        status: 403,
        providerName: provider,
      });
      res.status(403).json({
        error: 'MCP_POISONING_DETECTED',
        reason: mcpPoisoningDecision.reason || 'mcp_poisoning_detected',
        findings: (mcpPoisoningDecision.findings || []).map((finding) => finding.code),
        correlation_id: correlationId,
      });
      return {
        handled: true,
        bodyText,
        bodyJson,
        precomputedLocalScan,
        precomputedInjection,
        injectionScore,
        shadowDecision: null,
      };
    }
  }

  let providerHostname;
  try {
    providerHostname = new URL(baseUrl).hostname;
  } catch {
    const diagnostics = {
      errorSource: 'sentinel',
      upstreamError: false,
      provider,
      retryCount: 0,
      circuitState: 'closed',
      correlationId,
    };
    responseHeaderDiagnostics(res, diagnostics);
    finalizeRequestTelemetry({
      decision: 'invalid_provider_url',
      status: 400,
      providerName: provider,
    });
    res.status(400).json({ error: 'INVALID_PROVIDER_URL', message: `Invalid provider URL: ${baseUrl}` });
    return {
      handled: true,
      bodyText,
      bodyJson,
      precomputedLocalScan,
      precomputedInjection,
      injectionScore,
      shadowDecision: null,
    };
  }

  const policyDecision = server.policyEngine.check({
    method,
    hostname: providerHostname,
    pathname: parsedPath.pathname,
    bodyText,
    bodyJson,
    requestBytes: rawBody.length,
    headers: req.headers,
    provider,
    rateLimitKey: req.headers['x-sentinel-agent-id'],
    clientIp: extractClientIp(req),
    injectionResult,
  });
  applyRateLimitHeaders(res, policyDecision.rateLimit);

  const policyInjectionScore = Number(policyDecision.injection?.score || 0);
  if (policyInjectionScore > 0) {
    server.stats.injection_detected += 1;
  }

  if (server.autoImmune.isEnabled() && policyInjectionScore > 0) {
    const learning = server.autoImmune.learn({
      text: bodyText,
      score: policyInjectionScore,
      source: policyDecision.reason || 'injection_score',
    });
    if (learning.learned) {
      server.stats.auto_immune_learned += 1;
      if (server.autoImmune.observability) {
        res.setHeader('x-sentinel-auto-immune-learn', 'true');
        if (learning.fingerprint) {
          res.setHeader('x-sentinel-auto-immune-fingerprint', learning.fingerprint);
        }
      }
    }
  }

  let shadowDecision = null;
  if (server.shadowOS.isEnabled()) {
    shadowDecision = server.shadowOS.evaluate({
      headers: req.headers || {},
      bodyJson,
      method,
      path: parsedPath.pathname,
      provider,
      effectiveMode,
      correlationId,
    });
    if (shadowDecision?.evaluated) {
      server.stats.shadow_os_evaluated += 1;
      if (server.shadowOS.observability) {
        res.setHeader('x-sentinel-shadow-os', shadowDecision.detected ? 'detected' : 'clean');
        res.setHeader('x-sentinel-shadow-os-tools', String((shadowDecision.highRiskTools || []).length));
      }
    }
    if (shadowDecision?.detected) {
      server.stats.shadow_os_detected += 1;
      warnings.push(`shadow_os:${shadowDecision.violations?.[0]?.rule || 'causal_violation'}`);
      server.stats.warnings_total += 1;

      if (shadowDecision.shouldBlock) {
        server.stats.blocked_total += 1;
        server.stats.policy_blocked += 1;
        server.stats.shadow_os_blocked += 1;
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
          decision: 'blocked_shadow_os',
          reasons: ['shadow_os_causal_violation'],
          pii_types: [],
          redactions: 0,
          duration_ms: Date.now() - requestStart,
          request_bytes: rawBody.length,
          response_status: 409,
          response_bytes: 0,
          provider,
          shadow_os_violations: shadowDecision.violations || [],
          shadow_os_high_risk_tools: shadowDecision.highRiskTools || [],
        });
        server.writeStatus();
        finalizeRequestTelemetry({
          decision: 'blocked_policy',
          status: 409,
          providerName: provider,
        });
        res.status(409).json({
          error: 'SHADOW_OS_VIOLATION',
          reason: shadowDecision.reason,
          violations: shadowDecision.violations || [],
          correlation_id: correlationId,
        });
        return {
          handled: true,
          bodyText,
          bodyJson,
          precomputedLocalScan,
          precomputedInjection,
          injectionScore: policyInjectionScore,
          shadowDecision,
        };
      }
    }
  }

  if (policyDecision.matched && policyDecision.action === 'block') {
    if (effectiveMode === 'enforce') {
      if (policyDecision.reason === 'prompt_injection_detected') {
        const deceived = await server.maybeServeDeceptionResponse({
          res,
          trigger: 'injection',
          provider,
          effectiveMode,
          wantsStream,
          injectionScore: policyInjectionScore,
          correlationId,
          requestStart,
          requestBytes: rawBody.length,
          piiTypes: [],
          redactedCount: 0,
          warnings,
          routePlan,
          finalizeRequestTelemetry,
        });
        if (deceived) {
          return {
            handled: true,
            bodyText,
            bodyJson,
            precomputedLocalScan,
            precomputedInjection,
            injectionScore: policyInjectionScore,
            shadowDecision,
          };
        }
      }
      server.stats.blocked_total += 1;
      server.stats.policy_blocked += 1;
      if (policyDecision.reason === 'prompt_injection_detected') {
        server.stats.injection_blocked += 1;
      }
      const blockedStatusCode = policyDecision.reason === 'rate_limit_exceeded' ? 429 : 403;
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
        statusCode: blockedStatusCode,
        requestStart,
      });
      server.auditLogger.write({
        timestamp: new Date().toISOString(),
        correlation_id: correlationId,
        config_version: server.config.version,
        mode: effectiveMode,
        decision: 'blocked',
        reasons: [policyDecision.reason || 'policy_violation'],
        rule: policyDecision.rule,
        rate_limit_limit: policyDecision.rateLimit?.limit,
        rate_limit_remaining: policyDecision.rateLimit?.remaining,
        rate_limit_window_ms: policyDecision.rateLimit?.windowMs,
        rate_limit_burst: policyDecision.rateLimit?.burst,
        rate_limit_retry_after_ms: policyDecision.rateLimit?.retryAfterMs,
        pii_types: [],
        redactions: 0,
        duration_ms: 0,
        request_bytes: rawBody.length,
        response_status: blockedStatusCode,
        response_bytes: 0,
        provider,
      });
      server.writeStatus();
      finalizeRequestTelemetry({
        decision: 'blocked_policy',
        status: blockedStatusCode,
        providerName: provider,
      });
      if (policyDecision.reason === 'rate_limit_exceeded') {
        res.status(blockedStatusCode).json({
          error: 'RATE_LIMIT_EXCEEDED',
          reason: policyDecision.reason,
          rule: policyDecision.rule,
          message: policyDecision.message,
          rate_limit: {
            limit: policyDecision.rateLimit?.limit,
            remaining: policyDecision.rateLimit?.remaining,
            burst: policyDecision.rateLimit?.burst,
            window_ms: policyDecision.rateLimit?.windowMs,
            retry_after_ms: policyDecision.rateLimit?.retryAfterMs,
          },
          correlation_id: correlationId,
        });
      } else {
        res.status(blockedStatusCode).json({
          error: 'POLICY_VIOLATION',
          reason: policyDecision.reason,
          rule: policyDecision.rule,
          message: policyDecision.message,
          injection_score: policyInjectionScore || undefined,
          correlation_id: correlationId,
        });
      }
      return {
        handled: true,
        bodyText,
        bodyJson,
        precomputedLocalScan,
        precomputedInjection,
        injectionScore: policyInjectionScore,
        shadowDecision,
      };
    }

    warnings.push(`policy:${policyDecision.rule || 'blocked-rule'}`);
    if (policyDecision.reason === 'prompt_injection_detected') {
      warnings.push(`injection:${policyInjectionScore.toFixed(3)}`);
    } else if (policyDecision.reason === 'rate_limit_exceeded') {
      warnings.push(`rate_limit:${policyDecision.rule || 'policy-rate-limit'}`);
    }
    server.stats.warnings_total += 1;
  }

  return {
    handled: false,
    bodyText,
    bodyJson,
    precomputedLocalScan,
    precomputedInjection,
    injectionScore: policyInjectionScore,
    shadowDecision,
  };
}

async function runPiiStage({
  server,
  req,
  res,
  bodyText,
  bodyJson,
  precomputedLocalScan,
  piiVaultSessionKey,
  provider,
  breakerKey,
  correlationId,
  effectiveMode,
  requestStart,
  rawBody,
  warnings,
  finalizeRequestTelemetry,
  piiTypes,
  redactedCount,
  piiProviderUsed,
}) {
  let piiBlocked = false;
  let piiVaultDecision = null;

  if (server.config.pii.enabled) {
    let piiEvaluation;
    try {
      piiEvaluation = await server.piiProviderEngine.scan(bodyText, req.headers, {
        precomputedLocal: precomputedLocalScan,
      });
    } catch (error) {
      if (String(error.kind || '').startsWith('rapidapi_')) {
        server.stats.rapidapi_error_count += 1;
      }
      const diagnostics = {
        errorSource: 'sentinel',
        upstreamError: false,
        provider,
        retryCount: 0,
        circuitState: server.circuitBreakers.getProviderState(breakerKey).state,
        correlationId,
      };
      responseHeaderDiagnostics(res, diagnostics);
      finalizeRequestTelemetry({
        decision: 'pii_provider_error',
        status: 502,
        providerName: provider,
        error,
      });
      res.status(502).json({
        error: 'PII_PROVIDER_ERROR',
        message: 'PII provider failed and fallback is disabled',
        correlation_id: correlationId,
      });
      return {
        handled: true,
        bodyText,
        bodyJson,
        piiTypes,
        redactedCount,
        piiProviderUsed,
      };
    }

    const piiResult = piiEvaluation.result;
    const piiMeta = piiEvaluation.meta;
    piiProviderUsed = piiMeta.providerUsed;
    res.setHeader('x-sentinel-pii-provider', piiProviderUsed);
    if (piiMeta.fallbackUsed) {
      server.stats.pii_provider_fallbacks += 1;
      if (String(piiMeta.fallbackReason || '').startsWith('rapidapi_')) {
        server.stats.rapidapi_error_count += 1;
      }
      warnings.push('pii_provider_fallback_local');
      if (piiMeta.fallbackReason === 'rapidapi_quota') {
        warnings.push('pii_provider_quota_exceeded');
      }
    }

    if (piiResult && piiResult.findings.length > 0) {
      piiTypes = flattenFindings(piiResult.findings);
      const topSeverity = highestSeverity(piiResult.findings);
      const severityAction = server.config.pii.severity_actions[topSeverity] || 'log';

      if (severityAction === 'block' && effectiveMode === 'enforce') {
        piiBlocked = true;
      }

      if (severityAction === 'redact') {
        bodyText = piiResult.redactedText;
        redactedCount = piiResult.findings.length;
        if (bodyJson) {
          const reparsed = safeJsonParse(bodyText);
          if (reparsed) {
            bodyJson = reparsed;
          }
        }
      }

      if (!piiBlocked) {
        warnings.push(`pii:${topSeverity}`);
        server.stats.warnings_total += 1;
      }
    }

    if (!piiBlocked && piiResult && piiResult.findings.length > 0 && server.piiVault.isEnabled()) {
      piiVaultDecision = server.piiVault.applyIngress({
        text: bodyText,
        findings: piiResult.findings,
        sessionKey: piiVaultSessionKey,
      });
      if (piiVaultDecision.detected) {
        if (piiVaultDecision.applied) {
          bodyText = piiVaultDecision.text;
          const reparsed = safeJsonParse(bodyText);
          if (reparsed) {
            bodyJson = reparsed;
          }
          server.stats.pii_vault_tokenized += Number(piiVaultDecision.replacements || 0);
          warnings.push(`pii_vault:tokenized:${piiVaultDecision.replacements || 0}`);
          server.stats.warnings_total += 1;
          if (server.piiVault.observability) {
            res.setHeader('x-sentinel-pii-vault', 'tokenized');
            res.setHeader(
              'x-sentinel-pii-vault-mappings',
              String(Array.isArray(piiVaultDecision.mappings) ? piiVaultDecision.mappings.length : 0)
            );
          }
        } else if (piiVaultDecision.monitorOnly) {
          warnings.push('pii_vault:monitor');
          server.stats.warnings_total += 1;
          if (server.piiVault.observability) {
            res.setHeader('x-sentinel-pii-vault', 'monitor');
          }
        }
      }
    }
  }

  if (piiBlocked) {
    server.stats.blocked_total += 1;
    server.stats.pii_blocked += 1;

    const diagnostics = {
      errorSource: 'sentinel',
      upstreamError: false,
      provider,
      retryCount: 0,
      circuitState: server.circuitBreakers.getProviderState(breakerKey).state,
      correlationId,
    };
    responseHeaderDiagnostics(res, diagnostics);
    if (warnings.length > 0) {
      res.setHeader('x-sentinel-warning', warnings.join(','));
    }
    res.setHeader('x-sentinel-pii-provider', piiProviderUsed);
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
      decision: 'blocked',
      reasons: ['pii_detected'],
      pii_types: piiTypes,
      redactions: redactedCount,
      duration_ms: 0,
      request_bytes: rawBody.length,
      response_status: 403,
      response_bytes: 0,
      provider,
    });
    server.writeStatus();
    finalizeRequestTelemetry({
      decision: 'blocked_pii',
      status: 403,
      providerName: provider,
    });

    res.status(403).json({
      error: 'PII_DETECTED',
      reason: 'pii_detected',
      pii_types: piiTypes,
      correlation_id: correlationId,
    });
    return {
      handled: true,
      bodyText,
      bodyJson,
      piiTypes,
      redactedCount,
      piiProviderUsed,
    };
  }

  return {
    handled: false,
    bodyText,
    bodyJson,
    piiTypes,
    redactedCount,
    piiProviderUsed,
  };
}

module.exports = {
  runInjectionAndPolicyStage,
  runPiiStage,
};
