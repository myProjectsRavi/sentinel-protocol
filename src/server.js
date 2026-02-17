const fs = require('fs');
const express = require('express');
const { v4: uuidv4 } = require('uuid');

const logger = require('./utils/logger');
const { PIIScanner } = require('./engines/pii-scanner');
const { PolicyEngine } = require('./engines/policy-engine');
const { InMemoryRateLimiter } = require('./engines/rate-limiter');
const { resolveProvider } = require('./upstream/router');
const { UpstreamClient } = require('./upstream/client');
const { RuntimeOverrideManager } = require('./runtime/override');
const { CircuitBreakerManager } = require('./resilience/circuit-breaker');
const { AuditLogger } = require('./logging/audit-logger');
const { StatusStore } = require('./status/store');
const { loadOptimizerPlugin } = require('./optimizer/loader');
const { createTelemetry } = require('./telemetry');
const { PIIProviderEngine } = require('./pii/provider-engine');
const {
  PID_FILE_PATH,
  STATUS_FILE_PATH,
  OVERRIDE_FILE_PATH,
  AUDIT_LOG_PATH,
  ensureSentinelHome,
} = require('./utils/paths');

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'trailers',
  'transfer-encoding',
  'upgrade',
]);

function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function tryParseJson(text) {
  try {
    return {
      ok: true,
      value: JSON.parse(text),
      error: null,
    };
  } catch (error) {
    return {
      ok: false,
      value: null,
      error,
    };
  }
}

function flattenFindings(findings) {
  return Array.from(new Set(findings.map((item) => item.id))).sort();
}

function highestSeverity(findings) {
  const rank = { low: 1, medium: 2, high: 3, critical: 4 };
  let current = null;
  for (const finding of findings) {
    if (!current || rank[finding.severity] > rank[current]) {
      current = finding.severity;
    }
  }
  return current;
}

function responseHeaderDiagnostics(res, diagnostics) {
  res.setHeader('x-sentinel-error-source', diagnostics.errorSource);
  res.setHeader('x-sentinel-upstream-error', String(Boolean(diagnostics.upstreamError)));
  res.setHeader('x-sentinel-provider', diagnostics.provider);
  res.setHeader('x-sentinel-retry-count', String(diagnostics.retryCount));
  res.setHeader('x-sentinel-circuit-state', diagnostics.circuitState);
  res.setHeader('x-sentinel-correlation-id', diagnostics.correlationId);
}

function scrubForwardHeaders(inputHeaders = {}) {
  const headers = { ...inputHeaders };
  const connectionTokens = new Set(
    String(headers.connection || '')
      .split(',')
      .map((token) => token.trim().toLowerCase())
      .filter(Boolean)
  );

  for (const key of Object.keys(headers)) {
    const lowered = key.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lowered) || connectionTokens.has(lowered)) {
      delete headers[key];
    }
  }

  return headers;
}

class SentinelServer {
  constructor(config, options = {}) {
    ensureSentinelHome();

    this.config = config;
    this.options = options;
    this.app = express();
    this.startedAt = Date.now();
    this.stats = {
      requests_total: 0,
      blocked_total: 0,
      policy_blocked: 0,
      pii_blocked: 0,
      pii_provider_fallbacks: 0,
      rapidapi_error_count: 0,
      upstream_errors: 0,
      warnings_total: 0,
    };

    this.rateLimiter = new InMemoryRateLimiter();
    this.policyEngine = new PolicyEngine(config, this.rateLimiter);
    this.piiScanner = new PIIScanner({
      maxScanBytes: config.pii.max_scan_bytes,
      regexSafetyCapBytes: config.pii.regex_safety_cap_bytes,
    });
    this.telemetry = createTelemetry({
      enabled: config.runtime?.telemetry?.enabled !== false,
      serviceVersion: '0.2.0',
    });
    this.piiProviderEngine = new PIIProviderEngine({
      piiConfig: config.pii,
      localScanner: this.piiScanner,
      telemetry: this.telemetry,
    });
    this.circuitBreakers = new CircuitBreakerManager(config.runtime.upstream.circuit_breaker);
    this.upstreamClient = new UpstreamClient({
      timeoutMs: config.proxy.timeout_ms,
      retryConfig: config.runtime.upstream.retry,
      circuitBreakers: this.circuitBreakers,
      telemetry: this.telemetry,
    });

    this.overrideManager = new RuntimeOverrideManager(OVERRIDE_FILE_PATH);
    this.auditLogger = new AuditLogger(AUDIT_LOG_PATH);
    this.statusStore = new StatusStore(STATUS_FILE_PATH);
    this.optimizerPlugin = loadOptimizerPlugin();

    this.setupApp();
  }

  computeEffectiveMode() {
    if (this.options.dryRun) {
      return 'monitor';
    }

    if (this.options.failOpen || this.config.runtime.fail_open || this.overrideManager.getOverride().emergency_open) {
      return 'monitor';
    }

    return this.config.mode;
  }

  currentStatusPayload() {
    return {
      service_status: this.server ? 'running' : 'stopped',
      configured_mode: this.config.mode,
      effective_mode: this.computeEffectiveMode(),
      emergency_open: this.overrideManager.getOverride().emergency_open,
      providers: this.circuitBreakers.snapshot(),
      pii_provider_mode: this.config.pii.provider_mode,
      pii_provider_fallbacks: this.stats.pii_provider_fallbacks,
      rapidapi_error_count: this.stats.rapidapi_error_count,
      uptime_seconds: Math.floor((Date.now() - this.startedAt) / 1000),
      version: this.config.version,
      counters: this.stats,
      pid: process.pid,
    };
  }

  writeStatus() {
    this.statusStore.write(this.currentStatusPayload());
  }

  setupApp() {
    this.app.use(
      express.raw({
        type: '*/*',
        limit: Number(this.config.proxy.max_body_bytes || 1048576),
      })
    );

    this.app.use((error, req, res, next) => {
      if (!error) {
        next();
        return;
      }

      if (error.type === 'entity.too.large') {
        res.status(413).json({
          error: 'REQUEST_BODY_TOO_LARGE',
          message: 'Request body exceeds proxy.max_body_bytes',
        });
        return;
      }

      next(error);
    });

    this.app.get('/_sentinel/health', (req, res) => {
      res.status(200).json({ status: 'ok' });
    });

    this.app.all('*', async (req, res) => {
      const correlationId = uuidv4();
      const method = req.method.toUpperCase();
      const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
      let bodyText = rawBody.toString('utf8');
      const parsedPath = new URL(req.originalUrl, 'http://localhost');
      const requestStart = Date.now();
      const requestSpan = this.telemetry.startSpan('sentinel.request', {
        method,
        route: parsedPath.pathname,
        correlation_id: correlationId,
      });
      let requestFinalized = false;

      const finalizeRequestTelemetry = ({ decision, status, providerName, error }) => {
        if (requestFinalized) {
          return;
        }
        requestFinalized = true;
        const latencyMs = Date.now() - requestStart;
        const attrs = {
          decision,
          status_code: Number(status || 0),
          provider: providerName || 'unknown',
          effective_mode: this.computeEffectiveMode(),
        };
        this.telemetry.recordLatencyMs(latencyMs, attrs);
        if (decision === 'blocked_policy' || decision === 'blocked_pii') {
          this.telemetry.addBlocked(attrs);
        }
        if (decision === 'upstream_error' || decision === 'stream_error') {
          this.telemetry.addUpstreamError(attrs);
        }
        this.telemetry.endSpan(requestSpan, attrs, error);
      };

      this.stats.requests_total += 1;
      this.telemetry.addRequest({
        method,
        route: parsedPath.pathname,
      });

      let provider;
      let baseUrl;
      let resolvedIp = null;
      let resolvedFamily = null;
      let upstreamHostname = null;
      let upstreamHostHeader = null;
      try {
        const resolved = await resolveProvider(req, this.config);
        provider = resolved.provider;
        baseUrl = resolved.baseUrl;
        resolvedIp = resolved.resolvedIp || null;
        resolvedFamily = resolved.resolvedFamily || null;
        upstreamHostname = resolved.upstreamHostname || null;
        upstreamHostHeader = resolved.upstreamHostHeader || null;
      } catch (error) {
        const diagnostics = {
          errorSource: 'sentinel',
          upstreamError: false,
          provider: 'unknown',
          retryCount: 0,
          circuitState: 'closed',
          correlationId,
        };
        responseHeaderDiagnostics(res, diagnostics);
        finalizeRequestTelemetry({
          decision: 'invalid_provider_target',
          status: 400,
          providerName: 'unknown',
        });
        return res.status(400).json({ error: 'INVALID_PROVIDER_TARGET', message: error.message });
      }

      const contentType = String(req.headers['content-type'] || '').toLowerCase();
      let bodyJson = null;
      if (contentType.includes('application/json') && bodyText.length > 0) {
        const parsedBody = tryParseJson(bodyText);
        if (!parsedBody.ok) {
          const diagnostics = {
            errorSource: 'sentinel',
            upstreamError: false,
            provider,
            retryCount: 0,
            circuitState: this.circuitBreakers.getProviderState(provider).state,
            correlationId,
          };
          responseHeaderDiagnostics(res, diagnostics);
          finalizeRequestTelemetry({
            decision: 'invalid_json',
            status: 400,
            providerName: provider,
            error: parsedBody.error,
          });
          return res.status(400).json({
            error: 'INVALID_JSON_BODY',
            message: 'Request body is not valid JSON.',
            correlation_id: correlationId,
          });
        }
        bodyJson = parsedBody.value;
      }
      const warnings = [];
      const effectiveMode = this.computeEffectiveMode();

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
        return res.status(400).json({ error: 'INVALID_PROVIDER_URL', message: `Invalid provider URL: ${baseUrl}` });
      }

      const policyDecision = this.policyEngine.check({
        method,
        hostname: providerHostname,
        pathname: parsedPath.pathname,
        bodyText,
        bodyJson,
        requestBytes: rawBody.length,
        headers: req.headers,
        provider,
        rateLimitKey: req.headers['x-sentinel-agent-id'],
      });

      if (policyDecision.matched && policyDecision.action === 'block') {
        if (effectiveMode === 'enforce') {
          this.stats.blocked_total += 1;
          this.stats.policy_blocked += 1;
          const diagnostics = {
            errorSource: 'sentinel',
            upstreamError: false,
            provider,
            retryCount: 0,
            circuitState: this.circuitBreakers.getProviderState(provider).state,
            correlationId,
          };

          responseHeaderDiagnostics(res, diagnostics);
          this.auditLogger.write({
            timestamp: new Date().toISOString(),
            correlation_id: correlationId,
            config_version: this.config.version,
            mode: effectiveMode,
            decision: 'blocked',
            reasons: ['policy_violation'],
            rule: policyDecision.rule,
            pii_types: [],
            redactions: 0,
            duration_ms: 0,
            request_bytes: rawBody.length,
            response_status: 403,
            response_bytes: 0,
            provider,
          });
          this.writeStatus();
          finalizeRequestTelemetry({
            decision: 'blocked_policy',
            status: 403,
            providerName: provider,
          });
          return res.status(403).json({
            error: 'POLICY_VIOLATION',
            reason: policyDecision.reason,
            rule: policyDecision.rule,
            message: policyDecision.message,
            correlation_id: correlationId,
          });
        }
        warnings.push(`policy:${policyDecision.rule || 'blocked-rule'}`);
        this.stats.warnings_total += 1;
      }

      let piiBlocked = false;
      let redactedCount = 0;
      let piiTypes = [];
      let piiProviderUsed = 'local';

      if (this.config.pii.enabled) {
        let piiEvaluation;
        try {
          piiEvaluation = await this.piiProviderEngine.scan(bodyText, req.headers);
        } catch (error) {
          if (String(error.kind || '').startsWith('rapidapi_')) {
            this.stats.rapidapi_error_count += 1;
          }
          const diagnostics = {
            errorSource: 'sentinel',
            upstreamError: false,
            provider,
            retryCount: 0,
            circuitState: this.circuitBreakers.getProviderState(provider).state,
            correlationId,
          };
          responseHeaderDiagnostics(res, diagnostics);
          finalizeRequestTelemetry({
            decision: 'pii_provider_error',
            status: 502,
            providerName: provider,
            error,
          });
          return res.status(502).json({
            error: 'PII_PROVIDER_ERROR',
            message: 'PII provider failed and fallback is disabled',
            correlation_id: correlationId,
          });
        }

        const piiResult = piiEvaluation.result;
        const piiMeta = piiEvaluation.meta;
        piiProviderUsed = piiMeta.providerUsed;
        res.setHeader('x-sentinel-pii-provider', piiProviderUsed);
        if (piiMeta.fallbackUsed) {
          this.stats.pii_provider_fallbacks += 1;
          if (String(piiMeta.fallbackReason || '').startsWith('rapidapi_')) {
            this.stats.rapidapi_error_count += 1;
          }
          warnings.push('pii_provider_fallback_local');
          if (piiMeta.fallbackReason === 'rapidapi_quota') {
            warnings.push('pii_provider_quota_exceeded');
          }
        }

        if (piiResult && piiResult.findings.length > 0) {
          piiTypes = flattenFindings(piiResult.findings);
          const topSeverity = highestSeverity(piiResult.findings);
          const severityAction = this.config.pii.severity_actions[topSeverity] || 'log';

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
            this.stats.warnings_total += 1;
          }
        }
      }

      if (piiBlocked) {
        this.stats.blocked_total += 1;
        this.stats.pii_blocked += 1;

        const diagnostics = {
          errorSource: 'sentinel',
          upstreamError: false,
          provider,
          retryCount: 0,
          circuitState: this.circuitBreakers.getProviderState(provider).state,
          correlationId,
        };
        responseHeaderDiagnostics(res, diagnostics);
        if (warnings.length > 0) {
          res.setHeader('x-sentinel-warning', warnings.join(','));
        }
        res.setHeader('x-sentinel-pii-provider', piiProviderUsed);

        this.auditLogger.write({
          timestamp: new Date().toISOString(),
          correlation_id: correlationId,
          config_version: this.config.version,
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
        this.writeStatus();
        finalizeRequestTelemetry({
          decision: 'blocked_pii',
          status: 403,
          providerName: provider,
        });

        return res.status(403).json({
          error: 'PII_DETECTED',
          reason: 'pii_detected',
          pii_types: piiTypes,
          correlation_id: correlationId,
        });
      }

      if (req.headers['x-sentinel-optimize'] === 'true' && bodyJson && Array.isArray(bodyJson.messages)) {
        try {
          const result = this.optimizerPlugin.optimize(bodyJson.messages, {
            provider,
            profile: req.headers['x-sentinel-optimizer-profile'] || 'default',
          });
          if (result && result.improved && Array.isArray(result.messages)) {
            bodyJson.messages = result.messages;
            bodyText = JSON.stringify(bodyJson);
          }
        } catch (error) {
          logger.warn('Optimizer plugin failed', { error: error.message, correlationId });
          warnings.push('optimizer:plugin_error');
        }
      }

      const bodyBuffer = bodyJson ? Buffer.from(JSON.stringify(bodyJson)) : Buffer.from(bodyText || '', 'utf8');
      const forwardHeaders = scrubForwardHeaders(req.headers);
      const wantsStream =
        String(req.headers.accept || '').toLowerCase().includes('text/event-stream') ||
        (bodyJson && bodyJson.stream === true);
      const start = Date.now();

      const upstream = await this.upstreamClient.forwardRequest({
        provider,
        baseUrl,
        req,
        pathWithQuery: `${parsedPath.pathname}${parsedPath.search}`,
        method,
        bodyBuffer,
        correlationId,
        wantsStream,
        resolvedIp,
        resolvedFamily,
        upstreamHostname,
        upstreamHostHeader,
        forwardHeaders,
      });

      const durationMs = Date.now() - start;
      const diagnostics = upstream.diagnostics;

      if (warnings.length > 0) {
        res.setHeader('x-sentinel-warning', warnings.join(','));
      }
      res.setHeader('x-sentinel-pii-provider', piiProviderUsed);

      if (!upstream.ok) {
        this.stats.upstream_errors += 1;
        responseHeaderDiagnostics(res, diagnostics);
        for (const [key, value] of Object.entries(upstream.responseHeaders || {})) {
          res.setHeader(key, value);
        }

        this.auditLogger.write({
          timestamp: new Date().toISOString(),
          correlation_id: correlationId,
          config_version: this.config.version,
          mode: effectiveMode,
          decision: 'upstream_error',
          reasons: [upstream.body.error || 'upstream_error'],
          pii_types: piiTypes,
          redactions: redactedCount,
          duration_ms: durationMs,
          request_bytes: bodyBuffer.length,
          response_status: upstream.status,
          response_bytes: Buffer.byteLength(JSON.stringify(upstream.body)),
          provider,
        });

        this.writeStatus();
        finalizeRequestTelemetry({
          decision: 'upstream_error',
          status: upstream.status,
          providerName: provider,
        });
        return res.status(upstream.status).json(upstream.body);
      }

      if (upstream.status >= 400) {
        responseHeaderDiagnostics(res, diagnostics);
      }

      for (const [key, value] of Object.entries(upstream.responseHeaders || {})) {
        if (key === 'transfer-encoding' || key === 'content-length' || key === 'connection') {
          continue;
        }
        res.setHeader(key, value);
      }

      if (upstream.isStream) {
        res.status(upstream.status);
        let streamedBytes = 0;

        upstream.bodyStream.on('data', (chunk) => {
          streamedBytes += chunk.length;
        });

        upstream.bodyStream.on('end', () => {
          this.auditLogger.write({
            timestamp: new Date().toISOString(),
            correlation_id: correlationId,
            config_version: this.config.version,
            mode: effectiveMode,
            decision: 'forwarded_stream',
            reasons: warnings,
            pii_types: piiTypes,
            redactions: redactedCount,
            duration_ms: Date.now() - start,
            request_bytes: bodyBuffer.length,
            response_status: upstream.status,
            response_bytes: streamedBytes,
            provider,
          });
          this.writeStatus();
          finalizeRequestTelemetry({
            decision: 'forwarded_stream',
            status: upstream.status,
            providerName: provider,
          });
        });

        upstream.bodyStream.on('error', (error) => {
          this.stats.upstream_errors += 1;
          this.auditLogger.write({
            timestamp: new Date().toISOString(),
            correlation_id: correlationId,
            config_version: this.config.version,
            mode: effectiveMode,
            decision: 'stream_error',
            reasons: [error.message || 'stream_error'],
            pii_types: piiTypes,
            redactions: redactedCount,
            duration_ms: Date.now() - start,
            request_bytes: bodyBuffer.length,
            response_status: upstream.status,
            response_bytes: streamedBytes,
            provider,
          });
          this.writeStatus();
          finalizeRequestTelemetry({
            decision: 'stream_error',
            status: upstream.status,
            providerName: provider,
            error,
          });
          res.destroy(error);
        });

        upstream.bodyStream.pipe(res);
        return;
      }

      this.auditLogger.write({
        timestamp: new Date().toISOString(),
        correlation_id: correlationId,
        config_version: this.config.version,
        mode: effectiveMode,
        decision: 'forwarded',
        reasons: warnings,
        pii_types: piiTypes,
        redactions: redactedCount,
        duration_ms: durationMs,
        request_bytes: bodyBuffer.length,
        response_status: upstream.status,
        response_bytes: upstream.body.length,
        provider,
      });

      this.writeStatus();
      finalizeRequestTelemetry({
        decision: 'forwarded',
        status: upstream.status,
        providerName: provider,
      });
      res.status(upstream.status).send(upstream.body);
    });
  }

  start() {
    const host = this.config.proxy.host;
    const port = this.options.portOverride || this.config.proxy.port;

    fs.writeFileSync(PID_FILE_PATH, String(process.pid), 'utf8');

    RuntimeOverrideManager.writeOverride(OVERRIDE_FILE_PATH, false);
    this.overrideManager.startPolling(() => {
      this.writeStatus();
    });

    this.statusInterval = setInterval(() => {
      this.writeStatus();
    }, 2000);

    this.server = this.app.listen(port, host, () => {
      logger.info('Sentinel started', {
        host,
        port,
        configured_mode: this.config.mode,
        effective_mode: this.computeEffectiveMode(),
      });
      this.writeStatus();
    });

    return this.server;
  }

  async stop() {
    this.overrideManager.stopPolling();
    if (this.statusInterval) {
      clearInterval(this.statusInterval);
      this.statusInterval = null;
    }

    this.writeStatus();

    await new Promise((resolve) => {
      if (!this.server) {
        resolve();
        return;
      }
      this.server.close(resolve);
    });

    if (fs.existsSync(PID_FILE_PATH)) {
      fs.unlinkSync(PID_FILE_PATH);
    }

    this.server = null;
    this.writeStatus();
  }
}

module.exports = {
  SentinelServer,
};
