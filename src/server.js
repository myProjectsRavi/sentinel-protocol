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
const {
  PID_FILE_PATH,
  STATUS_FILE_PATH,
  OVERRIDE_FILE_PATH,
  AUDIT_LOG_PATH,
  ensureSentinelHome,
} = require('./utils/paths');

function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
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
      upstream_errors: 0,
      warnings_total: 0,
    };

    this.rateLimiter = new InMemoryRateLimiter();
    this.policyEngine = new PolicyEngine(config, this.rateLimiter);
    this.piiScanner = new PIIScanner({ maxScanBytes: config.pii.max_scan_bytes });
    this.circuitBreakers = new CircuitBreakerManager(config.runtime.upstream.circuit_breaker);
    this.upstreamClient = new UpstreamClient({
      timeoutMs: config.proxy.timeout_ms,
      retryConfig: config.runtime.upstream.retry,
      circuitBreakers: this.circuitBreakers,
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
        limit: '20mb',
      })
    );

    this.app.get('/_sentinel/health', (req, res) => {
      res.status(200).json({ status: 'ok' });
    });

    this.app.all('*', async (req, res) => {
      const correlationId = uuidv4();
      const method = req.method.toUpperCase();
      const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
      let bodyText = rawBody.toString('utf8');

      this.stats.requests_total += 1;

      let provider;
      let baseUrl;
      try {
        const resolved = resolveProvider(req);
        provider = resolved.provider;
        baseUrl = resolved.baseUrl;
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
        return res.status(400).json({ error: 'INVALID_PROVIDER_TARGET', message: error.message });
      }

      const parsedPath = new URL(req.originalUrl, 'http://localhost');
      const contentType = String(req.headers['content-type'] || '').toLowerCase();
      let bodyJson = contentType.includes('application/json') && bodyText.length > 0 ? safeJsonParse(bodyText) : null;
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

      const piiResult = this.config.pii.enabled ? this.piiScanner.scan(bodyText, { maxScanBytes: this.config.pii.max_scan_bytes }) : null;
      let piiBlocked = false;
      let redactedCount = 0;
      let piiTypes = [];

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
      const start = Date.now();

      const upstream = await this.upstreamClient.forwardRequest({
        provider,
        baseUrl,
        req,
        pathWithQuery: `${parsedPath.pathname}${parsedPath.search}`,
        method,
        bodyBuffer,
        correlationId,
      });

      const durationMs = Date.now() - start;
      const diagnostics = upstream.diagnostics;

      if (warnings.length > 0) {
        res.setHeader('x-sentinel-warning', warnings.join(','));
      }

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
