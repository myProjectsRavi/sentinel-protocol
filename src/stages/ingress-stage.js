const { v4: uuidv4 } = require('uuid');
const { RequestContext } = require('../core/request-context');

function initRequestEnvelope({ server, req, res }) {
  const correlationId = uuidv4();
  const piiVaultSessionKey = server.piiVault.deriveSessionKey(req.headers || {}, correlationId);
  const method = req.method.toUpperCase();
  const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  const bodyText = rawBody.toString('utf8');
  const parsedPath = new URL(req.originalUrl, 'http://localhost');
  const requestStart = Date.now();

  res.setHeader('x-sentinel-correlation-id', correlationId);

  const pipelineContext = new RequestContext({
    req,
    res,
    server,
    correlationId,
    requestStart,
  });
  pipelineContext
    .set('method', method)
    .set('path', parsedPath.pathname)
    .set('path_with_query', `${parsedPath.pathname}${parsedPath.search}`)
    .set('body_text', bodyText)
    .set('raw_body', rawBody);

  return {
    correlationId,
    piiVaultSessionKey,
    method,
    rawBody,
    bodyText,
    parsedPath,
    requestStart,
    pipelineContext,
  };
}

function attachProvenanceInterceptors({ server, res, correlationId, providerRef }) {
  const originalSend = res.send.bind(res);
  const originalJson = res.json.bind(res);

  res.send = (body) => {
    server.applyBufferedProvenanceHeaders(res, {
      body,
      statusCode: res.statusCode,
      provider: providerRef.value,
      correlationId,
    });
    return originalSend(body);
  };

  res.json = (body) => {
    server.applyBufferedProvenanceHeaders(res, {
      body,
      statusCode: res.statusCode,
      provider: providerRef.value,
      correlationId,
    });
    return originalJson(body);
  };
}

function createTelemetryFinalizer({ server, requestStart, requestSpan, onFinalize }) {
  let requestFinalized = false;
  return ({ decision, status, providerName, error }) => {
    if (requestFinalized) {
      return;
    }
    requestFinalized = true;
    const latencyMs = Date.now() - requestStart;
    server.prometheus.observeRequestDuration(latencyMs);
    const attrs = {
      decision,
      status_code: Number(status || 0),
      provider: providerName || 'unknown',
      effective_mode: server.computeEffectiveMode(),
    };
    server.telemetry.recordLatencyMs(latencyMs, attrs);
    if (decision === 'blocked_policy' || decision === 'blocked_pii' || decision === 'blocked_egress') {
      server.telemetry.addBlocked(attrs);
    }
    if (decision === 'upstream_error' || decision === 'stream_error') {
      server.telemetry.addUpstreamError(attrs);
    }
    server.telemetry.endSpan(requestSpan, attrs, error);
    if (typeof onFinalize === 'function') {
      onFinalize({ decision, status, providerName, error, latencyMs, attrs });
    }
  };
}

module.exports = {
  initRequestEnvelope,
  attachProvenanceInterceptors,
  createTelemetryFinalizer,
};
