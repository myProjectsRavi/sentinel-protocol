const { filterUpstreamResponseHeaders, responseHeaderDiagnostics } = require('./shared');

function applyForwardingHeaders({
  res,
  warnings,
  piiProviderUsed,
  semanticCacheHeader,
}) {
  if (warnings.length > 0) {
    res.setHeader('x-sentinel-warning', warnings.join(','));
  }
  res.setHeader('x-sentinel-pii-provider', piiProviderUsed);
  if (semanticCacheHeader && !res.getHeader('x-sentinel-semantic-cache')) {
    res.setHeader('x-sentinel-semantic-cache', semanticCacheHeader);
  }
}

function applyUpstreamResponseHeaders(res, upstreamResponseHeaders = {}) {
  for (const [key, value] of Object.entries(filterUpstreamResponseHeaders(upstreamResponseHeaders || {}))) {
    res.setHeader(key, value);
  }
}

function handleUpstreamErrorResponse({
  server,
  res,
  upstream,
  diagnostics,
  routedProvider,
  correlationId,
  finalizeRequestTelemetry,
  auditPayload,
}) {
  server.stats.upstream_errors += 1;
  responseHeaderDiagnostics(res, diagnostics);
  applyUpstreamResponseHeaders(res, upstream.responseHeaders || {});
  server.auditLogger.write(auditPayload);
  server.writeStatus();
  finalizeRequestTelemetry({
    decision: 'upstream_error',
    status: upstream.status,
    providerName: routedProvider,
  });
  return res.status(upstream.status).json(upstream.body);
}

module.exports = {
  applyForwardingHeaders,
  applyUpstreamResponseHeaders,
  handleUpstreamErrorResponse,
};
