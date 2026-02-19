const { responseHeaderDiagnostics, tryParseJson } = require('./shared');

function rejectUnsupportedMethod({ method, res, correlationId, finalizeRequestTelemetry }) {
  if (method !== 'TRACE' && method !== 'CONNECT') {
    return false;
  }
  finalizeRequestTelemetry({
    decision: 'method_not_allowed',
    status: 405,
    providerName: 'unknown',
  });
  res.status(405).json({
    error: 'METHOD_NOT_ALLOWED',
    message: `HTTP method ${method} is not allowed by Sentinel.`,
    correlation_id: correlationId,
  });
  return true;
}

async function runPipelineOrRespond({
  server,
  stageName,
  pipelineContext,
  res,
  provider,
  finalizeRequestTelemetry,
}) {
  await server.executePipelineStage(stageName, pipelineContext);
  if (!pipelineContext.isBlocked()) {
    return false;
  }
  const blocked = pipelineContext.shortCircuit;
  for (const [headerName, headerValue] of Object.entries(blocked.headers || {})) {
    res.setHeader(headerName, headerValue);
  }
  res.setHeader('x-sentinel-plugin-block', String(blocked.reason || 'plugin_block'));
  finalizeRequestTelemetry({
    decision: 'blocked_policy',
    status: blocked.statusCode,
    providerName: provider || 'unknown',
  });
  res.status(blocked.statusCode).json(blocked.body);
  return true;
}

function parseJsonBodyOrRespond({
  bodyText,
  req,
  provider,
  breakerKey,
  correlationId,
  server,
  res,
  finalizeRequestTelemetry,
}) {
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
        circuitState: server.circuitBreakers.getProviderState(breakerKey).state,
        correlationId,
      };
      responseHeaderDiagnostics(res, diagnostics);
      finalizeRequestTelemetry({
        decision: 'invalid_json',
        status: 400,
        providerName: provider,
        error: parsedBody.error,
      });
      res.status(400).json({
        error: 'INVALID_JSON_BODY',
        message: 'Request body is not valid JSON.',
        correlation_id: correlationId,
      });
      return {
        handled: true,
        bodyJson: null,
      };
    }
    bodyJson = parsedBody.value;
  }
  return {
    handled: false,
    bodyJson,
  };
}

function mergePipelineWarnings({ warnings, pluginWarnings, stats }) {
  if (!Array.isArray(pluginWarnings) || pluginWarnings.length === 0) {
    return;
  }
  for (const warning of pluginWarnings) {
    const value = String(warning);
    if (!warnings.includes(value)) {
      warnings.push(value);
      stats.warnings_total += 1;
    }
  }
}

module.exports = {
  rejectUnsupportedMethod,
  runPipelineOrRespond,
  parseJsonBodyOrRespond,
  mergePipelineWarnings,
};
