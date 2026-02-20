const http = require('http');
const https = require('https');

const logger = require('../utils/logger');
const { resolveUpstreamPlan } = require('../upstream/router');

const WEBSOCKET_MODES = new Set(['monitor', 'enforce']);
const WEBSOCKET_HOP_HEADERS = new Set([
  'connection',
  'host',
  'x-sentinel-target',
  'x-sentinel-custom-url',
  'x-sentinel-target-group',
  'x-sentinel-route-target',
  'x-sentinel-route-contract',
  'x-sentinel-route-source',
  'x-sentinel-route-group',
]);

function normalizeWebSocketMode(value) {
  const normalized = String(value || '').toLowerCase();
  return WEBSOCKET_MODES.has(normalized) ? normalized : 'monitor';
}

function toWebSocketUrl(baseUrl, requestUrl) {
  const base = new URL(String(baseUrl || ''));
  if (base.protocol === 'https:') {
    base.protocol = 'wss:';
  } else if (base.protocol === 'http:') {
    base.protocol = 'ws:';
  }
  return new URL(String(requestUrl || '/'), base);
}

function firstHeaderValue(value) {
  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
}

function extractClientIp(req, socket) {
  const xff = firstHeaderValue(req?.headers?.['x-forwarded-for']);
  if (xff) {
    return String(xff).split(',')[0].trim();
  }
  const xRealIp = firstHeaderValue(req?.headers?.['x-real-ip']);
  if (xRealIp) {
    return String(xRealIp).trim();
  }
  const socketAddress = socket?.remoteAddress;
  if (socketAddress) {
    return String(socketAddress).trim();
  }
  return '';
}

function buildUpstreamUpgradeHeaders(reqHeaders, upstreamHostHeader) {
  const out = {};
  for (const [key, value] of Object.entries(reqHeaders || {})) {
    const lowered = String(key).toLowerCase();
    if (WEBSOCKET_HOP_HEADERS.has(lowered) || lowered.startsWith('x-sentinel-')) {
      continue;
    }
    if (value === undefined || value === null) {
      continue;
    }
    out[lowered] = String(firstHeaderValue(value));
  }
  out.connection = 'Upgrade';
  out.upgrade = 'websocket';
  out.host = String(upstreamHostHeader || out.host || '');
  return out;
}

function formatHttpHeaders(headers = {}) {
  const lines = [];
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined || value === null) {
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        lines.push(`${name}: ${String(item)}`);
      }
      continue;
    }
    lines.push(`${name}: ${String(value)}`);
  }
  return lines;
}

function writeHttpResponse(socket, { statusCode, statusMessage, headers, body }) {
  if (!socket || socket.destroyed) {
    return;
  }
  const resolvedStatusCode = Number.isInteger(statusCode) ? statusCode : 500;
  const resolvedStatusMessage = String(
    statusMessage ||
      (resolvedStatusCode === 400
        ? 'Bad Request'
        : resolvedStatusCode === 401
          ? 'Unauthorized'
          : resolvedStatusCode === 403
            ? 'Forbidden'
            : resolvedStatusCode === 404
              ? 'Not Found'
              : resolvedStatusCode === 429
                ? 'Too Many Requests'
                : resolvedStatusCode === 503
                  ? 'Service Unavailable'
                  : 'Internal Server Error')
  );
  const payload = Buffer.isBuffer(body)
    ? body
    : Buffer.from(
        body && typeof body === 'object'
          ? JSON.stringify(body)
          : String(body || ''),
        'utf8'
      );
  const responseHeaders = {
    'content-type': 'application/json; charset=utf-8',
    'content-length': payload.length,
    connection: 'close',
    ...headers,
  };
  const head = [`HTTP/1.1 ${resolvedStatusCode} ${resolvedStatusMessage}`, ...formatHttpHeaders(responseHeaders), '', '']
    .join('\r\n');
  socket.write(head);
  if (payload.length > 0) {
    socket.write(payload);
  }
  socket.end();
}

function writeUpgradeResponse(socket, statusCode, headers = {}) {
  const lines = [
    `HTTP/1.1 ${statusCode} Switching Protocols`,
    ...formatHttpHeaders(headers),
    '',
    '',
  ].join('\r\n');
  socket.write(lines);
}

function safeClose(socket, error) {
  if (!socket || socket.destroyed) {
    return;
  }
  if (error) {
    socket.destroy(error);
    return;
  }
  socket.destroy();
}

function websocketRuntimeConfig(config = {}) {
  const runtime = config.runtime?.websocket || {};
  return {
    enabled: runtime.enabled !== false,
    mode: normalizeWebSocketMode(runtime.mode),
    connectTimeoutMs: Number(runtime.connect_timeout_ms || 15000),
    idleTimeoutMs: Number(runtime.idle_timeout_ms || 120000),
    maxConnections: Number(runtime.max_connections || 500),
  };
}

function createWebSocketAuditPayload({
  server,
  correlationId,
  mode,
  decision,
  reasons,
  provider,
  requestBytes,
  responseBytes,
  responseStatus,
  routePlan,
  upstreamTarget,
  startedAt,
}) {
  return {
    timestamp: new Date().toISOString(),
    correlation_id: correlationId,
    config_version: server.config.version,
    mode,
    decision,
    reasons,
    pii_types: [],
    redactions: 0,
    duration_ms: Math.max(0, Date.now() - startedAt),
    request_bytes: Math.max(0, Number(requestBytes || 0)),
    response_status: Number(responseStatus || 0),
    response_bytes: Math.max(0, Number(responseBytes || 0)),
    provider,
    upstream_target: upstreamTarget,
    route_source: routePlan?.routeSource,
    route_group: routePlan?.selectedGroup || undefined,
    route_contract: routePlan?.desiredContract,
    requested_target: routePlan?.requestedTarget,
    websocket: true,
  };
}

async function handleWebSocketUpgrade({ server, req, socket, head }) {
  const runtime = websocketRuntimeConfig(server.config);
  if (!runtime.enabled) {
    writeHttpResponse(socket, {
      statusCode: 404,
      body: {
        error: 'WEBSOCKET_DISABLED',
      },
    });
    return;
  }

  server.stats.websocket_upgrades_total += 1;
  if (server.activeWebSocketTunnels >= runtime.maxConnections) {
    server.stats.websocket_blocked += 1;
    server.auditLogger.write(
      createWebSocketAuditPayload({
        server,
        correlationId: 'ws-capacity',
        mode: runtime.mode,
        decision: 'blocked_websocket',
        reasons: ['websocket_capacity_exceeded'],
        provider: 'unknown',
        requestBytes: 0,
        responseBytes: 0,
        responseStatus: 503,
        routePlan: null,
        upstreamTarget: null,
        startedAt: Date.now(),
      })
    );
    server.writeStatus();
    writeHttpResponse(socket, {
      statusCode: 503,
      body: {
        error: 'WEBSOCKET_CAPACITY_EXCEEDED',
      },
    });
    return;
  }

  const startedAt = Date.now();
  const correlationId = `ws-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  let routePlan;
  try {
    routePlan = await resolveUpstreamPlan(req, server.config);
  } catch (error) {
    server.stats.websocket_errors += 1;
    server.auditLogger.write(
      createWebSocketAuditPayload({
        server,
        correlationId,
        mode: runtime.mode,
        decision: 'websocket_route_error',
        reasons: [String(error.message || 'route_error')],
        provider: 'unknown',
        requestBytes: 0,
        responseBytes: 0,
        responseStatus: 400,
        routePlan: null,
        upstreamTarget: null,
        startedAt,
      })
    );
    server.writeStatus();
    writeHttpResponse(socket, {
      statusCode: 400,
      body: {
        error: 'INVALID_PROVIDER_TARGET',
        message: String(error.message || 'route_error'),
      },
    });
    return;
  }

  const primary = routePlan.primary;
  const provider = primary.provider;
  const upstreamUrl = toWebSocketUrl(primary.baseUrl, req.url);
  const providerHostname = upstreamUrl.hostname;
  const clientIp = extractClientIp(req, socket);
  const policyDecision = server.policyEngine.check({
    method: String(req.method || 'GET').toUpperCase(),
    hostname: providerHostname,
    pathname: String(upstreamUrl.pathname || '/'),
    bodyText: '',
    bodyJson: {},
    requestBytes: 0,
    headers: req.headers || {},
    provider,
    rateLimitKey: req.headers?.['x-sentinel-agent-id'],
    clientIp,
    injectionResult: null,
  });

  const shouldBlockForPolicy = policyDecision.matched && policyDecision.action === 'block' && runtime.mode === 'enforce';
  if (shouldBlockForPolicy) {
    server.stats.websocket_blocked += 1;
    server.auditLogger.write(
      createWebSocketAuditPayload({
        server,
        correlationId,
        mode: runtime.mode,
        decision: 'blocked_websocket',
        reasons: [String(policyDecision.reason || 'policy_violation')],
        provider,
        requestBytes: 0,
        responseBytes: 0,
        responseStatus: policyDecision.reason === 'rate_limit_exceeded' ? 429 : 403,
        routePlan,
        upstreamTarget: upstreamUrl.toString(),
        startedAt,
      })
    );
    server.writeStatus();
    writeHttpResponse(socket, {
      statusCode: policyDecision.reason === 'rate_limit_exceeded' ? 429 : 403,
      body: {
        error: policyDecision.reason === 'rate_limit_exceeded' ? 'RATE_LIMIT_EXCEEDED' : 'POLICY_VIOLATION',
        reason: String(policyDecision.reason || 'policy_violation'),
        rule: policyDecision.rule || undefined,
        correlation_id: correlationId,
      },
    });
    return;
  }

  const connectHost = primary.resolvedIp || upstreamUrl.hostname;
  const connectPort = Number(upstreamUrl.port || (upstreamUrl.protocol === 'wss:' ? 443 : 80));
  const connectPath = `${upstreamUrl.pathname}${upstreamUrl.search}`;
  const upstreamHeaders = buildUpstreamUpgradeHeaders(
    req.headers || {},
    primary.upstreamHostHeader || upstreamUrl.host
  );
  const requestOptions = {
    protocol: upstreamUrl.protocol === 'wss:' ? 'https:' : 'http:',
    hostname: connectHost,
    port: connectPort,
    method: 'GET',
    path: connectPath,
    headers: upstreamHeaders,
    timeout: runtime.connectTimeoutMs,
  };
  if (upstreamUrl.protocol === 'wss:' && connectHost !== upstreamUrl.hostname) {
    requestOptions.servername = upstreamUrl.hostname;
  }
  const upstreamRequest = (upstreamUrl.protocol === 'wss:' ? https : http).request(requestOptions);
  let finalized = false;
  let tunnelStarted = false;
  let sentBytes = Buffer.isBuffer(head) ? head.length : 0;
  let recvBytes = 0;
  const extraReasons = [];
  if (policyDecision.matched && policyDecision.action === 'block') {
    extraReasons.push(`policy_monitor:${String(policyDecision.reason || policyDecision.rule || 'policy')}`);
  }
  const finalize = ({ decision, reasons, statusCode }) => {
    if (finalized) {
      return;
    }
    finalized = true;
    if (tunnelStarted) {
      server.activeWebSocketTunnels = Math.max(0, server.activeWebSocketTunnels - 1);
    }
    server.auditLogger.write(
      createWebSocketAuditPayload({
        server,
        correlationId,
        mode: runtime.mode,
        decision,
        reasons,
        provider,
        requestBytes: sentBytes,
        responseBytes: recvBytes,
        responseStatus: statusCode,
        routePlan,
        upstreamTarget: upstreamUrl.toString(),
        startedAt,
      })
    );
    server.writeStatus();
  };

  upstreamRequest.on('upgrade', (upstreamResponse, upstreamSocket, upstreamHead) => {
    server.stats.websocket_forwarded += 1;
    server.activeWebSocketTunnels += 1;
    tunnelStarted = true;
    if (Buffer.isBuffer(upstreamHead)) {
      recvBytes += upstreamHead.length;
    }
    const responseHeaders = {
      ...upstreamResponse.headers,
      'x-sentinel-correlation-id': correlationId,
      'x-sentinel-ws-mode': runtime.mode,
      'x-sentinel-route-source': String(routePlan.routeSource || ''),
      'x-sentinel-route-target': String(routePlan.requestedTarget || ''),
      'x-sentinel-route-contract': String(routePlan.desiredContract || ''),
    };
    if (extraReasons.length > 0) {
      responseHeaders['x-sentinel-ws-policy-warning'] = extraReasons.join(',');
    }
    writeUpgradeResponse(socket, upstreamResponse.statusCode || 101, responseHeaders);
    if (Buffer.isBuffer(upstreamHead) && upstreamHead.length > 0) {
      socket.write(upstreamHead);
    }
    if (Buffer.isBuffer(head) && head.length > 0) {
      upstreamSocket.write(head);
    }
    const trackedSockets = server.webSocketSockets instanceof Set ? server.webSocketSockets : null;
    if (trackedSockets) {
      trackedSockets.add(socket);
      trackedSockets.add(upstreamSocket);
      socket.once('close', () => {
        trackedSockets.delete(socket);
      });
      upstreamSocket.once('close', () => {
        trackedSockets.delete(upstreamSocket);
      });
    }

    const onClientData = (chunk) => {
      sentBytes += chunk.length;
    };
    const onUpstreamData = (chunk) => {
      recvBytes += chunk.length;
    };
    socket.on('data', onClientData);
    upstreamSocket.on('data', onUpstreamData);
    const idleTimeoutMs = Number.isFinite(runtime.idleTimeoutMs) && runtime.idleTimeoutMs > 0
      ? runtime.idleTimeoutMs
      : 120000;
    socket.setTimeout(idleTimeoutMs, () => {
      safeClose(socket, new Error('WEBSOCKET_IDLE_TIMEOUT'));
      safeClose(upstreamSocket, new Error('WEBSOCKET_IDLE_TIMEOUT'));
    });
    upstreamSocket.setTimeout(idleTimeoutMs, () => {
      safeClose(upstreamSocket, new Error('WEBSOCKET_IDLE_TIMEOUT'));
      safeClose(socket, new Error('WEBSOCKET_IDLE_TIMEOUT'));
    });

    socket.pipe(upstreamSocket);
    upstreamSocket.pipe(socket);

    const closeDecision = () => {
      if (trackedSockets) {
        trackedSockets.delete(socket);
        trackedSockets.delete(upstreamSocket);
      }
      finalize({
        decision: 'forwarded_websocket',
        reasons: extraReasons.length > 0 ? extraReasons : ['websocket_forwarded'],
        statusCode: 101,
      });
    };
    socket.once('close', closeDecision);
    upstreamSocket.once('close', closeDecision);
    socket.once('error', closeDecision);
    upstreamSocket.once('error', closeDecision);
  });

  upstreamRequest.on('response', (upstreamResponse) => {
    server.stats.websocket_errors += 1;
    const chunks = [];
    upstreamResponse.on('data', (chunk) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8'));
    });
    upstreamResponse.on('end', () => {
      const body = chunks.length > 0 ? Buffer.concat(chunks) : Buffer.alloc(0);
      recvBytes += body.length;
      finalize({
        decision: 'websocket_upstream_reject',
        reasons: ['upstream_non_upgrade_response'],
        statusCode: upstreamResponse.statusCode || 502,
      });
      writeHttpResponse(socket, {
        statusCode: upstreamResponse.statusCode || 502,
        statusMessage: upstreamResponse.statusMessage || 'Bad Gateway',
        headers: {
          'content-type': upstreamResponse.headers['content-type'] || 'text/plain; charset=utf-8',
        },
        body: body.length > 0 ? body : Buffer.from('Upstream rejected websocket upgrade', 'utf8'),
      });
    });
  });

  upstreamRequest.on('timeout', () => {
    upstreamRequest.destroy(new Error('WEBSOCKET_CONNECT_TIMEOUT'));
  });

  upstreamRequest.on('error', (error) => {
    server.stats.websocket_errors += 1;
    finalize({
      decision: 'websocket_error',
      reasons: [String(error.message || 'websocket_transport_error')],
      statusCode: 502,
    });
    writeHttpResponse(socket, {
      statusCode: 502,
      body: {
        error: 'WEBSOCKET_UPSTREAM_ERROR',
        message: String(error.message || 'websocket_transport_error'),
      },
    });
  });

  try {
    upstreamRequest.end();
  } catch (error) {
    server.stats.websocket_errors += 1;
    finalize({
      decision: 'websocket_error',
      reasons: [String(error.message || 'websocket_transport_error')],
      statusCode: 502,
    });
    logger.warn('websocket upgrade end failed', {
      correlation_id: correlationId,
      error: error.message,
    });
    writeHttpResponse(socket, {
      statusCode: 502,
      body: {
        error: 'WEBSOCKET_UPSTREAM_ERROR',
        message: String(error.message || 'websocket_transport_error'),
      },
    });
  }
}

module.exports = {
  handleWebSocketUpgrade,
  normalizeWebSocketMode,
  toWebSocketUrl,
};
