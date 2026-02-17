const {
  parseRetryAfterMs,
  jitterBackoffMs,
  methodRetryEligible,
  shouldRetryResponse,
  shouldRetryError,
} = require('../resilience/retry');
const { Readable } = require('stream');
const dns = require('dns');
const net = require('net');
const { Agent } = require('undici');

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

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function normalizeHeaderValue(value) {
  if (Array.isArray(value)) {
    return value.join(', ');
  }
  return value;
}

function parseConnectionHeaderTokens(value) {
  if (!value) {
    return new Set();
  }
  const raw = String(value);
  return new Set(
    raw
      .split(',')
      .map((token) => token.trim().toLowerCase())
      .filter(Boolean)
  );
}

function buildForwardHeaders(originalHeaders, bodyLength, hostHeader) {
  const headers = { ...originalHeaders };
  const connectionTokens = parseConnectionHeaderTokens(headers.connection);
  delete headers.host;
  delete headers['content-length'];

  for (const key of Object.keys(headers)) {
    const lowered = key.toLowerCase();
    if (lowered.startsWith('x-sentinel-')) {
      delete headers[key];
      continue;
    }
    if (HOP_BY_HOP_HEADERS.has(lowered) || connectionTokens.has(lowered)) {
      delete headers[key];
    }
  }

  headers.host = hostHeader;
  if (bodyLength > 0) {
    headers['content-length'] = String(bodyLength);
  }

  for (const [key, value] of Object.entries(headers)) {
    headers[key] = normalizeHeaderValue(value);
  }

  return headers;
}

function classifyTransportError(error) {
  if (error && (error.name === 'TimeoutError' || error.name === 'AbortError')) {
    return 'timeout';
  }
  return 'transport';
}

function copyResponseHeaders(response) {
  const headers = {};
  response.headers.forEach((value, key) => {
    headers[key] = value;
  });
  return headers;
}

class UpstreamClient {
  constructor(options) {
    this.timeoutMs = options.timeoutMs;
    this.retryConfig = options.retryConfig;
    this.circuitBreakers = options.circuitBreakers;
    this.telemetry = options.telemetry;
    this.dispatchers = new Map();
  }

  getPinnedDispatcher({ upstreamHostname, resolvedIp, resolvedFamily }) {
    if (!upstreamHostname || !resolvedIp) {
      return null;
    }

    const key = `${upstreamHostname}|${resolvedIp}|${resolvedFamily || net.isIP(resolvedIp) || 0}`;
    if (this.dispatchers.has(key)) {
      return this.dispatchers.get(key);
    }

    const family = Number(resolvedFamily || net.isIP(resolvedIp) || 0);
    const dispatcher = new Agent({
      connect: {
        lookup: (hostname, options, callback) => {
          if (hostname === upstreamHostname) {
            callback(null, resolvedIp, family || undefined);
            return;
          }
          dns.lookup(hostname, options, callback);
        },
        // Preserve SNI/certificate validation for HTTPS while pinning DNS resolution.
        servername: upstreamHostname,
      },
    });

    this.dispatchers.set(key, dispatcher);
    return dispatcher;
  }

  async forwardRequest(params) {
    const {
      provider,
      baseUrl,
      req,
      forwardHeaders: providedForwardHeaders,
      pathWithQuery,
      method,
      bodyBuffer,
      correlationId,
      wantsStream,
      resolvedIp,
      resolvedFamily,
      upstreamHostname: providedUpstreamHostname,
      upstreamHostHeader: providedUpstreamHostHeader,
    } = params;

    const gate = this.circuitBreakers.canRequest(provider);
    if (!gate.allowed) {
      this.telemetry?.addUpstreamError({
        provider,
        reason: 'circuit_open',
      });
      return {
        ok: false,
        status: 503,
        body: {
          error: 'UPSTREAM_CIRCUIT_OPEN',
          message: `Provider ${provider} circuit is open`,
        },
        diagnostics: {
          errorSource: 'upstream',
          upstreamError: true,
          provider,
          retryCount: 0,
          circuitState: gate.state,
          correlationId,
        },
        responseHeaders: {
          'retry-after': String(gate.retryAfterSeconds || 1),
        },
      };
    }

    const retryEnabled = this.retryConfig.enabled !== false;
    const maxAttempts = retryEnabled ? 1 + Number(this.retryConfig.max_attempts || 0) : 1;
    const eligibleMethod = methodRetryEligible(method, this.retryConfig, req.headers);

    const url = `${baseUrl}${pathWithQuery}`;
    const parsedUrl = new URL(url);
    const upstreamHostname = providedUpstreamHostname || parsedUrl.hostname;
    const upstreamHostHeader = providedUpstreamHostHeader || parsedUrl.host;
    const forwardHeaders = buildForwardHeaders(
      providedForwardHeaders || req.headers,
      bodyBuffer.length,
      upstreamHostHeader
    );
    const dispatcher = this.getPinnedDispatcher({
      upstreamHostname,
      resolvedIp,
      resolvedFamily,
    });
    const safeUpstreamUrl = (() => {
      try {
        return `${parsedUrl.origin}${parsedUrl.pathname}`;
      } catch {
        return baseUrl;
      }
    })();
    const forwardSpan = this.telemetry?.startSpan('sentinel.upstream.forward', {
      provider,
      method,
      upstream_url: safeUpstreamUrl,
      wants_stream: Boolean(wantsStream),
    });

    let retryCount = 0;
    let lastErrorType = null;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      const attemptSpan = this.telemetry?.startSpan('sentinel.upstream.attempt', {
        provider,
        method,
        attempt,
      });
      try {
        const controller = AbortSignal.timeout(this.timeoutMs);
        const response = await fetch(url, {
          method,
          headers: forwardHeaders,
          body: method === 'GET' || method === 'HEAD' ? undefined : bodyBuffer,
          signal: controller,
          ...(dispatcher ? { dispatcher } : {}),
        });

        const status = response.status;
        const responseHeaders = copyResponseHeaders(response);

        const retryableStatus = shouldRetryResponse(status);
        const canRetry = retryEnabled && eligibleMethod && attempt < maxAttempts && retryableStatus;

        if (canRetry) {
          this.telemetry?.endSpan(attemptSpan, {
            provider,
            method,
            status,
            retrying: true,
          });
          retryCount += 1;
          const delay = parseRetryAfterMs(response.headers.get('retry-after')) ?? jitterBackoffMs();
          await sleep(delay);
          continue;
        }

        if (status >= 500 || status === 429) {
          this.circuitBreakers.recordUpstreamFailure(provider, 'status');
          this.telemetry?.addUpstreamError({
            provider,
            reason: `status_${status}`,
          });
        } else {
          this.circuitBreakers.recordUpstreamSuccess(provider);
        }

        const contentType = String(response.headers.get('content-type') || '').toLowerCase();
        const streamEligible = Boolean(wantsStream) && Boolean(response.body) && status < 400;
        const isSSE = contentType.includes('text/event-stream');
        if (streamEligible && isSSE) {
          this.telemetry?.endSpan(attemptSpan, {
            provider,
            method,
            status,
            streamed: true,
          });
          this.telemetry?.endSpan(forwardSpan, {
            provider,
            method,
            status,
            streamed: true,
            retries: retryCount,
          });
          return {
            ok: true,
            status,
            isStream: true,
            bodyStream: Readable.fromWeb(response.body),
            responseHeaders,
            diagnostics: {
              errorSource: 'upstream',
              upstreamError: false,
              provider,
              retryCount,
              circuitState: this.circuitBreakers.getProviderState(provider).state,
              correlationId,
            },
          };
        }

        const responseBody = Buffer.from(await response.arrayBuffer());
        this.telemetry?.endSpan(attemptSpan, {
          provider,
          method,
          status,
          streamed: false,
        });
        this.telemetry?.endSpan(forwardSpan, {
          provider,
          method,
          status,
          retries: retryCount,
        });

        return {
          ok: true,
          status,
          isStream: false,
          body: responseBody,
          responseHeaders,
          diagnostics: {
            errorSource: 'upstream',
            upstreamError: status >= 400,
            provider,
            retryCount,
            circuitState: this.circuitBreakers.getProviderState(provider).state,
            correlationId,
          },
        };
      } catch (error) {
        const errorType = classifyTransportError(error);
        lastErrorType = errorType;
        this.telemetry?.endSpan(attemptSpan, {
          provider,
          method,
          error_type: errorType,
        }, error);

        const canRetry =
          retryEnabled &&
          eligibleMethod &&
          attempt < maxAttempts &&
          shouldRetryError(errorType);

        if (canRetry) {
          retryCount += 1;
          await sleep(jitterBackoffMs());
          continue;
        }

        this.circuitBreakers.recordUpstreamFailure(provider, errorType);
        this.telemetry?.addUpstreamError({
          provider,
          reason: errorType,
        });
        this.telemetry?.endSpan(forwardSpan, {
          provider,
          method,
          error_type: errorType,
          retries: retryCount,
        }, error);

        return {
          ok: false,
          status: errorType === 'timeout' ? 504 : 502,
          isStream: false,
          body: {
            error: errorType === 'timeout' ? 'UPSTREAM_TIMEOUT' : 'UPSTREAM_TRANSPORT_ERROR',
            message: error.message,
          },
          diagnostics: {
            errorSource: 'upstream',
            upstreamError: true,
            provider,
            retryCount,
            circuitState: this.circuitBreakers.getProviderState(provider).state,
            correlationId,
          },
          responseHeaders: {},
        };
      }
    }

    this.circuitBreakers.recordUpstreamFailure(provider, lastErrorType || 'transport');
    this.telemetry?.addUpstreamError({
      provider,
      reason: lastErrorType || 'transport',
    });
    this.telemetry?.endSpan(forwardSpan, {
      provider,
      method,
      error_type: lastErrorType || 'transport',
      retries: retryCount,
    }, new Error('UPSTREAM_UNAVAILABLE'));
    return {
      ok: false,
      status: 502,
      isStream: false,
      body: {
        error: 'UPSTREAM_UNAVAILABLE',
        message: 'Upstream is unavailable',
      },
      diagnostics: {
        errorSource: 'upstream',
        upstreamError: true,
        provider,
        retryCount,
        circuitState: this.circuitBreakers.getProviderState(provider).state,
        correlationId,
      },
      responseHeaders: {},
    };
  }
}

module.exports = {
  UpstreamClient,
};
