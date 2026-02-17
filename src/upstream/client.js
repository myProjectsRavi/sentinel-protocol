const {
  parseRetryAfterMs,
  jitterBackoffMs,
  methodRetryEligible,
  shouldRetryResponse,
  shouldRetryError,
} = require('../resilience/retry');

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function buildForwardHeaders(originalHeaders, bodyLength) {
  const headers = { ...originalHeaders };
  delete headers.host;
  delete headers.connection;
  delete headers['content-length'];
  delete headers['x-sentinel-target'];
  delete headers['x-sentinel-custom-url'];
  delete headers['x-sentinel-optimize'];
  delete headers['x-sentinel-optimizer-profile'];

  if (bodyLength > 0) {
    headers['content-length'] = String(bodyLength);
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
  }

  async forwardRequest(params) {
    const {
      provider,
      baseUrl,
      req,
      pathWithQuery,
      method,
      bodyBuffer,
      correlationId,
    } = params;

    const gate = this.circuitBreakers.canRequest(provider);
    if (!gate.allowed) {
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

    const forwardHeaders = buildForwardHeaders(req.headers, bodyBuffer.length);
    const url = `${baseUrl}${pathWithQuery}`;

    let retryCount = 0;
    let lastErrorType = null;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        const controller = AbortSignal.timeout(this.timeoutMs);
        const response = await fetch(url, {
          method,
          headers: forwardHeaders,
          body: method === 'GET' || method === 'HEAD' ? undefined : bodyBuffer,
          signal: controller,
        });

        const status = response.status;
        const responseHeaders = copyResponseHeaders(response);
        const responseBody = Buffer.from(await response.arrayBuffer());

        const retryableStatus = shouldRetryResponse(status);
        const canRetry = retryEnabled && eligibleMethod && attempt < maxAttempts && retryableStatus;

        if (canRetry) {
          retryCount += 1;
          const delay = parseRetryAfterMs(response.headers.get('retry-after')) ?? jitterBackoffMs();
          await sleep(delay);
          continue;
        }

        if (status >= 500 || status === 429) {
          this.circuitBreakers.recordUpstreamFailure(provider, 'status');
        } else {
          this.circuitBreakers.recordUpstreamSuccess(provider);
        }

        return {
          ok: true,
          status,
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

        return {
          ok: false,
          status: errorType === 'timeout' ? 504 : 502,
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
    return {
      ok: false,
      status: 502,
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
