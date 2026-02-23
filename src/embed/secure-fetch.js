function toBodyText(body) {
  if (body === undefined || body === null) {
    return '';
  }
  if (typeof body === 'string') {
    return body;
  }
  if (Buffer.isBuffer(body)) {
    return body.toString('utf8');
  }
  if (typeof body === 'object') {
    try {
      return JSON.stringify(body);
    } catch {
      return '';
    }
  }
  return String(body);
}

function getFetchImpl(options = {}) {
  if (typeof options.fetchImpl === 'function') {
    return options.fetchImpl;
  }
  if (typeof globalThis.fetch === 'function') {
    return globalThis.fetch.bind(globalThis);
  }
  throw new Error('secure_fetch_unavailable');
}

function responseFromJson(status, payload, headers = {}) {
  const body = JSON.stringify(payload);
  const responseHeaders = new Headers({
    'content-type': 'application/json',
    ...headers,
  });
  return new Response(body, {
    status,
    headers: responseHeaders,
  });
}

function normalizeHeaders(input) {
  const out = {};
  if (!input) {
    return out;
  }
  if (input instanceof Headers) {
    for (const [k, v] of input.entries()) {
      out[String(k).toLowerCase()] = String(v);
    }
    return out;
  }
  if (Array.isArray(input)) {
    for (const item of input) {
      if (Array.isArray(item) && item.length >= 2) {
        out[String(item[0]).toLowerCase()] = String(item[1]);
      }
    }
    return out;
  }
  if (typeof input === 'object') {
    for (const [k, v] of Object.entries(input)) {
      out[String(k).toLowerCase()] = String(v);
    }
  }
  return out;
}

function mergeRequestHeaders(input, extras = {}) {
  const merged = normalizeHeaders(input);
  for (const [key, value] of Object.entries(extras || {})) {
    merged[String(key).toLowerCase()] = String(value);
  }
  return merged;
}

async function secureFetch(server, url, options = {}) {
  const fetchImpl = getFetchImpl(options);
  const method = String(options.method || 'GET').toUpperCase();
  const bodyText = toBodyText(options.body);
  const headersLookup = mergeRequestHeaders(options.headers, {
    'x-sentinel-embed': '1',
  });
  const parsed = new URL(url);
  const provider = String(headersLookup['x-sentinel-target'] || parsed.hostname || 'custom').toLowerCase();

  const policyDecision = server.policyEngine.check({
    method,
    hostname: parsed.hostname,
    pathname: parsed.pathname,
    bodyText,
    bodyJson: (() => {
      try {
        return bodyText ? JSON.parse(bodyText) : {};
      } catch {
        return {};
      }
    })(),
    requestBytes: Buffer.byteLength(bodyText || '', 'utf8'),
    headers: headersLookup,
    provider,
    rateLimitKey: headersLookup['x-sentinel-agent-id'],
  });
  if (
    policyDecision?.matched
    && policyDecision.action === 'block'
    && String(server.computeEffectiveMode?.() || server.config.mode || 'monitor') === 'enforce'
  ) {
    return responseFromJson(403, {
      error: 'EMBED_POLICY_BLOCKED',
      reason: policyDecision.reason || 'policy_violation',
      rule: policyDecision.rule || null,
    }, {
      'x-sentinel-blocked-by': 'embed_policy',
    });
  }

  const requestInit = {
    ...options,
    method,
    headers: headersLookup,
  };
  const response = await fetchImpl(url, requestInit);
  const contentType = String(response.headers.get('content-type') || '').toLowerCase();
  if (!/json|text|xml|javascript/.test(contentType)) {
    return response;
  }

  let responseText = '';
  try {
    responseText = await response.clone().text();
  } catch {
    return response;
  }

  if (server.outputClassifier?.isEnabled?.()) {
    const classifierDecision = server.outputClassifier.classifyText(responseText, {
      effectiveMode: server.computeEffectiveMode?.() || server.config.mode || 'monitor',
    });
    if (classifierDecision.shouldBlock) {
      return responseFromJson(502, {
        error: 'EMBED_OUTPUT_BLOCKED',
        reason: classifierDecision.blockedBy?.[0] || 'output_classifier',
      }, {
        'x-sentinel-blocked-by': 'output_classifier',
      });
    }
  }

  if (server.outputSchemaValidator?.isEnabled?.()) {
    const schemaHeader = String(response.headers.get('x-sentinel-output-schema') || '');
    if (schemaHeader) {
      const schemaDecision = server.outputSchemaValidator.validateResponse(responseText, schemaHeader, {
        effectiveMode: server.computeEffectiveMode?.() || server.config.mode || 'monitor',
      });
      if (schemaDecision.shouldBlock) {
        return responseFromJson(502, {
          error: 'EMBED_OUTPUT_SCHEMA_BLOCKED',
          reason: schemaDecision.reason || 'output_schema_invalid',
        }, {
          'x-sentinel-blocked-by': 'output_schema_validator',
        });
      }
    }
  }

  return response;
}

module.exports = {
  secureFetch,
};
