const { UpstreamClient } = require('../../src/upstream/client');
const { SwarmProtocol } = require('../../src/security/swarm-protocol');

class FakeCircuitBreakers {
  constructor() {
    this.state = new Map();
  }

  canRequest(key) {
    this.getProviderState(key);
    return { allowed: true, state: 'closed', retryAfterSeconds: 0 };
  }

  getProviderState(key) {
    if (!this.state.has(key)) {
      this.state.set(key, { state: 'closed' });
    }
    return this.state.get(key);
  }

  recordUpstreamSuccess() {}

  recordUpstreamFailure() {}
}

function buildRoutePlan(provider = 'openai') {
  return {
    requestedTarget: provider,
    selectedGroup: null,
    routeSource: 'target',
    desiredContract: 'passthrough',
    candidates: [
      {
        targetName: provider,
        provider,
        baseUrl: 'https://provider.local',
        upstreamHostname: 'provider.local',
        upstreamHostHeader: 'provider.local',
        resolvedIp: null,
        resolvedFamily: null,
        staticHeaders: {},
        contract: 'passthrough',
        breakerKey: provider,
      },
    ],
    failover: {
      enabled: false,
      maxFailoverHops: 0,
      allowPostWithIdempotencyKey: false,
      onStatus: [429, 500, 502, 503, 504],
      onErrorTypes: ['timeout', 'transport', 'circuit_open'],
    },
  };
}

describe('UpstreamClient auth vault handling', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
    jest.restoreAllMocks();
    delete process.env.SENTINEL_OPENAI_API_KEY;
  });

  test('replaces dummy key and strips non-target provider auth headers', async () => {
    global.fetch = jest.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const client = new UpstreamClient({
      timeoutMs: 2000,
      retryConfig: {
        enabled: false,
        max_attempts: 0,
        allow_post_with_idempotency_key: false,
      },
      circuitBreakers: new FakeCircuitBreakers(),
      telemetry: null,
      authVaultConfig: {
        enabled: true,
        mode: 'replace_dummy',
        dummy_key: 'sk-sentinel-local',
        providers: {
          openai: {
            enabled: true,
            api_key: 'sk-real-openai',
            env_var: 'SENTINEL_OPENAI_API_KEY',
          },
        },
      },
    });

    const result = await client.forwardRequest({
      req: {
        headers: {
          authorization: 'Bearer sk-sentinel-local',
          'x-api-key': 'anthropic-secret',
          'x-goog-api-key': 'google-secret',
        },
      },
      method: 'POST',
      pathWithQuery: '/v1/chat/completions',
      bodyBuffer: Buffer.from(JSON.stringify({ message: 'hello' })),
      bodyJson: { message: 'hello' },
      correlationId: 'corr-vault-1',
      wantsStream: false,
      routePlan: buildRoutePlan('openai'),
    });

    expect(result.ok).toBe(true);
    expect(result.status).toBe(200);
    expect(global.fetch).toHaveBeenCalledTimes(1);

    const fetchOptions = global.fetch.mock.calls[0][1];
    expect(fetchOptions.headers.authorization).toBe('Bearer sk-real-openai');
    expect(fetchOptions.headers['x-api-key']).toBeUndefined();
    expect(fetchOptions.headers['x-goog-api-key']).toBeUndefined();
  });

  test('fails loudly in enforce mode when provider key is missing', async () => {
    global.fetch = jest.fn();

    const client = new UpstreamClient({
      timeoutMs: 2000,
      retryConfig: {
        enabled: false,
        max_attempts: 0,
        allow_post_with_idempotency_key: false,
      },
      circuitBreakers: new FakeCircuitBreakers(),
      telemetry: null,
      authVaultConfig: {
        enabled: true,
        mode: 'enforce',
        dummy_key: 'sk-sentinel-local',
        providers: {
          openai: {
            enabled: true,
            api_key: '',
            env_var: 'SENTINEL_OPENAI_API_KEY',
          },
        },
      },
    });

    const result = await client.forwardRequest({
      req: {
        headers: {
          authorization: 'Bearer sk-live-client-key',
        },
      },
      method: 'POST',
      pathWithQuery: '/v1/chat/completions',
      bodyBuffer: Buffer.from(JSON.stringify({ message: 'hello' })),
      bodyJson: { message: 'hello' },
      correlationId: 'corr-vault-2',
      wantsStream: false,
      routePlan: buildRoutePlan('openai'),
    });

    expect(result.ok).toBe(false);
    expect(result.status).toBe(502);
    expect(result.body.error).toBe('VAULT_PROVIDER_KEY_MISSING');
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('ghost mode strips telemetry headers and rewrites user-agent', async () => {
    global.fetch = jest.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const client = new UpstreamClient({
      timeoutMs: 2000,
      retryConfig: {
        enabled: false,
        max_attempts: 0,
        allow_post_with_idempotency_key: false,
      },
      circuitBreakers: new FakeCircuitBreakers(),
      telemetry: null,
      authVaultConfig: {
        enabled: false,
      },
      ghostModeConfig: {
        enabled: true,
        strip_headers: ['x-stainless-os', 'x-stainless-arch', 'user-agent'],
        override_user_agent: true,
        user_agent_value: 'Sentinel/1.0 (Privacy Proxy)',
      },
    });

    const result = await client.forwardRequest({
      req: {
        headers: {
          authorization: 'Bearer client-key',
          'x-stainless-os': 'darwin',
          'x-stainless-arch': 'arm64',
          'user-agent': 'OpenAI/Node 4.x',
        },
      },
      method: 'POST',
      pathWithQuery: '/v1/chat/completions',
      bodyBuffer: Buffer.from(JSON.stringify({ message: 'hello' })),
      bodyJson: { message: 'hello' },
      correlationId: 'corr-ghost-1',
      wantsStream: false,
      routePlan: buildRoutePlan('openai'),
    });

    expect(result.ok).toBe(true);
    const fetchOptions = global.fetch.mock.calls[0][1];
    expect(fetchOptions.headers['x-stainless-os']).toBeUndefined();
    expect(fetchOptions.headers['x-stainless-arch']).toBeUndefined();
    expect(fetchOptions.headers['user-agent']).toBe('Sentinel/1.0 (Privacy Proxy)');
  });

  test('ollama provider strips upstream API credential headers', async () => {
    global.fetch = jest.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const client = new UpstreamClient({
      timeoutMs: 2000,
      retryConfig: {
        enabled: false,
        max_attempts: 0,
        allow_post_with_idempotency_key: false,
      },
      circuitBreakers: new FakeCircuitBreakers(),
      telemetry: null,
      authVaultConfig: {
        enabled: false,
      },
      ghostModeConfig: {
        enabled: false,
      },
    });

    const result = await client.forwardRequest({
      req: {
        headers: {
          authorization: 'Bearer sk-live-openai',
          'x-api-key': 'sk-ant-live',
          'x-goog-api-key': 'AIza-live',
        },
      },
      method: 'POST',
      pathWithQuery: '/v1/chat/completions',
      bodyBuffer: Buffer.from(JSON.stringify({ message: 'hello' })),
      bodyJson: { message: 'hello' },
      correlationId: 'corr-ollama-1',
      wantsStream: false,
      routePlan: buildRoutePlan('ollama'),
    });

    expect(result.ok).toBe(true);
    const fetchOptions = global.fetch.mock.calls[0][1];
    expect(fetchOptions.headers.authorization).toBeUndefined();
    expect(fetchOptions.headers['x-api-key']).toBeUndefined();
    expect(fetchOptions.headers['x-goog-api-key']).toBeUndefined();
  });

  test('adds swarm envelope headers for eligible custom provider routes', async () => {
    global.fetch = jest.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const swarmProtocol = new SwarmProtocol(
      {
        enabled: true,
        mode: 'monitor',
        node_id: 'node-a',
        key_id: 'node-a',
        sign_outbound: true,
        sign_on_providers: ['custom'],
      },
      {
        now: () => 1700000000000,
        randomUuid: () => 'nonce-xyz',
      }
    );

    const client = new UpstreamClient({
      timeoutMs: 2000,
      retryConfig: {
        enabled: false,
        max_attempts: 0,
        allow_post_with_idempotency_key: false,
      },
      circuitBreakers: new FakeCircuitBreakers(),
      telemetry: null,
      authVaultConfig: { enabled: false },
      ghostModeConfig: { enabled: false },
      swarmProtocol,
    });

    const result = await client.forwardRequest({
      req: {
        headers: {},
      },
      method: 'POST',
      pathWithQuery: '/v1/chat/completions',
      bodyBuffer: Buffer.from(JSON.stringify({ message: 'hello' })),
      bodyJson: { message: 'hello' },
      correlationId: 'corr-swarm-1',
      wantsStream: false,
      routePlan: buildRoutePlan('custom'),
    });

    expect(result.ok).toBe(true);
    const fetchOptions = global.fetch.mock.calls[0][1];
    expect(fetchOptions.headers['x-sentinel-swarm-node-id']).toBe('node-a');
    expect(fetchOptions.headers['x-sentinel-swarm-signature']).toBeTruthy();
  });
});
