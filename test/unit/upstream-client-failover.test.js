const { UpstreamClient } = require('../../src/upstream/client');
const { once } = require('events');

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

describe('UpstreamClient failover routing', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
    jest.restoreAllMocks();
  });

  test('fails over to second candidate on retryable upstream status', async () => {
    global.fetch = jest
      .fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: 'provider down' }), {
        status: 503,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const client = new UpstreamClient({
      timeoutMs: 2000,
      retryConfig: {
        enabled: false,
        max_attempts: 0,
        allow_post_with_idempotency_key: false,
      },
      circuitBreakers: new FakeCircuitBreakers(),
      telemetry: null,
    });

    const result = await client.forwardRequest({
      req: { headers: {} },
      method: 'GET',
      pathWithQuery: '/v1/models',
      bodyBuffer: Buffer.alloc(0),
      bodyJson: null,
      correlationId: 'corr-1',
      wantsStream: false,
      routePlan: {
        requestedTarget: 'openai',
        selectedGroup: 'stable',
        routeSource: 'default_group',
        desiredContract: 'passthrough',
        candidates: [
          {
            targetName: 'provider-a',
            provider: 'openai',
            baseUrl: 'https://provider-a.local',
            upstreamHostname: 'provider-a.local',
            upstreamHostHeader: 'provider-a.local',
            resolvedIp: null,
            resolvedFamily: null,
            staticHeaders: {},
            contract: 'passthrough',
            breakerKey: 'openai:provider-a',
          },
          {
            targetName: 'provider-b',
            provider: 'openai',
            baseUrl: 'https://provider-b.local',
            upstreamHostname: 'provider-b.local',
            upstreamHostHeader: 'provider-b.local',
            resolvedIp: null,
            resolvedFamily: null,
            staticHeaders: {},
            contract: 'passthrough',
            breakerKey: 'openai:provider-b',
          },
        ],
        failover: {
          enabled: true,
          maxFailoverHops: 1,
          allowPostWithIdempotencyKey: false,
          onStatus: [503],
          onErrorTypes: ['timeout', 'transport', 'circuit_open'],
        },
      },
    });

    expect(result.ok).toBe(true);
    expect(result.status).toBe(200);
    expect(result.route.failoverUsed).toBe(true);
    expect(result.route.selectedTarget).toBe('provider-b');
    expect(global.fetch).toHaveBeenCalledTimes(2);
  });

  test('does not failover POST without idempotency key permission', async () => {
    global.fetch = jest.fn().mockResolvedValue(
      new Response(JSON.stringify({ error: 'provider down' }), {
        status: 503,
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
    });

    const result = await client.forwardRequest({
      req: { headers: {} },
      method: 'POST',
      pathWithQuery: '/v1/chat/completions',
      bodyBuffer: Buffer.from(JSON.stringify({ message: 'hi' })),
      bodyJson: { message: 'hi' },
      correlationId: 'corr-2',
      wantsStream: false,
      routePlan: {
        requestedTarget: 'openai',
        selectedGroup: 'stable',
        routeSource: 'default_group',
        desiredContract: 'passthrough',
        candidates: [
          {
            targetName: 'provider-a',
            provider: 'openai',
            baseUrl: 'https://provider-a.local',
            upstreamHostname: 'provider-a.local',
            upstreamHostHeader: 'provider-a.local',
            resolvedIp: null,
            resolvedFamily: null,
            staticHeaders: {},
            contract: 'passthrough',
            breakerKey: 'openai:provider-a',
          },
          {
            targetName: 'provider-b',
            provider: 'openai',
            baseUrl: 'https://provider-b.local',
            upstreamHostname: 'provider-b.local',
            upstreamHostHeader: 'provider-b.local',
            resolvedIp: null,
            resolvedFamily: null,
            staticHeaders: {},
            contract: 'passthrough',
            breakerKey: 'openai:provider-b',
          },
        ],
        failover: {
          enabled: true,
          maxFailoverHops: 1,
          allowPostWithIdempotencyKey: false,
          onStatus: [503],
          onErrorTypes: ['timeout', 'transport', 'circuit_open'],
        },
      },
    });

    expect(result.status).toBe(503);
    expect(result.route.failoverUsed).toBe(false);
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  test('does not failover when upstream SSE stream fails after first bytes', async () => {
    const encoder = new TextEncoder();
    const webStream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"choices":[{"delta":{"content":"hel"}}]}\n\n'));
        controller.error(new Error('upstream stream dropped'));
      },
    });

    global.fetch = jest.fn().mockResolvedValue(
      new Response(webStream, {
        status: 200,
        headers: { 'content-type': 'text/event-stream' },
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
    });

    const result = await client.forwardRequest({
      req: { headers: {} },
      method: 'GET',
      pathWithQuery: '/v1/chat/completions?stream=true',
      bodyBuffer: Buffer.alloc(0),
      bodyJson: null,
      correlationId: 'corr-stream-1',
      wantsStream: true,
      routePlan: {
        requestedTarget: 'openai',
        selectedGroup: 'stable',
        routeSource: 'default_group',
        desiredContract: 'passthrough',
        candidates: [
          {
            targetName: 'provider-a',
            provider: 'openai',
            baseUrl: 'https://provider-a.local',
            upstreamHostname: 'provider-a.local',
            upstreamHostHeader: 'provider-a.local',
            resolvedIp: null,
            resolvedFamily: null,
            staticHeaders: {},
            contract: 'passthrough',
            breakerKey: 'openai:provider-a',
          },
          {
            targetName: 'provider-b',
            provider: 'openai',
            baseUrl: 'https://provider-b.local',
            upstreamHostname: 'provider-b.local',
            upstreamHostHeader: 'provider-b.local',
            resolvedIp: null,
            resolvedFamily: null,
            staticHeaders: {},
            contract: 'passthrough',
            breakerKey: 'openai:provider-b',
          },
        ],
        failover: {
          enabled: true,
          maxFailoverHops: 1,
          allowPostWithIdempotencyKey: false,
          onStatus: [503],
          onErrorTypes: ['timeout', 'transport', 'circuit_open'],
        },
      },
    });

    expect(result.ok).toBe(true);
    expect(result.isStream).toBe(true);
    expect(result.route.failoverUsed).toBe(false);
    expect(result.route.selectedTarget).toBe('provider-a');
    expect(global.fetch).toHaveBeenCalledTimes(1);

    const [streamError] = await once(result.bodyStream, 'error');
    expect(streamError).toBeInstanceOf(Error);
  });
});
