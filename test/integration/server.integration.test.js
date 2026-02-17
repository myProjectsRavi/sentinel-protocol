const fs = require('fs');
const os = require('os');
const path = require('path');
const express = require('express');
const request = require('supertest');

process.env.SENTINEL_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-home-int-'));

const { SentinelServer } = require('../../src/server');
const { RuntimeOverrideManager } = require('../../src/runtime/override');
const { OVERRIDE_FILE_PATH } = require('../../src/utils/paths');

function createBaseConfig(overrides = {}) {
  return {
    version: 1,
    mode: 'enforce',
    proxy: {
      host: '127.0.0.1',
      port: 0,
      timeout_ms: 30000,
    },
    runtime: {
      fail_open: false,
      scanner_error_action: 'allow',
      upstream: {
        retry: {
          enabled: true,
          max_attempts: 1,
          allow_post_with_idempotency_key: false,
        },
        circuit_breaker: {
          enabled: true,
          window_size: 20,
          min_failures_to_evaluate: 8,
          failure_rate_threshold: 0.5,
          consecutive_timeout_threshold: 5,
          open_seconds: 20,
          half_open_success_threshold: 3,
        },
      },
    },
    pii: {
      enabled: true,
      max_scan_bytes: 262144,
      severity_actions: {
        critical: 'block',
        high: 'block',
        medium: 'redact',
        low: 'log',
      },
    },
    rules: [],
    whitelist: { domains: [] },
    logging: { level: 'info' },
    ...overrides,
  };
}

async function startUpstream(handler) {
  const app = express();
  app.use(express.raw({ type: '*/*' }));
  app.all('*', handler);

  const server = await new Promise((resolve) => {
    const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
  });

  const port = server.address().port;
  return {
    server,
    url: `http://127.0.0.1:${port}`,
  };
}

async function closeServer(server) {
  if (!server) {
    return;
  }
  await new Promise((resolve) => server.close(resolve));
}

describe('sentinel integration', () => {
  let sentinel;
  let upstream;

  afterEach(async () => {
    if (sentinel) {
      await sentinel.stop();
      sentinel = null;
    }
    if (upstream) {
      await closeServer(upstream.server);
      upstream = null;
    }
  });

  test('blocks critical PII in enforce mode', async () => {
    upstream = await startUpstream((req, res) => res.status(200).json({ ok: true }));
    sentinel = new SentinelServer(createBaseConfig());
    const server = sentinel.start();

    const payload = {
      text: 'openai key sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefgh',
    };

    const response = await request(server)
      .post('/v1/chat/completions')
      .set('content-type', 'application/json')
      .set('x-sentinel-target', 'custom')
      .set('x-sentinel-custom-url', upstream.url)
      .send(payload);

    expect(response.status).toBe(403);
    expect(response.body.error).toBe('PII_DETECTED');
    expect(response.headers['x-sentinel-error-source']).toBe('sentinel');
  });

  test('monitor mode does not block', async () => {
    upstream = await startUpstream((req, res) => res.status(200).json({ ok: true }));
    sentinel = new SentinelServer(createBaseConfig({ mode: 'monitor' }));
    const server = sentinel.start();

    const response = await request(server)
      .post('/v1/chat/completions')
      .set('content-type', 'application/json')
      .set('x-sentinel-target', 'custom')
      .set('x-sentinel-custom-url', upstream.url)
      .send({ text: 'openai key sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefgh' });

    expect(response.status).toBe(200);
    expect(response.headers['x-sentinel-warning']).toBeDefined();
  });

  test('returns timeout diagnostics when upstream hangs', async () => {
    upstream = await startUpstream((req, res) => {
      setTimeout(() => {
        res.status(200).json({ delayed: true });
      }, 200);
    });

    sentinel = new SentinelServer(
      createBaseConfig({
        proxy: {
          host: '127.0.0.1',
          port: 0,
          timeout_ms: 50,
        },
      })
    );

    const server = sentinel.start();

    const response = await request(server)
      .get('/v1/models')
      .set('x-sentinel-target', 'custom')
      .set('x-sentinel-custom-url', upstream.url);

    expect(response.status).toBe(504);
    expect(response.headers['x-sentinel-error-source']).toBe('upstream');
    expect(response.headers['x-sentinel-upstream-error']).toBe('true');
  });

  test('retries once on upstream 429 for idempotent method', async () => {
    let hits = 0;
    upstream = await startUpstream((req, res) => {
      hits += 1;
      res.status(429).json({ error: 'rate limited' });
    });

    sentinel = new SentinelServer(createBaseConfig());
    const server = sentinel.start();

    const response = await request(server)
      .get('/v1/models')
      .set('x-sentinel-target', 'custom')
      .set('x-sentinel-custom-url', upstream.url);

    expect(response.status).toBe(429);
    expect(response.headers['x-sentinel-retry-count']).toBe('1');
    expect(hits).toBe(2);
  });

  test('opens provider circuit and fast-fails subsequent request', async () => {
    upstream = await startUpstream((req, res) => {
      res.status(503).json({ error: 'unavailable' });
    });

    sentinel = new SentinelServer(
      createBaseConfig({
        runtime: {
          fail_open: false,
          scanner_error_action: 'allow',
          upstream: {
            retry: { enabled: true, max_attempts: 1, allow_post_with_idempotency_key: false },
            circuit_breaker: {
              enabled: true,
              window_size: 4,
              min_failures_to_evaluate: 2,
              failure_rate_threshold: 0.5,
              consecutive_timeout_threshold: 5,
              open_seconds: 20,
              half_open_success_threshold: 2,
            },
          },
        },
      })
    );

    const server = sentinel.start();

    await request(server).get('/v1/models').set('x-sentinel-target', 'custom').set('x-sentinel-custom-url', upstream.url);
    await request(server).get('/v1/models').set('x-sentinel-target', 'custom').set('x-sentinel-custom-url', upstream.url);

    const response = await request(server)
      .get('/v1/models')
      .set('x-sentinel-target', 'custom')
      .set('x-sentinel-custom-url', upstream.url);

    expect(response.status).toBe(503);
    expect(response.body.error).toBe('UPSTREAM_CIRCUIT_OPEN');
    expect(response.headers['x-sentinel-circuit-state']).toBe('open');
  });

  test('sentinel-local policy block does not affect breaker counters', async () => {
    upstream = await startUpstream((req, res) => {
      res.status(200).json({ ok: true });
    });

    sentinel = new SentinelServer(
      createBaseConfig({
        rules: [
          {
            name: 'block-local-path',
            match: { path_contains: '/blocked', method: 'POST' },
            action: 'block',
            message: 'blocked by policy',
          },
        ],
      })
    );

    const server = sentinel.start();

    const response = await request(server)
      .post('/blocked')
      .set('content-type', 'application/json')
      .set('x-sentinel-target', 'custom')
      .set('x-sentinel-custom-url', upstream.url)
      .send({ hello: 'world' });

    expect(response.status).toBe(403);

    const snapshot = sentinel.circuitBreakers.snapshot();
    expect(snapshot.custom.total_forwarded).toBe(0);
    expect(snapshot.custom.total_failures).toBe(0);
  });

  test('dry-run bypasses enforce blocking rules', async () => {
    upstream = await startUpstream((req, res) => {
      res.status(200).json({ ok: true });
    });

    sentinel = new SentinelServer(
      createBaseConfig({
        rules: [
          {
            name: 'block-local-path',
            match: { path_contains: '/blocked', method: 'POST' },
            action: 'block',
            message: 'blocked by policy',
          },
        ],
      }),
      { dryRun: true }
    );

    const server = sentinel.start();

    const response = await request(server)
      .post('/blocked')
      .set('content-type', 'application/json')
      .set('x-sentinel-target', 'custom')
      .set('x-sentinel-custom-url', upstream.url)
      .send({ hello: 'world' });

    expect(response.status).toBe(200);
  });

  test('emergency-open override degrades enforce to monitor', async () => {
    upstream = await startUpstream((req, res) => {
      res.status(200).json({ ok: true });
    });

    sentinel = new SentinelServer(
      createBaseConfig({
        rules: [
          {
            name: 'block-local-path',
            match: { path_contains: '/blocked', method: 'POST' },
            action: 'block',
            message: 'blocked by policy',
          },
        ],
      })
    );

    const server = sentinel.start();

    const blocked = await request(server)
      .post('/blocked')
      .set('content-type', 'application/json')
      .set('x-sentinel-target', 'custom')
      .set('x-sentinel-custom-url', upstream.url)
      .send({ hello: 'world' });

    expect(blocked.status).toBe(403);

    RuntimeOverrideManager.writeOverride(OVERRIDE_FILE_PATH, true);
    await new Promise((resolve) => setTimeout(resolve, 2300));

    const allowed = await request(server)
      .post('/blocked')
      .set('content-type', 'application/json')
      .set('x-sentinel-target', 'custom')
      .set('x-sentinel-custom-url', upstream.url)
      .send({ hello: 'world' });

    expect(allowed.status).toBe(200);
  });
});
