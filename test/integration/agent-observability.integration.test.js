const request = require('supertest');

const { SentinelServer } = require('../../src/server');
const {
  createSentinelHome,
  createBaseConfig,
  startUpstream,
  closeServer,
} = require('./helpers/http-harness');

createSentinelHome('sentinel-home-agent-observability-int-');

describe('agent observability integration', () => {
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

  test('upstream request includes traceparent header after ingress processing', async () => {
    const seen = { traceparent: '' };
    upstream = await startUpstream((req, res) => {
      seen.traceparent = String(req.headers.traceparent || '');
      res.status(200).json({ ok: true });
    });

    sentinel = new SentinelServer(
      createBaseConfig({
        mode: 'monitor',
        runtime: {
          agent_observability: {
            enabled: true,
            max_events_per_request: 32,
            max_field_length: 160,
          },
        },
      })
    );

    const server = sentinel.start();

    const response = await request(server)
      .post('/v1/chat/completions')
      .set('content-type', 'application/json')
      .set('x-sentinel-target', 'custom')
      .set('x-sentinel-custom-url', upstream.url)
      .send({ messages: [{ role: 'user', content: 'hello' }] });

    expect(response.status).toBe(200);
    expect(seen.traceparent).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/);
  });

  test('metrics endpoint includes agent observability counters', async () => {
    upstream = await startUpstream((req, res) => {
      res.status(200).json({ ok: true });
    });

    sentinel = new SentinelServer(
      createBaseConfig({
        mode: 'monitor',
        runtime: {
          agent_observability: {
            enabled: true,
            max_events_per_request: 32,
            max_field_length: 160,
          },
        },
      })
    );

    const server = sentinel.start();

    await request(server)
      .post('/v1/chat/completions')
      .set('content-type', 'application/json')
      .set('x-sentinel-target', 'custom')
      .set('x-sentinel-custom-url', upstream.url)
      .send({ messages: [{ role: 'user', content: 'hello' }] });

    const metrics = await request(server).get('/_sentinel/metrics');
    expect(metrics.status).toBe(200);
    expect(metrics.text).toContain('sentinel_agent_observability_event_total{event="agent.start"}');
    expect(metrics.text).toContain('sentinel_agent_observability_event_total{event="agent.complete"}');
    expect(metrics.text).toContain('sentinel_agent_observability_duration_ms_bucket');
  });
});
