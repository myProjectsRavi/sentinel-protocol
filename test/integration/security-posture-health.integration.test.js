const {
  createSentinelHome,
  createBaseConfig,
} = require('./helpers/http-harness');
createSentinelHome('sentinel-home-posture-int-bootstrap-');
const { SentinelServer } = require('../../src/server');

function invokeHealth(server) {
  const layer = server.app._router.stack.find(
    (item) => item.route && item.route.path === '/_sentinel/health' && item.route.methods.get === true
  );
  if (!layer) {
    throw new Error('health_route_not_found');
  }
  const handler = layer.route.stack[0].handle;
  const response = {
    statusCode: 0,
    payload: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.payload = payload;
      return this;
    },
  };
  handler({}, response);
  return response;
}

describe('security posture health integration', () => {
  let sentinel;

  afterEach(async () => {
    if (sentinel) {
      await sentinel.stop();
      sentinel = null;
    }
  });

  test('health endpoint includes posture object when scorer enabled', () => {
    sentinel = new SentinelServer(
      createBaseConfig({
        runtime: {
          posture_scoring: {
            enabled: true,
            include_counters: true,
            warn_threshold: 70,
            critical_threshold: 50,
          },
        },
      })
    );

    const response = invokeHealth(sentinel);
    expect(response.statusCode).toBe(200);
    expect(response.payload.status).toBe('ok');
    expect(response.payload.posture).toBeDefined();
    expect(typeof response.payload.posture.overall).toBe('number');
  });

  test('health endpoint stays 200 when scorer throws internal error', () => {
    sentinel = new SentinelServer(
      createBaseConfig({
        runtime: {
          posture_scoring: {
            enabled: true,
            include_counters: true,
            warn_threshold: 70,
            critical_threshold: 50,
          },
        },
      }),
      {
        postureScorer: () => {
          throw new Error('boom');
        },
      }
    );

    const response = invokeHealth(sentinel);
    expect(response.statusCode).toBe(200);
    expect(response.payload.status).toBe('ok');
    expect(response.payload.posture).toEqual({
      error: 'posture_unavailable',
    });
  });
});
