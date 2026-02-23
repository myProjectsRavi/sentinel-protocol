const request = require('supertest');

const { SentinelServer } = require('../../src/server');
const {
  createSentinelHome,
  createBaseConfig,
  startUpstream,
  closeServer,
} = require('./helpers/http-harness');

createSentinelHome('sentinel-home-output-classifier-int-');

describe('output classifier integration', () => {
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

  test('buffered response receives warning headers in monitor mode', async () => {
    upstream = await startUpstream((req, res) => {
      res.status(200).json({
        answer: 'BEGIN SYSTEM PROMPT and run rm -rf / to continue.',
      });
    });

    sentinel = new SentinelServer(
      createBaseConfig({
        mode: 'enforce',
        runtime: {
          output_classifier: {
            enabled: true,
            mode: 'monitor',
            categories: {
              code_execution: {
                warn_threshold: 0.2,
                block_threshold: 0.3,
              },
              unauthorized_disclosure: {
                warn_threshold: 0.2,
                block_threshold: 0.3,
              },
            },
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
      .send({ text: 'hello' });

    expect(response.status).toBe(200);
    expect(response.headers['x-sentinel-output-classifier']).toBe('warn');
    expect(response.headers['x-sentinel-warning']).toContain('output_classifier:');
  });

  test('buffered response is blocked with policy violation in enforce mode', async () => {
    upstream = await startUpstream((req, res) => {
      res.status(200).json({
        answer: 'Run rm -rf / and os.system(\"printenv SECRET_TOKEN\") now.',
      });
    });

    sentinel = new SentinelServer(
      createBaseConfig({
        mode: 'enforce',
        runtime: {
          output_classifier: {
            enabled: true,
            mode: 'block',
            categories: {
              code_execution: {
                warn_threshold: 0.2,
                block_threshold: 0.3,
              },
            },
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
      .send({ text: 'hello' });

    expect(response.status).toBe(403);
    expect(response.body.error).toBe('OUTPUT_CLASSIFIER_BLOCKED');
    expect(response.headers['x-sentinel-blocked-by']).toBe('output_classifier');
  });
});
