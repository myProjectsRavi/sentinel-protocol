const request = require('supertest');

const { SentinelServer } = require('../../src/server');
const {
  createSentinelHome,
  createBaseConfig,
  startUpstream,
  closeServer,
} = require('./helpers/http-harness');

createSentinelHome('sentinel-home-output-schema-int-');

describe('output schema validator integration', () => {
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

  test('configured schema violation yields 502 with x-sentinel-blocked-by=output_schema_validator', async () => {
    upstream = await startUpstream((req, res) => {
      res.status(200).json({
        id: 'resp-1',
        leaked: 'unexpected',
      });
    });

    sentinel = new SentinelServer(
      createBaseConfig({
        mode: 'enforce',
        runtime: {
          output_schema_validator: {
            enabled: true,
            mode: 'block',
            default_schema: 'chat_response',
            schemas: {
              chat_response: {
                type: 'object',
                required: ['id', 'choices'],
                additionalProperties: false,
                properties: {
                  id: { type: 'string' },
                  choices: { type: 'array' },
                },
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

    expect(response.status).toBe(502);
    expect(response.headers['x-sentinel-blocked-by']).toBe('output_schema_validator');
    expect(response.body.error).toBe('OUTPUT_SCHEMA_VALIDATION_FAILED');
  });
});
