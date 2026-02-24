const request = require('supertest');

const { SentinelServer } = require('../../src/server');
const {
  createSentinelHome,
  createBaseConfig,
  startUpstream,
  closeServer,
} = require('./helpers/http-harness');

createSentinelHome('sentinel-home-mcp-cert-pinning-int-');

describe('mcp certificate pinning integration', () => {
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

  test('mcp-like request is blocked for certificate pin mismatch in enforce mode', async () => {
    upstream = await startUpstream((req, res) => res.status(200).json({ ok: true }));
    sentinel = new SentinelServer(
      createBaseConfig({
        mode: 'enforce',
        runtime: {
          mcp_certificate_pinning: {
            enabled: true,
            mode: 'block',
            block_on_mismatch: true,
            pins: {
              'mcp-prod': ['b'.repeat(64)],
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
      .set('x-sentinel-mcp-server-id', 'mcp-prod')
      .set('x-sentinel-mcp-cert-sha256', 'a'.repeat(64))
      .send({
        tools: [
          {
            type: 'function',
            function: {
              name: 'search_docs',
              description: 'Search docs',
              parameters: {
                type: 'object',
                properties: {
                  query: { type: 'string' },
                },
                required: ['query'],
              },
            },
          },
        ],
      });

    expect(response.status).toBe(403);
    expect(response.body.error).toBe('MCP_CERTIFICATE_PINNING_DETECTED');
    expect(response.body.reason).toBe('mcp_certificate_pin_mismatch');
    expect(response.headers['x-sentinel-blocked-by']).toBe('mcp_certificate_pinning');
  });

  test('mcp-like request is forwarded in monitor mode with warning headers', async () => {
    upstream = await startUpstream((req, res) => res.status(200).json({ ok: true }));
    sentinel = new SentinelServer(
      createBaseConfig({
        mode: 'enforce',
        runtime: {
          mcp_certificate_pinning: {
            enabled: true,
            mode: 'monitor',
            block_on_mismatch: true,
            pins: {
              'mcp-monitor': ['b'.repeat(64)],
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
      .set('x-sentinel-mcp-server-id', 'mcp-monitor')
      .set('x-sentinel-mcp-cert-sha256', 'a'.repeat(64))
      .send({
        tools: [
          {
            type: 'function',
            function: {
              name: 'search_docs',
              description: 'Search docs',
              parameters: {
                type: 'object',
                properties: {
                  query: { type: 'string' },
                },
                required: ['query'],
              },
            },
          },
        ],
      });

    expect(response.status).toBe(200);
    expect(response.headers['x-sentinel-warning']).toContain('mcp_certificate_pinning:mcp_certificate_pin_mismatch');
    expect(response.headers['x-sentinel-mcp-cert-pinning']).toBe('mcp_certificate_pin_mismatch');
  });
});
