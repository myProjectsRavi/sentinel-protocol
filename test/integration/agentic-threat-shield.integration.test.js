const request = require('supertest');

const { SentinelServer } = require('../../src/server');
const {
  createSentinelHome,
  createBaseConfig,
  startUpstream,
  closeServer,
} = require('./helpers/http-harness');

createSentinelHome('sentinel-home-agentic-int-');

describe('agentic threat shield integration', () => {
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

  test('returns 403 with x-sentinel-blocked-by=agentic_threat_shield when enforce violation occurs', async () => {
    upstream = await startUpstream((req, res) => res.status(200).json({ ok: true }));
    sentinel = new SentinelServer(
      createBaseConfig({
        mode: 'enforce',
        runtime: {
          agentic_threat_shield: {
            enabled: true,
            mode: 'block',
            max_tool_call_depth: 1,
            max_agent_delegations: 10,
            detect_cycles: true,
            verify_identity_tokens: false,
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
      .set('x-sentinel-session-id', 'agentic-session-enforce')
      .set('x-sentinel-agent-id', 'agentic-agent-enforce')
      .send({
        tool_calls: [
          {
            function: {
              name: 'search_docs',
              arguments: '{}',
            },
            nested: {
              tool_calls: [
                {
                  function: {
                    name: 'search_docs',
                    arguments: '{}',
                  },
                },
              ],
            },
          },
        ],
      });

    expect(response.status).toBe(403);
    expect(response.body.error).toBe('AGENTIC_THREAT_DETECTED');
    expect(response.headers['x-sentinel-blocked-by']).toBe('agentic_threat_shield');
  });

  test('forwards request with x-sentinel-warning in monitor mode', async () => {
    upstream = await startUpstream((req, res) => res.status(200).json({ ok: true }));
    sentinel = new SentinelServer(
      createBaseConfig({
        mode: 'enforce',
        runtime: {
          agentic_threat_shield: {
            enabled: true,
            mode: 'monitor',
            max_tool_call_depth: 1,
            max_agent_delegations: 10,
            detect_cycles: true,
            verify_identity_tokens: false,
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
      .set('x-sentinel-session-id', 'agentic-session-monitor')
      .set('x-sentinel-agent-id', 'agentic-agent-monitor')
      .send({
        tool_calls: [
          {
            function: {
              name: 'search_docs',
              arguments: '{}',
            },
            nested: {
              tool_calls: [
                {
                  function: {
                    name: 'search_docs',
                    arguments: '{}',
                  },
                },
              ],
            },
          },
        ],
      });

    expect(response.status).toBe(200);
    expect(response.headers['x-sentinel-warning']).toContain('agentic:tool_call_depth_exceeded');
  });
});
