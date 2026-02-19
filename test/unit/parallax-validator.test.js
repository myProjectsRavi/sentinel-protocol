jest.mock('../../src/upstream/router', () => ({
  resolveUpstreamPlan: jest.fn(),
}));

const { resolveUpstreamPlan } = require('../../src/upstream/router');
const { ParallaxValidator } = require('../../src/engines/parallax-validator');

describe('ParallaxValidator', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('vetoes high-risk tool call when secondary model denies with high risk', async () => {
    resolveUpstreamPlan.mockResolvedValue({
      primary: {
        provider: 'ollama',
      },
      requestedTarget: 'ollama',
      selectedGroup: null,
      routeSource: 'target',
      desiredContract: 'openai_chat_v1',
      candidates: [],
      failover: {
        enabled: false,
        maxFailoverHops: 0,
        allowPostWithIdempotencyKey: false,
        onStatus: [],
        onErrorTypes: [],
      },
    });

    const upstreamClient = {
      forwardRequest: jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        body: Buffer.from(
          JSON.stringify({
            choices: [
              {
                message: {
                  content: '{"allow":false,"risk":0.95,"reason":"malicious"}',
                },
              },
            ],
          }),
          'utf8'
        ),
        responseHeaders: {
          'content-type': 'application/json',
        },
      }),
    };

    const validator = new ParallaxValidator(
      {
        enabled: true,
        mode: 'monitor',
        high_risk_tools: ['execute_shell'],
        secondary_target: 'ollama',
        risk_threshold: 0.7,
      },
      {
        upstreamClient,
        config: {},
      }
    );

    const responseBody = Buffer.from(
      JSON.stringify({
        choices: [
          {
            message: {
              tool_calls: [
                {
                  id: 'call_1',
                  type: 'function',
                  function: {
                    name: 'execute_shell',
                    arguments: '{"cmd":"rm -rf /"}',
                  },
                },
              ],
            },
          },
        ],
      }),
      'utf8'
    );

    const result = await validator.evaluate({
      req: {
        headers: {},
      },
      correlationId: 'corr-1',
      requestBodyJson: {
        model: 'gpt-4o-mini',
        messages: [{ role: 'user', content: 'delete everything' }],
      },
      responseBody,
      responseContentType: 'application/json',
    });

    expect(result.evaluated).toBe(true);
    expect(result.veto).toBe(true);
    expect(result.risk).toBe(0.95);
    expect(result.highRiskTools).toEqual(['execute_shell']);
    expect(upstreamClient.forwardRequest).toHaveBeenCalledTimes(1);
  });

  test('skips evaluation when no high-risk tools are present', async () => {
    const upstreamClient = {
      forwardRequest: jest.fn(),
    };
    const validator = new ParallaxValidator(
      {
        enabled: true,
        high_risk_tools: ['execute_shell'],
      },
      {
        upstreamClient,
        config: {},
      }
    );

    const responseBody = Buffer.from(
      JSON.stringify({
        choices: [
          {
            message: {
              tool_calls: [
                {
                  id: 'call_2',
                  type: 'function',
                  function: { name: 'search_docs', arguments: '{}' },
                },
              ],
            },
          },
        ],
      }),
      'utf8'
    );

    const result = await validator.evaluate({
      req: { headers: {} },
      correlationId: 'corr-2',
      requestBodyJson: { messages: [] },
      responseBody,
      responseContentType: 'application/json',
    });

    expect(result.evaluated).toBe(false);
    expect(result.reason).toBe('no_high_risk_tools');
    expect(upstreamClient.forwardRequest).not.toHaveBeenCalled();
  });
});
