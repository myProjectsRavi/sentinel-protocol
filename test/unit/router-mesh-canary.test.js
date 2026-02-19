const { resolveUpstreamPlan } = require('../../src/upstream/router');

describe('upstream route plan', () => {
  test('falls back to direct target when mesh is disabled', async () => {
    const plan = await resolveUpstreamPlan({ headers: {} }, {
      runtime: {
        upstream: {
          custom_targets: {
            enabled: false,
            allowlist: [],
            block_private_networks: true,
          },
        },
      },
    });

    expect(plan.requestedTarget).toBe('openai');
    expect(plan.candidates).toHaveLength(1);
    expect(plan.primary.provider).toBe('openai');
    expect(plan.failover.enabled).toBe(false);
  });

  test('selects canary split group with deterministic routing', async () => {
    const plan = await resolveUpstreamPlan(
      {
        headers: {
          'x-sentinel-target': 'openai',
          'x-sentinel-canary-key': 'agent-42',
        },
      },
      {
        runtime: {
          upstream: {
            custom_targets: {
              enabled: false,
              allowlist: [],
              block_private_networks: true,
            },
            resilience_mesh: {
              enabled: true,
              max_failover_hops: 1,
              groups: {
                stable: {
                  enabled: true,
                  contract: 'openai_chat_v1',
                  targets: ['openai'],
                },
                canary: {
                  enabled: true,
                  contract: 'openai_chat_v1',
                  targets: ['anthropic'],
                },
              },
            },
            canary: {
              enabled: true,
              key_header: 'x-sentinel-canary-key',
              splits: [
                {
                  name: 'openai-rollout',
                  match_target: 'openai',
                  group_a: 'stable',
                  group_b: 'canary',
                  weight_a: 0,
                  weight_b: 100,
                  sticky: true,
                },
              ],
            },
          },
        },
      }
    );

    expect(plan.routeSource).toBe('canary');
    expect(plan.selectedGroup).toBe('canary');
    expect(plan.canary?.name).toBe('openai-rollout');
    expect(plan.candidates).toHaveLength(1);
    expect(plan.primary.provider).toBe('anthropic');
  });

  test('respects explicit target group header over canary', async () => {
    const plan = await resolveUpstreamPlan(
      {
        headers: {
          'x-sentinel-target': 'openai',
          'x-sentinel-target-group': 'stable',
          'x-sentinel-canary-key': 'agent-42',
        },
      },
      {
        runtime: {
          upstream: {
            custom_targets: {
              enabled: false,
              allowlist: [],
              block_private_networks: true,
            },
            resilience_mesh: {
              enabled: true,
              groups: {
                stable: {
                  enabled: true,
                  targets: ['openai'],
                },
                canary: {
                  enabled: true,
                  targets: ['anthropic'],
                },
              },
            },
            canary: {
              enabled: true,
              splits: [
                {
                  name: 'openai-rollout',
                  match_target: 'openai',
                  group_a: 'stable',
                  group_b: 'canary',
                  weight_a: 0,
                  weight_b: 100,
                  sticky: true,
                },
              ],
            },
          },
        },
      }
    );

    expect(plan.routeSource).toBe('group_header');
    expect(plan.selectedGroup).toBe('stable');
    expect(plan.primary.provider).toBe('openai');
  });
});
