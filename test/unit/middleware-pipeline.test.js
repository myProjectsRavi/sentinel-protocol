const { MiddlewarePipeline } = require('../../src/core/middleware-pipeline');
const { RequestContext } = require('../../src/core/request-context');
const { PluginRegistry } = require('../../src/core/plugin-registry');

describe('middleware pipeline + plugin registry', () => {
  test('executes middleware by priority', async () => {
    const events = [];
    const pipeline = new MiddlewarePipeline({
      logger: { warn: () => {} },
    });
    pipeline.use('request:received', 'late', async () => {
      events.push('late');
    }, { priority: 20 });
    pipeline.use('request:received', 'early', async () => {
      events.push('early');
    }, { priority: 10 });

    await pipeline.execute('request:received', new RequestContext());
    expect(events).toEqual(['early', 'late']);
  });

  test('non-critical middleware errors do not throw', async () => {
    const pipeline = new MiddlewarePipeline({
      logger: { warn: () => {} },
    });
    pipeline.use('request:received', 'broken', async () => {
      throw new Error('boom');
    }, { critical: false });

    await expect(pipeline.execute('request:received', new RequestContext())).resolves.toEqual({
      stage: 'request:received',
      ran: 0,
    });
  });

  test('plugin hooks are registered into pipeline', async () => {
    const pipeline = new MiddlewarePipeline({
      logger: { warn: () => {} },
    });
    const registry = new PluginRegistry({
      logger: { info: () => {}, warn: () => {} },
      pipeline,
    });
    registry.register({
      name: 'sample-plugin',
      hooks: {
        'request:prepared': async (ctx) => {
          ctx.set('plugin_ok', true);
        },
      },
    });
    const ctx = new RequestContext();
    await pipeline.execute('request:prepared', ctx);
    expect(ctx.get('plugin_ok')).toBe(true);
  });
});
