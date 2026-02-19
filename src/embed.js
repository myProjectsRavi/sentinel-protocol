const { validateConfigShape } = require('./config/schema');
const { SentinelServer } = require('./server');

function toSafeString(value) {
  if (typeof value === 'string') {
    return value;
  }
  if (value === undefined || value === null) {
    return '';
  }
  return JSON.stringify(value);
}

function createSentinel(config, options = {}) {
  const normalizedConfig = validateConfigShape(config || {});
  const server = new SentinelServer(normalizedConfig, options);

  return {
    server,
    app: server.app,
    use(plugin) {
      server.use(plugin);
      return this;
    },
    middleware() {
      return server.app;
    },
    start() {
      server.start();
      return server;
    },
    stop() {
      return server.stop();
    },
    async scan(payload, requestHeaders = {}) {
      const text = toSafeString(payload);
      const pii = await server.piiProviderEngine.scan(text, requestHeaders);
      return {
        pii: pii.result,
        provider: pii.meta,
      };
    },
  };
}

module.exports = {
  createSentinel,
};
