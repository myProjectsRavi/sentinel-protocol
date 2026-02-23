const { validateConfigShape } = require('./config/schema');
const { SentinelServer } = require('./server');
const { createMiddleware } = require('./embed/middleware');
const { secureFetch: runSecureFetch } = require('./embed/secure-fetch');
const { createFrameworkCallbacks } = require('./embed/framework-callbacks');

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
  const frameworkCallbacks = createFrameworkCallbacks(server, options.framework || {});

  return {
    server,
    app: server.app,
    use(plugin) {
      server.use(plugin);
      return this;
    },
    middleware() {
      return createMiddleware(server);
    },
    async secureFetch(url, fetchOptions = {}) {
      return runSecureFetch(server, url, fetchOptions);
    },
    frameworkCallbacks() {
      return frameworkCallbacks;
    },
    langchainCallback() {
      return frameworkCallbacks.langchainCallback();
    },
    llamaIndexCallback() {
      return frameworkCallbacks.llamaIndexCallback();
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
