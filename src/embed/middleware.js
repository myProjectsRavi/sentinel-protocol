function createMiddleware(server) {
  return function sentinelMiddleware(req, res, next) {
    const app = server?.app;
    if (!app || typeof app !== 'function') {
      if (typeof next === 'function') {
        next(new Error('sentinel_middleware_unavailable'));
      }
      return;
    }
    if (typeof next === 'function') {
      app(req, res, next);
      return;
    }
    app(req, res);
  };
}

module.exports = {
  createMiddleware,
};
