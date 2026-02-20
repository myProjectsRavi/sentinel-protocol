const {
  createDashboardAccessGuard,
  isLocalAddress,
  estimateSavings,
} = require('../../src/monitor/dashboard-server');

function createMockResponse() {
  const headers = {};
  let finishHandler = null;
  return {
    headers,
    statusCode: 200,
    body: null,
    setHeader(name, value) {
      headers[String(name).toLowerCase()] = String(value);
    },
    once(event, handler) {
      if (event === 'finish') {
        finishHandler = handler;
      }
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      if (typeof finishHandler === 'function') {
        finishHandler();
      }
      return this;
    },
    emitFinish() {
      if (typeof finishHandler === 'function') {
        finishHandler();
      }
    },
  };
}

describe('dashboard server', () => {
  test('local address classifier works for loopback variants', () => {
    expect(isLocalAddress('127.0.0.1')).toBe(true);
    expect(isLocalAddress('::1')).toBe(true);
    expect(isLocalAddress('::ffff:127.0.0.1')).toBe(true);
    expect(isLocalAddress('10.0.0.2')).toBe(false);
  });

  test('savings estimator remains deterministic', () => {
    const value = estimateSavings({
      semantic_cache_hits: 10,
      blocked_total: 20,
    });
    expect(value).toBe(0.029);
  });

  test('emits dashboard access event for successful API request', async () => {
    const accessLogger = jest.fn();
    const guard = createDashboardAccessGuard({
      allowRemote: false,
      authToken: '',
      accessLogger,
    });
    const req = {
      method: 'GET',
      path: '/api/status',
      headers: {},
      socket: { remoteAddress: '127.0.0.1' },
    };
    const res = createMockResponse();
    let nextCalled = false;

    guard(req, res, () => {
      nextCalled = true;
    });
    expect(nextCalled).toBe(true);
    res.emitFinish();
    expect(accessLogger).toHaveBeenCalledWith(
      expect.objectContaining({
        method: 'GET',
        path: '/api/status',
        authRequired: false,
        authenticated: true,
        allowed: true,
        statusCode: 200,
      })
    );
  });

  test('emits dashboard access denied event when auth token is missing', async () => {
    const accessLogger = jest.fn();
    const guard = createDashboardAccessGuard({
      allowRemote: false,
      authToken: 'secret-token',
      accessLogger,
    });
    const req = {
      method: 'GET',
      path: '/api/status',
      headers: {},
      socket: { remoteAddress: '127.0.0.1' },
    };
    const res = createMockResponse();
    let nextCalled = false;

    guard(req, res, () => {
      nextCalled = true;
    });
    expect(nextCalled).toBe(false);
    expect(res.statusCode).toBe(401);
    expect(res.body).toEqual({ error: 'DASHBOARD_AUTH_REQUIRED' });
    expect(accessLogger).toHaveBeenCalledWith(
      expect.objectContaining({
        method: 'GET',
        path: '/api/status',
        authRequired: true,
        authenticated: false,
        allowed: false,
        reason: 'dashboard_auth_failed',
        statusCode: 401,
      })
    );
  });

});
