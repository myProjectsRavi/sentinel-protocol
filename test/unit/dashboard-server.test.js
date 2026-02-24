const {
  DashboardServer,
  createDashboardAccessGuard,
  isLocalAddress,
  estimateSavings,
  normalizeTeamTokens,
} = require('../../src/monitor/dashboard-server');
const request = require('supertest');

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

  test('normalizes team token map deterministically', () => {
    const normalized = normalizeTeamTokens({
      Alpha: ' token-a ',
      ' ': 'ignored',
      beta: '',
    });
    expect(normalized).toEqual({
      alpha: 'token-a',
    });
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

  test('supports team-scoped dashboard auth tokens', async () => {
    const accessLogger = jest.fn();
    const guard = createDashboardAccessGuard({
      allowRemote: false,
      authToken: '',
      teamTokens: { alpha: 'alpha-token' },
      teamHeader: 'x-sentinel-dashboard-team',
      accessLogger,
    });
    const req = {
      method: 'GET',
      path: '/api/status',
      headers: {
        'x-sentinel-dashboard-team': 'alpha',
        'x-sentinel-dashboard-token': 'alpha-token',
      },
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
        authRequired: true,
        authenticated: true,
        team: 'alpha',
        allowed: true,
      })
    );
  });

  test('returns explicit team errors when scoped dashboard auth headers are invalid', async () => {
    const accessLogger = jest.fn();
    const guard = createDashboardAccessGuard({
      allowRemote: false,
      teamTokens: { alpha: 'alpha-token' },
      teamHeader: 'x-sentinel-dashboard-team',
      accessLogger,
    });
    const missingTeamReq = {
      method: 'GET',
      path: '/api/status',
      headers: {
        'x-sentinel-dashboard-token': 'alpha-token',
      },
      socket: { remoteAddress: '127.0.0.1' },
    };
    const missingTeamRes = createMockResponse();
    guard(missingTeamReq, missingTeamRes, () => {});
    expect(missingTeamRes.statusCode).toBe(401);
    expect(missingTeamRes.body).toEqual({ error: 'DASHBOARD_TEAM_REQUIRED' });

    const unknownTeamReq = {
      method: 'GET',
      path: '/api/status',
      headers: {
        'x-sentinel-dashboard-team': 'bravo',
        'x-sentinel-dashboard-token': 'alpha-token',
      },
      socket: { remoteAddress: '127.0.0.1' },
    };
    const unknownTeamRes = createMockResponse();
    guard(unknownTeamReq, unknownTeamRes, () => {});
    expect(unknownTeamRes.statusCode).toBe(401);
    expect(unknownTeamRes.body).toEqual({ error: 'DASHBOARD_TEAM_UNKNOWN' });
  });

  test('exposes dashboard forensic replay endpoint', async () => {
    const dashboard = new DashboardServer({
      forensicReplayProvider: ({ snapshotId, overrides }) => ({
        enabled: true,
        snapshot_id: snapshotId || 'snap-default',
        replay: {
          replayed_at: '2026-02-24T00:00:00.000Z',
          overrides,
          results: [],
        },
        diff: {
          changed: false,
          deltas: [],
        },
      }),
    });
    const response = await request(dashboard.app)
      .post('/api/forensics/replay')
      .send({
        snapshot_id: 'snap-123',
        overrides: { injection_threshold: 0.4 },
      });
    expect(response.status).toBe(200);
    expect(response.body).toEqual(
      expect.objectContaining({
        snapshot_id: 'snap-123',
      })
    );
    expect(response.body.replay.overrides.injection_threshold).toBe(0.4);
  });

});
