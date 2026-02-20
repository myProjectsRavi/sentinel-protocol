const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');

process.env.SENTINEL_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-home-ws-int-'));

const { SentinelServer } = require('../../src/server');

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function createBaseConfig(overrides = {}) {
  const base = {
    version: 1,
    mode: 'enforce',
    proxy: {
      host: '127.0.0.1',
      port: 0,
      timeout_ms: 30000,
      max_body_bytes: 1048576,
    },
    runtime: {
      fail_open: false,
      scanner_error_action: 'allow',
      websocket: {
        enabled: true,
        mode: 'monitor',
        connect_timeout_ms: 15000,
        idle_timeout_ms: 120000,
        max_connections: 50,
      },
      upstream: {
        retry: {
          enabled: true,
          max_attempts: 1,
          allow_post_with_idempotency_key: false,
        },
        circuit_breaker: {
          enabled: true,
          window_size: 20,
          min_failures_to_evaluate: 8,
          failure_rate_threshold: 0.5,
          consecutive_timeout_threshold: 5,
          open_seconds: 20,
          half_open_success_threshold: 3,
        },
        custom_targets: {
          enabled: true,
          allowlist: ['127.0.0.1', 'localhost'],
          block_private_networks: false,
        },
      },
    },
    pii: {
      enabled: false,
      provider_mode: 'local',
      max_scan_bytes: 262144,
      regex_safety_cap_bytes: 51200,
      severity_actions: {
        critical: 'block',
        high: 'block',
        medium: 'redact',
        low: 'log',
      },
      rapidapi: {
        endpoint: 'https://pii-firewall-edge.p.rapidapi.com/redact',
        host: 'pii-firewall-edge.p.rapidapi.com',
        timeout_ms: 4000,
        request_body_field: 'text',
        fallback_to_local: true,
        allow_non_rapidapi_host: false,
        api_key: '',
        extra_body: {},
      },
    },
    injection: {
      enabled: false,
      threshold: 0.8,
      max_scan_bytes: 131072,
      action: 'block',
    },
    rules: [],
    whitelist: { domains: [] },
    logging: { level: 'error' },
  };

  return mergeObjects(base, overrides);
}

function mergeObjects(base, extra) {
  if (!extra || typeof extra !== 'object' || Array.isArray(extra)) {
    return extra === undefined ? base : extra;
  }
  const merged = { ...base };
  for (const [key, value] of Object.entries(extra)) {
    if (value && typeof value === 'object' && !Array.isArray(value) && merged[key] && typeof merged[key] === 'object' && !Array.isArray(merged[key])) {
      merged[key] = mergeObjects(merged[key], value);
      continue;
    }
    merged[key] = value;
  }
  return merged;
}

function waitForListening(server) {
  if (server.listening) {
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    const onListening = () => {
      server.off('error', onError);
      resolve();
    };
    const onError = (error) => {
      server.off('listening', onListening);
      reject(error);
    };
    server.once('listening', onListening);
    server.once('error', onError);
  });
}

function startWebSocketEchoServer() {
  return new Promise((resolve, reject) => {
    const sockets = new Set();
    const server = http.createServer((req, res) => {
      res.writeHead(426, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'upgrade_required' }));
    });
    server.on('connection', (socket) => {
      sockets.add(socket);
      socket.once('close', () => {
        sockets.delete(socket);
      });
    });
    server.on('upgrade', (req, socket, head) => {
      const key = String(req.headers['sec-websocket-key'] || '');
      const accept = crypto.createHash('sha1').update(`${key}${WS_GUID}`).digest('base64');
      socket.write(
        [
          'HTTP/1.1 101 Switching Protocols',
          'Upgrade: websocket',
          'Connection: Upgrade',
          `Sec-WebSocket-Accept: ${accept}`,
          '',
          '',
        ].join('\r\n')
      );
      if (Buffer.isBuffer(head) && head.length > 0) {
        socket.write(head);
      }
      socket.on('data', (chunk) => {
        socket.write(chunk);
      });
    });

    server.listen(0, '127.0.0.1');
    server.once('listening', () => {
      const port = server.address().port;
      resolve({
        server,
        sockets,
        url: `http://127.0.0.1:${port}`,
      });
    });
    server.once('error', reject);
  });
}

function closeServer(upstream) {
  if (!upstream) {
    return Promise.resolve();
  }
  const server = upstream.server || upstream;
  const sockets = upstream.sockets;
  if (sockets instanceof Set) {
    for (const socket of sockets) {
      socket.destroy();
    }
  }
  return new Promise((resolve) => server.close(resolve));
}

function parseHeaders(lines) {
  const headers = {};
  for (const line of lines) {
    const idx = line.indexOf(':');
    if (idx <= 0) {
      continue;
    }
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    headers[key] = value;
  }
  return headers;
}

function runUpgradeRequest({ port, path: requestPath, headers, payload }) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    let settled = false;
    const timeout = setTimeout(() => {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      reject(new Error('websocket integration timeout'));
    }, 4000);

    const requestLines = [
      `GET ${requestPath} HTTP/1.1`,
      'Host: 127.0.0.1',
      'Connection: Upgrade',
      'Upgrade: websocket',
      'Sec-WebSocket-Version: 13',
      `Sec-WebSocket-Key: ${Buffer.from('sentinel-test-key').toString('base64')}`,
      ...Object.entries(headers || {}).map(([name, value]) => `${name}: ${value}`),
      '',
      '',
    ];
    const requestBuffer = Buffer.from(requestLines.join('\r\n'), 'utf8');
    let received = Buffer.alloc(0);
    let headerEndIndex = -1;
    let parsed = false;
    let statusCode = 0;
    let responseHeaders = {};
    let sentPayload = false;

    socket.on('connect', () => {
      socket.write(requestBuffer);
    });
    socket.on('error', (error) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      reject(error);
    });
    socket.on('data', (chunk) => {
      received = Buffer.concat([received, chunk]);
      if (!parsed) {
        headerEndIndex = received.indexOf('\r\n\r\n');
        if (headerEndIndex === -1) {
          return;
        }
        const headText = received.slice(0, headerEndIndex).toString('utf8');
        const lines = headText.split('\r\n');
        const statusLine = lines.shift() || '';
        const match = statusLine.match(/^HTTP\/1\.1\s+(\d+)/i);
        statusCode = match ? Number(match[1]) : 0;
        responseHeaders = parseHeaders(lines);
        parsed = true;

        if (statusCode === 101 && payload && payload.length > 0 && !sentPayload) {
          sentPayload = true;
          socket.write(payload);
        }
      }

      if (parsed && statusCode !== 101) {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timeout);
        socket.destroy();
        resolve({
          statusCode,
          headers: responseHeaders,
          body: received.slice(headerEndIndex + 4).toString('utf8'),
        });
        return;
      }

      if (parsed && statusCode === 101 && payload && payload.length > 0) {
        const body = received.slice(headerEndIndex + 4);
        if (body.includes(payload)) {
          if (settled) {
            return;
          }
          settled = true;
          clearTimeout(timeout);
          socket.destroy();
          resolve({
            statusCode,
            headers: responseHeaders,
            body: body.toString('utf8'),
          });
        }
      }
    });
  });
}

describe('websocket interception integration', () => {
  let sentinel;
  let upstream;

  afterEach(async () => {
    if (sentinel) {
      await sentinel.stop();
      sentinel = null;
    }
    if (upstream) {
      await closeServer(upstream);
      upstream = null;
    }
  });

  test('forwards websocket upgrades in monitor mode with policy parity warnings', async () => {
    upstream = await startWebSocketEchoServer();
    sentinel = new SentinelServer(
      createBaseConfig({
        runtime: {
          websocket: {
            enabled: true,
            mode: 'monitor',
          },
        },
        rules: [
          {
            name: 'block-ws-path',
            match: {
              method: 'GET',
              path_contains: '/blocked',
            },
            action: 'block',
            message: 'blocked route',
          },
        ],
      })
    );
    const server = sentinel.start();
    await waitForListening(server);
    const port = server.address().port;

    const payload = Buffer.from('WS_MONITOR_PAYLOAD', 'utf8');
    const response = await runUpgradeRequest({
      port,
      path: '/blocked',
      headers: {
        'x-sentinel-target': 'custom',
        'x-sentinel-custom-url': upstream.url,
        'x-sentinel-agent-id': 'ws-agent-1',
      },
      payload,
    });

    expect(response.statusCode).toBe(101);
    expect(response.body).toContain('WS_MONITOR_PAYLOAD');
    expect(response.headers['x-sentinel-ws-mode']).toBe('monitor');
    expect(response.headers['x-sentinel-ws-policy-warning']).toContain('policy_monitor:policy_violation');
    expect(sentinel.currentStatusPayload().counters.websocket_forwarded).toBeGreaterThanOrEqual(1);
  });

  test('blocks websocket upgrades in enforce mode when policy blocks the path', async () => {
    upstream = await startWebSocketEchoServer();
    sentinel = new SentinelServer(
      createBaseConfig({
        runtime: {
          websocket: {
            enabled: true,
            mode: 'enforce',
          },
        },
        rules: [
          {
            name: 'block-ws-path',
            match: {
              method: 'GET',
              path_contains: '/blocked',
            },
            action: 'block',
            message: 'blocked route',
          },
        ],
      })
    );
    const server = sentinel.start();
    await waitForListening(server);
    const port = server.address().port;

    const response = await runUpgradeRequest({
      port,
      path: '/blocked',
      headers: {
        'x-sentinel-target': 'custom',
        'x-sentinel-custom-url': upstream.url,
        'x-sentinel-agent-id': 'ws-agent-2',
      },
      payload: Buffer.alloc(0),
    });

    expect(response.statusCode).toBe(403);
    expect(response.body).toContain('POLICY_VIOLATION');
    expect(sentinel.currentStatusPayload().counters.websocket_blocked).toBeGreaterThanOrEqual(1);
  });
});
