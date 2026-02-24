const express = require('express');

const { LogTailer, summarizePIITypes } = require('./tui');
const { AUDIT_LOG_PATH } = require('../utils/paths');

function isLocalAddress(address) {
  const value = String(address || '').toLowerCase();
  return (
    value === '::1' ||
    value === '127.0.0.1' ||
    value.startsWith('127.') ||
    value.startsWith('::ffff:127.')
  );
}

function estimateSavings(counters = {}) {
  const semanticHits = Number(counters.semantic_cache_hits || 0);
  const blocked = Number(counters.blocked_total || 0);
  // Conservative rough estimate for local dashboard visibility only.
  const semanticSavingsUsd = semanticHits * 0.0025;
  const blockedSavingsUsd = blocked * 0.0002;
  return Number((semanticSavingsUsd + blockedSavingsUsd).toFixed(4));
}

function createRequestId() {
  return `dash-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function createDashboardAccessGuard({ allowRemote, authToken, accessLogger }) {
  const enforceLocalOnly = allowRemote !== true;
  const token = String(authToken || '');
  const loggerFn = typeof accessLogger === 'function' ? accessLogger : null;
  return (req, res, next) => {
    const startedAt = Date.now();
    const requestId = createRequestId();
    const remoteAddr = req.socket?.remoteAddress || req.ip;
    const reqPath = String(req.path || req.url || '/');
    const method = String(req.method || 'GET').toUpperCase();
    const authRequired = token.length > 0;
    const providedToken = (req.headers || {})['x-sentinel-dashboard-token'];
    const authenticated = !authRequired || providedToken === token;
    let logged = false;
    const logAccess = ({ allowed, reason, statusCode }) => {
      if (logged || !loggerFn) {
        return;
      }
      logged = true;
      try {
        loggerFn({
          requestId,
          method,
          path: reqPath,
          remoteAddress: remoteAddr,
          localOnly: enforceLocalOnly,
          authRequired,
          authenticated,
          allowed,
          reason,
          statusCode,
          durationMs: Math.max(0, Date.now() - startedAt),
        });
      } catch {
        // Audit callback failures must never block dashboard responses.
      }
    };
    res.once('finish', () => {
      logAccess({
        allowed: res.statusCode < 400,
        reason: res.statusCode < 400 ? 'ok' : 'http_error',
        statusCode: res.statusCode,
      });
    });
    if (enforceLocalOnly && !isLocalAddress(remoteAddr)) {
      logAccess({
        allowed: false,
        reason: 'local_only_enforced',
        statusCode: 403,
      });
      res.status(403).json({ error: 'DASHBOARD_LOCAL_ONLY' });
      return;
    }
    if (authRequired && !authenticated) {
      logAccess({
        allowed: false,
        reason: 'dashboard_auth_failed',
        statusCode: 401,
      });
      res.status(401).json({ error: 'DASHBOARD_AUTH_REQUIRED' });
      return;
    }
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('x-frame-options', 'DENY');
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('cache-control', 'no-store');
    res.setHeader('content-security-policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
    next();
  };
}

const DASHBOARD_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Sentinel Matrix Dashboard</title>
  <style>
    :root { color-scheme: dark; }
    body {
      margin: 0;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      background: radial-gradient(circle at top, #10331b, #050805 60%);
      color: #b5f7c6;
    }
    .wrap { max-width: 1100px; margin: 0 auto; padding: 16px; }
    h1 { margin: 0 0 12px; color: #7fffa5; font-size: 20px; }
    .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 14px; }
    .card {
      background: rgba(9, 24, 13, 0.88);
      border: 1px solid #2f8048;
      border-radius: 8px;
      padding: 10px;
      min-height: 62px;
    }
    .k { color: #75d88f; font-size: 12px; }
    .v { color: #d8ffe5; font-size: 19px; font-weight: 700; margin-top: 4px; }
    .row { display: grid; grid-template-columns: 2fr 1fr; gap: 10px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { border-bottom: 1px solid #1f4f2d; padding: 6px 4px; text-align: left; }
    th { color: #8fd2a3; }
    .danger { color: #ff8b8b; }
    .ok { color: #8fffa8; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Sentinel Live Matrix</h1>
    <div class="k" style="margin-bottom:10px;">Playground: <a href="http://127.0.0.1:8787/_sentinel/playground" style="color:#9ed9ff;">/_sentinel/playground</a></div>
    <div class="grid">
      <div class="card"><div class="k">Requests</div><div id="req" class="v">0</div></div>
      <div class="card"><div class="k">Blocked</div><div id="blk" class="v">0</div></div>
      <div class="card"><div class="k">Semantic Cache Hits</div><div id="sch" class="v">0</div></div>
      <div class="card"><div class="k">Estimated Savings (USD)</div><div id="sav" class="v">0.0000</div></div>
    </div>
    <div class="row">
      <div class="card">
        <div class="k">Recent Requests</div>
        <table>
          <thead><tr><th>Time</th><th>Status</th><th>Decision</th><th>Reason</th></tr></thead>
          <tbody id="recent"></tbody>
        </table>
      </div>
      <div class="card">
        <div class="k">Top PII Types</div>
        <table>
          <thead><tr><th>Type</th><th>Hits</th></tr></thead>
          <tbody id="pii"></tbody>
        </table>
      </div>
    </div>
  </div>
  <script>
    async function tick() {
      const [statusRes, recentRes] = await Promise.all([
        fetch('/api/status', { cache: 'no-store' }),
        fetch('/api/recent', { cache: 'no-store' }),
      ]);
      if (!statusRes.ok || !recentRes.ok) return;
      const status = await statusRes.json();
      const recent = await recentRes.json();
      const c = status.counters || {};

      document.getElementById('req').textContent = String(c.requests_total || 0);
      document.getElementById('blk').textContent = String(c.blocked_total || 0);
      document.getElementById('sch').textContent = String(c.semantic_cache_hits || 0);
      document.getElementById('sav').textContent = String(recent.estimated_savings_usd || 0);

      const recentBody = document.getElementById('recent');
      recentBody.innerHTML = '';
      for (const row of recent.entries || []) {
        const tr = document.createElement('tr');
        const statusClass = Number(row.response_status || 0) >= 400 ? 'danger' : 'ok';
        tr.innerHTML = '<td>' + (row.timestamp || '').split('T')[1]?.replace('Z','') + '</td>'
          + '<td class="' + statusClass + '">' + String(row.response_status || '--') + '</td>'
          + '<td>' + String(row.decision || '--') + '</td>'
          + '<td>' + ((row.reasons || []).join(',') || '--') + '</td>';
        recentBody.appendChild(tr);
      }

      const piiBody = document.getElementById('pii');
      piiBody.innerHTML = '';
      for (const item of recent.top_pii || []) {
        const tr = document.createElement('tr');
        tr.innerHTML = '<td>' + String(item[0]) + '</td><td>' + String(item[1]) + '</td>';
        piiBody.appendChild(tr);
      }
    }
    tick();
    setInterval(tick, 1000);
  </script>
</body>
</html>`;

class DashboardServer {
  constructor(options = {}) {
    this.host = String(options.host || '127.0.0.1');
    this.port = Number(options.port || 8788);
    this.allowRemote = options.allowRemote === true;
    this.authToken = String(options.authToken || '');
    this.statusProvider = typeof options.statusProvider === 'function' ? options.statusProvider : () => ({});
    this.accessLogger = typeof options.accessLogger === 'function' ? options.accessLogger : null;
    this.auditTailer = new LogTailer(options.auditPath || AUDIT_LOG_PATH, {
      maxEntries: Number(options.maxAuditEntries || 300),
    });
    this.server = null;
    this.app = express();

    this.app.disable('x-powered-by');
    this.app.use(createDashboardAccessGuard({
      allowRemote: this.allowRemote,
      authToken: this.authToken,
      accessLogger: this.accessLogger,
    }));

    this.app.get('/', (req, res) => {
      res.type('html').send(DASHBOARD_HTML);
    });

    this.app.get('/api/status', (req, res) => {
      res.json(this.statusProvider());
    });

    this.app.get('/api/recent', (req, res) => {
      const entries = this.auditTailer.tick();
      const tail = entries.slice(Math.max(0, entries.length - 25)).reverse();
      const topPii = summarizePIITypes(entries);
      const status = this.statusProvider();
      res.json({
        entries: tail,
        top_pii: topPii,
        estimated_savings_usd: estimateSavings(status?.counters || {}),
      });
    });

    this.app.get('/health', (req, res) => {
      res.status(200).json({ status: 'ok' });
    });
  }

  async start() {
    if (this.server) {
      return this.server;
    }
    this.server = await new Promise((resolve) => {
      const instance = this.app.listen(this.port, this.host, () => resolve(instance));
    });
    return this.server;
  }

  async stop() {
    if (!this.server) {
      return;
    }
    const instance = this.server;
    this.server = null;
    await new Promise((resolve) => instance.close(resolve));
  }
}

module.exports = {
  DashboardServer,
  isLocalAddress,
  estimateSavings,
  createDashboardAccessGuard,
};
