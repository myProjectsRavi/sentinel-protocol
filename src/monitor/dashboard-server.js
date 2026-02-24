const crypto = require('crypto');
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

function normalizeTeamTokens(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return {};
  }
  const out = {};
  for (const [rawTeam, rawToken] of Object.entries(input)) {
    const team = String(rawTeam || '').trim().toLowerCase().slice(0, 64);
    const token = String(rawToken || '').trim();
    if (!team || !token) {
      continue;
    }
    out[team] = token.slice(0, 4096);
  }
  return out;
}

function safeTokenEqual(left, right) {
  const leftBuffer = Buffer.from(String(left || ''), 'utf8');
  const rightBuffer = Buffer.from(String(right || ''), 'utf8');
  if (leftBuffer.length !== rightBuffer.length || leftBuffer.length === 0) {
    return false;
  }
  try {
    return crypto.timingSafeEqual(leftBuffer, rightBuffer);
  } catch {
    return false;
  }
}

function createDashboardAccessGuard({ allowRemote, authToken, teamTokens, teamHeader, accessLogger }) {
  const enforceLocalOnly = allowRemote !== true;
  const token = String(authToken || '').trim();
  const scopedTokens = normalizeTeamTokens(teamTokens);
  const scopedTokenCount = Object.keys(scopedTokens).length;
  const scopedHeader = String(teamHeader || 'x-sentinel-dashboard-team').trim().toLowerCase() || 'x-sentinel-dashboard-team';
  const loggerFn = typeof accessLogger === 'function' ? accessLogger : null;
  return (req, res, next) => {
    const startedAt = Date.now();
    const requestId = createRequestId();
    const remoteAddr = req.socket?.remoteAddress || req.ip;
    const reqPath = String(req.path || req.url || '/');
    const method = String(req.method || 'GET').toUpperCase();
    const authRequired = token.length > 0 || scopedTokenCount > 0;
    const providedToken = String((req.headers || {})['x-sentinel-dashboard-token'] || '');
    const requestedTeam = String((req.headers || {})[scopedHeader] || '').trim().toLowerCase();
    const selectedTeam = scopedTokenCount > 0
      ? (requestedTeam || (Object.prototype.hasOwnProperty.call(scopedTokens, 'default') ? 'default' : ''))
      : '';
    const expectedToken = selectedTeam && scopedTokenCount > 0 ? scopedTokens[selectedTeam] : '';
    const authenticated = scopedTokenCount > 0
      ? safeTokenEqual(providedToken, expectedToken)
      : (!authRequired || safeTokenEqual(providedToken, token));
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
          team: selectedTeam || '',
          teamHeader: scopedHeader,
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
      let reason = 'dashboard_auth_failed';
      let error = 'DASHBOARD_AUTH_REQUIRED';
      if (scopedTokenCount > 0 && !selectedTeam) {
        reason = 'dashboard_team_required';
        error = 'DASHBOARD_TEAM_REQUIRED';
      } else if (scopedTokenCount > 0 && !expectedToken) {
        reason = 'dashboard_team_unknown';
        error = 'DASHBOARD_TEAM_UNKNOWN';
      }
      logAccess({
        allowed: false,
        reason,
        statusCode: 401,
      });
      res.status(401).json({ error });
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
    .wrap { max-width: 1240px; margin: 0 auto; padding: 16px; }
    h1 { margin: 0 0 12px; color: #7fffa5; font-size: 20px; }
    .grid { display: grid; grid-template-columns: repeat(6, 1fr); gap: 10px; margin-bottom: 14px; }
    .card {
      background: rgba(9, 24, 13, 0.88);
      border: 1px solid #2f8048;
      border-radius: 8px;
      padding: 10px;
      min-height: 62px;
    }
    .k { color: #75d88f; font-size: 12px; }
    .v { color: #d8ffe5; font-size: 18px; font-weight: 700; margin-top: 4px; }
    .row { display: grid; grid-template-columns: 2fr 1fr; gap: 10px; margin-bottom: 10px; }
    .row3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { border-bottom: 1px solid #1f4f2d; padding: 6px 4px; text-align: left; }
    th { color: #8fd2a3; }
    .danger { color: #ff8b8b; }
    .ok { color: #8fffa8; }
    .panel-title { margin-bottom: 8px; color: #a4f4be; font-size: 12px; }
    .muted { color: #7db58b; }
    code { color: #bce7ff; }
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
      <div class="card"><div class="k">Anomalies (5m)</div><div id="an5" class="v">0</div></div>
      <div class="card"><div class="k">Forensic Snapshots</div><div id="forc" class="v">0</div></div>
      <div class="card"><div class="k">Estimated Savings (USD)</div><div id="sav" class="v">0.0000</div></div>
    </div>

    <div class="row3" style="margin-bottom:10px;">
      <div class="card"><div class="k">MCP Shadow Detections</div><div id="mcpShadow" class="v">0</div></div>
      <div class="card"><div class="k">MCP Cert Pinning Detections</div><div id="mcpPin" class="v">0</div></div>
      <div class="card"><div class="k">Context Compression Detections</div><div id="ctxComp" class="v">0</div></div>
    </div>

    <div class="row">
      <div class="card">
        <div class="panel-title">Recent Requests</div>
        <table>
          <thead><tr><th>Time</th><th>Status</th><th>Decision</th><th>Reason</th></tr></thead>
          <tbody id="recent"></tbody>
        </table>
      </div>
      <div class="card">
        <div class="panel-title">Top PII Types</div>
        <table>
          <thead><tr><th>Type</th><th>Hits</th></tr></thead>
          <tbody id="pii"></tbody>
        </table>
      </div>
    </div>

    <div class="row">
      <div class="card">
        <div class="panel-title">Anomaly Heatmap</div>
        <table>
          <thead><tr><th>Engine</th><th>Events</th></tr></thead>
          <tbody id="heatmap"></tbody>
        </table>
      </div>
      <div class="card">
        <div class="panel-title">Forensic Snapshot Timeline</div>
        <table>
          <thead><tr><th>Captured</th><th>Decision</th><th>Reason</th></tr></thead>
          <tbody id="forensics"></tbody>
        </table>
      </div>
    </div>

    <div class="row">
      <div class="card">
        <div class="panel-title">Forensic Replay</div>
        <div class="muted" style="margin-bottom:8px;">Select a snapshot and run what-if thresholds without changing live policy.</div>
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:8px;margin-bottom:8px;">
          <select id="replaySnapshot"></select>
          <input id="replayInjectionThreshold" placeholder="injection threshold" />
          <input id="replayRebuffThreshold" placeholder="prompt rebuff threshold" />
          <button id="replayRun">Replay</button>
        </div>
        <pre id="replayResult" class="muted" style="margin:0;white-space:pre-wrap;max-height:220px;overflow:auto;"></pre>
      </div>
      <div class="card">
        <div class="panel-title">Hints</div>
        <div class="muted">Use <code>sentinel forensic replay --snapshot ... --overrides ...</code> for offline what-if analysis and <code>/_sentinel/forensic/replay</code> for direct runtime replay.</div>
      </div>
    </div>
  </div>
  <script>
    function toNumberOrNull(value) {
      const parsed = Number(value);
      return Number.isFinite(parsed) ? parsed : null;
    }

    function populateReplaySnapshots(forensics) {
      const select = document.getElementById('replaySnapshot');
      const previous = String(select.value || '');
      select.innerHTML = '';
      for (const item of (forensics.snapshots || []).slice(0, 50)) {
        const option = document.createElement('option');
        option.value = String(item.id || '');
        option.textContent = String(item.id || '') + ' :: ' + String(item.decision || 'unknown');
        select.appendChild(option);
      }
      if (previous && Array.from(select.options).some((option) => option.value === previous)) {
        select.value = previous;
      }
    }

    async function runReplay() {
      const resultEl = document.getElementById('replayResult');
      const snapshotId = String(document.getElementById('replaySnapshot').value || '');
      const injectionThreshold = toNumberOrNull(document.getElementById('replayInjectionThreshold').value);
      const promptRebuffThreshold = toNumberOrNull(document.getElementById('replayRebuffThreshold').value);

      const payload = {
        snapshot_id: snapshotId || undefined,
        overrides: {},
      };
      if (injectionThreshold !== null) {
        payload.overrides.injection_threshold = injectionThreshold;
      }
      if (promptRebuffThreshold !== null) {
        payload.overrides.prompt_rebuff_threshold = promptRebuffThreshold;
      }

      resultEl.textContent = 'Running replay...';
      try {
        const response = await fetch('/api/forensics/replay', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (!response.ok) {
          const body = await response.json().catch(() => ({}));
          resultEl.textContent = 'Replay failed: ' + String(body.error || response.status);
          return;
        }
        const replay = await response.json();
        const deltaKeys = Array.isArray(replay?.diff?.deltas) ? replay.diff.deltas.map((item) => item.key) : [];
        resultEl.textContent = JSON.stringify({
          snapshot_id: replay.snapshot_id,
          changed: replay?.diff?.changed === true,
          delta_keys: deltaKeys,
          replayed_at: replay?.replay?.replayed_at || null,
        }, null, 2);
      } catch (error) {
        resultEl.textContent = 'Replay failed: ' + String(error && error.message ? error.message : error);
      }
    }

    async function tick() {
      const [statusRes, recentRes, anomalyRes, forensicRes] = await Promise.all([
        fetch('/api/status', { cache: 'no-store' }),
        fetch('/api/recent', { cache: 'no-store' }),
        fetch('/api/anomalies', { cache: 'no-store' }),
        fetch('/api/forensics', { cache: 'no-store' }),
      ]);
      if (!statusRes.ok || !recentRes.ok || !anomalyRes.ok || !forensicRes.ok) return;

      const status = await statusRes.json();
      const recent = await recentRes.json();
      const anomalies = await anomalyRes.json();
      const forensics = await forensicRes.json();
      const c = status.counters || {};

      document.getElementById('req').textContent = String(c.requests_total || 0);
      document.getElementById('blk').textContent = String(c.blocked_total || 0);
      document.getElementById('sch').textContent = String(c.semantic_cache_hits || 0);
      document.getElementById('sav').textContent = String(recent.estimated_savings_usd || 0);
      document.getElementById('an5').textContent = String(anomalies.recent_5m_events || 0);
      document.getElementById('forc').textContent = String((forensics.snapshots || []).length || 0);

      document.getElementById('mcpShadow').textContent = String(c.mcp_shadow_detected || 0);
      document.getElementById('mcpPin').textContent = String(c.mcp_certificate_pinning_detected || 0);
      document.getElementById('ctxComp').textContent = String(c.context_compression_detected || 0);

      const recentBody = document.getElementById('recent');
      recentBody.innerHTML = '';
      for (const row of recent.entries || []) {
        const tr = document.createElement('tr');
        const statusClass = Number(row.response_status || 0) >= 400 ? 'danger' : 'ok';
        tr.innerHTML = '<td>' + (row.timestamp || '').split('T')[1]?.replace('Z', '') + '</td>'
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

      const heatmapBody = document.getElementById('heatmap');
      heatmapBody.innerHTML = '';
      for (const item of (anomalies.engine_heatmap || []).slice(0, 10)) {
        const tr = document.createElement('tr');
        tr.innerHTML = '<td>' + String(item.engine || 'unknown') + '</td><td>' + String(item.count || 0) + '</td>';
        heatmapBody.appendChild(tr);
      }

      const forensicBody = document.getElementById('forensics');
      forensicBody.innerHTML = '';
      for (const item of (forensics.snapshots || []).slice(0, 10)) {
        const tr = document.createElement('tr');
        tr.innerHTML = '<td>' + String((item.captured_at || '').replace('T', ' ').replace('Z', '')) + '</td>'
          + '<td>' + String(item.decision || '--') + '</td>'
          + '<td>' + String(item.reason || '--') + '</td>';
        forensicBody.appendChild(tr);
      }

      populateReplaySnapshots(forensics);
    }
    tick();
    document.getElementById('replayRun').addEventListener('click', () => {
      runReplay();
    });
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
    this.teamTokens = normalizeTeamTokens(options.teamTokens);
    this.teamHeader = String(options.teamHeader || 'x-sentinel-dashboard-team').trim().toLowerCase() || 'x-sentinel-dashboard-team';
    this.statusProvider = typeof options.statusProvider === 'function' ? options.statusProvider : () => ({});
    this.anomaliesProvider = typeof options.anomaliesProvider === 'function'
      ? options.anomaliesProvider
      : () => ({ enabled: false, total_events: 0, recent_5m_events: 0, engine_heatmap: [] });
    this.forensicsProvider = typeof options.forensicsProvider === 'function'
      ? options.forensicsProvider
      : () => ({ enabled: false, snapshots: [] });
    this.forensicReplayProvider = typeof options.forensicReplayProvider === 'function'
      ? options.forensicReplayProvider
      : () => ({ enabled: false, error: 'FORENSIC_DEBUGGER_DISABLED' });
    this.accessLogger = typeof options.accessLogger === 'function' ? options.accessLogger : null;
    this.auditTailer = new LogTailer(options.auditPath || AUDIT_LOG_PATH, {
      maxEntries: Number(options.maxAuditEntries || 300),
    });
    this.server = null;
    this.app = express();

    this.app.disable('x-powered-by');
    this.app.use(express.json({
      limit: '64kb',
    }));
    this.app.use(createDashboardAccessGuard({
      allowRemote: this.allowRemote,
      authToken: this.authToken,
      teamTokens: this.teamTokens,
      teamHeader: this.teamHeader,
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

    this.app.get('/api/anomalies', (req, res) => {
      res.json(this.anomaliesProvider());
    });

    this.app.get('/api/forensics', (req, res) => {
      res.json(this.forensicsProvider());
    });

    this.app.post('/api/forensics/replay', (req, res) => {
      const payload = req.body && typeof req.body === 'object' ? req.body : {};
      const snapshotId = String(payload.snapshot_id || '');
      const overrides = payload.overrides && typeof payload.overrides === 'object'
        ? payload.overrides
        : {};
      const result = this.forensicReplayProvider({
        snapshotId,
        overrides,
      });
      if (!result || result.enabled === false) {
        res.status(404).json({
          error: result?.error || 'FORENSIC_DEBUGGER_DISABLED',
        });
        return;
      }
      if (result.error) {
        const status = result.error === 'FORENSIC_SNAPSHOT_NOT_FOUND' ? 404 : 400;
        res.status(status).json({
          error: result.error,
        });
        return;
      }
      res.json(result);
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
  normalizeTeamTokens,
};
