const crypto = require('crypto');

function escapeHtml(value) {
  if (value === undefined || value === null) {
    return '';
  }
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function normalizeResultType(value) {
  const normalized = String(value || '').toLowerCase();
  return normalized === 'exfiltration' ? 'exfiltration' : 'injection';
}

function safeNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function fingerprintPrompt(prompt) {
  const digest = crypto.createHash('sha256').update(String(prompt || ''), 'utf8').digest('hex');
  return digest.slice(0, 16);
}

function summarizeVectors(results) {
  const counts = {};
  for (const item of results) {
    const key = String(item.vector || 'unknown');
    counts[key] = (counts[key] || 0) + 1;
  }
  return Object.entries(counts)
    .sort((a, b) => {
      if (b[1] !== a[1]) {
        return b[1] - a[1];
      }
      return String(a[0]).localeCompare(String(b[0]));
    })
    .slice(0, 20);
}

function toRenderableResults(report = {}) {
  const rawResults = Array.isArray(report.results) ? report.results : [];
  return rawResults
    .map((item) => ({
      type: normalizeResultType(item.type),
      vector: String(item.vector || 'unknown'),
      statusCode: safeNumber(item.status_code, 0),
      blocked: item.blocked === true,
      error: String(item.error || ''),
      caseId: fingerprintPrompt(item.prompt || ''),
    }))
    .sort((a, b) => {
      if (a.type !== b.type) {
        return a.type.localeCompare(b.type);
      }
      if (a.vector !== b.vector) {
        return a.vector.localeCompare(b.vector);
      }
      if (a.statusCode !== b.statusCode) {
        return a.statusCode - b.statusCode;
      }
      return a.caseId.localeCompare(b.caseId);
    });
}

function renderRedTeamHtmlReport(report = {}, options = {}) {
  const title = String(options.title || 'Sentinel Red-Team Report');
  const generatedAt = String(report.generated_at || '');
  const totalTests = safeNumber(report.total_tests, 0);
  const blockedTests = safeNumber(report.blocked_tests, 0);
  const scorePercent = safeNumber(report.score_percent, 0).toFixed(2);
  const requestErrors = safeNumber(report.request_errors, 0);
  const statusCodes = report.status_codes && typeof report.status_codes === 'object' ? report.status_codes : {};
  const results = toRenderableResults(report);
  const vectorSummary = summarizeVectors(results);
  const statusRows = Object.entries(statusCodes).sort((a, b) => String(a[0]).localeCompare(String(b[0])));

  const statusCodeTableRows = statusRows
    .map(([code, count]) => `<tr><td>${escapeHtml(code)}</td><td>${escapeHtml(count)}</td></tr>`)
    .join('');
  const vectorTableRows = vectorSummary
    .map(([vector, count]) => `<tr><td>${escapeHtml(vector)}</td><td>${escapeHtml(count)}</td></tr>`)
    .join('');
  const resultTableRows = results
    .map((item) => {
      const verdict = item.blocked ? 'blocked' : 'allowed';
      return `<tr><td>${escapeHtml(item.type)}</td><td>${escapeHtml(item.vector)}</td><td>${escapeHtml(item.statusCode)}</td><td>${escapeHtml(verdict)}</td><td>${escapeHtml(item.caseId)}</td><td>${escapeHtml(item.error || '--')}</td></tr>`;
    })
    .join('');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    :root { color-scheme: dark; }
    body { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; background: #05080b; color: #d7f5ff; }
    .wrap { max-width: 1100px; margin: 0 auto; padding: 16px; }
    h1 { margin: 0 0 8px; font-size: 20px; color: #8de8ff; }
    .meta { color: #9bb9c4; font-size: 12px; margin-bottom: 12px; }
    .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 14px; }
    .card { border: 1px solid #194c5f; border-radius: 8px; padding: 10px; background: #07131a; }
    .k { font-size: 12px; color: #8ab8c8; }
    .v { font-size: 20px; font-weight: 700; color: #dff7ff; margin-top: 4px; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { border-bottom: 1px solid #153744; padding: 6px 4px; text-align: left; }
    th { color: #91d4e8; }
    .hint { color: #8ab8c8; font-size: 11px; margin: 6px 0 0; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>${escapeHtml(title)}</h1>
    <div class="meta">generated_at=${escapeHtml(generatedAt)} | deterministic_case_ids=true | raw_prompts_exposed=false</div>
    <div class="grid">
      <div class="card"><div class="k">Total Tests</div><div class="v">${escapeHtml(totalTests)}</div></div>
      <div class="card"><div class="k">Blocked</div><div class="v">${escapeHtml(blockedTests)}</div></div>
      <div class="card"><div class="k">Score (%)</div><div class="v">${escapeHtml(scorePercent)}</div></div>
      <div class="card"><div class="k">Request Errors</div><div class="v">${escapeHtml(requestErrors)}</div></div>
    </div>
    <div class="row">
      <div class="card">
        <div class="k">Status Code Distribution</div>
        <table>
          <thead><tr><th>Status</th><th>Count</th></tr></thead>
          <tbody>${statusCodeTableRows || '<tr><td colspan="2">none</td></tr>'}</tbody>
        </table>
      </div>
      <div class="card">
        <div class="k">Top Attack Vectors</div>
        <table>
          <thead><tr><th>Vector</th><th>Count</th></tr></thead>
          <tbody>${vectorTableRows || '<tr><td colspan="2">none</td></tr>'}</tbody>
        </table>
      </div>
    </div>
    <div class="card">
      <div class="k">Case Results</div>
      <table>
        <thead><tr><th>Type</th><th>Vector</th><th>Status</th><th>Verdict</th><th>Case ID</th><th>Error</th></tr></thead>
        <tbody>${resultTableRows || '<tr><td colspan="6">none</td></tr>'}</tbody>
      </table>
      <div class="hint">Case IDs are SHA256(prompt) prefixes. Prompts are intentionally excluded to avoid sensitive payload leakage.</div>
    </div>
  </div>
</body>
</html>`;
}

module.exports = {
  renderRedTeamHtmlReport,
  fingerprintPrompt,
  toRenderableResults,
};
