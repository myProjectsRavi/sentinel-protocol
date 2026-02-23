const { escapeHtml } = require('./red-team-html-report');

const SCHEMA_VERSION = 'sentinel.owasp.llm-top10.v1';

function getPath(source, path, fallback) {
  let current = source;
  for (const key of path) {
    if (!current || typeof current !== 'object') {
      return fallback;
    }
    current = current[key];
  }
  return current === undefined ? fallback : current;
}

function normalizeComplianceMode(value) {
  return String(value || '').toLowerCase();
}

function enabledByPath(path, predicate = (value) => value === true) {
  return (config) => {
    const enabled = predicate(getPath(config, path, undefined));
    return {
      enabled,
      enforce: enabled,
    };
  };
}

const OWASP_LLM_TOP10_MAP = Object.freeze({
  LLM01: Object.freeze({
    title: 'Prompt Injection',
    controls: Object.freeze([
      Object.freeze({
        id: 'injection_scanner',
        config_key: 'injection.enabled|injection.action',
        evaluate: (config) => {
          const enabled = getPath(config, ['injection', 'enabled'], false) === true;
          const mode = normalizeComplianceMode(getPath(config, ['injection', 'action'], 'monitor'));
          return {
            enabled,
            enforce: enabled && mode === 'block',
          };
        },
      }),
      Object.freeze({
        id: 'prompt_rebuff',
        config_key: 'runtime.prompt_rebuff.enabled|runtime.prompt_rebuff.mode',
        evaluate: (config) => {
          const enabled = getPath(config, ['runtime', 'prompt_rebuff', 'enabled'], false) === true;
          const mode = normalizeComplianceMode(getPath(config, ['runtime', 'prompt_rebuff', 'mode'], 'monitor'));
          return {
            enabled,
            enforce: enabled && mode === 'block',
          };
        },
      }),
    ]),
  }),
  LLM02: Object.freeze({
    title: 'Insecure Output Handling',
    controls: Object.freeze([
      Object.freeze({
        id: 'egress_pii_scan',
        config_key: 'pii.egress.enabled|pii.egress.stream_block_mode',
        evaluate: (config) => {
          const enabled = getPath(config, ['pii', 'egress', 'enabled'], true) !== false;
          const streamMode = normalizeComplianceMode(getPath(config, ['pii', 'egress', 'stream_block_mode'], 'redact'));
          return {
            enabled,
            enforce: enabled && (streamMode === 'terminate' || normalizeComplianceMode(config.mode) === 'enforce'),
          };
        },
      }),
      Object.freeze({
        id: 'sandbox_experimental',
        config_key: 'runtime.sandbox_experimental.enabled|runtime.sandbox_experimental.mode',
        evaluate: (config) => {
          const enabled = getPath(config, ['runtime', 'sandbox_experimental', 'enabled'], false) === true;
          const mode = normalizeComplianceMode(getPath(config, ['runtime', 'sandbox_experimental', 'mode'], 'monitor'));
          return {
            enabled,
            enforce: enabled && mode === 'block',
          };
        },
      }),
    ]),
  }),
  LLM03: Object.freeze({
    title: 'Training Data Poisoning',
    controls: Object.freeze([
      Object.freeze({
        id: 'synthetic_poisoning_gate',
        config_key: 'runtime.synthetic_poisoning.enabled|runtime.synthetic_poisoning.mode',
        evaluate: (config) => {
          const enabled = getPath(config, ['runtime', 'synthetic_poisoning', 'enabled'], false) === true;
          const mode = normalizeComplianceMode(getPath(config, ['runtime', 'synthetic_poisoning', 'mode'], 'monitor'));
          return {
            enabled,
            enforce: enabled && mode === 'inject',
          };
        },
      }),
      Object.freeze({
        id: 'auto_immune',
        config_key: 'runtime.auto_immune.enabled|runtime.auto_immune.mode',
        evaluate: (config) => {
          const enabled = getPath(config, ['runtime', 'auto_immune', 'enabled'], false) === true;
          const mode = normalizeComplianceMode(getPath(config, ['runtime', 'auto_immune', 'mode'], 'monitor'));
          return {
            enabled,
            enforce: enabled && mode === 'block',
          };
        },
      }),
    ]),
  }),
  LLM04: Object.freeze({
    title: 'Model Denial of Service',
    controls: Object.freeze([
      Object.freeze({
        id: 'request_size_cap',
        config_key: 'proxy.max_body_bytes',
        evaluate: (config) => {
          const maxBody = Number(getPath(config, ['proxy', 'max_body_bytes'], 0));
          return {
            enabled: Number.isFinite(maxBody) && maxBody > 0,
            enforce: Number.isFinite(maxBody) && maxBody > 0,
          };
        },
      }),
      Object.freeze({
        id: 'rate_limiter',
        config_key: 'runtime.rate_limiter.default_limit',
        evaluate: (config) => {
          const limit = Number(getPath(config, ['runtime', 'rate_limiter', 'default_limit'], 0));
          return {
            enabled: Number.isFinite(limit) && limit > 0,
            enforce: Number.isFinite(limit) && limit > 0,
          };
        },
      }),
    ]),
  }),
  LLM05: Object.freeze({
    title: 'Supply Chain Vulnerabilities',
    controls: Object.freeze([
      Object.freeze({
        id: 'mcp_poisoning',
        config_key: 'runtime.mcp_poisoning.enabled|runtime.mcp_poisoning.mode',
        evaluate: (config) => {
          const enabled = getPath(config, ['runtime', 'mcp_poisoning', 'enabled'], false) === true;
          const mode = normalizeComplianceMode(getPath(config, ['runtime', 'mcp_poisoning', 'mode'], 'monitor'));
          return {
            enabled,
            enforce: enabled && mode === 'block',
          };
        },
      }),
      Object.freeze({
        id: 'policy_bundle_provenance',
        config_key: 'runtime.provenance.enabled',
        evaluate: (config) => {
          const enabled = getPath(config, ['runtime', 'provenance', 'enabled'], false) === true;
          return {
            enabled,
            enforce: enabled,
          };
        },
      }),
    ]),
  }),
  LLM06: Object.freeze({
    title: 'Sensitive Information Disclosure',
    controls: Object.freeze([
      Object.freeze({
        id: 'pii_ingress',
        config_key: 'pii.enabled',
        evaluate: (config) => {
          const enabled = getPath(config, ['pii', 'enabled'], true) !== false;
          return {
            enabled,
            enforce: enabled && normalizeComplianceMode(config.mode) === 'enforce',
          };
        },
      }),
      Object.freeze({
        id: 'pii_vault',
        config_key: 'runtime.pii_vault.enabled|runtime.pii_vault.mode',
        evaluate: (config) => {
          const enabled = getPath(config, ['runtime', 'pii_vault', 'enabled'], false) === true;
          const mode = normalizeComplianceMode(getPath(config, ['runtime', 'pii_vault', 'mode'], 'monitor'));
          return {
            enabled,
            enforce: enabled && mode === 'active',
          };
        },
      }),
    ]),
  }),
  LLM07: Object.freeze({
    title: 'Insecure Plugin Design',
    controls: Object.freeze([
      Object.freeze({
        id: 'canary_tools',
        config_key: 'runtime.canary_tools.enabled|runtime.canary_tools.mode',
        evaluate: (config) => {
          const enabled = getPath(config, ['runtime', 'canary_tools', 'enabled'], false) === true;
          const mode = normalizeComplianceMode(getPath(config, ['runtime', 'canary_tools', 'mode'], 'monitor'));
          return {
            enabled,
            enforce: enabled && mode === 'block',
          };
        },
      }),
      Object.freeze({
        id: 'sandbox_experimental',
        config_key: 'runtime.sandbox_experimental.enabled|runtime.sandbox_experimental.mode',
        evaluate: (config) => {
          const enabled = getPath(config, ['runtime', 'sandbox_experimental', 'enabled'], false) === true;
          const mode = normalizeComplianceMode(getPath(config, ['runtime', 'sandbox_experimental', 'mode'], 'monitor'));
          return {
            enabled,
            enforce: enabled && mode === 'block',
          };
        },
      }),
    ]),
  }),
  LLM08: Object.freeze({
    title: 'Excessive Agency',
    controls: Object.freeze([
      Object.freeze({
        id: 'loop_breaker',
        config_key: 'runtime.loop_breaker.enabled|runtime.loop_breaker.action',
        evaluate: (config) => {
          const enabled = getPath(config, ['runtime', 'loop_breaker', 'enabled'], false) === true;
          const action = normalizeComplianceMode(getPath(config, ['runtime', 'loop_breaker', 'action'], 'warn'));
          return {
            enabled,
            enforce: enabled && action === 'block',
          };
        },
      }),
      Object.freeze({
        id: 'agentic_threat_shield',
        config_key: 'runtime.agentic_threat_shield.enabled|runtime.agentic_threat_shield.mode',
        evaluate: (config) => {
          const enabled = getPath(config, ['runtime', 'agentic_threat_shield', 'enabled'], false) === true;
          const mode = normalizeComplianceMode(getPath(config, ['runtime', 'agentic_threat_shield', 'mode'], 'monitor'));
          return {
            enabled,
            enforce: enabled && mode === 'block',
          };
        },
      }),
    ]),
  }),
  LLM09: Object.freeze({
    title: 'Overreliance',
    controls: Object.freeze([
      Object.freeze({
        id: 'intent_drift',
        config_key: 'runtime.intent_drift.enabled|runtime.intent_drift.mode',
        evaluate: (config) => {
          const enabled = getPath(config, ['runtime', 'intent_drift', 'enabled'], false) === true;
          const mode = normalizeComplianceMode(getPath(config, ['runtime', 'intent_drift', 'mode'], 'monitor'));
          return {
            enabled,
            enforce: enabled && mode === 'block',
          };
        },
      }),
      Object.freeze({
        id: 'cognitive_rollback',
        config_key: 'runtime.cognitive_rollback.enabled|runtime.cognitive_rollback.mode',
        evaluate: (config) => {
          const enabled = getPath(config, ['runtime', 'cognitive_rollback', 'enabled'], false) === true;
          const mode = normalizeComplianceMode(getPath(config, ['runtime', 'cognitive_rollback', 'mode'], 'monitor'));
          return {
            enabled,
            enforce: enabled && mode === 'auto',
          };
        },
      }),
    ]),
  }),
  LLM10: Object.freeze({
    title: 'Model Theft',
    controls: Object.freeze([
      Object.freeze({
        id: 'provenance_signing',
        config_key: 'runtime.provenance.enabled',
        evaluate: enabledByPath(['runtime', 'provenance', 'enabled']),
      }),
      Object.freeze({
        id: 'swarm_protocol',
        config_key: 'runtime.swarm.enabled',
        evaluate: enabledByPath(['runtime', 'swarm', 'enabled']),
      }),
    ]),
  }),
});

function controlStatus(controlResult = {}) {
  if (controlResult.enforce === true) {
    return 'covered';
  }
  if (controlResult.enabled === true) {
    return 'partially_covered';
  }
  return 'missing';
}

function evaluateRisk(config, riskCode, definition) {
  const controls = (definition.controls || []).map((control) => {
    const evaluation = control.evaluate(config);
    return {
      id: control.id,
      config_key: control.config_key,
      status: controlStatus(evaluation),
      enabled: evaluation.enabled === true,
      enforce: evaluation.enforce === true,
    };
  });

  const allCovered = controls.every((control) => control.status === 'covered');
  const anyCoveredOrPartial = controls.some(
    (control) => control.status === 'covered' || control.status === 'partially_covered'
  );
  const status = allCovered ? 'covered' : anyCoveredOrPartial ? 'partially_covered' : 'missing';
  return {
    code: riskCode,
    title: definition.title,
    status,
    controls,
  };
}

function summarizeRisks(risks = []) {
  const out = {
    covered: 0,
    partially_covered: 0,
    missing: 0,
  };
  for (const risk of risks) {
    if (risk.status === 'covered') {
      out.covered += 1;
    } else if (risk.status === 'partially_covered') {
      out.partially_covered += 1;
    } else {
      out.missing += 1;
    }
  }
  return out;
}

function generateOWASPComplianceReport(config = {}, options = {}) {
  const sortedRiskCodes = Object.keys(OWASP_LLM_TOP10_MAP).sort((a, b) => a.localeCompare(b));
  const risks = sortedRiskCodes.map((code) => evaluateRisk(config, code, OWASP_LLM_TOP10_MAP[code]));
  const summary = summarizeRisks(risks);

  return {
    schema_version: SCHEMA_VERSION,
    report_id: String(options.reportId || 'sentinel-owasp-llm-top10'),
    generated_at: options.generatedAt || null,
    risks,
    summary: {
      ...summary,
      total: risks.length,
    },
  };
}

function renderOWASPLLMHtmlReport(report = {}, options = {}) {
  const title = String(options.title || 'Sentinel OWASP LLM Top 10 Compliance Report');
  const risks = Array.isArray(report.risks) ? report.risks : [];
  const rows = risks
    .map((risk) => {
      const controls = Array.isArray(risk.controls) ? risk.controls : [];
      const controlsSummary = controls
        .map((control) => `${control.id}:${control.status}`)
        .sort((a, b) => a.localeCompare(b))
        .join(', ');
      return `<tr><td>${escapeHtml(risk.code)}</td><td>${escapeHtml(risk.title)}</td><td>${escapeHtml(
        risk.status
      )}</td><td>${escapeHtml(controlsSummary)}</td></tr>`;
    })
    .join('');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    body { margin: 0; background: #f6faf7; color: #163529; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    .wrap { max-width: 1100px; margin: 0 auto; padding: 20px; }
    h1 { margin: 0 0 10px; color: #0a6b45; font-size: 22px; }
    .meta { font-size: 12px; color: #3f5f52; margin-bottom: 16px; }
    table { width: 100%; border-collapse: collapse; background: #ffffff; border: 1px solid #d1e4d9; }
    th, td { text-align: left; border-bottom: 1px solid #dbeadf; padding: 8px; font-size: 12px; vertical-align: top; }
    th { background: #ecf6ef; color: #194c36; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>${escapeHtml(title)}</h1>
    <div class="meta">schema_version=${escapeHtml(String(report.schema_version || SCHEMA_VERSION))} | deterministic=true | raw_payloads_exposed=false</div>
    <table>
      <thead>
        <tr>
          <th>Risk</th>
          <th>Category</th>
          <th>Status</th>
          <th>Mapped Controls</th>
        </tr>
      </thead>
      <tbody>${rows || '<tr><td colspan="4">no data</td></tr>'}</tbody>
    </table>
  </div>
</body>
</html>`;
}

module.exports = {
  SCHEMA_VERSION,
  OWASP_LLM_TOP10_MAP,
  generateOWASPComplianceReport,
  renderOWASPLLMHtmlReport,
};
