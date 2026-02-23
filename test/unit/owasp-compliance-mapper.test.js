const {
  OWASP_LLM_TOP10_MAP,
  generateOWASPComplianceReport,
  renderOWASPLLMHtmlReport,
} = require('../../src/governance/owasp-compliance-mapper');

function createConfig(overrides = {}) {
  const base = {
    mode: 'enforce',
    proxy: { max_body_bytes: 1048576 },
    injection: { enabled: true, action: 'block' },
    pii: {
      enabled: true,
      egress: {
        enabled: true,
        stream_block_mode: 'terminate',
      },
    },
    runtime: {
      prompt_rebuff: { enabled: true, mode: 'block' },
      sandbox_experimental: { enabled: true, mode: 'block' },
      synthetic_poisoning: { enabled: true, mode: 'inject' },
      auto_immune: { enabled: true, mode: 'block' },
      rate_limiter: { default_limit: 60 },
      mcp_poisoning: { enabled: true, mode: 'block' },
      provenance: { enabled: true },
      pii_vault: { enabled: true, mode: 'active' },
      canary_tools: { enabled: true, mode: 'block' },
      loop_breaker: { enabled: true, action: 'block' },
      agentic_threat_shield: { enabled: true, mode: 'block' },
      intent_drift: { enabled: true, mode: 'block' },
      cognitive_rollback: { enabled: true, mode: 'auto' },
      swarm: { enabled: true },
    },
  };
  return {
    ...base,
    ...overrides,
    runtime: {
      ...base.runtime,
      ...(overrides.runtime || {}),
    },
    pii: {
      ...base.pii,
      ...(overrides.pii || {}),
      egress: {
        ...base.pii.egress,
        ...((overrides.pii || {}).egress || {}),
      },
    },
    injection: {
      ...base.injection,
      ...(overrides.injection || {}),
    },
  };
}

describe('owasp compliance mapper', () => {
  test('contains complete LLM01-LLM10 mapping keys', () => {
    const keys = Object.keys(OWASP_LLM_TOP10_MAP).sort((a, b) => a.localeCompare(b));
    expect(keys).toEqual([
      'LLM01',
      'LLM02',
      'LLM03',
      'LLM04',
      'LLM05',
      'LLM06',
      'LLM07',
      'LLM08',
      'LLM09',
      'LLM10',
    ]);
  });

  test('classifies covered when all mapped controls enabled', () => {
    const report = generateOWASPComplianceReport(createConfig());
    expect(report.risks.every((risk) => risk.status === 'covered')).toBe(true);
  });

  test('classifies partially_covered when monitor-only controls are active', () => {
    const report = generateOWASPComplianceReport(
      createConfig({
        injection: { enabled: true, action: 'allow' },
        runtime: {
          prompt_rebuff: { enabled: true, mode: 'monitor' },
        },
      })
    );
    const risk = report.risks.find((item) => item.code === 'LLM01');
    expect(risk.status).toBe('partially_covered');
  });

  test('classifies missing when required controls are disabled', () => {
    const report = generateOWASPComplianceReport(
      createConfig({
        injection: { enabled: false, action: 'block' },
        runtime: {
          prompt_rebuff: { enabled: false, mode: 'block' },
        },
      })
    );
    const risk = report.risks.find((item) => item.code === 'LLM01');
    expect(risk.status).toBe('missing');
  });

  test('html report is deterministic and escapes unsafe characters', () => {
    const report = generateOWASPComplianceReport(createConfig());
    const first = renderOWASPLLMHtmlReport(report, {
      title: 'Unsafe <script>alert(1)</script>',
    });
    const second = renderOWASPLLMHtmlReport(report, {
      title: 'Unsafe <script>alert(1)</script>',
    });

    expect(first).toBe(second);
    expect(first.includes('<script>alert(1)</script>')).toBe(false);
    expect(first.includes('&lt;script&gt;alert(1)&lt;/script&gt;')).toBe(true);
  });
});
