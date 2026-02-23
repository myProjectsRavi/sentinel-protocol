#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');

const { AgenticThreatShield } = require('../src/security/agentic-threat-shield');
const { MCPPoisoningDetector } = require('../src/security/mcp-poisoning-detector');
const { PromptRebuffEngine } = require('../src/engines/prompt-rebuff');

function parseArg(name) {
  const idx = process.argv.indexOf(name);
  if (idx === -1) {
    return '';
  }
  return String(process.argv[idx + 1] || '').trim();
}

function parseIntArg(name, fallback, min = 1, max = Number.MAX_SAFE_INTEGER) {
  const raw = parseArg(name);
  if (!raw) {
    return fallback;
  }
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    return fallback;
  }
  return parsed;
}

function safeNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function percentile(sortedValues, p) {
  if (!Array.isArray(sortedValues) || sortedValues.length === 0) {
    return 0;
  }
  const normalized = Math.min(1, Math.max(0, Number(p || 0)));
  const idx = Math.floor((sortedValues.length - 1) * normalized);
  return sortedValues[idx] || 0;
}

function computeStats(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  const sum = sorted.reduce((acc, value) => acc + value, 0);
  const mean = sorted.length > 0 ? sum / sorted.length : 0;
  return {
    iterations: sorted.length,
    mean_ms: Number(mean.toFixed(6)),
    p50_ms: Number(percentile(sorted, 0.5).toFixed(6)),
    p95_ms: Number(percentile(sorted, 0.95).toFixed(6)),
    p99_ms: Number(percentile(sorted, 0.99).toFixed(6)),
    min_ms: Number((sorted[0] || 0).toFixed(6)),
    max_ms: Number((sorted[sorted.length - 1] || 0).toFixed(6)),
  };
}

function runMicrobench(name, fn, { warmup, iterations }) {
  for (let i = 0; i < warmup; i += 1) {
    fn(i);
  }
  const samples = new Array(iterations);
  for (let i = 0; i < iterations; i += 1) {
    const start = performance.now();
    fn(i);
    samples[i] = performance.now() - start;
  }
  return {
    name,
    ...computeStats(samples),
  };
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function loadThresholds(filePath) {
  const defaults = {
    warmup_iterations: 1500,
    measure_iterations: 8000,
    engines: {
      agentic_threat_shield: { max_p95_ms: 1.0 },
      mcp_poisoning_detector: { max_p95_ms: 1.0 },
      prompt_rebuff_engine: { max_p95_ms: 0.5 },
    },
    global: {
      max_sum_p95_ms: 2.0,
    },
  };

  if (!fs.existsSync(filePath)) {
    return defaults;
  }
  const parsed = readJson(filePath);
  return {
    ...defaults,
    ...(parsed || {}),
    engines: {
      ...defaults.engines,
      ...((parsed && parsed.engines) || {}),
    },
    global: {
      ...defaults.global,
      ...((parsed && parsed.global) || {}),
    },
  };
}

function renderSummary(result) {
  return `${result.name} mean=${result.mean_ms.toFixed(4)}ms p50=${result.p50_ms.toFixed(4)}ms p95=${result.p95_ms.toFixed(4)}ms p99=${result.p99_ms.toFixed(4)}ms`;
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function createDefaultReportPath(rootDir) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  return path.join(rootDir, 'metrics', `p0-engine-perf-${stamp}.json`);
}

function buildBenches() {
  const sessionPool = 64;
  const serverPool = 16;

  const agentic = new AgenticThreatShield({
    enabled: true,
    mode: 'block',
    max_tool_call_depth: 10,
    max_agent_delegations: 24,
    max_analysis_nodes: 4096,
    max_tool_calls_analyzed: 1024,
    detect_cycles: true,
    verify_identity_tokens: false,
  });
  const agenticBody = {
    messages: [{ role: 'user', content: 'summarize and route' }],
    tool_calls: [
      { function: { name: 'delegate_agent', arguments: '{"delegate_to":"agent-b"}' } },
      { function: { name: 'search_docs', arguments: '{"query":"policy"}' } },
      {
        function: { name: 'delegate_agent', arguments: '{"delegate_to":"agent-c"}' },
        nested: {
          tool_calls: [
            { function: { name: 'search_docs', arguments: '{"query":"security"}' } },
          ],
        },
      },
    ],
  };

  const mcp = new MCPPoisoningDetector({
    enabled: true,
    mode: 'monitor',
    description_threshold: 0.65,
    max_tools: 64,
    max_drift_snapshot_bytes: 131072,
    detect_config_drift: true,
    sanitize_arguments: true,
  });
  const mcpBody = {
    tools: [
      {
        type: 'function',
        function: {
          name: 'search_docs',
          description: 'Search internal documentation by query.',
          parameters: {
            type: 'object',
            properties: {
              query: { type: 'string' },
              limit: { type: 'number' },
            },
            required: ['query'],
          },
        },
      },
      {
        type: 'function',
        function: {
          name: 'fetch_status',
          description: 'Fetch service status for dashboards.',
          parameters: {
            type: 'object',
            properties: {
              service: { type: 'string' },
            },
            required: ['service'],
          },
        },
      },
    ],
  };

  const rebuff = new PromptRebuffEngine({
    enabled: true,
    mode: 'monitor',
    sensitivity: 'balanced',
    max_body_chars: 8192,
    max_response_chars: 8192,
    warn_threshold: 0.65,
    block_threshold: 0.85,
  });
  const rebuffBodyText = 'Summarize this ADR with no policy bypass.';
  const rebuffInjection = {
    score: 0.12,
    neural: { score: 0.08 },
  };

  return [
    {
      name: 'agentic_threat_shield',
      run: (i) => {
        agentic.evaluate({
          headers: {
            'x-sentinel-session-id': `session-${i % sessionPool}`,
            'x-sentinel-agent-id': `agent-${i % sessionPool}`,
          },
          bodyJson: agenticBody,
          correlationId: `corr-${i}`,
          effectiveMode: 'monitor',
        });
      },
    },
    {
      name: 'mcp_poisoning_detector',
      run: (i) => {
        mcp.inspect({
          bodyJson: mcpBody,
          toolArgs: {
            query: 'security hardening',
            limit: 5,
          },
          serverId: `server-${i % serverPool}`,
          serverConfig: { version: 1, region: 'local' },
          effectiveMode: 'monitor',
        });
      },
    },
    {
      name: 'prompt_rebuff_engine',
      run: (i) => {
        rebuff.evaluate({
          headers: {
            'x-sentinel-session-id': `session-${i % sessionPool}`,
          },
          correlationId: `corr-${i}`,
          bodyText: rebuffBodyText,
          injectionResult: rebuffInjection,
          effectiveMode: 'monitor',
        });
      },
    },
  ];
}

function main() {
  const rootDir = process.cwd();
  const thresholdsPath = parseArg('--thresholds') || path.join(rootDir, 'metrics', 'p0-engine-perf-thresholds.json');
  const thresholds = loadThresholds(thresholdsPath);
  const warmup = parseIntArg('--warmup', safeNumber(thresholds.warmup_iterations, 1500), 100, 1_000_000);
  const iterations = parseIntArg('--iterations', safeNumber(thresholds.measure_iterations, 8000), 1000, 2_000_000);
  const reportPath = parseArg('--report') || createDefaultReportPath(rootDir);

  const benchResults = {};
  for (const bench of buildBenches()) {
    const result = runMicrobench(bench.name, bench.run, { warmup, iterations });
    benchResults[bench.name] = result;
    process.stdout.write(`${renderSummary(result)}\n`);
  }

  const failures = [];
  let p95Sum = 0;
  for (const [name, result] of Object.entries(benchResults)) {
    const threshold = safeNumber(thresholds.engines?.[name]?.max_p95_ms, Number.POSITIVE_INFINITY);
    p95Sum += result.p95_ms;
    if (result.p95_ms > threshold) {
      failures.push(`${name} p95 too high: ${result.p95_ms.toFixed(4)}ms > ${threshold.toFixed(4)}ms`);
    }
  }

  const maxP95Sum = safeNumber(thresholds.global?.max_sum_p95_ms, Number.POSITIVE_INFINITY);
  if (p95Sum > maxP95Sum) {
    failures.push(`combined p95 budget exceeded: ${p95Sum.toFixed(4)}ms > ${maxP95Sum.toFixed(4)}ms`);
  }

  const report = {
    generated_at: new Date().toISOString(),
    thresholds_path: thresholdsPath,
    warmup_iterations: warmup,
    measure_iterations: iterations,
    thresholds,
    results: benchResults,
    combined: {
      p95_sum_ms: Number(p95Sum.toFixed(6)),
      max_p95_sum_ms: Number(maxP95Sum.toFixed(6)),
    },
    status: failures.length === 0 ? 'pass' : 'fail',
    failures,
  };

  ensureDir(path.dirname(reportPath));
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  process.stdout.write(`P0 perf report: ${reportPath}\n`);

  if (failures.length > 0) {
    process.stderr.write(`${failures.join('\n')}\n`);
    process.exit(1);
  }
  process.stdout.write('P0 perf gate passed.\n');
}

try {
  main();
} catch (error) {
  process.stderr.write(`P0 perf gate failed: ${error.message}\n`);
  process.exit(1);
}
