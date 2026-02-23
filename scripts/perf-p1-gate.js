#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');

const { classifyEvent } = require('../src/governance/atlas-tracker');
const { AIBOMGenerator } = require('../src/governance/aibom-generator');
const { computeSecurityPosture } = require('../src/governance/security-posture');
const { generateOWASPComplianceReport } = require('../src/governance/owasp-compliance-mapper');

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
    measure_iterations: 10000,
    modules: {
      atlas_tracker: { max_p95_ms: 0.6 },
      aibom_generator: { max_p95_ms: 1.2 },
      security_posture: { max_p95_ms: 0.8 },
      owasp_mapper: { max_p95_ms: 1.0 },
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
    modules: {
      ...defaults.modules,
      ...((parsed && parsed.modules) || {}),
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
  return path.join(rootDir, 'metrics', `p1-engine-perf-${stamp}.json`);
}

function buildBenches() {
  const atlasEvent = {
    decision: 'blocked_policy',
    reasons: ['injection:high', 'prompt_injection_detected', 'policy:block'],
    engine: 'injection_scanner',
  };

  const aibom = new AIBOMGenerator({
    maxEntriesPerCategory: 256,
    pruneInterval: 32,
    maxTraversalDepth: 8,
    maxTraversalNodes: 512,
    maxToolsPerRecord: 64,
  });

  const postureConfig = {
    mode: 'enforce',
    injection: { enabled: true, action: 'block' },
    pii: {
      enabled: true,
      egress: {
        enabled: true,
        stream_enabled: true,
        stream_block_mode: 'terminate',
        entropy: { enabled: true, mode: 'block' },
      },
    },
    runtime: {
      prompt_rebuff: { enabled: true, mode: 'block' },
      mcp_poisoning: { enabled: true, mode: 'block' },
      auto_immune: { enabled: true, mode: 'block' },
      websocket: { enabled: true, mode: 'enforce' },
      provenance: { enabled: true, mode: 'enforce' },
      pii_vault: { enabled: true, mode: 'active' },
      upstream: { ghost_mode: { enabled: true, mode: 'active' } },
      honeytoken: { enabled: true, mode: 'active' },
      loop_breaker: { enabled: true, action: 'block' },
      agentic_threat_shield: { enabled: true, mode: 'block' },
      intent_throttle: { enabled: true, mode: 'block' },
      intent_drift: { enabled: true, mode: 'block' },
      canary_tools: { enabled: true, mode: 'block' },
      sandbox_experimental: { enabled: true, mode: 'block' },
    },
  };

  const owaspConfig = {
    ...postureConfig,
    proxy: {
      max_body_bytes: 1048576,
    },
    runtime: {
      ...postureConfig.runtime,
      synthetic_poisoning: { enabled: true, mode: 'inject' },
      swarm: { enabled: true },
      rate_limiter: { default_limit: 60 },
      cognitive_rollback: { enabled: true, mode: 'auto' },
    },
  };

  return [
    {
      name: 'atlas_tracker',
      run: () => {
        classifyEvent(atlasEvent);
      },
    },
    {
      name: 'aibom_generator',
      run: (i) => {
        const session = i % 128;
        aibom.recordRoute({
          provider: 'openai',
          routePlan: {
            routeSource: 'header',
            requestedTarget: 'openai',
          },
        });
        aibom.recordRequest({
          provider: 'openai',
          headers: {
            'x-sentinel-agent-id': `agent-${session}`,
          },
          body: {
            model: 'gpt-4o-mini',
            tools: [
              { function: { name: 'search_docs' } },
              { function: { name: 'lookup_policy' } },
            ],
          },
        });
        aibom.recordResponse({
          provider: 'openai',
          headers: {
            'x-openai-model': 'gpt-4o-mini',
          },
          body: {
            id: `resp-${i}`,
          },
        });
      },
    },
    {
      name: 'security_posture',
      run: () => {
        computeSecurityPosture({
          config: postureConfig,
          counters: {
            requests_total: 10000,
            upstream_errors: 500,
            blocked_total: 900,
          },
        });
      },
    },
    {
      name: 'owasp_mapper',
      run: () => {
        generateOWASPComplianceReport(owaspConfig);
      },
    },
  ];
}

function main() {
  const rootDir = process.cwd();
  const thresholdsPath = parseArg('--thresholds') || path.join(rootDir, 'metrics', 'p1-engine-perf-thresholds.json');
  const thresholds = loadThresholds(thresholdsPath);
  const warmup = parseIntArg('--warmup', safeNumber(thresholds.warmup_iterations, 1500), 100, 1_000_000);
  const iterations = parseIntArg('--iterations', safeNumber(thresholds.measure_iterations, 10000), 1000, 2_000_000);
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
    const threshold = safeNumber(thresholds.modules?.[name]?.max_p95_ms, Number.POSITIVE_INFINITY);
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
  process.stdout.write(`P1 perf report: ${reportPath}\n`);

  if (failures.length > 0) {
    process.stderr.write(`${failures.join('\n')}\n`);
    process.exit(1);
  }
  process.stdout.write('P1 perf gate passed.\n');
}

try {
  main();
} catch (error) {
  process.stderr.write(`P1 perf gate failed: ${error.message}\n`);
  process.exit(1);
}
