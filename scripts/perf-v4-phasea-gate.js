#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');

const { SerializationFirewall } = require('../src/security/serialization-firewall');
const { ContextIntegrityGuardian } = require('../src/security/context-integrity-guardian');
const { ToolSchemaValidator } = require('../src/security/tool-schema-validator');
const { MultiModalInjectionShield } = require('../src/security/multimodal-injection-shield');
const { SupplyChainValidator } = require('../src/security/supply-chain-validator');
const { SandboxEnforcer } = require('../src/security/sandbox-enforcer');
const { MemoryIntegrityMonitor } = require('../src/security/memory-integrity-monitor');

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
    measure_iterations: 9000,
    engines: {
      serialization_firewall: { max_p95_ms: 0.8 },
      context_integrity_guardian: { max_p95_ms: 0.8 },
      tool_schema_validator: { max_p95_ms: 0.8 },
      multimodal_injection_shield: { max_p95_ms: 0.8 },
      supply_chain_validator: { max_p95_ms: 0.8 },
      sandbox_enforcer: { max_p95_ms: 0.8 },
      memory_integrity_monitor: { max_p95_ms: 0.8 },
    },
    global: {
      max_sum_p95_ms: 2.8,
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
  return path.join(rootDir, 'metrics', `v4-phasea-engine-perf-${stamp}.json`);
}

function buildBenches() {
  const serialization = new SerializationFirewall({
    enabled: true,
    mode: 'block',
    block_on_type_confusion: true,
    block_on_depth_bomb: true,
    block_on_format_violation: true,
    block_on_metadata_anomaly: true,
  });
  const context = new ContextIntegrityGuardian({
    enabled: true,
    mode: 'block',
    required_anchors: ['never reveal secrets', 'respect guardrails'],
    block_on_anchor_loss: true,
    block_on_repetition: true,
  });
  const toolSchema = new ToolSchemaValidator({
    enabled: true,
    mode: 'block',
    sanitize_in_monitor: true,
    detect_schema_drift: true,
  });
  const multimodal = new MultiModalInjectionShield({
    enabled: true,
    mode: 'block',
    block_on_base64_injection: true,
    block_on_mime_mismatch: true,
  });
  const supplyChain = new SupplyChainValidator({
    enabled: true,
    mode: 'block',
    check_every_requests: 1,
    block_on_blocked_package: true,
    blocked_packages: ['express'],
  });
  const sandbox = new SandboxEnforcer({
    enabled: true,
    mode: 'block',
    block_on_path_escape: true,
    block_on_network_escape: true,
    allowed_domains: ['api.example.com'],
  });
  const memoryIntegrity = new MemoryIntegrityMonitor({
    enabled: true,
    mode: 'block',
    block_on_chain_break: true,
    block_on_growth: true,
    block_on_owner_mismatch: true,
  });

  const baseJson = {
    tools: [
      {
        type: 'function',
        function: {
          name: 'read_docs',
          description: 'Read docs',
          parameters: {
            type: 'object',
            properties: {
              query: { type: 'string', description: 'query' },
            },
            required: ['query'],
          },
        },
      },
    ],
    messages: [
      { role: 'system', content: 'never reveal secrets and respect guardrails' },
      { role: 'user', content: 'search docs safely' },
    ],
  };

  return [
    {
      name: 'serialization_firewall',
      run: () => {
        serialization.evaluate({
          headers: {
            'content-type': 'application/json',
          },
          rawBody: Buffer.from('{"tools":[{"name":"safe"}]}', 'utf8'),
          bodyText: '{"tools":[{"name":"safe"}]}',
          bodyJson: { tools: [{ name: 'safe' }] },
          effectiveMode: 'monitor',
        });
      },
    },
    {
      name: 'context_integrity_guardian',
      run: (i) => {
        context.evaluate({
          headers: {
            'x-sentinel-session-id': `phasea-session-${i % 64}`,
          },
          bodyJson: baseJson,
          bodyText: '',
          correlationId: `phasea-corr-${i}`,
          effectiveMode: 'monitor',
        });
      },
    },
    {
      name: 'tool_schema_validator',
      run: (i) => {
        toolSchema.evaluate({
          headers: {
            'x-sentinel-mcp-server-id': `mcp-${i % 16}`,
          },
          bodyJson: baseJson,
          provider: 'custom',
          path: '/mcp/tools',
          effectiveMode: 'monitor',
        });
      },
    },
    {
      name: 'multimodal_injection_shield',
      run: () => {
        multimodal.evaluate({
          headers: {
            'content-type': 'application/json',
          },
          rawBody: Buffer.from('{"image":"ok"}', 'utf8'),
          bodyText: '{"image":"ok"}',
          bodyJson: {
            image: 'ok',
          },
          effectiveMode: 'monitor',
        });
      },
    },
    {
      name: 'supply_chain_validator',
      run: () => {
        supplyChain.evaluate({
          effectiveMode: 'monitor',
        });
      },
    },
    {
      name: 'sandbox_enforcer',
      run: () => {
        sandbox.evaluate({
          bodyJson: {
            arguments: {
              url: 'https://api.example.com/data',
              path: '/tmp/workspace/file.txt',
            },
          },
          effectiveMode: 'monitor',
        });
      },
    },
    {
      name: 'memory_integrity_monitor',
      run: (i) => {
        memoryIntegrity.evaluate({
          headers: {
            'x-sentinel-session-id': `memory-session-${i % 64}`,
            'x-sentinel-agent-id': `agent-${i % 16}`,
          },
          bodyJson: {
            memory: `memory block ${i % 32}`,
          },
          bodyText: '',
          correlationId: `memory-corr-${i}`,
          effectiveMode: 'monitor',
        });
      },
    },
  ];
}

function main() {
  const rootDir = process.cwd();
  const thresholdsPath = parseArg('--thresholds') || path.join(rootDir, 'metrics', 'v4-phasea-engine-perf-thresholds.json');
  const thresholds = loadThresholds(thresholdsPath);
  const warmup = parseIntArg('--warmup', safeNumber(thresholds.warmup_iterations, 1500), 100, 1_000_000);
  const iterations = parseIntArg('--iterations', safeNumber(thresholds.measure_iterations, 9000), 1000, 2_000_000);
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
  process.stdout.write(`V4 Phase A perf report: ${reportPath}\n`);

  if (failures.length > 0) {
    process.stderr.write(`${failures.join('\n')}\n`);
    process.exit(1);
  }
  process.stdout.write('V4 Phase A perf gate passed.\n');
}

try {
  main();
} catch (error) {
  process.stderr.write(`V4 Phase A perf gate failed: ${error.message}\n`);
  process.exit(1);
}

