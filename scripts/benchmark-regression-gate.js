#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

function parseArg(name) {
  const idx = process.argv.indexOf(name);
  if (idx === -1) {
    return '';
  }
  return String(process.argv[idx + 1] || '').trim();
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function findLatestBenchmarkReport(metricsDir) {
  if (!fs.existsSync(metricsDir)) {
    return '';
  }
  const files = fs
    .readdirSync(metricsDir)
    .filter((file) => /^benchmark-\d{4}-\d{2}-\d{2}(?:[Tt][\w:-]+)?\.json$/.test(file))
    .sort();
  if (files.length === 0) {
    return '';
  }
  return path.join(metricsDir, files[files.length - 1]);
}

function safeNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function formatPercent(value) {
  return `${safeNumber(value, 0).toFixed(2)}%`;
}

function formatFloat(value) {
  return safeNumber(value, 0).toFixed(2);
}

function main() {
  const root = process.cwd();
  const reportArg = parseArg('--report');
  const thresholdsPath = parseArg('--thresholds') || path.join(root, 'metrics', 'benchmark-thresholds.json');
  const reportPath = reportArg || findLatestBenchmarkReport(path.join(root, 'metrics'));
  if (!reportPath || !fs.existsSync(reportPath)) {
    throw new Error('No benchmark report found. Run `npm run benchmark` first.');
  }

  let thresholds = {
    min_req_sec_ratio_vs_direct: 0.55,
    max_p95_ratio_vs_direct: 1.9,
    max_overhead_p95_percent: 75,
    max_overhead_p95_ms: 45,
  };
  if (fs.existsSync(thresholdsPath)) {
    const parsed = readJson(thresholdsPath);
    thresholds = {
      ...thresholds,
      ...(parsed || {}),
    };
  }

  const report = readJson(reportPath);
  const directReq = safeNumber(report?.direct?.requests_per_sec, 0);
  const sentinelReq = safeNumber(report?.sentinel?.requests_per_sec, 0);
  const directP95 = Math.max(0.001, safeNumber(report?.direct?.latency_ms?.p95, 0));
  const sentinelP95 = safeNumber(report?.sentinel?.latency_ms?.p95, 0);
  const overheadPercent = safeNumber(report?.overhead?.p95_percent, 0);
  const overheadMs = safeNumber(report?.overhead?.p95_ms, sentinelP95 - directP95);

  const reqRatio = directReq > 0 ? sentinelReq / directReq : 0;
  const p95Ratio = sentinelP95 / directP95;

  const failures = [];
  if (reqRatio < Number(thresholds.min_req_sec_ratio_vs_direct)) {
    failures.push(
      `req/sec ratio too low: ${formatFloat(reqRatio)} < ${formatFloat(thresholds.min_req_sec_ratio_vs_direct)}`
    );
  }
  if (p95Ratio > Number(thresholds.max_p95_ratio_vs_direct)) {
    failures.push(
      `p95 latency ratio too high: ${formatFloat(p95Ratio)} > ${formatFloat(thresholds.max_p95_ratio_vs_direct)}`
    );
  }
  if (overheadPercent > Number(thresholds.max_overhead_p95_percent)) {
    failures.push(
      `p95 overhead percent too high: ${formatPercent(overheadPercent)} > ${formatPercent(
        thresholds.max_overhead_p95_percent
      )}`
    );
  }
  if (overheadMs > Number(thresholds.max_overhead_p95_ms)) {
    failures.push(
      `p95 overhead ms too high: ${formatFloat(overheadMs)}ms > ${formatFloat(thresholds.max_overhead_p95_ms)}ms`
    );
  }

  process.stdout.write(`Benchmark gate report: ${reportPath}\n`);
  process.stdout.write(`direct req/sec=${formatFloat(directReq)} sentinel req/sec=${formatFloat(sentinelReq)} ratio=${formatFloat(reqRatio)}\n`);
  process.stdout.write(`direct p95=${formatFloat(directP95)}ms sentinel p95=${formatFloat(sentinelP95)}ms ratio=${formatFloat(p95Ratio)}\n`);
  process.stdout.write(`overhead p95=${formatFloat(overheadMs)}ms (${formatPercent(overheadPercent)})\n`);

  if (failures.length > 0) {
    process.stderr.write(`${failures.join('\n')}\n`);
    process.exit(1);
  }

  process.stdout.write('Benchmark regression gate passed.\n');
}

try {
  main();
} catch (error) {
  process.stderr.write(`Benchmark regression gate failed: ${error.message}\n`);
  process.exit(1);
}
