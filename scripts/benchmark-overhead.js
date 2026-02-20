#!/usr/bin/env node

const fs = require('fs');
const os = require('os');
const path = require('path');
const express = require('express');
const autocannon = require('autocannon');

const { SentinelServer } = require('../src/server');

process.env.NODE_ENV = process.env.NODE_ENV || 'production';
process.env.SENTINEL_HOME = process.env.SENTINEL_HOME || fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-bench-home-'));

function parseIntArg(name, defaultValue) {
  const idx = process.argv.indexOf(name);
  if (idx === -1) {
    return defaultValue;
  }
  const value = Number(process.argv[idx + 1]);
  return Number.isInteger(value) && value > 0 ? value : defaultValue;
}

function sleep(ms) {
  if (!Number.isFinite(ms) || ms <= 0) {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    timer.unref?.();
  });
}

function runAutocannon(options) {
  return new Promise((resolve, reject) => {
    autocannon(options, (error, result) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(result);
    });
  });
}

function listenServer(app, port, host, label) {
  return new Promise((resolve, reject) => {
    const server = app.listen(port, host);
    const onListening = () => {
      server.off('error', onError);
      resolve(server);
    };
    const onError = (error) => {
      server.off('listening', onListening);
      reject(new Error(`${label} listen failed: ${error.message}`));
    };
    server.once('listening', onListening);
    server.once('error', onError);
  });
}

function waitForListening(server, label) {
  if (server?.listening) {
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    const onListening = () => {
      server.off('error', onError);
      resolve();
    };
    const onError = (error) => {
      server.off('listening', onListening);
      reject(new Error(`${label} listen failed: ${error.message}`));
    };
    server.once('listening', onListening);
    server.once('error', onError);
  });
}

function extractMetrics(result) {
  const p95Approx = result.latency.p95 ?? result.latency.p97_5 ?? result.latency.p99 ?? result.latency.average;
  return {
    requests_per_sec: Number(result.requests.average.toFixed(2)),
    throughput_bytes_per_sec: Number(result.throughput.average.toFixed(2)),
    latency_ms: {
      avg: Number(result.latency.average.toFixed(2)),
      p50: Number(result.latency.p50.toFixed(2)),
      p95: Number(p95Approx.toFixed(2)),
      p99: Number(result.latency.p99.toFixed(2)),
      max: Number(result.latency.max.toFixed(2)),
    },
  };
}

function makeConfig(sentinelPort) {
  return {
    version: 1,
    mode: 'monitor',
    proxy: {
      host: '127.0.0.1',
      port: sentinelPort,
      timeout_ms: 30000,
      max_body_bytes: 1048576,
    },
    runtime: {
      fail_open: false,
      scanner_error_action: 'allow',
      telemetry: { enabled: false },
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
          enabled: false,
          allowlist: [],
          block_private_networks: true,
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
}

async function startUpstream({ upstreamLatencyMs = 0 } = {}) {
  const app = express();
  app.use(express.raw({ type: '*/*', limit: '1mb' }));
  app.post('/v1/chat/completions', async (req, res) => {
    await sleep(upstreamLatencyMs);
    res.status(200).json({ ok: true });
  });
  app.get('/v1/models', async (req, res) => {
    await sleep(upstreamLatencyMs);
    res.status(200).json({ data: [{ id: 'model-1' }] });
  });

  const server = await listenServer(app, 0, '127.0.0.1', 'benchmark upstream');
  const port = server.address().port;
  return { server, port };
}

function printSummary(direct, sentinel, overhead) {
  const lines = [
    '',
    'Benchmark summary',
    '=================',
    `Direct p95 latency:   ${direct.latency_ms.p95} ms`,
    `Sentinel p95 latency: ${sentinel.latency_ms.p95} ms`,
    `Overhead p95:         ${overhead.p95_ms} ms (${overhead.p95_percent}%)`,
    `Direct req/sec:       ${direct.requests_per_sec}`,
    `Sentinel req/sec:     ${sentinel.requests_per_sec}`,
    `Req/sec delta:        ${overhead.requests_per_sec_delta}`,
    '',
  ];
  process.stdout.write(`${lines.join('\n')}\n`);
}

async function main() {
  const duration = parseIntArg('--duration', 12);
  const connections = parseIntArg('--connections', 64);
  const pipelining = parseIntArg('--pipelining', 1);
  const upstreamLatencyMs = parseIntArg('--upstream-latency-ms', 25);

  const upstream = await startUpstream({ upstreamLatencyMs });
  const upstreamUrl = `http://127.0.0.1:${upstream.port}`;
  process.env.SENTINEL_OPENAI_URL = upstreamUrl;
  const sentinelConfig = makeConfig(0);
  const sentinel = new SentinelServer(sentinelConfig, { runDoctor: false });
  // Benchmark transport/enforcement overhead without filesystem persistence skew.
  sentinel.auditLogger.write = () => {};
  sentinel.writeStatus = () => {};
  const sentinelHttpServer = sentinel.start();
  await waitForListening(sentinelHttpServer, 'benchmark sentinel');
  const sentinelPort = sentinelHttpServer.address().port;

  const postBody = JSON.stringify({
    messages: [{ role: 'user', content: 'hello benchmark' }],
    stream: false,
  });

  try {
    const directResult = await runAutocannon({
      url: `http://127.0.0.1:${upstream.port}/v1/chat/completions`,
      method: 'POST',
      body: postBody,
      headers: { 'content-type': 'application/json' },
      connections,
      duration,
      pipelining,
    });

    const sentinelResult = await runAutocannon({
      url: `http://127.0.0.1:${sentinelPort}/v1/chat/completions`,
      method: 'POST',
      body: postBody,
      headers: {
        'content-type': 'application/json',
        'x-sentinel-target': 'openai',
      },
      connections,
      duration,
      pipelining,
    });

    const direct = extractMetrics(directResult);
    const proxied = extractMetrics(sentinelResult);
    const percentBaseline = direct.latency_ms.p95 > 0 ? direct.latency_ms.p95 : direct.latency_ms.avg || 1;
    const overhead = {
      p95_ms: Number((proxied.latency_ms.p95 - direct.latency_ms.p95).toFixed(2)),
      p95_percent: Number(
        (((proxied.latency_ms.p95 - direct.latency_ms.p95) / percentBaseline) * 100).toFixed(2)
      ),
      requests_per_sec_delta: Number((proxied.requests_per_sec - direct.requests_per_sec).toFixed(2)),
    };

    const report = {
      generated_at: new Date().toISOString(),
      benchmark: {
        duration_seconds: duration,
        connections,
        pipelining,
        upstream_latency_ms: upstreamLatencyMs,
      },
      direct,
      sentinel: proxied,
      overhead,
    };

    const outputPath = path.join(process.cwd(), 'metrics', `benchmark-${new Date().toISOString().slice(0, 10)}.json`);
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');

    printSummary(direct, proxied, overhead);
    process.stdout.write(`Saved report: ${outputPath}\n`);
  } finally {
    await sentinel.stop();
    await new Promise((resolve) => upstream.server.close(resolve));
  }
}

main().catch((error) => {
  process.stderr.write(`Benchmark failed: ${error.message}\n`);
  process.exit(1);
});
