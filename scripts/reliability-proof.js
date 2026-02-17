#!/usr/bin/env node

const fs = require('fs');
const os = require('os');
const path = require('path');
const { once } = require('events');
const express = require('express');
const autocannon = require('autocannon');

const { SentinelServer } = require('../src/server');

process.env.NODE_ENV = process.env.NODE_ENV || 'production';
process.env.SENTINEL_HOME = process.env.SENTINEL_HOME || fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-reliability-home-'));

function parseIntArg(name, defaultValue) {
  const idx = process.argv.indexOf(name);
  if (idx === -1) {
    return defaultValue;
  }
  const value = Number(process.argv[idx + 1]);
  return Number.isInteger(value) && value > 0 ? value : defaultValue;
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

function makeConfig(sentinelPort, timeoutMs = 500) {
  return {
    version: 1,
    mode: 'monitor',
    proxy: {
      host: '127.0.0.1',
      port: sentinelPort,
      timeout_ms: timeoutMs,
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
          open_seconds: 2,
          half_open_success_threshold: 3,
        },
        custom_targets: {
          enabled: true,
          allowlist: ['127.0.0.1', 'localhost'],
          block_private_networks: false,
        },
      },
    },
    pii: {
      enabled: true,
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
      semantic: {
        enabled: false,
        model_id: 'Xenova/bert-base-NER',
        cache_dir: '~/.sentinel/models',
        score_threshold: 0.6,
        max_scan_bytes: 32768,
      },
    },
    injection: {
      enabled: true,
      threshold: 0.8,
      max_scan_bytes: 131072,
      action: 'block',
    },
    rules: [],
    whitelist: { domains: [] },
    logging: { level: 'error' },
  };
}

async function startUpstream(handler) {
  const app = express();
  app.use(express.raw({ type: '*/*', limit: '1mb' }));
  app.all('*', handler);
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  return {
    server,
    url: `http://127.0.0.1:${server.address().port}`,
  };
}

async function closeNodeServer(server) {
  if (!server) return;
  await new Promise((resolve) => server.close(resolve));
}

function parseResultBody(text) {
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

async function callSentinel({ sentinelPort, upstreamUrl, method = 'GET', path = '/v1/models', body }) {
  const headers = {
    'x-sentinel-target': 'custom',
    'x-sentinel-custom-url': upstreamUrl,
  };
  let payload;
  if (body !== undefined) {
    headers['content-type'] = 'application/json';
    payload = JSON.stringify(body);
  }

  const response = await fetch(`http://127.0.0.1:${sentinelPort}${path}`, {
    method,
    headers,
    body: payload,
  });
  const text = await response.text();
  return {
    status: response.status,
    headers: Object.fromEntries(response.headers.entries()),
    body: parseResultBody(text),
  };
}

async function runStressScenario(durationSeconds, connections) {
  const upstream = await startUpstream((req, res) => {
    res.status(200).json({ ok: true, provider: 'stable' });
  });
  const sentinel = new SentinelServer(makeConfig(0, 800));
  const server = sentinel.start();
  if (!server.listening) {
    await once(server, 'listening');
  }
  const sentinelPort = server.address().port;

  try {
    const postBody = JSON.stringify({
      messages: [{ role: 'user', content: 'Explain secure retries with one example.' }],
      stream: false,
    });
    const result = await runAutocannon({
      url: `http://127.0.0.1:${sentinelPort}/v1/chat/completions`,
      method: 'POST',
      body: postBody,
      headers: {
        'content-type': 'application/json',
        'x-sentinel-target': 'custom',
        'x-sentinel-custom-url': upstream.url,
      },
      duration: durationSeconds,
      connections,
      pipelining: 1,
    });

    return {
      duration_seconds: durationSeconds,
      connections,
      requests_total: result.requests.total,
      errors: result.errors,
      timeouts: result.timeouts,
      non2xx: result['non2xx'],
      requests_per_sec: Number(result.requests.average.toFixed(2)),
      latency_ms: {
        avg: Number(result.latency.average.toFixed(2)),
        p95: Number((result.latency.p95 ?? result.latency.p97_5 ?? result.latency.p99 ?? result.latency.average).toFixed(2)),
        p99: Number(result.latency.p99.toFixed(2)),
        max: Number(result.latency.max.toFixed(2)),
      },
      status_snapshot: sentinel.currentStatusPayload(),
    };
  } finally {
    await sentinel.stop();
    await closeNodeServer(upstream.server);
  }
}

async function runChaos503Scenario(requestCount) {
  let upstreamHits = 0;
  const upstream = await startUpstream((req, res) => {
    upstreamHits += 1;
    res.setHeader('retry-after', '0');
    res.status(503).json({ error: 'upstream_maintenance' });
  });
  const sentinel = new SentinelServer(makeConfig(0, 500));
  const server = sentinel.start();
  if (!server.listening) {
    await once(server, 'listening');
  }
  const sentinelPort = server.address().port;

  const byStatus = {};
  let circuitOpenFastFails = 0;
  let upstreamAttributedErrors = 0;

  try {
    for (let i = 0; i < requestCount; i += 1) {
      const response = await callSentinel({
        sentinelPort,
        upstreamUrl: upstream.url,
      });
      byStatus[response.status] = (byStatus[response.status] || 0) + 1;

      if (response.headers['x-sentinel-error-source'] === 'upstream') {
        upstreamAttributedErrors += 1;
      }
      if (response.body?.error === 'UPSTREAM_CIRCUIT_OPEN') {
        circuitOpenFastFails += 1;
      }
    }

    const status = sentinel.currentStatusPayload();
    return {
      requests_sent: requestCount,
      upstream_hits: upstreamHits,
      responses_by_status: byStatus,
      upstream_attributed_errors: upstreamAttributedErrors,
      circuit_open_fast_fails: circuitOpenFastFails,
      provider_state: status.providers.custom || null,
    };
  } finally {
    await sentinel.stop();
    await closeNodeServer(upstream.server);
  }
}

async function runChaosTimeoutScenario(requestCount) {
  let upstreamHits = 0;
  const upstream = await startUpstream(async (req, res) => {
    upstreamHits += 1;
    await new Promise((resolve) => setTimeout(resolve, 1200));
    res.status(200).json({ ok: true });
  });
  const sentinel = new SentinelServer(makeConfig(0, 200));
  const server = sentinel.start();
  if (!server.listening) {
    await once(server, 'listening');
  }
  const sentinelPort = server.address().port;

  const byStatus = {};
  let timeoutHeaders = 0;
  let circuitOpenFastFails = 0;

  try {
    for (let i = 0; i < requestCount; i += 1) {
      const response = await callSentinel({
        sentinelPort,
        upstreamUrl: upstream.url,
      });
      byStatus[response.status] = (byStatus[response.status] || 0) + 1;

      if (response.body?.error === 'UPSTREAM_TIMEOUT') {
        timeoutHeaders += 1;
      }
      if (response.body?.error === 'UPSTREAM_CIRCUIT_OPEN') {
        circuitOpenFastFails += 1;
      }
    }

    const status = sentinel.currentStatusPayload();
    return {
      requests_sent: requestCount,
      upstream_hits: upstreamHits,
      responses_by_status: byStatus,
      timeout_errors: timeoutHeaders,
      circuit_open_fast_fails: circuitOpenFastFails,
      provider_state: status.providers.custom || null,
    };
  } finally {
    await sentinel.stop();
    await closeNodeServer(upstream.server);
  }
}

function printSummary(report) {
  const stress = report.scenarios.stress;
  const chaos503 = report.scenarios.chaos_503;
  const chaosTimeout = report.scenarios.chaos_timeout;
  const lines = [
    '',
    'Reliability proof summary',
    '=========================',
    `Stress req/sec: ${stress.requests_per_sec}`,
    `Stress p95 latency: ${stress.latency_ms.p95}ms`,
    `Stress non2xx/errors/timeouts: ${stress.non2xx}/${stress.errors}/${stress.timeouts}`,
    `Chaos 503 circuit fast-fails: ${chaos503.circuit_open_fast_fails} (upstream hits: ${chaos503.upstream_hits}/${chaos503.requests_sent})`,
    `Chaos timeout circuit fast-fails: ${chaosTimeout.circuit_open_fast_fails} (upstream hits: ${chaosTimeout.upstream_hits}/${chaosTimeout.requests_sent})`,
    '',
  ];
  process.stdout.write(lines.join('\n'));
}

async function main() {
  const durationSeconds = parseIntArg('--duration', 8);
  const connections = parseIntArg('--connections', 40);
  const chaosRequests = parseIntArg('--chaos-requests', 20);
  const timeoutRequests = parseIntArg('--timeout-requests', 12);

  const report = {
    generated_at: new Date().toISOString(),
    benchmark: {
      duration_seconds: durationSeconds,
      connections,
      chaos_requests: chaosRequests,
      timeout_requests: timeoutRequests,
    },
    scenarios: {
      stress: await runStressScenario(durationSeconds, connections),
      chaos_503: await runChaos503Scenario(chaosRequests),
      chaos_timeout: await runChaosTimeoutScenario(timeoutRequests),
    },
  };

  report.gates = {
    stress_no_errors: report.scenarios.stress.errors === 0 && report.scenarios.stress.timeouts === 0,
    chaos_503_circuit_opened: report.scenarios.chaos_503.circuit_open_fast_fails > 0,
    chaos_timeout_circuit_opened: report.scenarios.chaos_timeout.circuit_open_fast_fails > 0,
  };

  fs.mkdirSync(path.join(process.cwd(), 'metrics'), { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:]/g, '-');
  const outputPath = path.join(process.cwd(), 'metrics', `reliability-${timestamp}.json`);
  fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  printSummary(report);
  process.stdout.write(`Saved report: ${outputPath}\n`);
}

main().catch((error) => {
  process.stderr.write(`Reliability proof failed: ${error.message}\n`);
  process.exit(1);
});
