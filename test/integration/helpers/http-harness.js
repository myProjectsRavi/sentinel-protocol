const fs = require('fs');
const os = require('os');
const path = require('path');
const express = require('express');

function createSentinelHome(prefix = 'sentinel-home-int-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  process.env.SENTINEL_HOME = dir;
  return dir;
}

function deepMerge(base, extra) {
  if (!extra || typeof extra !== 'object' || Array.isArray(extra)) {
    return extra === undefined ? base : extra;
  }

  const out = { ...base };
  for (const [key, value] of Object.entries(extra)) {
    if (
      value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      base &&
      typeof base[key] === 'object' &&
      !Array.isArray(base[key])
    ) {
      out[key] = deepMerge(base[key], value);
      continue;
    }
    out[key] = value;
  }
  return out;
}

function createBaseConfig(overrides = {}) {
  const base = {
    version: 1,
    mode: 'enforce',
    proxy: {
      host: '127.0.0.1',
      port: 0,
      timeout_ms: 30000,
    },
    runtime: {
      fail_open: false,
      scanner_error_action: 'allow',
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
    },
    injection: {
      enabled: true,
      threshold: 0.8,
      max_scan_bytes: 131072,
      action: 'block',
    },
    rules: [],
    whitelist: { domains: [] },
    logging: { level: 'info' },
  };

  return deepMerge(base, overrides);
}

async function startUpstream(handler) {
  const app = express();
  app.use(express.raw({ type: '*/*' }));
  app.all('*', handler);

  const server = await new Promise((resolve, reject) => {
    const instance = app.listen(0, '127.0.0.1');
    const onListening = () => {
      instance.off('error', onError);
      resolve(instance);
    };
    const onError = (error) => {
      instance.off('listening', onListening);
      reject(error);
    };
    instance.once('listening', onListening);
    instance.once('error', onError);
  });

  const port = server.address().port;
  return {
    server,
    url: `http://127.0.0.1:${port}`,
  };
}

async function closeServer(server) {
  if (!server) {
    return;
  }
  await new Promise((resolve) => server.close(resolve));
}

module.exports = {
  createSentinelHome,
  createBaseConfig,
  startUpstream,
  closeServer,
};
