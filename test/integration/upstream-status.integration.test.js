const fs = require('fs');
const os = require('os');
const path = require('path');
const request = require('supertest');

process.env.SENTINEL_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-upstream-status-'));

const { SentinelServer } = require('../../src/server');
const { STATUS_FILE_PATH, AUDIT_LOG_PATH } = require('../../src/utils/paths');

function createBaseConfig() {
  return {
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
          enabled: false,
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
      max_scan_bytes: 262144,
      severity_actions: {
        critical: 'block',
        high: 'block',
        medium: 'redact',
        low: 'log',
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
    logging: { level: 'info' },
  };
}

function readLatestAuditEvent() {
  const lines = fs
    .readFileSync(AUDIT_LOG_PATH, 'utf8')
    .split(/\r?\n/)
    .filter(Boolean);
  return JSON.parse(lines[lines.length - 1]);
}

const failureCases = [
  ['429 response', 429, 'UPSTREAM_RATE_LIMITED', 'status', 'closed'],
  ['5xx response', 503, 'UPSTREAM_5XX', 'status', 'closed'],
  ['timeout', 504, 'UPSTREAM_TIMEOUT', 'timeout', 'closed'],
  ['transport error', 502, 'UPSTREAM_TRANSPORT_ERROR', 'transport', 'closed'],
  ['circuit open', 503, 'UPSTREAM_CIRCUIT_OPEN', 'circuit_open', 'open'],
];

describe('upstream failure status accounting', () => {
  let sentinel;

  beforeEach(() => {
    for (const filePath of [STATUS_FILE_PATH, AUDIT_LOG_PATH]) {
      try {
        fs.unlinkSync(filePath);
      } catch {
        // file may not exist yet
      }
    }
  });

  afterEach(async () => {
    if (sentinel) {
      await sentinel.stop();
      sentinel = null;
    }
  });

  test.each(failureCases)(
    'increments persisted status exactly once for %s',
    async (_name, status, errorCode, failureType, circuitState) => {
      sentinel = new SentinelServer(createBaseConfig());
      sentinel.upstreamClient.forwardRequest = jest.fn(async ({ correlationId }) => ({
        ok: false,
        status,
        isStream: false,
        body: {
          error: errorCode,
          message: `simulated ${failureType}`,
        },
        responseHeaders: status === 429 ? { 'retry-after': '1' } : {},
        diagnostics: {
          errorSource: 'upstream',
          upstreamError: true,
          provider: 'openai',
          retryCount: 0,
          circuitState,
          correlationId,
        },
        route: {
          selectedProvider: 'openai',
          selectedTarget: 'openai',
          selectedBreakerKey: 'openai',
          failoverUsed: false,
          failoverChain: [],
        },
        failureType,
      }));

      const server = sentinel.start();
      const response = await request(server).get('/v1/models');

      expect(response.status).toBe(status);
      expect(response.body.error).toBe(errorCode);
      expect(response.headers['x-sentinel-error-source']).toBe('upstream');
      expect(sentinel.stats.upstream_errors).toBe(1);

      const persisted = JSON.parse(fs.readFileSync(STATUS_FILE_PATH, 'utf8'));
      expect(persisted.counters.upstream_errors).toBe(1);
      expect(persisted.service_status).toBe('running');

      await sentinel.auditLogger.flush();
      const audit = readLatestAuditEvent();
      expect(audit.decision).toBe('upstream_error');
      expect(audit.response_status).toBe(status);
      expect(audit.provider).toBe('openai');
    }
  );
});
