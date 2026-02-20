const { PassThrough, Writable } = require('stream');

const { PIIScanner } = require('../../src/engines/pii-scanner');

jest.mock('../../src/egress/sse-redaction-transform', () => {
  const { Transform } = require('stream');
  class MockSSERedactionTransform extends Transform {
    constructor(options = {}) {
      super();
      this.options = options;
      this.blockEmitted = false;
    }

    _transform(chunk, encoding, callback) {
      if (!this.blockEmitted && typeof this.options.onDetection === 'function') {
        this.blockEmitted = true;
        this.options.onDetection({
          action: 'block',
          severity: 'critical',
          findings: [{ id: 'mock_pii' }],
          projectedRedaction: '[REDACTED_MOCK]',
        });
      }
      callback(null, chunk);
    }
  }
  return { SSERedactionTransform: MockSSERedactionTransform };
});

const { runStreamEgressStage } = require('../../src/stages/egress/stream-egress-stage');

function waitFor(predicate, timeoutMs = 2000, intervalMs = 10) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const tick = () => {
      if (predicate()) {
        resolve();
        return;
      }
      if (Date.now() - start >= timeoutMs) {
        reject(new Error('timeout waiting for condition'));
        return;
      }
      setTimeout(tick, intervalMs);
    };
    tick();
  });
}

class MockResponse extends Writable {
  constructor() {
    super();
    this.headers = {};
    this.statusCode = 200;
    this.on('error', () => {});
  }

  _write(chunk, encoding, callback) {
    this.headersSent = true;
    callback();
  }

  status(code) {
    this.statusCode = code;
    return this;
  }

  setHeader(name, value) {
    this.headers[String(name).toLowerCase()] = String(value);
  }

  getHeader(name) {
    return this.headers[String(name).toLowerCase()];
  }

  addTrailers(trailers) {
    this.trailers = {
      ...(this.trailers || {}),
      ...(trailers || {}),
    };
  }
}

function createServer({ budgetCharge } = {}) {
  return {
    config: {
      version: 1,
      pii: {
        severity_actions: {
          critical: 'block',
          high: 'block',
          medium: 'redact',
          low: 'log',
        },
      },
    },
    stats: {
      blocked_total: 0,
      egress_detected: 0,
      egress_blocked: 0,
      egress_stream_redacted: 0,
      egress_entropy_detected: 0,
      egress_entropy_redacted: 0,
      egress_entropy_blocked: 0,
      pii_vault_detokenized: 0,
      upstream_errors: 0,
      warnings_total: 0,
      budget_charged_usd: 0,
    },
    piiScanner: new PIIScanner({
      maxScanBytes: 262144,
      regexSafetyCapBytes: 51200,
    }),
    piiVault: {
      observability: false,
      createEgressStreamTransform: jest.fn(() => null),
    },
    provenanceSigner: {
      signStreamTrailers: false,
      createStreamContext: jest.fn(() => null),
      isEnabled: jest.fn(() => false),
    },
    budgetStore: {
      recordStream: jest.fn(async () => ({
        charged: true,
        chargedUsd: 0.012,
        spentUsd: 1.23,
        remainingUsd: 8.77,
        ...(budgetCharge || {}),
      })),
    },
    latencyNormalizer: {
      recordSuccess: jest.fn(),
    },
    auditLogger: {
      write: jest.fn(),
    },
    writeStatus: jest.fn(),
  };
}

function createStageInput(overrides = {}) {
  const upstreamBody = new PassThrough();
  upstreamBody.on('error', () => {});
  return {
    upstreamBody,
    args: {
      server: createServer(),
      res: new MockResponse(),
      upstream: {
        isStream: true,
        status: 200,
        bodyStream: upstreamBody,
        responseHeaders: { 'content-type': 'application/json' },
        route: { failoverUsed: false },
      },
      egressConfig: {
        enabled: false,
        streamEnabled: false,
        streamBlockMode: 'redact',
        maxScanBytes: 262144,
        sseLineMaxBytes: 16384,
        entropy: { enabled: false, mode: 'monitor' },
      },
      effectiveMode: 'enforce',
      correlationId: 'cid-stream-test',
      routedProvider: 'openai',
      piiVaultSessionKey: 'sess-1',
      warnings: [],
      bodyBuffer: Buffer.from('{"messages":[{"role":"user","content":"hello"}]}', 'utf8'),
      requestStart: Date.now() - 10,
      start: Date.now() - 10,
      replayedFromVcr: false,
      replayedFromSemanticCache: false,
      routePlan: {
        routeSource: 'default',
        selectedGroup: '',
        desiredContract: 'passthrough',
        requestedTarget: 'openai',
      },
      honeytokenDecision: null,
      canaryToolDecision: null,
      canaryTriggered: null,
      parallaxDecision: null,
      cognitiveRollbackDecision: null,
      omniShieldDecision: null,
      intentDriftDecision: null,
      sandboxDecision: null,
      redactedCount: 0,
      piiTypes: [],
      routedTarget: 'https://api.openai.com/v1/chat/completions',
      finalizeRequestTelemetry: jest.fn(),
      ...(overrides || {}),
    },
  };
}

describe('runStreamEgressStage audit parity', () => {
  test('writes forwarded_stream audit payload with stream egress extension fields', async () => {
    const { upstreamBody, args } = createStageInput();

    const result = await runStreamEgressStage(args);
    expect(result.handled).toBe(true);

    upstreamBody.end(Buffer.from('{"ok":true}', 'utf8'));

    await waitFor(() => args.server.auditLogger.write.mock.calls.length === 1);
    const payload = args.server.auditLogger.write.mock.calls[0][0];

    expect(payload.decision).toBe('forwarded_stream');
    expect(payload.response_status).toBe(200);
    expect(payload.egress_pii_types).toEqual([]);
    expect(payload.egress_entropy_findings).toEqual([]);
    expect(payload.egress_projected_redaction).toBeUndefined();
    expect(payload.egress_block_severity).toBeUndefined();
    expect(payload.egress_entropy_mode).toBeUndefined();
    expect(payload.egress_entropy_projected_redaction).toBeUndefined();
    expect(args.finalizeRequestTelemetry).toHaveBeenCalledWith(
      expect.objectContaining({
        decision: 'forwarded_stream',
        status: 200,
        providerName: 'openai',
      })
    );
  });

  test('writes blocked_egress_stream audit payload on terminate-mode stream block', async () => {
    const { upstreamBody, args } = createStageInput();
    args.upstream.responseHeaders['content-type'] = 'text/event-stream';
    args.egressConfig = {
      enabled: true,
      streamEnabled: true,
      streamBlockMode: 'terminate',
      maxScanBytes: 65536,
      sseLineMaxBytes: 16384,
      entropy: { enabled: false, mode: 'monitor' },
    };

    const result = await runStreamEgressStage(args);
    expect(result.handled).toBe(true);

    upstreamBody.write(Buffer.from('data: test\n\n', 'utf8'));

    await waitFor(() =>
      args.server.auditLogger.write.mock.calls.some((call) => call[0]?.decision === 'blocked_egress_stream')
    );
    const blocked = args.server.auditLogger.write.mock.calls.find((call) => call[0]?.decision === 'blocked_egress_stream')[0];

    expect(blocked.response_status).toBe(499);
    expect(blocked.reasons).toContain('egress_stream_blocked');
    expect(blocked.egress_pii_types).toEqual(['mock_pii']);
    expect(blocked.egress_projected_redaction).toBe('[REDACTED_MOCK]');
    expect(blocked.egress_block_severity).toBe('critical');
    expect(blocked.egress_entropy_findings).toEqual([]);
    expect(args.finalizeRequestTelemetry).toHaveBeenCalledWith(
      expect.objectContaining({
        decision: 'blocked_egress',
        status: 499,
        providerName: 'openai',
      })
    );
  });

  test('writes stream_error payload for non-blocked stream failures', async () => {
    const { upstreamBody, args } = createStageInput();

    const result = await runStreamEgressStage(args);
    expect(result.handled).toBe(true);

    const streamFailure = new Error('UPSTREAM_STREAM_FAILURE');
    upstreamBody.destroy(streamFailure);

    await waitFor(() =>
      args.server.auditLogger.write.mock.calls.some((call) => call[0]?.decision === 'stream_error')
    );
    const streamError = args.server.auditLogger.write.mock.calls.find((call) => call[0]?.decision === 'stream_error')[0];

    expect(streamError.reasons).toEqual(['UPSTREAM_STREAM_FAILURE']);
    expect(streamError.response_status).toBe(200);
    expect(streamError.egress_pii_types).toBeUndefined();
    expect(streamError.egress_entropy_findings).toBeUndefined();
    expect(args.server.stats.upstream_errors).toBe(1);
    expect(args.finalizeRequestTelemetry).toHaveBeenCalledWith(
      expect.objectContaining({
        decision: 'stream_error',
        status: 200,
        providerName: 'openai',
        error: streamFailure,
      })
    );
  });
});
