const { mergePipelineWarnings, rejectUnsupportedMethod } = require('../../src/stages/policy-stage');
const { applyForwardingHeaders } = require('../../src/stages/egress-stage');
const { safeJsonParse, tryParseJson } = require('../../src/stages/shared');

function createMockResponse() {
  const headers = {};
  return {
    headers,
    setHeader(name, value) {
      headers[String(name).toLowerCase()] = String(value);
    },
    getHeader(name) {
      return headers[String(name).toLowerCase()];
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
  };
}

describe('stage modules', () => {
  test('mergePipelineWarnings appends unique warnings and increments counter', () => {
    const warnings = ['existing'];
    const stats = { warnings_total: 0 };
    mergePipelineWarnings({
      warnings,
      pluginWarnings: ['existing', 'new-warning'],
      stats,
    });
    expect(warnings).toEqual(['existing', 'new-warning']);
    expect(stats.warnings_total).toBe(1);
  });

  test('rejectUnsupportedMethod handles TRACE', () => {
    const res = createMockResponse();
    const finalize = jest.fn();
    const handled = rejectUnsupportedMethod({
      method: 'TRACE',
      res,
      correlationId: 'cid',
      finalizeRequestTelemetry: finalize,
    });
    expect(handled).toBe(true);
    expect(res.statusCode).toBe(405);
    expect(res.body.error).toBe('METHOD_NOT_ALLOWED');
    expect(finalize).toHaveBeenCalledTimes(1);
  });

  test('applyForwardingHeaders sets warning and provider headers', () => {
    const res = createMockResponse();
    applyForwardingHeaders({
      res,
      warnings: ['w1', 'w2'],
      piiProviderUsed: 'local',
      semanticCacheHeader: 'miss',
    });
    expect(res.getHeader('x-sentinel-warning')).toBe('w1,w2');
    expect(res.getHeader('x-sentinel-pii-provider')).toBe('local');
    expect(res.getHeader('x-sentinel-semantic-cache')).toBe('miss');
  });

  test('shared JSON helpers are safe', () => {
    expect(safeJsonParse('{')).toBeNull();
    expect(tryParseJson('{').ok).toBe(false);
    expect(tryParseJson('{"a":1}').ok).toBe(true);
  });
});
