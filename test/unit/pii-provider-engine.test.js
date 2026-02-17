const { PIIProviderEngine } = require('../../src/pii/provider-engine');
const { PIIScanner } = require('../../src/engines/pii-scanner');

function basePiiConfig(overrides = {}) {
  return {
    provider_mode: 'local',
    max_scan_bytes: 262144,
    rapidapi: {
      endpoint: 'https://pii-firewall-edge.p.rapidapi.com/redact',
      host: 'pii-firewall-edge.p.rapidapi.com',
      timeout_ms: 2000,
      request_body_field: 'text',
      fallback_to_local: true,
      allow_non_rapidapi_host: false,
      api_key: '',
      extra_body: {},
    },
    ...overrides,
  };
}

describe('PIIProviderEngine', () => {
  test('local mode uses local scanner', async () => {
    const scanner = new PIIScanner();
    const engine = new PIIProviderEngine({
      piiConfig: basePiiConfig({ provider_mode: 'local' }),
      localScanner: scanner,
    });

    const result = await engine.scan('openai key sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefgh');
    expect(result.meta.providerUsed).toBe('local');
    expect(result.result.findings.length).toBeGreaterThan(0);
  });

  test('rapidapi mode falls back to local on rapid error', async () => {
    const scanner = new PIIScanner();
    const rapidClient = {
      scan: jest.fn(async () => {
        const error = new Error('quota exceeded');
        error.kind = 'rapidapi_quota';
        throw error;
      }),
    };

    const engine = new PIIProviderEngine({
      piiConfig: basePiiConfig({ provider_mode: 'rapidapi' }),
      localScanner: scanner,
      rapidClient,
    });

    const result = await engine.scan('openai key sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefgh');
    expect(result.meta.fallbackUsed).toBe(true);
    expect(result.meta.fallbackReason).toBe('rapidapi_quota');
    expect(result.meta.providerUsed).toBe('local');
    expect(result.result.findings.length).toBeGreaterThan(0);
  });

  test('hybrid mode merges local and rapid findings', async () => {
    const scanner = new PIIScanner();
    const rapidClient = {
      scan: jest.fn(async () => ({
        findings: [
          {
            id: 'rapid_email',
            severity: 'medium',
            value: 'john@example.com',
          },
        ],
        redactedText: 'user [REDACTED_EMAIL]',
        highestSeverity: 'medium',
        scanTruncated: false,
      })),
    };

    const engine = new PIIProviderEngine({
      piiConfig: basePiiConfig({ provider_mode: 'hybrid' }),
      localScanner: scanner,
      rapidClient,
    });

    const result = await engine.scan('openai key sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefgh and email john@example.com');
    expect(result.meta.providerUsed).toBe('hybrid');
    expect(result.result.findings.some((f) => f.id === 'rapid_email')).toBe(true);
    expect(result.result.findings.some((f) => f.id === 'openai_api_key')).toBe(true);
  });
});
