const { RapidApiPIIClient } = require('../../src/pii/rapidapi-client');

describe('RapidApiPIIClient', () => {
  let originalFetch;
  let originalEnvKey;

  beforeEach(() => {
    originalFetch = global.fetch;
    originalEnvKey = process.env.SENTINEL_RAPIDAPI_KEY;
    delete process.env.SENTINEL_RAPIDAPI_KEY;
  });

  afterEach(() => {
    global.fetch = originalFetch;
    if (originalEnvKey === undefined) {
      delete process.env.SENTINEL_RAPIDAPI_KEY;
    } else {
      process.env.SENTINEL_RAPIDAPI_KEY = originalEnvKey;
    }
  });

  test('uses request header key with highest priority', async () => {
    global.fetch = jest.fn(async () => {
      return new Response(
        JSON.stringify({
          findings: [{ type: 'email', severity: 'high', value: 'john@example.com' }],
          redacted_text: 'hello [REDACTED_EMAIL]',
        }),
        {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }
      );
    });

    process.env.SENTINEL_RAPIDAPI_KEY = 'env-key';
    const client = new RapidApiPIIClient({
      endpoint: 'https://pii-firewall-edge.p.rapidapi.com/redact',
      host: 'pii-firewall-edge.p.rapidapi.com',
      timeout_ms: 2000,
      request_body_field: 'text',
      api_key: 'config-key',
    });

    const result = await client.scan('hello john@example.com', {
      'x-sentinel-rapidapi-key': 'header-key',
    });

    expect(global.fetch).toHaveBeenCalledTimes(1);
    const [url, options] = global.fetch.mock.calls[0];
    expect(url).toBe('https://pii-firewall-edge.p.rapidapi.com/redact');
    expect(options.headers['x-rapidapi-key']).toBe('header-key');
    expect(options.headers['x-rapidapi-host']).toBe('pii-firewall-edge.p.rapidapi.com');
    expect(result.highestSeverity).toBe('high');
  });

  test('throws rapidapi_no_key when no key source is present', async () => {
    const client = new RapidApiPIIClient({
      endpoint: 'https://pii-firewall-edge.p.rapidapi.com/redact',
      host: 'pii-firewall-edge.p.rapidapi.com',
      timeout_ms: 2000,
      request_body_field: 'text',
      api_key: '',
    });

    await expect(client.scan('hello world', {})).rejects.toMatchObject({
      kind: 'rapidapi_no_key',
    });
  });

  test('rejects non-rapidapi endpoint host by default', async () => {
    const client = new RapidApiPIIClient({
      endpoint: 'https://example.com/redact',
      timeout_ms: 2000,
      request_body_field: 'text',
      api_key: 'abc',
    });

    await expect(client.scan('hello world', {})).rejects.toThrow(/rapidapi.com/i);
  });

  test('uses in-memory cache to avoid duplicate upstream calls for identical text', async () => {
    global.fetch = jest.fn(async () => {
      return new Response(
        JSON.stringify({
          findings: [{ type: 'email', severity: 'medium', value: 'john@example.com' }],
          redacted_text: 'hello [REDACTED_EMAIL_ADDRESS]',
        }),
        {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }
      );
    });

    const client = new RapidApiPIIClient({
      endpoint: 'https://pii-firewall-edge.p.rapidapi.com/redact',
      host: 'pii-firewall-edge.p.rapidapi.com',
      timeout_ms: 2000,
      max_timeout_ms: 1500,
      cache_max_entries: 32,
      cache_ttl_ms: 10000,
      request_body_field: 'text',
      api_key: 'config-key',
    });

    const first = await client.scan('hello john@example.com', {});
    const second = await client.scan('hello john@example.com', {});

    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(first.cacheHit).toBe(false);
    expect(second.cacheHit).toBe(true);
  });

  test('caps effective timeout to max_timeout_ms', () => {
    const client = new RapidApiPIIClient({
      endpoint: 'https://pii-firewall-edge.p.rapidapi.com/redact',
      host: 'pii-firewall-edge.p.rapidapi.com',
      timeout_ms: 5000,
      max_timeout_ms: 1200,
      request_body_field: 'text',
      api_key: 'config-key',
    });

    expect(client.timeoutMs).toBe(1200);
  });
});
