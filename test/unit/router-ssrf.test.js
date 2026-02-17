const { validateCustomTargetUrl, resolveProvider } = require('../../src/upstream/router');

describe('custom target SSRF protections', () => {
  test('rejects when custom targets are disabled', async () => {
    await expect(
      validateCustomTargetUrl('https://api.example.com', {
        enabled: false,
        allowlist: ['api.example.com'],
        block_private_networks: true,
      })
    ).rejects.toThrow(/disabled/);
  });

  test('rejects non-allowlisted host', async () => {
    await expect(
      validateCustomTargetUrl('https://evil.example.net', {
        enabled: true,
        allowlist: ['api.example.com'],
        block_private_networks: false,
      })
    ).rejects.toThrow(/not allowlisted/);
  });

  test('rejects private IP when block_private_networks is enabled', async () => {
    await expect(
      validateCustomTargetUrl('http://127.0.0.1:9000', {
        enabled: true,
        allowlist: ['127.0.0.1'],
        block_private_networks: true,
      })
    ).rejects.toThrow(/Blocked private/);
  });

  test('allows custom URL when allowlisted and private blocking disabled', async () => {
    await expect(
      validateCustomTargetUrl('http://127.0.0.1:9000', {
        enabled: true,
        allowlist: ['127.0.0.1'],
        block_private_networks: false,
      })
    ).resolves.toMatchObject({
      url: 'http://127.0.0.1:9000/',
      hostname: '127.0.0.1',
      hostHeader: '127.0.0.1:9000',
      resolvedIp: '127.0.0.1',
      resolvedFamily: 4,
    });
  });

  test('rejects URL with credentials', async () => {
    await expect(
      validateCustomTargetUrl('https://user:pass@api.example.com', {
        enabled: true,
        allowlist: ['api.example.com'],
        block_private_networks: true,
      })
    ).rejects.toThrow(/must not include credentials/);
  });

  test('resolveProvider returns pinned metadata for custom targets', async () => {
    const req = {
      headers: {
        'x-sentinel-target': 'custom',
        'x-sentinel-custom-url': 'http://127.0.0.1:9100',
      },
    };

    const result = await resolveProvider(req, {
      runtime: {
        upstream: {
          custom_targets: {
            enabled: true,
            allowlist: ['127.0.0.1'],
            block_private_networks: false,
          },
        },
      },
    });

    expect(result).toMatchObject({
      provider: 'custom',
      baseUrl: 'http://127.0.0.1:9100/',
      upstreamHostname: '127.0.0.1',
      upstreamHostHeader: '127.0.0.1:9100',
      resolvedIp: '127.0.0.1',
      resolvedFamily: 4,
    });
  });
});
