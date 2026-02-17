const { validateCustomTargetUrl } = require('../../src/upstream/router');

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
    ).resolves.toContain('127.0.0.1:9000');
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
});
