const fs = require('fs');
const path = require('path');
const { OmniShield, parseDataImageUrl, approximateBase64Bytes } = require('../../src/engines/omni-shield');

const CHAOS_FIXTURES = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'hardening', 'omni-plugin-chaos-cases.json'), 'utf8')
);

describe('OmniShield', () => {
  test('parses data image urls', () => {
    const parsed = parseDataImageUrl('data:image/png;base64,QUJDRA==');
    expect(parsed.mediaType).toBe('image/png');
    expect(approximateBase64Bytes(parsed.base64Data)).toBeGreaterThan(0);
  });

  test('detects image payloads in monitor mode without blocking', () => {
    const shield = new OmniShield({
      enabled: true,
      mode: 'monitor',
      allow_remote_image_urls: false,
      target_roles: ['user'],
    });

    const decision = shield.inspect({
      effectiveMode: 'enforce',
      bodyJson: {
        messages: [
          {
            role: 'user',
            content: [
              {
                type: 'image_url',
                image_url: {
                  url: 'https://example.com/screenshot.png',
                },
              },
            ],
          },
        ],
      },
    });

    expect(decision.detected).toBe(true);
    expect(decision.shouldBlock).toBe(false);
  });

  test('blocks policy-violating image payloads in block+enforce mode', () => {
    const shield = new OmniShield({
      enabled: true,
      mode: 'block',
      allow_remote_image_urls: false,
      target_roles: ['user'],
    });

    const decision = shield.inspect({
      effectiveMode: 'enforce',
      bodyJson: {
        messages: [
          {
            role: 'user',
            content: [
              {
                type: 'image_url',
                image_url: {
                  url: 'https://example.com/screenshot.png',
                },
              },
            ],
          },
        ],
      },
    });

    expect(decision.detected).toBe(true);
    expect(decision.shouldBlock).toBe(true);
    expect(decision.violating_findings.length).toBeGreaterThan(0);
  });

  test('plugin sanitizes base64 image payloads when explicitly enabled', async () => {
    const shield = new OmniShield({
      enabled: true,
      mode: 'monitor',
      allow_base64_images: true,
      plugin: {
        enabled: true,
        mode: 'always',
        provider: 'builtin_mask',
        fail_closed: false,
      },
    });
    const bodyJson = {
      messages: [
        {
          role: 'user',
          content: [
            {
              type: 'image_url',
              image_url: {
                url: 'data:image/png;base64,QUJDRA==',
              },
            },
          ],
        },
      ],
    };

    const inspected = shield.inspect({
      effectiveMode: 'monitor',
      bodyJson,
    });
    const sanitized = await shield.sanitizePayload({
      bodyJson,
      findings: inspected.findings,
      effectiveMode: 'monitor',
    });

    expect(sanitized.applied).toBe(true);
    const outUrl = sanitized.bodyJson.messages[0].content[0].image_url.url;
    expect(outUrl).toContain('data:image/png;base64,');
    expect(outUrl).not.toContain('QUJDRA==');
  });

  test('plugin can fail closed when unsupported findings remain', async () => {
    const shield = new OmniShield({
      enabled: true,
      mode: 'monitor',
      plugin: {
        enabled: true,
        mode: 'enforce',
        provider: 'builtin_mask',
        fail_closed: true,
      },
    });
    const bodyJson = {
      messages: [
        {
          role: 'user',
          content: [
            {
              type: 'image_url',
              image_url: {
                url: 'https://example.com/private.png',
              },
            },
          ],
        },
      ],
    };
    const inspected = shield.inspect({
      effectiveMode: 'enforce',
      bodyJson,
    });
    const sanitized = await shield.sanitizePayload({
      bodyJson,
      findings: inspected.findings,
      effectiveMode: 'enforce',
    });
    expect(sanitized.applied).toBe(false);
    expect(sanitized.shouldBlock).toBe(true);
  });

  test('plugin fail-closed chaos fixtures', async () => {
    const bodyJson = {
      messages: [
        {
          role: 'user',
          content: [
            {
              type: 'image_url',
              image_url: {
                url: 'https://example.com/private.png',
              },
            },
          ],
        },
      ],
    };

    for (const fixture of CHAOS_FIXTURES) {
      const shield = new OmniShield({
        enabled: true,
        mode: 'monitor',
        plugin: {
          enabled: true,
          mode: 'enforce',
          provider: 'custom',
          fail_closed: fixture.fail_closed === true,
          timeout_ms: 50,
        },
      });
      switch (fixture.behavior) {
        case 'throw_sync':
          shield.loadedPlugin = () => {
            throw new Error('sync_boom');
          };
          break;
        case 'reject_async':
          shield.loadedPlugin = async () => {
            throw new Error('async_boom');
          };
          break;
        case 'timeout_async':
          shield.loadedPlugin = () => new Promise(() => {});
          break;
        case 'malformed_result':
          shield.loadedPlugin = () => 'bad-result';
          break;
        case 'unsupported':
          shield.loadedPlugin = () => ({
            applied: false,
            rewrites: 0,
            unsupported: 2,
            bodyJson,
          });
          break;
        default:
          throw new Error(`Unknown chaos fixture behavior: ${fixture.behavior}`);
      }

      const inspected = shield.inspect({
        effectiveMode: 'enforce',
        bodyJson,
      });
      const sanitized = await shield.sanitizePayload({
        bodyJson,
        findings: inspected.findings,
        effectiveMode: 'enforce',
      });
      expect(Boolean(sanitized.shouldBlock)).toBe(Boolean(fixture.expect_block));
      expect(String(sanitized.reason)).toBe(String(fixture.expect_reason));
    }
  });
});
