const { OmniShield, parseDataImageUrl, approximateBase64Bytes } = require('../../src/engines/omni-shield');

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
});
