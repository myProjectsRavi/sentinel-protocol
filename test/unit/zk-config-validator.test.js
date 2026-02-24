const { ZKConfigValidator } = require('../../src/config/zk-config-validator');

describe('ZKConfigValidator', () => {
  test('detects secrets and creates proof', () => {
    const validator = new ZKConfigValidator({
      enabled: true,
      hmac_key: 'test-hmac-key',
    });
    const result = validator.evaluate({
      runtime: {
        prompt_rebuff: {
          enabled: true,
        },
      },
      api_key: 'sk-test-secret-1234567890',
    }, {
      knownRuntimeKeys: ['prompt_rebuff'],
    });

    expect(result.valid).toBe(false);
    expect(result.findings.some((item) => item.code.includes('secret'))).toBe(true);
    expect(result.proof.algorithm).toBe('hmac-sha256');
    expect(typeof result.proof.signature).toBe('string');
    expect(result.proof.signature.length).toBe(64);
  });

  test('redacts secret fields in safe export', () => {
    const validator = new ZKConfigValidator({
      enabled: true,
      redaction_text: '[MASKED]',
    });
    const exported = validator.safeExport({
      runtime: {},
      auth_token: 'Bearer abcdefghijklmnop',
    });

    expect(exported.redacted_config.auth_token).toBe('[MASKED]');
  });
});
