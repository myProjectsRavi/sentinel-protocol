const { OutputSchemaValidator } = require('../../src/egress/output-schema-validator');

function baseValidatorConfig(mode = 'monitor') {
  return {
    enabled: true,
    mode,
    default_schema: 'chat_schema',
    schemas: {
      chat_schema: {
        type: 'object',
        required: ['id', 'choices'],
        additionalProperties: false,
        properties: {
          id: { type: 'string' },
          choices: { type: 'array' },
        },
      },
    },
  };
}

describe('output schema validator', () => {
  test('passes valid response for declared schema', () => {
    const validator = new OutputSchemaValidator(baseValidatorConfig('monitor'));
    const result = validator.validateBuffer({
      headers: {},
      contentType: 'application/json',
      bodyBuffer: Buffer.from(JSON.stringify({ id: 'a', choices: [] }), 'utf8'),
      effectiveMode: 'enforce',
    });
    expect(result.valid).toBe(true);
    expect(result.shouldWarn).toBe(false);
  });

  test('fails when required field is missing', () => {
    const validator = new OutputSchemaValidator(baseValidatorConfig('monitor'));
    const result = validator.validateBuffer({
      headers: {},
      contentType: 'application/json',
      bodyBuffer: Buffer.from(JSON.stringify({ id: 'a' }), 'utf8'),
      effectiveMode: 'enforce',
    });
    expect(result.valid).toBe(false);
    expect(result.mismatches.some((item) => item.code === 'required_missing')).toBe(true);
  });

  test('fails when field type mismatches declared type', () => {
    const validator = new OutputSchemaValidator(baseValidatorConfig('monitor'));
    const result = validator.validateBuffer({
      headers: {},
      contentType: 'application/json',
      bodyBuffer: Buffer.from(JSON.stringify({ id: 123, choices: [] }), 'utf8'),
      effectiveMode: 'enforce',
    });
    expect(result.valid).toBe(false);
    expect(result.mismatches.some((item) => item.code === 'type_mismatch')).toBe(true);
  });

  test('flags extra fields when additionalProperties=false', () => {
    const validator = new OutputSchemaValidator(baseValidatorConfig('monitor'));
    const result = validator.validateBuffer({
      headers: {},
      contentType: 'application/json',
      bodyBuffer: Buffer.from(JSON.stringify({ id: 'a', choices: [], leaked: 'secret' }), 'utf8'),
      effectiveMode: 'enforce',
    });
    expect(result.valid).toBe(false);
    expect(result.extraFields).toContain('$.leaked');
  });

  test('monitor mode emits warning and forwards response', () => {
    const validator = new OutputSchemaValidator(baseValidatorConfig('monitor'));
    const result = validator.validateBuffer({
      headers: {},
      contentType: 'application/json',
      bodyBuffer: Buffer.from(JSON.stringify({ id: 'a' }), 'utf8'),
      effectiveMode: 'enforce',
    });
    expect(result.shouldWarn).toBe(true);
    expect(result.shouldBlock).toBe(false);
  });

  test('enforce mode blocks response on validation failure', () => {
    const validator = new OutputSchemaValidator(baseValidatorConfig('block'));
    const result = validator.validateBuffer({
      headers: {},
      contentType: 'application/json',
      bodyBuffer: Buffer.from(JSON.stringify({ id: 'a' }), 'utf8'),
      effectiveMode: 'enforce',
    });
    expect(result.shouldWarn).toBe(true);
    expect(result.shouldBlock).toBe(true);
  });

  test('handles malformed non-json response without throw', () => {
    const validator = new OutputSchemaValidator(baseValidatorConfig('block'));
    const result = validator.validateBuffer({
      headers: {},
      contentType: 'application/json',
      bodyBuffer: Buffer.from('{"id":', 'utf8'),
      effectiveMode: 'enforce',
    });
    expect(result.valid).toBe(false);
    expect(result.mismatches.some((item) => item.code === 'response_parse_error')).toBe(true);
  });
});
