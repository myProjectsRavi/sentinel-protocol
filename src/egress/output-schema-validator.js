const { isTextualContentType } = require('./response-scanner');
const { clampPositiveInt, normalizeMode } = require('../utils/primitives');

const VALID_NODE_KEYS = new Set(['type', 'required', 'properties', 'enum', 'additionalProperties']);
const SUPPORTED_TYPES = new Set(['object', 'array', 'string', 'number', 'integer', 'boolean', 'null']);

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function normalizeConfig(input = {}) {
  const config = isObject(input) ? input : {};
  const schemas = isObject(config.schemas) ? config.schemas : {};

  return {
    enabled: config.enabled === true,
    mode: normalizeMode(config.mode, 'monitor', ['monitor', 'block']),
    defaultSchema: String(config.default_schema || '').trim(),
    schemaHeader: String(config.schema_header || 'x-sentinel-output-schema').toLowerCase(),
    maxBodyBytes: clampPositiveInt(config.max_body_bytes, 1024 * 1024, 128, 16 * 1024 * 1024),
    schemas,
  };
}

function normalizePath(path) {
  const raw = String(path || '$').replace(/\.+/g, '.');
  return raw.startsWith('$') ? raw : `$.${raw}`;
}

function detectType(value) {
  if (value === null) {
    return 'null';
  }
  if (Array.isArray(value)) {
    return 'array';
  }
  if (Number.isInteger(value)) {
    return 'integer';
  }
  return typeof value;
}

function addError(errors, path, code, message) {
  errors.push({
    path: normalizePath(path),
    code,
    message,
  });
}

function validateSchemaNodeShape(node, path = '$', errors = []) {
  if (!isObject(node)) {
    addError(errors, path, 'schema_invalid', 'schema node must be an object');
    return errors;
  }

  for (const key of Object.keys(node)) {
    if (!VALID_NODE_KEYS.has(key)) {
      addError(errors, path, 'schema_unsupported_key', `unsupported schema key: ${key}`);
    }
  }

  if (node.type !== undefined && !SUPPORTED_TYPES.has(String(node.type))) {
    addError(errors, path, 'schema_invalid_type', `unsupported type: ${node.type}`);
  }

  if (node.required !== undefined && !Array.isArray(node.required)) {
    addError(errors, path, 'schema_invalid_required', '`required` must be an array');
  }

  if (node.properties !== undefined && !isObject(node.properties)) {
    addError(errors, path, 'schema_invalid_properties', '`properties` must be an object');
  }

  if (node.enum !== undefined && !Array.isArray(node.enum)) {
    addError(errors, path, 'schema_invalid_enum', '`enum` must be an array');
  }

  if (node.additionalProperties !== undefined && typeof node.additionalProperties !== 'boolean') {
    addError(errors, path, 'schema_invalid_additionalProperties', '`additionalProperties` must be boolean');
  }

  if (isObject(node.properties)) {
    for (const [name, child] of Object.entries(node.properties)) {
      validateSchemaNodeShape(child, `${normalizePath(path)}.${name}`, errors);
    }
  }

  return errors;
}

function validateEnum(value, schema, path, errors) {
  if (!Array.isArray(schema.enum)) {
    return;
  }
  let matched = false;
  for (const candidate of schema.enum) {
    if (Object.is(candidate, value)) {
      matched = true;
      break;
    }
  }
  if (!matched) {
    addError(errors, path, 'enum_mismatch', 'value is not in enum');
  }
}

function validateType(value, schemaType, path, errors) {
  if (!schemaType) {
    return;
  }

  const actual = detectType(value);
  if (schemaType === 'number') {
    if (typeof value !== 'number' || Number.isNaN(value)) {
      addError(errors, path, 'type_mismatch', `expected number, got ${actual}`);
    }
    return;
  }

  if (schemaType === 'integer') {
    if (!Number.isInteger(value)) {
      addError(errors, path, 'type_mismatch', `expected integer, got ${actual}`);
    }
    return;
  }

  if (actual !== schemaType) {
    addError(errors, path, 'type_mismatch', `expected ${schemaType}, got ${actual}`);
  }
}

function validateValue(value, schema, path, errors, extraFields) {
  if (!isObject(schema)) {
    addError(errors, path, 'schema_invalid', 'schema node must be object');
    return;
  }

  validateType(value, schema.type, path, errors);
  validateEnum(value, schema, path, errors);

  if (schema.type === 'object' && isObject(value)) {
    const properties = isObject(schema.properties) ? schema.properties : {};
    const required = Array.isArray(schema.required) ? schema.required : [];

    for (const field of required) {
      if (!Object.prototype.hasOwnProperty.call(value, field)) {
        addError(errors, `${normalizePath(path)}.${field}`, 'required_missing', 'required field missing');
      }
    }

    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!Object.prototype.hasOwnProperty.call(properties, key)) {
          const fieldPath = `${normalizePath(path)}.${key}`;
          extraFields.push(fieldPath);
          addError(errors, fieldPath, 'additional_property', 'field is not allowed by schema');
        }
      }
    }

    for (const [field, childSchema] of Object.entries(properties)) {
      if (Object.prototype.hasOwnProperty.call(value, field)) {
        validateValue(value[field], childSchema, `${normalizePath(path)}.${field}`, errors, extraFields);
      }
    }
  }
}

function findHeaderValue(headers = {}, wanted) {
  const target = String(wanted || '').toLowerCase();
  for (const [key, value] of Object.entries(headers || {})) {
    if (String(key).toLowerCase() === target) {
      return String(Array.isArray(value) ? value[0] : value || '').trim();
    }
  }
  return '';
}

class OutputSchemaValidator {
  constructor(config = {}) {
    this.config = normalizeConfig(config);
  }

  isEnabled() {
    return this.config.enabled === true;
  }

  resolveSchemaName(input = {}) {
    const fromHeader = findHeaderValue(input.headers, this.config.schemaHeader);
    if (fromHeader) {
      return fromHeader;
    }
    return this.config.defaultSchema;
  }

  validateBuffer(input = {}) {
    const enabled = this.isEnabled();
    const effectiveMode = String(input.effectiveMode || 'monitor').toLowerCase();
    const contentType = String(input.contentType || '').toLowerCase();
    const schemaName = this.resolveSchemaName({ headers: input.headers || {} });

    if (!enabled || !schemaName) {
      return {
        enabled,
        applied: false,
        schemaName,
        valid: true,
        shouldWarn: false,
        shouldBlock: false,
        mismatches: [],
        extraFields: [],
        reasons: [],
      };
    }

    const schema = this.config.schemas[schemaName];
    if (!schema) {
      return {
        enabled: true,
        applied: true,
        schemaName,
        valid: false,
        shouldWarn: true,
        shouldBlock: this.config.mode === 'block' && effectiveMode === 'enforce',
        mismatches: [
          {
            path: '$',
            code: 'schema_not_found',
            message: `schema not found: ${schemaName}`,
          },
        ],
        extraFields: [],
        reasons: ['output_schema_validator:schema_not_found'],
      };
    }

    const schemaShapeErrors = validateSchemaNodeShape(schema, '$', []);
    if (schemaShapeErrors.length > 0) {
      return {
        enabled: true,
        applied: true,
        schemaName,
        valid: false,
        shouldWarn: true,
        shouldBlock: this.config.mode === 'block' && effectiveMode === 'enforce',
        mismatches: schemaShapeErrors,
        extraFields: [],
        reasons: ['output_schema_validator:schema_invalid'],
      };
    }

    if (!Buffer.isBuffer(input.bodyBuffer) || input.bodyBuffer.length === 0) {
      return {
        enabled: true,
        applied: true,
        schemaName,
        valid: false,
        shouldWarn: true,
        shouldBlock: this.config.mode === 'block' && effectiveMode === 'enforce',
        mismatches: [
          {
            path: '$',
            code: 'response_empty',
            message: 'response body is empty',
          },
        ],
        extraFields: [],
        reasons: ['output_schema_validator:response_empty'],
      };
    }

    if (!isTextualContentType(contentType) || !contentType.includes('json')) {
      return {
        enabled: true,
        applied: true,
        schemaName,
        valid: false,
        shouldWarn: true,
        shouldBlock: this.config.mode === 'block' && effectiveMode === 'enforce',
        mismatches: [
          {
            path: '$',
            code: 'response_not_json',
            message: 'response content-type is not JSON',
          },
        ],
        extraFields: [],
        reasons: ['output_schema_validator:response_not_json'],
      };
    }

    const boundedBuffer =
      input.bodyBuffer.length > this.config.maxBodyBytes
        ? input.bodyBuffer.subarray(0, this.config.maxBodyBytes)
        : input.bodyBuffer;

    let parsed;
    try {
      parsed = JSON.parse(boundedBuffer.toString('utf8'));
    } catch {
      return {
        enabled: true,
        applied: true,
        schemaName,
        valid: false,
        shouldWarn: true,
        shouldBlock: this.config.mode === 'block' && effectiveMode === 'enforce',
        mismatches: [
          {
            path: '$',
            code: 'response_parse_error',
            message: 'response JSON parse failed',
          },
        ],
        extraFields: [],
        reasons: ['output_schema_validator:response_parse_error'],
      };
    }

    const mismatches = [];
    const extraFields = [];
    validateValue(parsed, schema, '$', mismatches, extraFields);

    const valid = mismatches.length === 0;
    return {
      enabled: true,
      applied: true,
      schemaName,
      valid,
      shouldWarn: !valid,
      shouldBlock: !valid && this.config.mode === 'block' && effectiveMode === 'enforce',
      mismatches,
      extraFields,
      reasons: valid ? [] : ['output_schema_validator:validation_failed'],
    };
  }
}

module.exports = {
  VALID_NODE_KEYS,
  SUPPORTED_TYPES,
  OutputSchemaValidator,
  normalizeOutputSchemaValidatorConfig: normalizeConfig,
  validateSchemaNodeShape,
};
