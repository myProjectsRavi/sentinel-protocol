# P2-009 Structured Output Validator

## Priority

- P2

## Goal

Validate structured model responses against a deterministic schema subset to catch drift and exfiltration through unexpected fields.

## Scope

- `src/egress/output-schema-validator.js` (new)
- `src/stages/egress/buffered-egress-stage.js`
- `src/config/schema.js`
- `src/config/default.yaml`
- `docs/QUICKSTART.md`

## File-Level Acceptance Checklist

- [ ] `src/egress/output-schema-validator.js` supports deterministic subset only: `type`, `required`, `properties`, `enum`, `additionalProperties`.
- [ ] Validator reports exact mismatch list with field paths.
- [ ] Extra fields are flagged as exfiltration signal.
- [ ] `src/config/schema.js` validates `runtime.output_schema_validator.schemas`.
- [ ] `src/config/default.yaml` keeps feature disabled by default and monitor-first when enabled.
- [ ] `docs/QUICKSTART.md` includes minimal schema config example.

## Exact Test Cases

- `test/unit/output-schema-validator.test.js`
- `test('passes valid response for declared schema', ...)`
- `test('fails when required field is missing', ...)`
- `test('fails when field type mismatches declared type', ...)`
- `test('flags extra fields when additionalProperties=false', ...)`
- `test('monitor mode emits warning and forwards response', ...)`
- `test('enforce mode blocks response on validation failure', ...)`
- `test('handles malformed non-json response without throw', ...)`
- `test/integration/output-schema-validator.integration.test.js`
- `test('configured schema violation yields 502 with x-sentinel-blocked-by=output_schema_validator', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/output-schema-validator.test.js
npm run test:integration -- test/integration/output-schema-validator.integration.test.js
```

