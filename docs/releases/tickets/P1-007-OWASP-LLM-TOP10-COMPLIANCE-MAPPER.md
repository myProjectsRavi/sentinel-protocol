# P1-007 OWASP LLM Top 10 Compliance Mapper

## Priority

- P1

## Goal

Generate formal OWASP LLM Top 10 coverage evidence mapped to Sentinel controls, with deterministic JSON/HTML outputs.

## Scope

- `src/governance/owasp-compliance-mapper.js` (new)
- `src/governance/red-team-html-report.js` (template reuse helpers)
- `cli/sentinel.js` (`compliance owasp-llm`)
- `docs/OWASP_LLM_TOP10_SENTINEL_MAP.md` (new)
- `README.md` (proof links section update)

## File-Level Acceptance Checklist

- [ ] `src/governance/owasp-compliance-mapper.js` ships explicit mapping for `LLM01` through `LLM10`.
- [ ] Mapping output includes status: `covered`, `partially_covered`, `missing`.
- [ ] HTML output reuses hardened escaping/no-raw-payload patterns.
- [ ] `cli/sentinel.js` supports `sentinel compliance owasp-llm --report html --out ...`.
- [ ] `docs/OWASP_LLM_TOP10_SENTINEL_MAP.md` documents each category, mapped engines, and current gap notes.
- [ ] README proof block references OWASP mapping report location.

## Exact Test Cases

- `test/unit/owasp-compliance-mapper.test.js`
- `test('contains complete LLM01-LLM10 mapping keys', ...)`
- `test('classifies covered when all mapped controls enabled', ...)`
- `test('classifies partially_covered when monitor-only controls are active', ...)`
- `test('classifies missing when required controls are disabled', ...)`
- `test('html report is deterministic and escapes unsafe characters', ...)`
- `test/integration/owasp-compliance.integration.test.js`
- `test('cli compliance owasp-llm writes report with expected metadata', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/owasp-compliance-mapper.test.js
npm run test:integration -- test/integration/owasp-compliance.integration.test.js
node ./cli/sentinel.js compliance owasp-llm --report html --out ./owasp-llm-report.html
```

