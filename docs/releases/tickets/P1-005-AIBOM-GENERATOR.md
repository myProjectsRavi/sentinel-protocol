# P1-005 AIBOM Generator

## Priority

- P1

## Goal

Produce an AI Bill of Materials artifact from observed provider/model/tool/agent traffic, alongside existing SBOM outputs.

## Scope

- `src/governance/aibom-generator.js` (new)
- `src/server.js` (record events only)
- `src/stages/routing-stage.js`
- `src/stages/egress/buffered-egress-stage.js`
- `cli/sentinel.js` (`aibom export`)
- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`

## File-Level Acceptance Checklist

- [ ] `src/governance/aibom-generator.js` stores bounded, TTL-capped inventory (`providers`, `models`, `tools`, `agents`).
- [ ] Request and response metadata both contribute to model/provider identification.
- [ ] `cli/sentinel.js` adds `sentinel aibom export --format json --out ...`.
- [ ] CI workflow uploads `aibom.json` artifact on quality gates.
- [ ] Release workflow uploads `aibom.json` artifact for tags.
- [ ] Export output is deterministic and excludes raw prompt/message content.

## Exact Test Cases

- `test/unit/aibom-generator.test.js`
- `test('deduplicates providers/models and increments request_count', ...)`
- `test('extracts model from request body when response headers are absent', ...)`
- `test('extracts model from response headers when available', ...)`
- `test('sorts export arrays deterministically', ...)`
- `test('never persists raw prompt text in output artifact', ...)`
- `test/integration/aibom-export.integration.test.js`
- `test('traffic through sentinel yields non-empty aibom providers/models export', ...)`
- `test('aibom export command writes valid json artifact', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/aibom-generator.test.js
npm run test:integration -- test/integration/aibom-export.integration.test.js
node ./cli/sentinel.js aibom export --format json --out ./aibom.json
```

