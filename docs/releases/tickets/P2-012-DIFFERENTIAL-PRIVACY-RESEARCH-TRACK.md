# P2-012 Differential Privacy Research Track

## Priority

- P2 (research-only, non-blocking)

## Goal

Prototype differential-privacy utilities in advisory mode only, with no mutation of production request path until parity and utility gates are met.

## Scope

- `src/privacy/differential-privacy.js` (new)
- `src/config/schema.js`
- `src/config/default.yaml`
- `cli/sentinel.js` (`privacy simulate`)
- `docs/releases/research/WASM_SCANNER_RESEARCH_TRACK.md` (cross-track note)
- `docs/releases/research/DIFFERENTIAL_PRIVACY_RESEARCH_TRACK.md` (new)

## File-Level Acceptance Checklist

- [ ] `src/privacy/differential-privacy.js` provides Laplace mechanism with injectable RNG for deterministic tests.
- [ ] Privacy budget accounting implemented with strict caps and explicit exhaustion state.
- [ ] No inline mutation of live prompt/output paths in default runtime.
- [ ] CLI simulation command produces advisory report only.
- [ ] Config keys under `runtime.differential_privacy.*` are strict and disabled by default.
- [ ] Research doc captures threat model, utility tradeoffs, and promotion criteria.

## Exact Test Cases

- `test/unit/differential-privacy.test.js`
- `test('laplace noisify returns deterministic output when seeded rng is supplied', ...)`
- `test('noisifyEmbeddings preserves vector length and numeric type', ...)`
- `test('privacy budget decreases on each simulation call', ...)`
- `test('returns exhausted state when epsilon budget reaches zero', ...)`
- `test('disabled mode returns passthrough values with no mutation', ...)`
- `test/integration/differential-privacy.integration.test.js`
- `test('privacy simulate command writes advisory report and does not affect request responses', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/differential-privacy.test.js
npm run test:integration -- test/integration/differential-privacy.integration.test.js
node ./cli/sentinel.js privacy simulate --in ./test/fixtures/privacy/numeric.json --out ./privacy-sim-report.json
```

