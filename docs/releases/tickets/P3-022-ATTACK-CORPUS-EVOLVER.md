# P3-022 Self-Evolving Attack Corpus

## Priority

- P3 (Tier 2)

## Goal

Continuously derive sanitized adversarial fixture candidates from blocked traffic with strict privacy controls.

## Scope

- `src/governance/attack-corpus-evolver.js` (new)
- `src/governance/red-team.js`
- `cli/sentinel.js`
- `src/config/schema.js`
- `src/config/default.yaml`

## File-Level Acceptance Checklist

- [ ] Captures candidate prompts only from blocked detections.
- [ ] Sanitizes PII/secrets and stores fingerprint-first records.
- [ ] Deduplicates by canonical intent hash.
- [ ] Classifies into fixture family labels.
- [ ] Disabled by default with retention controls.

## Exact Test Cases

- `test/unit/attack-corpus-evolver.test.js`
- `test('ingests blocked event into sanitized candidate', ...)`
- `test('deduplicates semantically identical payload family', ...)`
- `test('never stores raw secret token patterns', ...)`
- `test('exports deterministic fixture pack ordering', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/attack-corpus-evolver.test.js
```
