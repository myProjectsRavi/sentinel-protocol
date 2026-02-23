# P2-011 Adversarial Robustness Expansion

## Priority

- P2

## Goal

Extend red-team realism with additional adversarial evasion families while preserving deterministic output and no sensitive prompt leakage.

## Scope

- `src/governance/adversarial-robustness.js` (new)
- `src/governance/red-team.js`
- `src/governance/red-team-html-report.js`
- `test/fixtures/adversarial-attack-fixtures.json` (new)
- `docs/RELIABILITY_PROOF.md` (add adversarial run step)

## File-Level Acceptance Checklist

- [ ] Fixture pack adds at least 200 new adversarial cases.
- [ ] New families included: homoglyph, token smuggling, instruction hierarchy bypass, multi-turn escalation.
- [ ] `src/governance/red-team.js` imports fixtures deterministically and preserves stable case IDs.
- [ ] HTML report includes vector-family distribution section with escaped output.
- [ ] No raw sensitive prompt text in report output; fingerprints only.

## Exact Test Cases

- `test/unit/adversarial-robustness.test.js`
- `test('loads fixture corpus with expected minimum case count', ...)`
- `test('includes required adversarial vector families', ...)`
- `test('produces deterministic case ordering and ids across runs', ...)`
- `test('detects unicode homoglyph variants as same canonical attack intent', ...)`
- `test('detects token-boundary smuggling variants', ...)`
- `test/integration/red-team-adversarial.integration.test.js`
- `test('red-team run includes adversarial fixture families in summary counts', ...)`
- `test('html report exposes fingerprints and never raw prompts', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/adversarial-robustness.test.js
npm run test:integration -- test/integration/red-team-adversarial.integration.test.js
node ./cli/sentinel.js red-team run --url http://127.0.0.1:8787 --target openai --report html --out ./red-team-adversarial.html
```

