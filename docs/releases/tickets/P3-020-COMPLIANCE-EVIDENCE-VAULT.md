# P3-020 Compliance Evidence Vault

## Priority

- P3 (Tier 2)

## Goal

Provide tamper-evident evidence chain for compliance controls and outcomes.

## Scope

- `src/governance/evidence-vault.js` (new)
- `src/stages/audit-stage.js`
- `cli/sentinel.js`
- `src/config/schema.js`
- `src/config/default.yaml`

## File-Level Acceptance Checklist

- [ ] Append-only evidence ledger with chain hash/Merkle-ready structure.
- [ ] Control-level evidence entries (enabled, detected, blocked counts).
- [ ] Verification API for point-in-time entry integrity.
- [ ] Export packet command for SOC2/ISO/EU AI Act artifacts.
- [ ] Retention pruning with deterministic boundaries.

## Exact Test Cases

- `test/unit/evidence-vault.test.js`
- `test('appends evidence entries with chain hash continuity', ...)`
- `test('fails verification on tampered middle entry', ...)`
- `test('exports deterministic compliance packet', ...)`
- `test('retention pruning removes out-of-window entries only', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/evidence-vault.test.js
```
