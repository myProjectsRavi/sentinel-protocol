# P3-024 Request Replay and Forensic Debugger

## Priority

- P3 (Tier 3)

## Goal

Enable replay/what-if forensic analysis for incident investigation without leaking sensitive payload data.

## Scope

- `src/governance/forensic-debugger.js` (new)
- `src/runtime/vcr-store.js`
- `cli/sentinel.js`
- `docs/OUTAGE-RUNBOOK.md`

## File-Level Acceptance Checklist

- [ ] Captures replay-safe snapshots (summary/full modes).
- [ ] Replays snapshot through current engine stack deterministically.
- [ ] Supports what-if config overrides for threshold comparison.
- [ ] Produces diff report for changed decisions.
- [ ] Redacts sensitive fields in exported forensic reports.

## Exact Test Cases

- `test/unit/forensic-debugger.test.js`
- `test('replay reproduces original deterministic decisions', ...)`
- `test('what-if threshold override changes only expected decisions', ...)`
- `test('diff report includes engine-level deltas with stable keys', ...)`
- `test('export redacts configured sensitive fields', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/forensic-debugger.test.js
```
