# P3-018 Cost and Latency Budget Autopilot

## Priority

- P3 (Tier 1)

## Goal

Provide advisory optimization for cost/latency routing under budget and SLA constraints.

## Scope

- `src/optimizer/budget-autopilot.js` (new)
- `src/runtime/doctor.js`
- `src/config/schema.js`
- `src/config/default.yaml`

## File-Level Acceptance Checklist

- [ ] Tracks provider/model cost and latency percentiles.
- [ ] Predicts budget exhaustion window.
- [ ] Emits route recommendations in advisory mode.
- [ ] Auto-switch remains disabled by default.
- [ ] Deterministic recommendation for same metrics snapshot.

## Exact Test Cases

- `test/unit/budget-autopilot.test.js`
- `test('computes per-provider blended cost/latency score', ...)`
- `test('predicts exhaustion hours for configured budget window', ...)`
- `test('returns advisory recommendation without forcing route change', ...)`
- `test('deterministic output for fixed input counters', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/budget-autopilot.test.js
```
