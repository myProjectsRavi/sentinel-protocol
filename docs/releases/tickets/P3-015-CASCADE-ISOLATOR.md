# P3-015 Cascading Blast Radius Isolator

## Priority

- P3 (Tier 0)

## Goal

Contain compromise propagation across multi-agent workflows with trust-graph caps.

## Scope

- `src/security/cascade-isolator.js` (new)
- `src/stages/policy/agentic-stage.js`
- `src/config/schema.js`
- `src/config/default.yaml`

## File-Level Acceptance Checklist

- [ ] Directed trust graph maintained per session.
- [ ] Max downstream influence caps enforced.
- [ ] Anomaly threshold trips propagation breaker.
- [ ] Impact-map summary emitted in telemetry-safe structure.
- [ ] Bounded nodes/edges and deterministic traversal.

## Exact Test Cases

- `test/unit/cascade-isolator.test.js`
- `test('builds trust graph and computes downstream reach', ...)`
- `test('blocks propagation when blast radius threshold exceeded', ...)`
- `test('returns monitor warning when configured monitor mode', ...)`
- `test('respects max_nodes and max_edges caps', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/cascade-isolator.test.js
```
