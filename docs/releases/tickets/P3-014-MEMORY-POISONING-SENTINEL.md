# P3-014 Memory Poisoning Sentinel

## Priority

- P3 (Tier 0)

## Goal

Detect and quarantine suspicious memory writes that can poison long-lived agent context.

## Scope

- `src/security/memory-poisoning-sentinel.js` (new)
- `src/stages/policy/agentic-stage.js`
- `src/config/schema.js`
- `src/config/default.yaml`

## File-Level Acceptance Checklist

- [ ] Ingress memory write scanning with bounded input.
- [ ] Rolling memory integrity hash snapshots per session.
- [ ] Drift alerting and contradiction checks against anchor list.
- [ ] Quarantine decision path (`monitor` warning / `block` in enforce).
- [ ] TTL + max session caps enforced.

## Exact Test Cases

- `test/unit/memory-poisoning-sentinel.test.js`
- `test('detects poisoned write with injection override language', ...)`
- `test('detects contradiction against policy anchors', ...)`
- `test('returns quarantine recommendation in monitor mode', ...)`
- `test('blocks write in enforce mode when configured', ...)`
- `test('prunes stale session snapshots', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/memory-poisoning-sentinel.test.js
```
