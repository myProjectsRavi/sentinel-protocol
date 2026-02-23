# P3-017 Semantic Firewall Rules DSL

## Priority

- P3 (Tier 1)

## Goal

Introduce expressive policy DSL compiled at startup into deterministic evaluators.

## Scope

- `src/policy/semantic-firewall-dsl.js` (new)
- `src/config/schema.js`
- `src/config/default.yaml`
- `src/engines/policy-engine.js`

## File-Level Acceptance Checklist

- [ ] Parser supports AND/OR/NOT and comparison operators.
- [ ] Compile-time only; no runtime parsing on hot path.
- [ ] Deterministic evaluator output with strict field allowlist.
- [ ] YAML fallback remains backward compatible.
- [ ] Syntax errors fail config load loudly.

## Exact Test Cases

- `test/unit/semantic-firewall-dsl.test.js`
- `test('compiles valid DSL rule into executable predicate', ...)`
- `test('rejects invalid token sequence with explicit error', ...)`
- `test('evaluates compound condition deterministically', ...)`
- `test('preserves legacy YAML rule behavior when DSL absent', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/semantic-firewall-dsl.test.js
```
