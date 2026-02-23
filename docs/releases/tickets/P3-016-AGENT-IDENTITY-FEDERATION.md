# P3-016 Agent Identity Federation Protocol

## Priority

- P3 (Tier 0)

## Goal

Provide signed, capability-scoped delegation tokens for zero-trust agent-to-agent identity.

## Scope

- `src/security/agent-identity-federation.js` (new)
- `src/stages/policy/agentic-stage.js`
- `src/config/schema.js`
- `src/config/default.yaml`

## File-Level Acceptance Checklist

- [ ] Signed token issuance and validation with expiration.
- [ ] Delegation chain verification and capability narrowing.
- [ ] Session/correlation binding to prevent replay.
- [ ] Impersonation detection path with explicit reason codes.
- [ ] Config-driven key material and mode behavior.

## Exact Test Cases

- `test/unit/agent-identity-federation.test.js`
- `test('issues signed capability token and verifies signature', ...)`
- `test('rejects widened capability on delegated token chain', ...)`
- `test('rejects replay across different correlation id', ...)`
- `test('detects impersonation claim mismatch', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/agent-identity-federation.test.js
```
