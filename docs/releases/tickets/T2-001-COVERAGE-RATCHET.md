# T2-001 Coverage Ratchet

## Priority

- Tier-2

## Goal

Raise enforced code coverage thresholds while preserving deterministic behavior and CI stability.

## Scope

- `jest.coverage.config.js`
- unit/integration tests for low-coverage high-risk modules
- CI quality-gates coverage step

## Acceptance Criteria

- Coverage thresholds raised to at least:
  - statements: `65`
  - lines: `65`
  - functions: `75`
  - branches: `55`
- `npm run test:coverage:gate` passes on clean checkout.
- No use of `--forceExit` or weakened Jest strictness.
- New tests include at least one path each for:
  - websocket upgrade failure handling
  - dashboard auth/audit flow
  - stage orchestration error path
- No production code behavior drift from baseline (`release-baseline-7186f1f`).

## Verification Commands

```bash
npm run test:coverage:gate
npm run test:unit
npm run test:integration
```

