# Differential Privacy Research Track (Advisory-Only)

## Track Type

- Research track (P2), non-blocking
- Advisory-only until explicit promotion criteria are met

## Objective

Prototype calibrated Laplace-noise utilities for numeric and embedding-like vectors while preserving deterministic governance behavior in the live request path.

## Guardrails

- Disabled by default (`runtime.differential_privacy.enabled: false`).
- No mutation of ingress/egress live request paths.
- CLI-only simulation path (`sentinel privacy simulate`).
- Explicit privacy-budget exhaustion states are surfaced in output reports.

## Threat Model Scope

- Mitigates direct memorization risk for numeric features and embedding vectors in offline simulation workflows.
- Does not claim complete model-level privacy guarantees in production traffic.
- Does not replace existing PII/injection policy controls.

## Utility Tradeoffs

- Higher privacy (`epsilon` lower) increases noise and can reduce downstream utility.
- Lower privacy (`epsilon` higher) preserves utility but weakens privacy guarantees.
- Budget depletion must terminate simulation with explicit exhausted state.

## Promotion Criteria

Promotion from research to runtime path requires all of:

1. Semantic parity proof:
- No policy-action drift in benchmark replay corpus.

2. Utility evidence:
- Documented task-level quality impact for representative workloads.

3. Reliability and performance:
- No regression in existing CI quality gates and reliability proof runs.

4. Safety contract:
- Config remains explicit and monitor-first for any future runtime wiring.

## Current Interface

```bash
node ./cli/sentinel.js privacy simulate --in ./test/fixtures/privacy/numeric.json --out ./privacy-sim-report.json
```

Output contract:
- `advisory_only: true`
- budget snapshot before/after
- exhausted state
- no runtime mutation side effects
