# Sentinel Protocol P0-P2-012 Implementation Backlog

## Objective

Ship the next alien-tech tranche without semantic drift, while preserving local-first determinism, monitor-first rollout, and enterprise evidence quality.

## Ordering

1. `P0-001` Agentic Threat Shield
2. `P0-002` MCP Poisoning Detector
3. `P0-003` Prompt Rebuff Engine
4. `P1-004` MITRE ATLAS Tracker
5. `P1-005` AIBOM Generator
6. `P1-006` Security Posture Scoring
7. `P1-007` OWASP LLM Top 10 Compliance Mapper
8. `P2-008` Output Content Classifier
9. `P2-009` Structured Output Validator
10. `P2-010` Agent Observability Engine
11. `P2-011` Adversarial Robustness Expansion
12. `P2-012` Differential Privacy Research Track

## Program Guardrails

- No new runtime dependencies.
- No silent behavior changes.
- New controls default to monitor/advisory mode.
- All keys must be schema-validated with unknown-key rejection.
- No raw secret/prompt leakage in logs, reports, or artifacts.
- `src/server.js` must not absorb new business logic; logic belongs in modules/stages.

## Quality Gates (All Tickets)

```bash
npm run lint
npm run openapi:validate
npm run test:unit:ci
npm run test:integration
npm run test:coverage:gate
npm run benchmark -- --duration 3 --connections 16 --pipelining 1
npm run benchmark:gate
npm run reliability -- --duration 4 --connections 20 --chaos-requests 16 --timeout-requests 10 --websocket-requests 8
```

## Performance Contract

- Fast path SLO: `p50 <= 5ms`, `p95 <= 12ms` on 8GB profile.
- Deep path SLO: `p50 <= 12ms`, `p95 <= 30ms`.
- Memory: no unbounded maps; enforce TTL/caps for all new accumulators.

