# Sentinel Protocol P3-P5-024 Alien Roadmap v2 Backlog

## Objective

Ship the 2026 agentic-security tranche without semantic drift while preserving Sentinel's local-first, deterministic, monitor-first contract.

## Ordering

1. `P3-013` MCP Shadow Detector
2. `P3-014` Memory Poisoning Sentinel
3. `P3-015` Cascading Blast Radius Isolator
4. `P3-016` Agent Identity Federation Protocol
5. `P3-017` Semantic Firewall Rules DSL
6. `P3-018` Cost and Latency Budget Autopilot
7. `P3-019` Universal SDK Embed Mode
8. `P3-020` Compliance Evidence Vault
9. `P3-021` Cross-Agent Threat Propagation Graph
10. `P3-022` Self-Evolving Attack Corpus
11. `P3-023` Tool Use Anomaly Detector
12. `P3-024` Request Replay and Forensic Debugger

## Guardrails

- No new runtime dependencies.
- All engines default `enabled: false` and `mode: monitor` when applicable.
- All stateful engines must enforce bounded memory (`max_entries`, `ttl_ms`, or equivalent).
- Unknown key rejection remains mandatory for every new runtime config block.
- No raw secret/prompt leakage in logs/reports/artifacts.
- Deterministic outputs for identical input + config.
- No hot-path blocking work for visualization/reporting features.

## Required Quality Gates

```bash
npm run lint
npm run openapi:validate
npm run test:unit:ci
npm run test:integration
npm run test:coverage:gate
npm run benchmark:gate
npm run perf:p0:gate
npm run perf:p1:gate
npm run perf:p2:gate
```

## New Perf Contract (P3 Engines)

- Per-engine microbench gates for all hot-path engines.
- Default threshold in CI: `p95 <= 2ms` for engine eval in runner profile.
- Memory cap checks for all stateful engines.
