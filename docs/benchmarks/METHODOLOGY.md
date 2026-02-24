# Benchmark Methodology

Last updated: 2026-02-24

## Goals

- Measure Sentinel proxy overhead versus direct upstream for identical request shape.
- Keep benchmark reproducible and scriptable in CI.
- Publish machine-readable artifacts for regression gates.

## Sentinel Load Test (Reproducible)

Command:

```bash
npm run benchmark -- --duration 3 --connections 16 --pipelining 1
npm run benchmark:gate
```

Primary output artifact:

- `metrics/benchmark-YYYY-MM-DD.json`

Canonical release snapshot used for comparison page:

- `docs/benchmarks/results/sentinel-v4.json` (sourced from `metrics/benchmark-2026-02-23.json`)

## Workload Shape

- Endpoint: `/v1/chat/completions`
- Request type: OpenAI-compatible chat completion payload
- Modes: direct upstream and through Sentinel proxy
- Sentinel profile for baseline overhead: monitor-first, injection + PII baseline toggles as defined by benchmark harness

## Fairness Rules

- Same request payload and concurrency across compared paths.
- Same host machine and Node runtime for direct-vs-sentinel runs.
- No cherry-picked percentile: report at least p50/p95/p99.
- If a competitor metric is unavailable from reproducible local execution, report as `not_measured` explicitly.

## Competitor Comparison Data

Competitor coverage and setup data is tracked in:

- `docs/benchmarks/results/competitor-coverage.json`

Current state:

- OWASP coverage mapping is based on each tool's public documentation.
- Latency and setup timings are only claimed when reproducible in this repo.
- Unknown/unreproduced metrics are intentionally left null to avoid unverifiable claims.

## Quarterly Refresh Process

1. Re-run `npm run benchmark` and `npm run benchmark:gate`.
2. Update `docs/benchmarks/results/sentinel-v4.json` from latest stable metric file.
3. Re-verify competitor docs and refresh `competitor-coverage.json` with `last_verified`.
4. Update comparison table date in `docs/benchmarks/COMPETITOR_COMPARISON.md`.
