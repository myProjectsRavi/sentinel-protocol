# Benchmarks

This project ships reproducible performance and regression gates for Sentinel proxy overhead.

## Quick Run

```bash
npm run benchmark -- --duration 3 --connections 16 --pipelining 1
npm run benchmark:gate
npm run benchmark:datasets
```

Reliability stress/chaos path:

```bash
npm run reliability -- --websocket-requests 8
```

## Published Benchmark Artifacts

- Methodology: `docs/benchmarks/METHODOLOGY.md`
- Competitor comparison: `docs/benchmarks/COMPETITOR_COMPARISON.md`
- Sentinel benchmark snapshot: `docs/benchmarks/results/sentinel-v4.json`
- OWASP coverage matrix data: `docs/benchmarks/results/competitor-coverage.json`
- Standard adversarial datasets snapshot: `docs/benchmarks/results/standard-datasets.json`
- Standard dataset fixtures: `docs/benchmarks/datasets/*.json`

## Current Sentinel Baseline (published)

- direct p95: `33 ms`
- sentinel p95: `34 ms`
- p95 overhead: `1 ms` (`3.03%`)
- throughput delta: `-57 req/sec`

Source: `docs/benchmarks/results/sentinel-v4.json`

## Standard Adversarial Dataset Baseline

- datasets: `advbench-mini`, `trojai-mini`
- total cases: `30`
- expected-detection cases: `24`
- overall detection rate: `100%` (threshold `85%`)
- false positives: `0`

Source: `docs/benchmarks/results/standard-datasets.json`

## Regression Policy

- Benchmark gate fails CI on configured regression thresholds (`npm run benchmark:gate`).
- Separate perf gates cover P0/P1/P2/P3/V4 engine groups.
- Reliability suite validates timeout, circuit-breaker, chaos, and websocket paths.

## Notes

- Run with `NODE_ENV=production` for realistic behavior.
- Use comparisons from the same runner profile when evaluating regressions.
- Competitor metrics are only asserted when reproducible in-repo; otherwise marked `not_measured`.
