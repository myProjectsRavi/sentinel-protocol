# Benchmarks

This project ships a reproducible benchmark harness to measure Sentinel overhead versus direct upstream calls.

## Goal

- Keep p95 proxy overhead under 5ms for baseline monitor mode traffic.
- Track request/sec delta and tail latency on every release.

## Run

```bash
npm run benchmark
npm run benchmark:gate
```

Reliability (stress + chaos scenarios):

```bash
npm run reliability -- --websocket-requests 8
```

Custom run parameters:

```bash
node ./scripts/benchmark-overhead.js --duration 20 --connections 100 --pipelining 1
```

The script writes JSON reports to:

- `metrics/benchmark-YYYY-MM-DD.json`
- `metrics/reliability-<timestamp>.json`

## What It Measures

1. Direct upstream traffic (`/v1/chat/completions`)
2. Same traffic through Sentinel with:
1. `mode=monitor`
2. `pii.enabled=false`
3. `injection.enabled=false`
4. `x-sentinel-target=openai` mapped to local upstream endpoint

Outputs include:

- `direct.latency_ms.p95`
- `sentinel.latency_ms.p95`
- `overhead.p95_ms`
- `requests_per_sec_delta`

## Interpreting Results

- `overhead.p95_ms <= 5` is healthy baseline.
- If overhead regresses:
1. Profile body parsing and regex paths.
2. Verify no accidental sync file IO in hot path.
3. Check custom target DNS pinning/agent behavior.

## Notes

- Run with `NODE_ENV=production` for realistic results.
- Benchmark host and network conditions affect absolute numbers.
- Compare deltas across versions, not raw values from different machines.
- Reliability gates currently cover:
1. Stress run without transport errors/timeouts.
2. Chaos-503 scenario where circuit breaker opens and fast-fails.
3. Chaos-timeout scenario where timeout streak opens breaker and fast-fails.
4. WebSocket upgrade forwarding stability with monitor-first interception enabled.
