# Reliability Proof (Stress + Chaos)

Last run: `2026-02-17T12:56:21.929Z`  
Report: `metrics/reliability-2026-02-17T12-56-34.537Z.json`

## Command

```bash
npm run reliability
```

## Test Profile

1. Stress:
- Duration: 8s
- Concurrency: 40
- Path: `POST /v1/chat/completions` (through Sentinel, custom provider route)

2. Chaos 503:
- Requests: 20
- Upstream behavior: always `503` (`Retry-After: 0`)
- Goal: verify fast circuit-open fail behavior and upstream attribution headers

3. Chaos Timeout:
- Requests: 12
- Upstream behavior: delayed response beyond Sentinel timeout
- Goal: verify timeout-triggered breaker open and fail-fast behavior

## Results

1. Stress
- Requests/sec: `5226.38`
- p95 latency: `14ms`
- Non-2xx: `0`
- Transport errors/timeouts: `0/0`

2. Chaos 503
- Responses: `20 x 503` (expected in failure scenario)
- Circuit fast-fails (`UPSTREAM_CIRCUIT_OPEN`): `12`
- Upstream hits: `16 / 20` (4 requests avoided by open breaker path)
- Provider state: `open`

3. Chaos Timeout
- Responses: `5 x 504` (timeouts), `7 x 503` (circuit-open fast-fails)
- Circuit fast-fails (`UPSTREAM_CIRCUIT_OPEN`): `7`
- Upstream hits: `10 / 12` (2 requests avoided by open breaker path)
- Provider state: `open` with `consecutive_timeouts=5`

## Gates

1. `stress_no_errors`: `true`
2. `chaos_503_circuit_opened`: `true`
3. `chaos_timeout_circuit_opened`: `true`

All reliability gates passed for this run.
