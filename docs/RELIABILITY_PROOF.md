# Reliability Proof (Stress + Chaos)

Last run: `2026-02-20T04:39:25.696Z`  
Report: `metrics/reliability-2026-02-20T04-39-34.516Z.json`

## Command

```bash
npm run reliability
```

## Test Profile

1. Stress:
- Duration: 4s
- Concurrency: 20
- Path: `POST /v1/chat/completions` (through Sentinel, custom provider route)

2. Chaos 503:
- Requests: 16
- Upstream behavior: always `503` (`Retry-After: 0`)
- Goal: verify fast circuit-open fail behavior and upstream attribution headers

3. Chaos Timeout:
- Requests: 10
- Upstream behavior: delayed response beyond Sentinel timeout
- Goal: verify timeout-triggered breaker open and fail-fast behavior

## Results

1. Stress
- Requests/sec: `4600`
- p95 latency: `8ms`
- Non-2xx: `0`
- Transport errors/timeouts: `0/0`

2. Chaos 503
- Responses: `16 x 503` (expected in failure scenario)
- Circuit fast-fails (`UPSTREAM_CIRCUIT_OPEN`): `8`
- Upstream hits: `16 / 16`
- Provider state: `open`

3. Chaos Timeout
- Responses: `5 x 504` (timeouts), `5 x 503` (circuit-open fast-fails)
- Circuit fast-fails (`UPSTREAM_CIRCUIT_OPEN`): `5`
- Upstream hits: `10 / 10`
- Provider state: `open` with `consecutive_timeouts=5`

## Gates

1. `stress_no_errors`: `true`
2. `chaos_503_circuit_opened`: `true`
3. `chaos_timeout_circuit_opened`: `true`

All reliability gates passed for this run.

## Adversarial Robustness Verification

Run deterministic adversarial coverage and HTML output safety check:

```bash
node ./cli/sentinel.js red-team run --url http://127.0.0.1:8787 --target openai --report html --out ./red-team-adversarial.html
```

Validation expectations:
- report includes a `Vector Family Distribution` section
- report does not include raw prompt payloads (`raw_prompts_exposed=false`)
- case identifiers are deterministic (`case_id` or SHA256-derived fallback)
