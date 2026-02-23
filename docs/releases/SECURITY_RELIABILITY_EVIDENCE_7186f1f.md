# Sentinel Protocol Security & Reliability Evidence

## Baseline Freeze

- Baseline commit: `7186f1fdad29c927753e4c08a32fa47ab0257ec9`
- Baseline tag: `release-baseline-7186f1f`
- Baseline branch at freeze: `main`
- Freeze date: `2026-02-20`

## CI Evidence (Public Links)

- Full workflow run (all stages successful):
  - `https://github.com/myProjectsRavi/sentinel-protocol/actions/runs/22214993518`
- Quality gates job (coverage gate, benchmark gate, bootstrap path, SBOM generation):
  - `https://github.com/myProjectsRavi/sentinel-protocol/actions/runs/22214993518/job/64256888360`
- Docker build + quickstart smoke job:
  - `https://github.com/myProjectsRavi/sentinel-protocol/actions/runs/22214993518/job/64256947051`

## SBOM Evidence

- CI artifact name: `sbom-ci`
- Artifact page:
  - `https://github.com/myProjectsRavi/sentinel-protocol/actions/runs/22214993518#artifacts`
- Artifact id (run-scoped): `5585713197`
- Artifact digest (from run UI):  
  `sha256:fdff3692aca5cc48d31c402b7a8455fa6033290f2aee43f5172970a9365ca171`

## Benchmark Gate Evidence

- Threshold config:
  - `metrics/benchmark-thresholds.json`
- Baseline benchmark snapshot:
  - `metrics/benchmark-baseline-7186f1f.json`

### Baseline benchmark result (local replay matching CI command profile)

- Command:
  - `npm run benchmark -- --duration 3 --connections 16 --pipelining 1`
- Result:
  - direct req/sec: `570.67`
  - sentinel req/sec: `497.67`
  - req/sec ratio: `0.87`
  - direct p95: `30.00 ms`
  - sentinel p95: `35.00 ms`
  - p95 ratio: `1.17`
  - p95 overhead: `5.00 ms` (`16.67%`)
- Gate command:
  - `npm run benchmark:gate`
- Gate status:
  - `passed`

## P1 Module Micro-Perf Gate

- Threshold config:
  - `metrics/p1-engine-perf-thresholds.json`
- Gate command:
  - `npm run perf:p1:gate`
- SLO target:
  - combined p95 across P1 modules (`atlas`, `aibom`, `posture`, `owasp mapper`) stays under `2.0 ms` on runner profile.

## Reliability Evidence

- Versioned reliability reports:
  - `metrics/reliability-2026-02-17T12-56-34.537Z.json`
  - `metrics/reliability-2026-02-18T03-27-00.369Z.json`
  - `metrics/reliability-2026-02-18T03-45-04.590Z.json`
  - `metrics/reliability-2026-02-18T04-03-55.251Z.json`
  - `metrics/reliability-2026-02-18T04-20-13.801Z.json`
  - `metrics/reliability-2026-02-18T16-38-39.936Z.json`
  - `metrics/reliability-2026-02-18T16-43-21.265Z.json`
  - `metrics/reliability-2026-02-18T16-44-32.321Z.json`
  - `metrics/reliability-2026-02-18T17-18-44.508Z.json`
  - `metrics/reliability-2026-02-20T03-56-57.355Z.json`
  - `metrics/reliability-2026-02-20T04-08-57.248Z.json`
  - `metrics/reliability-2026-02-20T04-39-34.516Z.json`
- Report count at baseline proof publish: `12`
- Integrity manifest (SHA256 for every reliability report):
  - `metrics/reliability-manifest-7186f1f.sha256`

## Security Quality Evidence

- Lint gate:
  - `npm run lint` passed
- OpenAPI contract gate:
  - `npm run openapi:validate` passed
- Unit/integration/reliability gates:
  - all passed in run `22214993518`
- Dependency audit:
  - `npm audit --omit=dev --audit-level=high` passed (`0 vulnerabilities`)

## Posture Evidence Format Extension

Future release evidence pages will include posture snapshots from:

- `GET /_sentinel/health` (`posture.overall`, `posture.categories`, thresholds)
- `sentinel posture --json --audit-path <path>`

Posture is advisory-only and does not alter enforcement decisions.

## Repro Commands

```bash
# Verify baseline commit/tag
git rev-parse release-baseline-7186f1f

# Benchmark evidence
npm run benchmark -- --duration 3 --connections 16 --pipelining 1
npm run benchmark:gate

# Reliability evidence
ls -1 metrics/reliability-*.json | wc -l
shasum -a 256 metrics/reliability-*.json
```
