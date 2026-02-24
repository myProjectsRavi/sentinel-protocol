# Sentinel Protocol V4 Phase A Security & Reliability Evidence

## Scope
- Branch: `main`
- Package: `sentinel-protocol@1.0.0`
- Phase: V4 Phase A (P0 + P1 shipping set)
- Evidence date: 2026-02-24

## What Is Covered
- New runtime engines (monitor-first, config-driven):
  - `serialization_firewall`
  - `context_integrity_guardian`
  - `tool_schema_validator`
  - `multimodal_injection_shield`
  - `supply_chain_validator`
  - `sandbox_enforcer`
  - `memory_integrity_monitor`
- Full schema contract + defaults + strict validation
- Runtime wiring through policy/agentic stages (not decorative)
- Unit + integration + coverage + benchmark + perf gates

## Local Validation Snapshot (2026-02-24)
1. `npm run lint` -> pass
2. `npm run openapi:validate` -> pass
3. `npm run test:unit:ci` -> pass
4. `npm run test:integration` -> pass
5. `npm run test:coverage:gate` -> pass
6. `npm run benchmark:gate` -> pass
7. `npm run perf:p0:gate` -> pass
8. `npm run perf:p1:gate` -> pass
9. `npm run perf:v4:phasea:gate` -> pass
10. `npm run reliability` -> blocked in sandbox (`listen EPERM 127.0.0.1`), must validate in GitHub Actions/non-sandbox runtime

## CI Artifact Expectations
- SBOM:
  - `sbom.cyclonedx.json`
  - `sbom.spdx.json`
- AIBOM:
  - `aibom.json`
- Performance reports:
  - `metrics/p0-engine-perf-*.json`
  - `metrics/p1-engine-perf-*.json`
  - `metrics/p2-engine-perf-*.json`
  - `metrics/p3-engine-perf-*.json`
  - `metrics/v4-phasea-engine-perf-*.json`

## Reviewer Quick Verification Checklist
1. Confirm CI workflow run is green on `test`, `quality-gates`, and `docker-build`.
2. Confirm `quality-gates` includes `npm run perf:v4:phasea:gate`.
3. Confirm artifact bundle contains SBOM + AIBOM + all perf reports.
4. Confirm wiring guard test passes:
   - `test/unit/server-pipeline-hooks.test.js`
5. Confirm no reliability drift in non-sandbox CI:
   - `npm run reliability -- --duration 4 --connections 20 --chaos-requests 16 --timeout-requests 10 --websocket-requests 8`

## Notes for Emin/Sone Review
- Phase A engines are integrated into the live request path:
  - `/Users/ravitejanekkalapu/Documents/sentinel-protocol/src/stages/policy/pii-injection-stage.js`
  - `/Users/ravitejanekkalapu/Documents/sentinel-protocol/src/stages/policy/agentic-stage.js`
- Constructor/runtime/status wiring:
  - `/Users/ravitejanekkalapu/Documents/sentinel-protocol/src/server.js`
- Config contract:
  - `/Users/ravitejanekkalapu/Documents/sentinel-protocol/src/config/schema.js`
  - `/Users/ravitejanekkalapu/Documents/sentinel-protocol/src/config/default.yaml`

