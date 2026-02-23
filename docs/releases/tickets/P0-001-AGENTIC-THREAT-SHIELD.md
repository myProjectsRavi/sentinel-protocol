# P0-001 Agentic Threat Shield

## Priority

- P0

## Goal

Add deterministic controls for tool-call chain abuse: depth limits, delegation limits, cycle detection, and optional agent identity verification.

## Scope

- `src/security/agentic-threat-shield.js` (new)
- `src/stages/policy/agentic-stage.js` (new)
- `src/server.js` (stage wiring only)
- `src/config/schema.js`
- `src/config/default.yaml`
- `src/telemetry/prometheus.js`
- `docs/QUICKSTART.md`

## File-Level Acceptance Checklist

- [ ] `src/security/agentic-threat-shield.js` exports deterministic evaluator with:
- [ ] `max_tool_call_depth`, `max_agent_delegations`, `detect_cycles`, `verify_identity_tokens`.
- [ ] `src/stages/policy/agentic-stage.js` enforces monitor/enforce behavior and returns standardized stage decision payload.
- [ ] `src/server.js` adds `runOrchestratedStage('agentic_threat_shield', ...)` with no inline business logic expansion.
- [ ] `src/config/schema.js` validates `runtime.agentic_threat_shield.*` and rejects unknown keys.
- [ ] `src/config/default.yaml` includes safe defaults (`enabled=false`, `mode=monitor`).
- [ ] `src/telemetry/prometheus.js` exports counters for detected, blocked, and error totals.
- [ ] `docs/QUICKSTART.md` includes opt-in config snippet and mode behavior.

## Exact Test Cases

- `test/unit/agentic-threat-shield.test.js`
- `test('allows request when depth and delegation stay below thresholds', ...)`
- `test('returns detect-only decision in monitor mode when depth exceeded', ...)`
- `test('returns block decision in enforce mode when depth exceeded', ...)`
- `test('detects cycle in tool call graph and annotates reason=agentic_cycle_detected', ...)`
- `test('verifies valid HMAC agent identity token', ...)`
- `test('rejects invalid agent identity token in enforce mode', ...)`
- `test('caps in-memory session graph by ttl and max entries', ...)`
- `test/integration/agentic-threat-shield.integration.test.js`
- `test('returns 403 with x-sentinel-blocked-by=agentic_threat_shield when enforce violation occurs', ...)`
- `test('forwards request with x-sentinel-warning in monitor mode', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/agentic-threat-shield.test.js
npm run test:integration -- test/integration/agentic-threat-shield.integration.test.js
npm run benchmark:gate
```

