# P0-002 MCP Poisoning Detector

## Priority

- P0

## Goal

Harden MCP mode against tool description poisoning, schema abuse, and config drift without introducing external dependencies.

## Scope

- `src/security/mcp-poisoning-detector.js` (new)
- `src/mcp/server.js`
- `src/engines/injection-scanner.js` (reuse heuristics only)
- `src/config/schema.js`
- `src/config/default.yaml`
- `src/telemetry/prometheus.js`
- `docs/INTEGRATIONS.md`

## File-Level Acceptance Checklist

- [ ] `src/security/mcp-poisoning-detector.js` implements:
- [ ] deterministic tool schema allowlist checks (required fields/types).
- [ ] description poisoning scan via reused injection scanner path.
- [ ] config drift monitor using stable hash over MCP config snapshot.
- [ ] tool argument sanitizer for unsafe encoded payload artifacts.
- [ ] `src/mcp/server.js` invokes detector at registration and call-time.
- [ ] `src/config/schema.js` validates `runtime.mcp_poisoning.*` contract.
- [ ] `src/config/default.yaml` defaults to monitor mode and bounded state.
- [ ] `src/telemetry/prometheus.js` adds `mcp_poisoning_detected_total`, `mcp_poisoning_blocked_total`, `mcp_config_drift_total`.
- [ ] `docs/INTEGRATIONS.md` documents MCP poisoning protection and opt-in enforce mode.

## Exact Test Cases

- `test/unit/mcp-poisoning-detector.test.js`
- `test('accepts valid tool schema with no poisoning indicators', ...)`
- `test('flags tool description containing hidden system override text', ...)`
- `test('flags tool description containing zero-width obfuscation payload', ...)`
- `test('detects config drift when server config hash changes', ...)`
- `test('sanitizes suspicious encoded characters in tool arguments', ...)`
- `test('monitor mode returns warning without blocking', ...)`
- `test('enforce mode returns block decision with reason=mcp_poisoning_detected', ...)`
- `test/integration/mcp-poisoning.integration.test.js`
- `test('mcp request is blocked in enforce mode for poisoned tool description', ...)`
- `test('mcp request is forwarded with warning header in monitor mode', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/mcp-poisoning-detector.test.js
npm run test:integration -- test/integration/mcp-poisoning.integration.test.js
npm run test:integration -- test/unit/mcp-server.test.js
```

