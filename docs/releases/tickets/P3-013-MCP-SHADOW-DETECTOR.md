# P3-013 MCP Shadow Detector

## Priority

- P3 (Tier 0)

## Goal

Detect MCP shadowing patterns: late tool registration, schema drift for same tool, and near-name collision takeover attempts.

## Scope

- `src/security/mcp-shadow-detector.js` (new)
- `src/stages/policy/pii-injection-stage.js`
- `src/mcp/server.js`
- `src/server.js`
- `src/telemetry/prometheus.js`
- `src/config/schema.js`
- `src/config/default.yaml`

## File-Level Acceptance Checklist

- [ ] `src/security/mcp-shadow-detector.js` provides deterministic inspect API with bounded state.
- [ ] Tracks per-server tool registry snapshots with hash drift detection.
- [ ] Detects name collision (exact + normalized + edit-distance budget).
- [ ] Detects late registration after first snapshot for same server.
- [ ] Supports monitor/block modes with monitor-first default.
- [ ] Wiring in HTTP MCP-like path and MCP JSON-RPC inspect path.
- [ ] Metrics exported for detected, blocked, drift, late-registration, collisions.

## Exact Test Cases

- `test/unit/mcp-shadow-detector.test.js`
- `test('returns clean decision for stable MCP tool snapshot', ...)`
- `test('detects schema drift for same server/tool name', ...)`
- `test('detects late registration after baseline snapshot', ...)`
- `test('detects near-name collision across MCP servers', ...)`
- `test('enforce mode blocks when detector mode is block', ...)`
- `test('prunes stale server entries by ttl and max entries', ...)`
- `test/integration/mcp-shadow.integration.test.js`
- `test('mcp-like request emits warning header in monitor mode', ...)`
- `test('mcp-like request is blocked in enforce mode when shadow detected', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/mcp-shadow-detector.test.js
npm run test:integration -- test/integration/mcp-shadow.integration.test.js
```
