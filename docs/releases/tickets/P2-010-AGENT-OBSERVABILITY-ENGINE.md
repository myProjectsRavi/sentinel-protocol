# P2-010 Agent Observability Engine

## Priority

- P2

## Goal

Add lightweight agent lifecycle telemetry and trace-context propagation for multi-agent workflows without external collectors.

## Scope

- `src/telemetry/agent-observability.js` (new)
- `src/stages/ingress-stage.js`
- `src/stages/policy/agentic-stage.js`
- `src/stages/routing-stage.js`
- `src/stages/egress-stage.js`
- `src/telemetry/prometheus.js`
- `src/config/schema.js`
- `src/config/default.yaml`

## File-Level Acceptance Checklist

- [ ] `src/telemetry/agent-observability.js` parses/generates `traceparent` and optional `tracestate`.
- [ ] Lifecycle events emitted: `agent.start`, `agent.tool_call`, `agent.delegate`, `agent.complete`, `agent.error`.
- [ ] Upstream forwarding preserves/sets trace headers consistently.
- [ ] Prometheus exports event counters and duration histogram.
- [ ] Config contract `runtime.agent_observability.*` is strict and default-safe.
- [ ] Feature stays telemetry-only; no request blocking decisions.

## Exact Test Cases

- `test/unit/agent-observability.test.js`
- `test('parses valid incoming traceparent and preserves trace id', ...)`
- `test('generates traceparent when missing', ...)`
- `test('emits lifecycle event sequence for successful request', ...)`
- `test('emits agent.error event on stage exception', ...)`
- `test('sanitizes event fields to avoid raw prompt leakage', ...)`
- `test/integration/agent-observability.integration.test.js`
- `test('upstream request includes traceparent header after ingress processing', ...)`
- `test('metrics endpoint includes agent observability counters', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/agent-observability.test.js
npm run test:integration -- test/integration/agent-observability.integration.test.js
curl -s http://127.0.0.1:8787/_sentinel/metrics | rg agent_observability
```

