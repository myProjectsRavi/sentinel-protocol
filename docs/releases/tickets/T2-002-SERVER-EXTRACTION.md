# T2-002 Server Extraction

## Priority

- Tier-2

## Goal

Further decompose `src/server.js` to improve maintainability and plugin/stage clarity without semantic drift.

## Scope

- `src/server.js`
- new runtime modules under `src/runtime/` or `src/stages/`
- tests proving unchanged request lifecycle behavior

## Acceptance Criteria

- `src/server.js` reduced to `<= 1500` lines.
- Extract at least these responsibilities into dedicated modules:
  - startup/shutdown lifecycle
  - transport listeners (HTTP/upgrade)
  - dashboard wiring
  - orchestrated stage execution wrapper
  - status emission plumbing
- Public API compatibility preserved for:
  - `SentinelServer`
  - existing CLI start path
  - embed API integration points
- `npm run test:integration` and `npm run reliability -- --duration 4 --connections 20 --chaos-requests 16 --timeout-requests 10 --websocket-requests 8` pass.
- Benchmark gate remains passing (`npm run benchmark:gate`).

## Verification Commands

```bash
npm run test:integration
npm run reliability -- --duration 4 --connections 20 --chaos-requests 16 --timeout-requests 10 --websocket-requests 8
npm run benchmark:gate
wc -l src/server.js
```

