# Contributing to Sentinel Protocol

Sentinel Protocol targets enterprise-grade reliability and deterministic security behavior. Contributions are welcome, but changes must preserve policy determinism, config contracts, and monitor-first rollout safety.

## Prerequisites

- Node.js `>=20`
- npm `>=10`
- Docker (optional, for quickstart/ops path validation)

## Local Setup

```bash
npm install
npm run lint
npm run openapi:validate
npm run test:unit
```

Integration/reliability runs require a normal local runtime or CI (sandboxed environments may block listen sockets).

## Required Checks Before PR

- `npm run lint`
- `npm run openapi:validate`
- `npm run test:unit`
- `npm run test:integration`
- `npm run reliability -- --duration 4 --connections 20 --chaos-requests 16 --timeout-requests 10 --websocket-requests 8`
- `npm run benchmark -- --duration 4 --connections 20`
- `npm run benchmark:gate`

## Guardrails for Changes

- Keep behavior config-driven. No hidden defaults that silently change security posture.
- Prefer monitor-first for new/experimental defenses.
- Keep policy decisions deterministic and auditable.
- Never log raw secrets, keys, or sensitive prompt payloads in diagnostics artifacts.
- Preserve strict schema validation and unknown-key rejection.
- Preserve fail-open/dry-run/emergency control invariants.

## Plugin Development

Use the plugin interface through pipeline hooks. Start with the minimal walkthrough in `docs/PLUGIN_TUTORIAL.md`.

Core expectations for plugins:

- Declare a stable plugin `name`.
- Operate through hook context (`get`, `set`, `warn`, `block`) only.
- Keep hook side effects deterministic.
- Treat scanner/model errors explicitly and avoid fail-closed surprises unless configured.

## Commit Quality

- Add or update tests for behavior changes.
- Keep diffs focused and avoid unrelated refactors.
- Document new config keys in `README.md` and `docs/QUICKSTART.md`.

## Security Reporting

Do not open public issues for undisclosed vulnerabilities. Follow `SECURITY.md`.
