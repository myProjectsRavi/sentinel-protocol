# Framework Detection Matrix (P0)

Last validated: 2026-02-24

## Scope

This validates framework detection and quick-start snippet emission for:

- `express`
- `fastify`
- `nextjs`
- `koa`
- `hono`
- `nestjs`
- no-framework fallback

## Reproduction

```bash
npm run ci:framework:detect:smoke
```

## Detection Matrix

| Fixture | Expected | Detected | Snippet Printed | Result |
|---|---|---|---|---|
| `dependencies.express` | express | express | yes | pass |
| `dependencies.fastify` | fastify | fastify | yes | pass |
| `dependencies.next` | nextjs | nextjs | yes | pass |
| `dependencies.koa` | koa | koa | yes | pass |
| `dependencies.@hono/node-server` | hono | hono | yes | pass |
| `dependencies.@nestjs/core` | nestjs | nestjs | yes | pass |
| none | none | none | no detection banner | pass |

## Snippet Contract

For detected frameworks, CLI output includes:

- proxy-mode snippet with `baseURL: 'http://127.0.0.1:8787/v1'`
- target header example (`x-sentinel-target`)
- embed-mode snippet:

```js
const { createSentinel } = require('sentinel-protocol');
const sentinel = createSentinel(config);
app.use(sentinel.middleware());
sentinel.start();
```

## Guardrails

- Detection is read-only (no source-file mutation).
- Snippet guidance is print-only.
- Unknown framework projects resolve to `none` with no false positives.
