# P3-019 Universal SDK Embed Mode

## Priority

- P3 (Tier 1)

## Goal

Expand embed API into full programmatic Sentinel surface for middleware/fetch/framework callbacks.

## Scope

- `src/embed.js`
- `src/embed/middleware.js` (new)
- `src/embed/secure-fetch.js` (new)
- `src/embed/framework-callbacks.js` (new)
- `index.d.ts`

## File-Level Acceptance Checklist

- [ ] Exposes middleware, secureFetch, framework callback adapters.
- [ ] Uses same config contract as proxy mode.
- [ ] Works in serverless (no mandatory process globals).
- [ ] Typed declaration updates for embed subpath.
- [ ] No semantic drift from existing `createSentinel` behavior.

## Exact Test Cases

- `test/unit/embed-api.test.js`
- `test/unit/embed-secure-fetch.test.js`
- `test/unit/embed-framework-callbacks.test.js`
- `test('middleware path enforces same policy decisions as proxy mode', ...)`
- `test('secureFetch injects sentinel headers and returns governed response', ...)`
- `test('langchain callback emits lifecycle events without mutation side effects', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/embed-api.test.js test/unit/embed-secure-fetch.test.js test/unit/embed-framework-callbacks.test.js
```
