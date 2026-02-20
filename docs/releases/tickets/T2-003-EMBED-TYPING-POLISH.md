# T2-003 Embed Typing Polish

## Priority

- Tier-2

## Goal

Provide a first-class TypeScript contract for `sentinel-protocol/embed` with no ambiguous `unknown`-driven DX gaps.

## Scope

- `embed.d.ts`
- `index.d.ts` exports for embed surface
- TS consumer validation fixture

## Acceptance Criteria

- `import { createSentinel } from 'sentinel-protocol/embed'` resolves explicit types.
- `embed.d.ts` contains embed-specific typed surface and does not rely solely on wildcard re-export.
- Replace `unknown` with concrete interfaces for:
  - embedded scan request options
  - scan findings
  - middleware delegate signatures
- Add a minimal typecheck fixture that compiles with `tsc --noEmit` and uses:
  - `createSentinel`
  - `middleware()`
  - `scan()`
- No runtime packaging/export regressions.

## Verification Commands

```bash
npm run lint
npm test
npx --yes typescript@5.6.3 --noEmit test/types/embed-consumer.ts
```

