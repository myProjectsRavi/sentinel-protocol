# Hero GIF Validation

Last validated: 2026-02-24

## Artifact

- file: `docs/assets/sentinel-hero.gif`
- dimensions: `480x270`
- duration: `12s`
- sha256: `50ae5f7a8fbe3435c8f06f60aec489dd420e104fac72e2084734ac4d847dd3d0`

## Reproduction

```bash
node ./scripts/generate-hero-gif.js
```

The generator is deterministic and dependency-free (Node built-ins only).
