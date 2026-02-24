# VS Code Extension Packaging Validation

## Goal

Produce a deterministic `.vsix` artifact in CI/release without changing Sentinel runtime dependencies.

## Commands

Local packaging:

```bash
npm run ci:vscode:package
```

Expected output:

- `dist/sentinel-protocol-vscode-<version>.vsix`

## CI Wiring

- Quality gates workflow runs `npm run ci:vscode:package`.
- Artifact upload includes `dist/*.vsix` in `sbom-ci`.
- Release workflow packages `.vsix` and uploads it with SBOM/AIBOM artifacts.
- Optional marketplace publish runs only when `VSCE_PAT` secret is set.

## Validation Criteria

1. `npm run ci:vscode:package` exits `0`.
2. `dist/*.vsix` exists after build.
3. CI artifact includes the generated `.vsix`.
