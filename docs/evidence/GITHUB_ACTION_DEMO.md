# GitHub Action Demo (P0)

Last validated: 2026-02-24

## Action Path

- Local action definition: `.github/actions/security-scan/action.yml`
- Entry point: `.github/actions/security-scan/index.js`
- Tests: `.github/actions/security-scan/test/action.test.js`

## One-Line Usage

```yaml
- uses: myProjectsRavi/sentinel-protocol/.github/actions/security-scan@v1
```

## Full Job Example

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - uses: myProjectsRavi/sentinel-protocol/.github/actions/security-scan@v1
        with:
          threshold: '0.85'
          eval-file: 'sentinel-eval.json'
          fail-on-regression: 'true'
          post-comment: 'true'
          sarif-output: 'security-scan.sarif'
```

## Contract

| Capability | Status | Evidence |
|---|---|---|
| local-only scanning (no API key required) | pass | uses `InjectionScanner` + `AdversarialEvalHarness` locally |
| configurable threshold gate | pass | `threshold` input, non-zero exit on failure |
| custom eval cases (`sentinel-eval.json`) | pass | supports array or `{cases:[...]}` |
| PR comment output | pass | posts markdown comment when findings/regression exist |
| SARIF output | pass | optional `sarif-output` artifact |
| runtime under 30s (default corpus) | pass | action unit tests execute in sub-second local path |

## Reproduction

```bash
npx jest --runInBand .github/actions/security-scan/test/action.test.js
```
