# OWASP Reference Implementation Submission Pack

Last updated: 2026-02-24

## Objective

Provide a deterministic, evidence-backed submission package positioning Sentinel Protocol as a practical local AI governance reference implementation aligned to OWASP LLM Top 10 controls.

## Claim Boundary (Strict)

- Only in-repo, reproducible metrics are claimed.
- Unknown or non-reproduced competitor metrics stay `not_measured`.
- Coverage claims are mapped to concrete engine modules and config paths.

## Submission Artifacts

Use `docs/owasp/submission-manifest.json` as the single source of truth for immutable artifact hashes.

Core artifacts include:

- `docs/OWASP_LLM_TOP10_SENTINEL_MAP.md`
- `docs/OWASP-HARDENING.md`
- `docs/openapi.yaml`
- `docs/SECURITY_RELIABILITY_EVIDENCE_V4_PHASEA.md`
- `docs/benchmarks/METHODOLOGY.md`
- `docs/benchmarks/results/standard-datasets.json`
- `README.md`
- `CHANGELOG.md`

## Reproduction Commands

```bash
npm run lint
npm test -- --runInBand
npm run openapi:validate
npm run benchmark:gate
npm run benchmark:datasets
node ./scripts/prepare-owasp-submission-pack.js
```

## External Submission Checklist

1. Verify all CI gates are green for the target branch/tag.
2. Re-generate `docs/owasp/submission-manifest.json` and commit if hashes changed.
3. Confirm OWASP mapping file references current engine names and control paths.
4. Include benchmark methodology and scope limitations verbatim in submission notes.
5. Attach manifest and evidence links in the OWASP issue/PR description.

## Suggested OWASP Submission Template

- Project: Sentinel Protocol
- Version: 1.0.0
- Type: Local-first AI governance firewall and policy perimeter
- Primary interfaces: HTTP proxy, websocket interception, embed middleware, control-plane APIs
- OWASP mapping: `docs/OWASP_LLM_TOP10_SENTINEL_MAP.md`
- Evidence manifest: `docs/owasp/submission-manifest.json`
- Repro command set: from this document
- Scope note: adversarial benchmark pack is mini-fixture based for deterministic local CI execution

## Non-Overclaim Statement

Sentinel does not claim certified compliance status. It provides deterministic controls, mappings, and verifiable evidence artifacts to accelerate independent security review and governance workflows.
