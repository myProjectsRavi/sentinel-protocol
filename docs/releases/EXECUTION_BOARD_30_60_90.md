# Sentinel Protocol 30/60/90 Execution Board

## Board Objective

Convert validated baseline quality into sustained enterprise adoption while keeping release train stability and zero semantic drift in core controls.

## 30 Days (P0 Delivery Lock + Tier-2 Start)

### Outcomes

- Preserve baseline reliability/security guarantees from `release-baseline-7186f1f`.
- Open and execute Tier-2 tickets with strict acceptance gates.
- Start WASM scanner research track in shadow mode only.

### Deliverables

- Tier-2 ticket set:
  - `docs/releases/tickets/T2-001-COVERAGE-RATCHET.md`
  - `docs/releases/tickets/T2-002-SERVER-EXTRACTION.md`
  - `docs/releases/tickets/T2-003-EMBED-TYPING-POLISH.md`
- WASM research charter:
  - `docs/releases/research/WASM_SCANNER_RESEARCH_TRACK.md`
- Release proof package:
  - `docs/releases/SECURITY_RELIABILITY_EVIDENCE_7186f1f.md`

### Exit Criteria

- No regression in:
  - CI lint/audit/integration/reliability/quality-gates
  - Docker quickstart smoke
- No default behavior changes in enforcement paths.
- Research path remains opt-in and monitor-only.

## 60 Days (Tier-2 Completion + Maintainer Trust Lift)

### Outcomes

- Improve maintainability and contributor trust without production drift.

### Deliverables

- Coverage ratchet merged and stable in CI.
- `server.js` extraction milestone merged with line-count reduction target met.
- `sentinel-protocol/embed` declaration quality upgraded to explicit typed contract.
- Evidence docs refreshed per release.

### Exit Criteria

- Tier-2 tickets closed with acceptance criteria satisfied.
- CI remains green on all jobs for two consecutive release candidates.
- No increase in open-handle/test-flake incidents.

## 90 Days (Enterprise Readiness Consolidation)

### Outcomes

- Turn baseline trust into procurement-grade readiness and pilot execution velocity.

### Deliverables

- Hard proof pages for each release baseline.
- Reliability evidence refresh with updated manifest and report growth.
- Optional WASM scanner decision memo:
  - promote to guarded beta, or keep deferred with evidence.

### Exit Criteria

- Enterprise review packet can be sent without ad hoc prep.
- Stable release cadence maintained.
- Deferred-item research track has explicit promote/defer decision with metrics.

## Board Rules (Non-Negotiable)

- Monitor-first before enforce-first for all new detection paths.
- Config contract remains strict:
  - unknown-key rejection
  - no silent defaults
- No release without:
  - CI quality gates pass
  - benchmark gate pass
  - SBOM artifacts generated
  - Docker smoke pass

