# WASM Scanner Research Track (Deferred Flagship)

## Track Type

- Research track (deferred item), non-blocking for release train

## Vision

Evaluate a WebAssembly scanner engine for PII/injection workloads with strict semantic parity and measurable throughput gains.

## Non-Negotiable Guardrails

- No default-path replacement during research.
- WASM path stays opt-in and monitor-only until parity proof is met.
- Core CI/release gates remain unchanged and required for every merge.
- Any mismatch between JS and WASM classifiers is audit-logged.

## Hypotheses

- Throughput: WASM scanner can achieve at least `2x` throughput vs JS baseline in synthetic and mixed corpora.
- Latency: p95 scan latency improves by at least `30%` under equivalent load.
- Parity: detection decision parity reaches at least `99.9%` on baseline corpora.

## Phases

### R0: Harness & Corpus Lock

- Build deterministic corpus runner that executes JS and WASM side-by-side.
- Freeze baseline corpora and expected labels.
- Emit diff reports with machine-readable mismatch classes.

### R1: PII Scanner Prototype (Monitor Only)

- Implement minimal WASM PII path.
- Compare against existing JS scanner on corpora and replay traffic traces.
- Publish parity + throughput report.

### R2: Injection Scanner Prototype (Monitor Only)

- Implement injection scan parity harness.
- Validate unicode/obfuscation handling parity.
- Publish parity + throughput report.

### R3: Promotion Decision

- Promote only if all criteria are met; otherwise defer with documented blockers.

## Promotion Criteria

- Parity:
  - false-negative delta = `0` on critical/high findings in baseline corpora
  - overall parity >= `99.9%`
- Performance:
  - p95 latency improvement >= `30%`
  - sustained throughput improvement >= `2x`
- Stability:
  - no event-loop regressions
  - no CI/reliability regressions

## Release-Train Stability Rules

- WASM code paths gated behind explicit config flags.
- No policy action changes driven by WASM output unless JS/WASM agree.
- If disagreement occurs:
  - use JS decision
  - record mismatch telemetry
  - mark request as research-observed only

