# Standard Adversarial Dataset Pack

This folder contains deterministic, redistribution-safe mini datasets used by Sentinel's in-repo standard adversarial benchmark harness.

## Why mini datasets

- Full upstream benchmark datasets can have licensing/distribution constraints.
- CI requires deterministic, local, zero-network execution.
- These fixtures preserve attack-family coverage for regression checks.

## Datasets

- `advbench-mini.json`
  - AdvBench-inspired prompt-injection and tool-abuse patterns.
- `trojai-mini.json`
  - TrojAI-style trigger/evasion prompt patterns.

## Reproduction

```bash
npm run benchmark:datasets
```

Output:

- `docs/benchmarks/results/standard-datasets.json`

## Scope boundary

These are benchmark fixtures, not claims of parity with full upstream datasets. Sentinel reports this explicitly to avoid over-claiming.
