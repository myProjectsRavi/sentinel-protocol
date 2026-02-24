# Competitor Comparison (Adoption Sprint P0)

Last verified: 2026-02-24

## Summary

Sentinel currently publishes reproducible in-repo latency evidence with CI gates. Competitor coverage is mapped from public docs and marked as `not_measured` when this repo cannot reproduce a fair local benchmark path.

## Latency and Setup

| Tool | p95 Overhead (ms) | Time to First Protection | Source |
|---|---:|---:|---|
| Sentinel Protocol | 1 | 90s | `docs/benchmarks/results/sentinel-v4.json`, `docs/evidence/WIZARD_VALIDATION.md` |
| LLM Guard | not_measured | not_measured | public docs only |
| Rebuff | not_measured | not_measured | public docs only |
| NeMo Guardrails | not_measured | not_measured | public docs only |
| Lakera Guard | not_measured | not_measured | public docs only |

## OWASP LLM Top 10 Coverage Matrix

Legend: `full`, `partial`, `none`

| Tool | LLM01 | LLM02 | LLM03 | LLM04 | LLM05 | LLM06 | LLM07 | LLM08 | LLM09 | LLM10 |
|---|---|---|---|---|---|---|---|---|---|---|
| Sentinel Protocol | full | full | full | full | full | full | full | full | full | full |
| LLM Guard | partial | partial | none | none | none | partial | none | none | partial | none |
| Rebuff | partial | none | none | none | none | none | none | none | partial | none |
| NeMo Guardrails | partial | partial | none | none | none | partial | partial | partial | partial | none |
| Lakera Guard | partial | partial | none | none | none | partial | partial | partial | partial | none |

Machine-readable source: `docs/benchmarks/results/competitor-coverage.json`

## Fairness Notes

- Sentinel values are measured via the reproducible harness in this repo.
- Competitor rows intentionally avoid fabricated latency/setup numbers.
- When comparable reproducible harnesses are added, this page should be updated and date-stamped.
