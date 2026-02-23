# OWASP LLM Top 10 Sentinel Mapping

This document tracks Sentinel control coverage against OWASP LLM Top 10 (`LLM01` to `LLM10`).

Status semantics:

- `covered`: mapped controls enabled in enforce-capable mode.
- `partially_covered`: mapped controls enabled but monitor/warn-only.
- `missing`: mapped controls disabled.

## Mapping Matrix

| Risk | Category | Sentinel Controls | Current Gap Notes |
|---|---|---|---|
| `LLM01` | Prompt Injection | `injection_scanner`, `prompt_rebuff` | Promote monitor-only deployments to block mode after evidence review. |
| `LLM02` | Insecure Output Handling | `pii.egress`, `sandbox_experimental` | Sandbox remains optional; enable for high-risk tool execution paths. |
| `LLM03` | Training Data Poisoning | `synthetic_poisoning`, `auto_immune` | Synthetic poisoning is strict-gated and should remain opt-in. |
| `LLM04` | Model Denial of Service | `proxy.max_body_bytes`, `rate_limiter` | Tune per-route limits for heavy internal batch paths. |
| `LLM05` | Supply Chain Vulnerabilities | `mcp_poisoning`, `provenance` | Expand signed policy-bundle rollout in multi-team deployments. |
| `LLM06` | Sensitive Information Disclosure | `pii ingress`, `pii_vault` | Vault active mode can be phased for selected flows first. |
| `LLM07` | Insecure Plugin Design | `canary_tools`, `sandbox_experimental` | Keep plugin hooks monitor-first before block promotion. |
| `LLM08` | Excessive Agency | `loop_breaker`, `agentic_threat_shield` | Strengthen identity token verification in enterprise profiles. |
| `LLM09` | Overreliance | `intent_drift`, `cognitive_rollback` | Auto rollback should remain controlled with explicit approvals. |
| `LLM10` | Model Theft | `provenance_signing`, `swarm_protocol` | Swarm is optional; provenance should be default in regulated environments. |

## Report Generation

```bash
node ./cli/sentinel.js compliance owasp-llm --report html --out ./owasp-llm-report.html
```

JSON output is also supported:

```bash
node ./cli/sentinel.js compliance owasp-llm --report json --out ./owasp-llm-report.json
```
