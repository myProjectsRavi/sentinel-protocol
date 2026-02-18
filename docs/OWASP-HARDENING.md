# OWASP Hardening Matrix

This document maps Sentinel v1 hardenings to 20 common OWASP-style risk classes (Web + API + LLM agent operations).

## Implemented Controls

1. Injection (prompt/policy): heuristic injection scanner + enforce threshold rules.
2. Prompt-injection exfiltration: ingress policy checks + heuristic and optional neural injection scoring.
3. Sensitive data exposure (ingress): local/rapidapi/hybrid PII scanner with severity actions.
4. Sensitive data exposure (egress): buffered response scanning + SSE redaction or optional stream termination.
5. SSRF/custom target abuse: strict allowlist + private-network blocking + DNS/IP pinning.
6. DNS rebinding TOCTOU: custom target resolution returns pinned IP used by upstream client.
7. Request smuggling: hop-by-hop request header scrubbing.
8. Response smuggling/header confusion: hop-by-hop response header scrubbing.
9. Broken auth by leaked internal headers: strips `x-sentinel-*` before upstream forwarding.
10. Security misconfiguration: strict config schema validation with unknown-key rejection.
11. Unsafe config evolution: versioned config + migration + backup + loud failures.
12. DoS via oversized request bodies: `proxy.max_body_bytes` hard cap.
13. Regex-based DoS risk: scanner regex safety cap + scan budget.
14. Event-loop saturation: worker-thread scan pool offloads heavy local scanning.
15. Upstream outage confusion: explicit `x-sentinel-*` attribution headers on failures.
16. Retry storms: conservative retry policy (idempotent by default + bounded attempts).
17. Cascading provider failure: per-provider circuit breaker with half-open probes.
18. Unsafe emergency recovery: `--dry-run`, `--fail-open`, `emergency-open` with logging.
19. Method abuse: TRACE/CONNECT denied with explicit 405.
20. Runtime observability gaps: audit logs, status endpoint, TUI monitor, telemetry hooks.

## Current Gaps (Planned)

1. Streaming egress block mode: current SSE mode redacts but does not mid-stream hard-block.
2. Neural injection classifier: heuristics are implemented; model-assisted detection is optional roadmap.
3. Integration tests in restricted sandboxes: network-binding constraints can block integration runs.
