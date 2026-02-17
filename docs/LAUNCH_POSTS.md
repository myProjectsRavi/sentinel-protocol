# Launch Posts

## Hacker News (Show HN)

**Title**
Show HN: Sentinel Protocol - Local firewall for AI agents (PII, policy, outage diagnostics)

**Body**
I built Sentinel Protocol, a local firewall that sits between AI agents and upstream providers.

What it does in v0.1.0:
- Monitor/warn/enforce modes
- Deterministic policy engine
- PII/secret scanning with block/redact actions
- Per-provider circuit breaker + conservative retries
- Explicit `x-sentinel-*` diagnostics to separate Sentinel faults from upstream outages
- Recovery controls: `--dry-run`, `--fail-open`, `emergency-open`

Repo: https://github.com/myProjectsRavi/sentinel-protocol
Release: https://github.com/myProjectsRavi/sentinel-protocol/releases/tag/v0.1.0

## X/Twitter Thread

1. I shipped Sentinel Protocol v0.1.0: a local firewall for AI agents.
2. It enforces deterministic policy + PII controls before traffic reaches model providers.
3. Added outage diagnostics headers so teams can instantly tell whether Sentinel failed or upstream failed.
4. Added per-provider circuit breaker + conservative retries (no unsafe POST retries by default).
5. Added recovery controls for production safety: `--dry-run`, `--fail-open`, and `emergency-open`.
6. Repo: https://github.com/myProjectsRavi/sentinel-protocol
7. Release notes: https://github.com/myProjectsRavi/sentinel-protocol/releases/tag/v0.1.0

## Reddit (r/LangChain / r/LocalLLaMA / r/MachineLearning)

**Title**
Sentinel Protocol v0.1.0 - Local AI agent firewall with PII blocking, policy enforcement, and upstream outage diagnostics

**Body**
I released Sentinel Protocol v0.1.0.

It runs locally in front of agent traffic and adds:
- policy-as-code rules (`monitor/warn/enforce`)
- critical/high PII blocking and medium redaction
- per-provider circuit breaker
- conservative retry logic
- diagnostic headers to quickly identify upstream vs firewall failures

GitHub: https://github.com/myProjectsRavi/sentinel-protocol
Release: https://github.com/myProjectsRavi/sentinel-protocol/releases/tag/v0.1.0
