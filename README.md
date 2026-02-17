# sentinel-protocol

Sentinel Protocol is a local firewall for AI agents.

It provides:
- Deterministic policy enforcement (`monitor`, `warn`, `enforce`)
- PII/secret detection with severity actions (`block`, `redact`, `log`)
- Upstream resilience (conservative retry + per-provider circuit breaker)
- Explicit outage diagnostics via `x-sentinel-*` response headers
- Strict config versioning and migration with backup
- Emergency recovery controls (`--dry-run`, `--fail-open`, `emergency-open`)

## Quick Start

```bash
npm install
node ./cli/sentinel.js init
node ./cli/sentinel.js start
```

Then point your agent base URL to:

```text
http://127.0.0.1:8787
```

Use `x-sentinel-target: anthropic|openai|google|custom` to route providers.

See docs:
- `docs/QUICKSTART.md`
- `docs/OUTAGE-RUNBOOK.md`
- `docs/POLICY-GUIDE.md`
