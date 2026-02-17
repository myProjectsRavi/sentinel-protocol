# sentinel-protocol

Sentinel Protocol is a local firewall for AI agents.

It provides:
- Deterministic policy enforcement (`monitor`, `warn`, `enforce`)
- PII/secret detection with severity actions (`block`, `redact`, `log`)
- PII provider modes: `local`, `rapidapi`, `hybrid` (with local fallback controls)
- Heuristic prompt-injection detection (`injection_threshold` policy matching)
- DNS-rebinding-resistant custom upstream routing (IP pinning + Host/SNI preservation)
- Upstream resilience (conservative retry + per-provider circuit breaker)
- SSE streaming passthrough for `text/event-stream` responses
- OpenTelemetry hooks for spans and metrics
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
`custom` targets are disabled by default and require explicit allowlisting in config.

## PII Provider Modes

Configure in `sentinel.yaml`:

```yaml
pii:
  provider_mode: local # local | rapidapi | hybrid
  rapidapi:
    endpoint: "https://pii-firewall-edge.p.rapidapi.com/redact"
    host: "pii-firewall-edge.p.rapidapi.com"
    fallback_to_local: true
```

Key resolution priority for `rapidapi` and `hybrid`:
1. Request header: `x-sentinel-rapidapi-key`
2. Env var: `SENTINEL_RAPIDAPI_KEY`
3. Config: `pii.rapidapi.api_key`

BYOK policy:
- Sentinel does not ship a shared RapidAPI key.
- Use your own RapidAPI subscription key.
- Prefer `SENTINEL_RAPIDAPI_KEY` over storing keys in `sentinel.yaml`.

`x-sentinel-*` headers are stripped before forwarding upstream, so Sentinel-only routing and keys are not leaked to OpenAI/Anthropic/Google/custom providers.

Preflight check before startup:

```bash
node ./cli/sentinel.js doctor
```

The doctor command warns when `NODE_ENV` is not `production`.

MCP mode:

```bash
node ./cli/sentinel.js mcp
```

Terminal monitor:

```bash
node ./cli/sentinel.js monitor
```

## Docker

Build image (Debian slim, non-root runtime):

```bash
docker build -t sentinel-protocol:latest .
```

Optional: preload semantic model during build to remove first-request model download latency:

```bash
docker build -t sentinel-protocol:latest --build-arg PRELOAD_SEMANTIC_MODEL=true .
```

Run with one command (read-only config mount + writable runtime state volume):

```bash
docker run --rm -p 8787:8787 \
  -e NODE_ENV=production \
  -e SENTINEL_HOME=/var/lib/sentinel \
  -v $(pwd)/config/sentinel.yaml:/etc/sentinel/sentinel.yaml:ro \
  -v sentinel-data:/var/lib/sentinel \
  sentinel-protocol:latest start --config /etc/sentinel/sentinel.yaml --port 8787
```

The included `docker-compose.yml` already mounts a writable model cache volume:
`sentinel-models:/home/sentinel/.sentinel/models`.

Compose (hardened defaults: `read_only`, `no-new-privileges`, `cap_drop: ALL`):

```bash
docker compose up --build
```

Pre-download semantic model manually:

```bash
node ./cli/sentinel.js models download --config ./config/sentinel.yaml
```

See docs:
- `docs/QUICKSTART.md`
- `docs/OUTAGE-RUNBOOK.md`
- `docs/POLICY-GUIDE.md`
- `docs/DEMO_VIDEO_SCRIPT.md`
- `docs/INTEGRATIONS.md`
- `BENCHMARKS.md`
