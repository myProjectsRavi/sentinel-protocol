# Sentinel Protocol (v1.0)

Sentinel Protocol is a local firewall for AI agents.

Sentinel is the only Open Source AI Firewall that runs PII detection in Worker Threads and performs Real-Time Neural Injection analysis without blocking the Event Loop. It supports Bi-directional SSE Stream Redaction out of the box.

It provides:
- Deterministic policy enforcement (`monitor`, `warn`, `enforce`)
- PII/secret detection with severity actions (`block`, `redact`, `log`)
- Format-preserving masking mode for test-safe pseudonyms (`pii.redaction.mode: format_preserving`)
- Bi-directional protection: ingress request scanning + egress response scanning/redaction
- PII provider modes: `local`, `rapidapi`, `hybrid` (with local fallback controls)
- Heuristic prompt-injection detection (`injection_threshold` policy matching)
- Optional neural injection classifier (`injection.neural.*`) with weighted merge
- VCR mode for deterministic API testing (`runtime.vcr.mode: record|replay`)
- Experimental semantic cache (opt-in, off by default) to reduce repeat LLM calls
- Local-only live dashboard (`runtime.dashboard.enabled: true`) on `127.0.0.1:8788`
- Worker-thread scan pool to reduce event-loop blocking under load
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
  egress:
    enabled: true
    max_scan_bytes: 65536
    stream_enabled: true
    sse_line_max_bytes: 16384
    stream_block_mode: redact # redact | terminate
  rapidapi:
    endpoint: "https://pii-firewall-edge.p.rapidapi.com/redact"
    host: "pii-firewall-edge.p.rapidapi.com"
    max_timeout_ms: 1500
    cache_max_entries: 1024
    cache_ttl_ms: 300000
    fallback_to_local: true
injection:
  threshold: 0.8
  neural:
    enabled: false
    model_id: "Xenova/all-MiniLM-L6-v2"
    timeout_ms: 1200
    weight: 1
    mode: max # max | blend
runtime:
  vcr:
    enabled: false
    mode: off # off | record | replay
    strict_replay: false
  semantic_cache:
    enabled: false # experimental, opt-in
    similarity_threshold: 0.95
    max_entry_bytes: 262144
    max_ram_mb: 64
  dashboard:
    enabled: false
    host: 127.0.0.1
    port: 8788
    auth_token: "" # required when allow_remote=true
pii:
  redaction:
    mode: placeholder # placeholder | format_preserving
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

VCR mode (deterministic test replay):

```bash
node ./cli/sentinel.js start --record
# ...run agent tests...
node ./cli/sentinel.js stop
node ./cli/sentinel.js start --replay
```

Enable local dashboard for current run:

```bash
node ./cli/sentinel.js start --dashboard
# dashboard: http://127.0.0.1:8788
```

Security note:
- `runtime.dashboard.allow_remote=true` requires `runtime.dashboard.auth_token` (enforced by config validation).
- Semantic cache embeddings run in worker threads; keep `runtime.worker_pool.enabled=true`.

## Docker

Build image (Debian slim, non-root runtime):

```bash
docker build -t sentinel-protocol:latest .
```

Optional: preload semantic and neural models during build to remove first-request model download latency:

```bash
docker build -t sentinel-protocol:latest \
  --build-arg PRELOAD_SEMANTIC_MODEL=true \
  --build-arg PRELOAD_NEURAL_MODEL=true .
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
- `docs/RELIABILITY_PROOF.md`
- `docs/OWASP-HARDENING.md`
- `BENCHMARKS.md`
