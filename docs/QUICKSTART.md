# Quickstart

## 1. Primary Bootstrap (npx)

```bash
npx sentinel-protocol init
npx sentinel-protocol start
```

This is the primary onboarding path for docs/tutorials.

## 2. Alternate Bootstrap (source checkout)

```bash
npm install
node ./cli/sentinel.js init
node ./cli/sentinel.js start
```

`init` creates:
- `~/.sentinel/sentinel.yaml`

## 3. Alternate Ops Path (Docker)

```bash
docker-compose up -d
```

## 4. Startup Notes

Startup runs `doctor` checks automatically. Run explicitly:

```bash
node ./cli/sentinel.js doctor
```

Set production mode for safer runtime defaults:

```bash
NODE_ENV=production npx sentinel-protocol start
```

Optional safe startup flags:

```bash
npx sentinel-protocol start --dry-run
npx sentinel-protocol start --fail-open
npx sentinel-protocol start --skip-doctor
```

## 5. Configure agent

Set base URL to:

```text
http://127.0.0.1:8787
```

Route to provider with header:
- `x-sentinel-target: openai`
- `x-sentinel-target: anthropic`
- `x-sentinel-target: google`
- `x-sentinel-target: ollama`
- `x-sentinel-target: custom` + `x-sentinel-custom-url`

`custom` targets are disabled by default for SSRF safety.
Enable in `sentinel.yaml`:

```yaml
runtime:
  upstream:
    custom_targets:
      enabled: true
      allowlist:
        - api.example.com
      block_private_networks: true
```

Body and scan safety defaults:

```yaml
proxy:
  max_body_bytes: 1048576 # 1MB default

pii:
  regex_safety_cap_bytes: 51200 # 50KB regex budget

runtime:
  websocket:
    enabled: true
    mode: monitor
    connect_timeout_ms: 15000
    idle_timeout_ms: 120000
    max_connections: 500
  loop_breaker:
    enabled: true
    action: block
    window_ms: 30000
    repeat_threshold: 4
    max_recent: 5
  upstream:
    ghost_mode:
      enabled: false
      override_user_agent: true
      user_agent_value: "Sentinel/1.0 (Privacy Proxy)"
```

## 6. Configure PII provider mode

Choose one:
- `local`: local scanner only (default)
- `rapidapi`: use RapidAPI scanner as primary
- `hybrid`: local + RapidAPI merge

Example:

```yaml
pii:
  provider_mode: hybrid
  rapidapi:
    endpoint: "https://pii-firewall-edge.p.rapidapi.com/redact"
    host: "pii-firewall-edge.p.rapidapi.com"
    fallback_to_local: true
```

Provide RapidAPI key via one of:
- request header: `x-sentinel-rapidapi-key`
- env var: `SENTINEL_RAPIDAPI_KEY`
- config: `pii.rapidapi.api_key`

BYOK required:
- Sentinel does not provide a shared RapidAPI key.
- Prefer `SENTINEL_RAPIDAPI_KEY` for secure local key handling.

On RapidAPI failures:
- `rapidapi` + `fallback_to_local: true` -> local scanner fallback
- `rapidapi` + `fallback_to_local: false` -> `502 PII_PROVIDER_ERROR`
- `hybrid` -> local result still applies; warning header indicates fallback

Sentinel strips all `x-sentinel-*` headers before forwarding upstream.

## 6.1 Optional: Local API Key Vault (dummy-key replacement)

Use this when running untrusted agent code/packages locally.

```yaml
runtime:
  upstream:
    auth_vault:
      enabled: true
      mode: replace_dummy # replace_dummy | enforce
      dummy_key: "sk-sentinel-local"
      providers:
        openai:
          enabled: true
          api_key: "" # prefer env var
          env_var: "SENTINEL_OPENAI_API_KEY"
```

Recommended:
- Set real keys in env vars (`SENTINEL_OPENAI_API_KEY`, `SENTINEL_ANTHROPIC_API_KEY`, `SENTINEL_GOOGLE_API_KEY`).
- In your app, use dummy credentials (for example `OPENAI_API_KEY=sk-sentinel-local`).
- `replace_dummy`: replace only dummy keys.
- `enforce`: strip client keys and fail closed if vault keys are missing.

## 7. Configure prompt-injection detection

Injection scanning is enabled by default. You can tune the default threshold and add rule-level controls.

```yaml
injection:
  enabled: true
  threshold: 0.8
  max_scan_bytes: 131072
  action: block

rules:
  - name: block-prompt-injection
    match:
      injection_threshold: 0.8
    action: block
```

### 7.1 Opt-in: Agentic Threat Shield + Prompt Rebuff

Default posture is disabled + monitor-first. Enable in monitor, then promote to block after audit evidence.

```yaml
runtime:
  agentic_threat_shield:
    enabled: true
    mode: monitor # monitor | block
    max_tool_call_depth: 10
    max_agent_delegations: 5
    max_analysis_nodes: 4096
    max_tool_calls_analyzed: 1024
    detect_cycles: true
    verify_identity_tokens: false

  prompt_rebuff:
    enabled: true
    mode: monitor # monitor | block
    sensitivity: balanced # permissive | balanced | paranoid
    warn_threshold: 0.65
    block_threshold: 0.85
    max_body_chars: 8192
    max_response_chars: 8192
```

Behavior:
- `monitor`: forwards request and adds warning/diagnostic headers.
- `block` + global `mode: enforce`: returns `403` on qualifying violations.

### 7.2 Optional: Output schema validation (monitor-first)

Use this to detect structured-response drift and exfiltration via unexpected fields.

```yaml
runtime:
  output_schema_validator:
    enabled: true
    mode: monitor # monitor | block
    default_schema: chat_response_minimal
    schemas:
      chat_response_minimal:
        type: object
        required: [id, choices]
        additionalProperties: false
        properties:
          id:
            type: string
          choices:
            type: array
```

When promoted to `mode: block` with global `mode: enforce`, schema mismatches return:
- `502`
- `x-sentinel-blocked-by: output_schema_validator`

## 8. Optional semantic scanner

Semantic NER runs locally and is disabled by default.

1. Install optional dependency:

```bash
npm install @xenova/transformers
```

2. Enable scanner in config:

```yaml
pii:
  semantic:
    enabled: true
    model_id: Xenova/bert-base-NER
    cache_dir: "~/.sentinel/models"
    score_threshold: 0.6
    max_scan_bytes: 32768
```

## 9. MCP and monitor modes

Run Sentinel as minimal MCP server:

```bash
node ./cli/sentinel.js mcp
```

Open terminal dashboard:

```bash
node ./cli/sentinel.js monitor
```

Web dashboard auth/binding defaults:

- Bind host defaults to `127.0.0.1` (localhost-only).
- Optional production auth token: `runtime.dashboard.auth_token`.
- If `runtime.dashboard.allow_remote=true`, a non-empty `runtime.dashboard.auth_token` is required.

## 10. Check status

Human output:

```bash
node ./cli/sentinel.js status
```

JSON output:

```bash
node ./cli/sentinel.js status --json
```

Provider observability fields:
- `pii_provider_mode`
- `pii_provider_fallbacks`
- `rapidapi_error_count`

## 11. Benchmark overhead

```bash
npm run benchmark
```

See `BENCHMARKS.md` and generated files in `metrics/`.

## 12. Emergency recovery

Enable emergency pass-through:

```bash
node ./cli/sentinel.js emergency-open on
```

Disable emergency pass-through:

```bash
node ./cli/sentinel.js emergency-open off
```
