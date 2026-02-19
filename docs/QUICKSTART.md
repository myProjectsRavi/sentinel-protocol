# Quickstart

## 1. Install

```bash
npm install
```

## 2. Initialize config

```bash
node ./cli/sentinel.js init
```

This creates:
- `/Users/ravitejanekkalapu/.sentinel/sentinel.yaml`

## 3. Start Sentinel

```bash
node ./cli/sentinel.js start
```

Startup runs `doctor` checks automatically. To run explicitly:

```bash
node ./cli/sentinel.js doctor
```

Set production mode for safer runtime defaults:

```bash
NODE_ENV=production node ./cli/sentinel.js start
```

Optional safe startup flags:

```bash
node ./cli/sentinel.js start --dry-run
node ./cli/sentinel.js start --fail-open
node ./cli/sentinel.js start --skip-doctor
```

## 4. Configure agent

Set base URL to:

```text
http://127.0.0.1:8787
```

Route to provider with header:
- `x-sentinel-target: openai`
- `x-sentinel-target: anthropic`
- `x-sentinel-target: google`
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

## 5. Configure PII provider mode

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

## 5.1 Optional: Local API Key Vault (dummy-key replacement)

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

## 6. Configure prompt-injection detection

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

## 7. Optional semantic scanner

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

## 8. MCP and monitor modes

Run Sentinel as minimal MCP server:

```bash
node ./cli/sentinel.js mcp
```

Open terminal dashboard:

```bash
node ./cli/sentinel.js monitor
```

## 9. Check status

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

## 10. Benchmark overhead

```bash
npm run benchmark
```

See `BENCHMARKS.md` and generated files in `metrics/`.

## 11. Emergency recovery

Enable emergency pass-through:

```bash
node ./cli/sentinel.js emergency-open on
```

Disable emergency pass-through:

```bash
node ./cli/sentinel.js emergency-open off
```
