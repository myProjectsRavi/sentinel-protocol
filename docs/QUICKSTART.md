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

## 6. Check status

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

## 7. Emergency recovery

Enable emergency pass-through:

```bash
node ./cli/sentinel.js emergency-open on
```

Disable emergency pass-through:

```bash
node ./cli/sentinel.js emergency-open off
```
