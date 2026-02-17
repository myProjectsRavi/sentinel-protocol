# Demo Video Script (RapidAPI Fallback)

Goal: show that Sentinel remains safe and available when RapidAPI key is missing.

## 90-second flow

1. Run doctor check:

```bash
node ./cli/sentinel.js doctor
```

2. Run automated demo script:

```bash
./scripts/demo-rapidapi-fallback.sh
```

3. Highlight these outputs on screen:
- `Doctor summary` with warnings (no key found).
- `x-sentinel-warning: pii_provider_fallback_local` on forwarded request.
- `403 PII_DETECTED` on critical secret payload.
- `status --json` showing:
  - `pii_provider_mode`
  - `pii_provider_fallbacks`
  - `rapidapi_error_count`

## Voiceover points

1. Sentinel is BYOK only and does not embed a shared RapidAPI key.
2. In `rapidapi` mode with fallback enabled, local scanner keeps traffic flowing during key/quota outages.
3. Enforce mode still blocks critical secrets deterministically.
4. Provider observability makes outages and fallback visible in `status --json`.
