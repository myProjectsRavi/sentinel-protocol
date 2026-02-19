# Outage Troubleshooting Runbook

## Goal

Determine whether failure is inside Sentinel or at upstream provider.

## Diagnostic headers

On error responses, Sentinel sets:
- `x-sentinel-error-source: upstream|sentinel`
- `x-sentinel-upstream-error: true|false`
- `x-sentinel-provider`
- `x-sentinel-retry-count`
- `x-sentinel-circuit-state`
- `x-sentinel-correlation-id`

## Rapid triage

1. If `x-sentinel-error-source=sentinel`
- Check policy and PII actions in `sentinel.yaml`
- Check `--dry-run`/`--fail-open` and emergency override state
- If error is `VAULT_PROVIDER_KEY_MISSING`, verify `runtime.upstream.auth_vault.*` and provider env vars.

2. If `x-sentinel-error-source=upstream`
- Inspect status code:
  - `503` + `x-sentinel-circuit-state=open`: breaker fast-fail due to upstream instability
  - `504`: upstream timeout
  - `502`: upstream transport/network failure
  - `429`: provider rate-limited

3. Confirm runtime state:

```bash
node ./cli/sentinel.js status --json
```

## Recovery controls

Immediate no-block mode:

```bash
node ./cli/sentinel.js start --dry-run
```

Emergency pass-through while running:

```bash
node ./cli/sentinel.js emergency-open on
```

## Notes

- Circuit breaker tracks only forwarded upstream outcomes.
- Sentinel local policy/PII blocks do not change breaker counters.
