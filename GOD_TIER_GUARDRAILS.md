# God Tier Guardrails

This document defines hardening controls for Sentinel's newest high-risk modules and the attack fixtures that must pass before release.

## Scope

1. Two-way PII Vault (`/Users/ravitejanekkalapu/Documents/sentinel-protocol/src/pii/two-way-vault.js`)
2. Intent Drift Detector (`/Users/ravitejanekkalapu/Documents/sentinel-protocol/src/runtime/intent-drift.js`)
3. Omni-Shield Plugin Path (`/Users/ravitejanekkalapu/Documents/sentinel-protocol/src/engines/omni-shield.js`)
4. Experimental Sandbox (`/Users/ravitejanekkalapu/Documents/sentinel-protocol/src/sandbox/experimental-sandbox.js`)

## Module Guardrails

### 1) Two-way PII Vault

- Session isolation: tokens are reversible only inside the same session key.
- Rewrite DoS guardrails:
  - `runtime.pii_vault.max_egress_rewrite_entries`
  - `runtime.pii_vault.max_payload_bytes`
  - `runtime.pii_vault.max_replacements_per_pass`
- Safe degradation: oversize payloads are skipped, not hard-failed.
- Stream-safe detokenization with UTF-8 boundary handling.

### 2) Intent Drift Detector

- Volatile-token normalization to prevent noisy false drift from:
  - UUIDs
  - trace/request IDs
  - ISO timestamps
  - long random hex IDs
- Role scoping (`target_roles`) to avoid tool/noise poisoning.
- Risk-delta hardening:
  - `risk_keywords`
  - `risk_boost`
- Drift decision uses adjusted distance (`adjustedDistance`) to resist embedding-collision bypass.

### 3) Omni-Shield Plugin Path

- Strict opt-in plugin execution.
- Async-safe execution with timeout:
  - `runtime.omni_shield.plugin.timeout_ms`
- Fail-closed behavior remains explicit:
  - `runtime.omni_shield.plugin.fail_closed`
- Result-shape validation defends against malformed plugin outputs.
- Plugin errors are classified (`plugin_error`, `plugin_timeout`) and observable.

### 4) Experimental Sandbox

- Evasion normalization and variant generation:
  - escaped hex/unicode decoding
  - zero-width char stripping
  - string-concat normalization
  - optional base64 decode pathway
- Tunable controls:
  - `normalize_evasion`
  - `decode_base64`
  - `max_decoded_bytes`
  - `max_variants_per_candidate`
- Tool-target filtering reduces false positives for non-execution traffic.

## Attack Fixture Suites

Fixtures live in:

- `/Users/ravitejanekkalapu/Documents/sentinel-protocol/test/fixtures/hardening/drift-bypass-cases.json`
- `/Users/ravitejanekkalapu/Documents/sentinel-protocol/test/fixtures/hardening/omni-plugin-chaos-cases.json`
- `/Users/ravitejanekkalapu/Documents/sentinel-protocol/test/fixtures/hardening/sandbox-evasion-cases.json`
- `/Users/ravitejanekkalapu/Documents/sentinel-protocol/test/fixtures/hardening/vault-attack-cases.json`

Validated by:

- `/Users/ravitejanekkalapu/Documents/sentinel-protocol/test/unit/intent-drift.test.js`
- `/Users/ravitejanekkalapu/Documents/sentinel-protocol/test/unit/omni-shield.test.js`
- `/Users/ravitejanekkalapu/Documents/sentinel-protocol/test/unit/experimental-sandbox.test.js`
- `/Users/ravitejanekkalapu/Documents/sentinel-protocol/test/unit/two-way-pii-vault.test.js`

## Release Gate

Before release, all must pass:

```bash
npm run test:unit
```

Recommended focused run:

```bash
npm test -- --runInBand \
  test/unit/two-way-pii-vault.test.js \
  test/unit/intent-drift.test.js \
  test/unit/omni-shield.test.js \
  test/unit/experimental-sandbox.test.js \
  test/unit/config-loader.test.js \
  test/unit/doctor.test.js
```

## Operating Guidance

- Start in `monitor` for new controls.
- Enable hard-block (`block`/`fail_closed`) only after fixture pass + traffic shadow validation.
- Keep plugin timeout conservative (100-5000ms).
- Keep drift `risk_boost` conservative (`0-0.4`) to limit false positives.
