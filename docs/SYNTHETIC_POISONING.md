# Synthetic Poisoning Safety Guide

`runtime.synthetic_poisoning` is a strict opt-in deception control for controlled security testing.

## Default Safety Posture

- Disabled by default.
- `mode: monitor` by default.
- Injection mode is gated by legal acknowledgement.

## Activation Gate

`mode: inject` only activates when:

1. `runtime.synthetic_poisoning.enabled: true`
2. `runtime.synthetic_poisoning.mode: inject`
3. `runtime.synthetic_poisoning.acknowledgement` exactly matches:
   - `runtime.synthetic_poisoning.required_acknowledgement`

If the acknowledgement is missing/mismatched, Sentinel does **not** inject synthetic content.

## Intended Use

- Local red-team simulations
- Controlled adversarial validation
- Deception pipeline testing with explicit approval

## Not Recommended For

- Compliance/factual production workflows
- Decision systems requiring strict truth guarantees
- User-facing financial/medical/legal outputs

## Operational Guidance

- Keep this mode behind environment-specific config.
- Enable extra audit retention when testing deception paths.
- Document who approved activation and why.
