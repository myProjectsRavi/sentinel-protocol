# Formal Verification Pack (Research Track)

Last updated: 2026-02-24

This folder contains lightweight formal specs for core Sentinel invariants.

## Scope

These specs are engineering proofs for critical decision invariants. They are not a full formal model of the whole runtime.

- `specs/serialization-firewall.tla`
- `specs/injection-guard.tla`
- `specs/threat-intel-mesh.als`

## Invariants Covered

- Serialization firewall must block gadget/depth-bomb payload states.
- Injection guard must block in `mode=block` + `effective_mode=enforce` when score crosses threshold.
- Threat-intel mesh import policy must reject unsigned peer snapshots when unsigned import is disabled.

## Running TLA+ (TLC)

```bash
# from a machine with tla2tools.jar installed
java -cp tla2tools.jar tlc2.TLC docs/formal/specs/serialization-firewall.cfg
java -cp tla2tools.jar tlc2.TLC docs/formal/specs/injection-guard.cfg
```

## Running Alloy

Open `docs/formal/specs/threat-intel-mesh.als` in Alloy Analyzer and run:

- `check UnsignedImportMustBeDenied for 5`
- `check SignedImportMayBeAccepted for 5`

## Notes

- These specs are deterministic and intentionally minimal.
- They document control invariants and expected safety properties for external review.
