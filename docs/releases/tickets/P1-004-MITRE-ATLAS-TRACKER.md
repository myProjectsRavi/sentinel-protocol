# P1-004 MITRE ATLAS Tracker

## Priority

- P1

## Goal

Classify Sentinel detections using MITRE ATLAS technique IDs and emit deterministic attack-surface evidence.

## Scope

- `src/governance/atlas-tracker.js` (new)
- `src/stages/audit-stage.js`
- `src/governance/compliance-engine.js`
- `cli/sentinel.js` (`atlas report`)
- `docs/OWASP-HARDENING.md` (cross-reference section)

## File-Level Acceptance Checklist

- [ ] `src/governance/atlas-tracker.js` includes versioned engine->technique mapping table.
- [ ] `src/stages/audit-stage.js` enriches events with `atlas.technique_id`, `atlas.tactic`, `atlas.name`, `atlas.severity`.
- [ ] `src/governance/compliance-engine.js` summarizes top techniques and counts.
- [ ] `cli/sentinel.js` adds `sentinel atlas report --audit-path ... --out ...`.
- [ ] ATLAS output is stable-sorted and deterministic.
- [ ] Unknown engine names map to explicit `UNMAPPED` category (no null holes).

## Exact Test Cases

- `test/unit/atlas-tracker.test.js`
- `test('maps known engine injection_scanner to a non-empty atlas technique id', ...)`
- `test('returns UNMAPPED for unknown engine names', ...)`
- `test('aggregates counts by technique with stable sort', ...)`
- `test('exports deterministic navigator-compatible payload for identical input', ...)`
- `test/integration/atlas-audit.integration.test.js`
- `test('audit records include atlas enrichment fields for blocked injection event', ...)`
- `test('atlas report command writes json with expected schema', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/atlas-tracker.test.js
npm run test:integration -- test/integration/atlas-audit.integration.test.js
node ./cli/sentinel.js atlas report --audit-path ~/.sentinel/audit.jsonl --out ./atlas-report.json
```

