# P3-021 Cross-Agent Threat Propagation Graph

## Priority

- P3 (Tier 2)

## Goal

Map and score threat propagation across agents/tools/providers for incident response and design hardening.

## Scope

- `src/governance/threat-propagation-graph.js` (new)
- `src/stages/audit-stage.js`
- `cli/sentinel.js`

## File-Level Acceptance Checklist

- [ ] Builds temporal directed graph from detection/audit events.
- [ ] Computes downstream risk score per node.
- [ ] Exports JSON, DOT, Mermaid formats.
- [ ] Windowed analysis remains bounded by max events.
- [ ] Runs outside hot path (async/offline processing).

## Exact Test Cases

- `test/unit/threat-propagation-graph.test.js`
- `test('builds graph edges from correlated detection events', ...)`
- `test('computes propagation score deterministically', ...)`
- `test('exports stable Mermaid and DOT output', ...)`
- `test('enforces max event cap without crash', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/threat-propagation-graph.test.js
```
