# P3-023 Tool Use Anomaly Detector

## Priority

- P3 (Tier 3)

## Goal

Detect statistically anomalous tool-use patterns per agent without external ML services.

## Scope

- `src/security/tool-use-anomaly.js` (new)
- `src/stages/policy/agentic-stage.js`
- `src/config/schema.js`
- `src/config/default.yaml`

## File-Level Acceptance Checklist

- [ ] Learns baseline during warm-up window.
- [ ] Scores anomalies with bounded statistical metrics (z-score/ratio).
- [ ] Tracks sequence anomalies (e.g. read-all -> export -> outbound).
- [ ] No block decision before warm-up completion.
- [ ] Bounded per-agent state and periodic pruning.

## Exact Test Cases

- `test/unit/tool-use-anomaly.test.js`
- `test('does not alert during warm-up window', ...)`
- `test('flags high-volume deviation after warm-up', ...)`
- `test('flags suspicious sequence chain pattern', ...)`
- `test('returns deterministic score for fixed history', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/tool-use-anomaly.test.js
```
