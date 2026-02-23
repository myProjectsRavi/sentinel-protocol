# P2-008 Output Content Classifier

## Priority

- P2

## Goal

Classify model outputs for toxicity, dangerous code guidance, hallucination signals, and unauthorized disclosure using deterministic local heuristics.

## Scope

- `src/egress/output-classifier.js` (new)
- `src/stages/egress/buffered-egress-stage.js`
- `src/stages/egress/stream-egress-stage.js`
- `src/config/schema.js`
- `src/config/default.yaml`
- `src/telemetry/prometheus.js`

## File-Level Acceptance Checklist

- [ ] `src/egress/output-classifier.js` implements deterministic category scorers with bounded runtime.
- [ ] Buffered egress path invokes classifier before final send.
- [ ] Stream egress path supports partial/classification events without leaking raw chunks.
- [ ] Config keys `runtime.output_classifier.*` are schema-validated and monitor-first.
- [ ] Prometheus counters for category detections and blocks are emitted.
- [ ] Enforce mode blocks only when configured category threshold is met.

## Exact Test Cases

- `test/unit/output-classifier.test.js`
- `test('flags toxicity when high-risk lexical patterns exceed threshold', ...)`
- `test('flags dangerous code execution guidance in assistant output', ...)`
- `test('flags unauthorized disclosure of system prompt markers', ...)`
- `test('returns advisory-only decision in monitor mode', ...)`
- `test('returns blocking decision in enforce mode for configured categories', ...)`
- `test('classification result is deterministic for same output text', ...)`
- `test/integration/output-classifier.integration.test.js`
- `test('buffered response receives warning headers in monitor mode', ...)`
- `test('buffered response is blocked with policy violation in enforce mode', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/output-classifier.test.js
npm run test:integration -- test/integration/output-classifier.integration.test.js
npm run benchmark:gate
```

