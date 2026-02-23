# P0-003 Prompt Rebuff Engine

## Priority

- P0

## Goal

Upgrade injection defense by correlating heuristic score, neural score, and canary verification into one deterministic confidence model.

## Scope

- `src/engines/prompt-rebuff.js` (new)
- `src/stages/policy/pii-injection-stage.js`
- `src/engines/canary-tool-trap.js`
- `src/config/schema.js`
- `src/config/default.yaml`
- `src/telemetry/prometheus.js`
- `src/governance/red-team.js` (new rebuff vectors)

## File-Level Acceptance Checklist

- [ ] `src/engines/prompt-rebuff.js` provides `evaluate()` and deterministic confidence output.
- [ ] Rebuff score includes weighted inputs: heuristic, neural, canary leak signal.
- [ ] `src/stages/policy/pii-injection-stage.js` integrates rebuff with monitor/enforce handling and unified reasons.
- [ ] `src/config/schema.js` adds `runtime.prompt_rebuff.*` with strict key validation.
- [ ] `src/config/default.yaml` sets `enabled=false`, `mode=monitor`, `sensitivity=balanced`.
- [ ] `src/telemetry/prometheus.js` adds metrics for `prompt_rebuff_detected_total`, `prompt_rebuff_blocked_total`, `prompt_rebuff_errors_total`.
- [ ] `src/governance/red-team.js` includes rebuff-specific test prompts to prevent regression.

## Exact Test Cases

- `test/unit/prompt-rebuff.test.js`
- `test('returns low confidence for benign input', ...)`
- `test('returns high confidence when heuristic and neural both exceed thresholds', ...)`
- `test('raises confidence when canary appears in forbidden output position', ...)`
- `test('monitor mode never blocks even when confidence is high', ...)`
- `test('enforce mode blocks when confidence >= block threshold', ...)`
- `test('produces deterministic score for same input and config', ...)`
- `test/integration/prompt-rebuff.integration.test.js`
- `test('returns 403 and reason=prompt_rebuff_high_confidence in enforce mode', ...)`
- `test('adds x-sentinel-warning=prompt_rebuff_high_confidence in monitor mode', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/prompt-rebuff.test.js
npm run test:integration -- test/integration/prompt-rebuff.integration.test.js
npm run test:coverage:gate
```

