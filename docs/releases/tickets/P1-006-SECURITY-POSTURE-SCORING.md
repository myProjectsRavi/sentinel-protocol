# P1-006 Security Posture Scoring

## Priority

- P1

## Goal

Provide a deterministic, non-blocking posture score for enterprise buyer readability and release evidence.

## Scope

- `src/governance/security-posture.js` (new)
- `src/server.js` (`/_sentinel/health` enrichment)
- `cli/sentinel.js` (`posture --json`)
- `src/config/schema.js` (`runtime.posture_scoring.*`)
- `src/config/default.yaml`
- `docs/releases/SECURITY_RELIABILITY_EVIDENCE_7186f1f.md` (format extension for future releases)

## File-Level Acceptance Checklist

- [ ] `src/governance/security-posture.js` computes category and overall scores from config and counters.
- [ ] Score calculation is deterministic for identical inputs.
- [ ] `/_sentinel/health` includes `posture` block and does not fail endpoint on scorer error.
- [ ] `cli/sentinel.js` provides `sentinel posture --json --audit-path ...`.
- [ ] Schema/defaults for posture scoring are strict and bounded.
- [ ] Posture is advisory only; it does not block traffic.

## Exact Test Cases

- `test/unit/security-posture.test.js`
- `test('returns deterministic score for identical config and counter inputs', ...)`
- `test('penalizes disabled enforce-capable controls', ...)`
- `test('computes category breakdown ingress/egress/privacy/agentic', ...)`
- `test('handles missing audit data without throw', ...)`
- `test/integration/security-posture-health.integration.test.js`
- `test('health endpoint includes posture object when scorer enabled', ...)`
- `test('health endpoint stays 200 when scorer throws internal error', ...)`

## Verification Commands

```bash
npm run lint
npm run test:unit -- test/unit/security-posture.test.js
npm run test:integration -- test/integration/security-posture-health.integration.test.js
node ./cli/sentinel.js posture --json
```

