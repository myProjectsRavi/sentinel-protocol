# 72-Hour Launch Triage Runbook

## SLA
- First response to new issue: under 4 hours
- Hotfix decision: within 12 hours for high-severity regressions
- Patch release target: same day for critical reliability issues

## Severity
- P0: startup broken, data leak, false block that bricks common flows
- P1: outage diagnostics missing/wrong, retry/circuit behavior wrong
- P2: docs gaps, edge-case CLI quality

## Triage cadence
- Check queue every 15 minutes for first 12 hours
- Check queue every 30 minutes for next 60 hours

## Required issue template fields
- Expected behavior
- Actual behavior
- Sentinel mode (`monitor/warn/enforce`)
- Provider target
- Relevant `x-sentinel-*` headers
- Minimal reproduction payload

## Decision rules
- If uncertainty exists between upstream and Sentinel, prioritize collecting headers + correlation id
- Do not add new features during 72-hour window
- Scope for hotfix is reliability-only
