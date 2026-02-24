# Init Wizard Validation (P0)

Last validated: 2026-02-24

## Scope

This validates the adoption-path init behavior for:

- non-interactive CI-safe init (`--yes`)
- profile application (`minimal|standard|paranoid`)
- provider target injection (`openai|anthropic|ollama`)
- idempotent re-run behavior
- doctor summary output

## Reproduction

```bash
npm run ci:init:wizard:smoke
```

## Acceptance Checklist

| Criterion | Status | Evidence |
|---|---|---|
| `sentinel init --yes` is non-interactive and exits 0 | pass | `scripts/ci-init-wizard-smoke.js` |
| provider selection writes upstream target entries | pass | target assertions per matrix case |
| `--profile minimal` enforces monitor + 8 runtime engines + 512MB cap | pass | schema + engine-count assertions |
| doctor runs on init and warns without hard-failing | pass | `Doctor summary:` asserted in stdout |
| idempotent second run without `--force` | pass | asserts `Config already exists` |

## Matrix (9 Paths)

| Profile | Provider | Mode | Runtime Engines Enabled | Doctor Summary | Idempotent |
|---|---|---:|---:|---:|---:|
| minimal | openai | monitor | 8 | yes | yes |
| minimal | anthropic | monitor | 8 | yes | yes |
| minimal | ollama | monitor | 8 | yes | yes |
| standard | openai | monitor | 3 | yes | yes |
| standard | anthropic | monitor | 3 | yes | yes |
| standard | ollama | monitor | 3 | yes | yes |
| paranoid | openai | enforce | 68 | yes | yes |
| paranoid | anthropic | enforce | 68 | yes | yes |
| paranoid | ollama | enforce | 68 | yes | yes |

## Notes

- Interactive mode (`sentinel init` without `--yes`) prompts only when stdin/stdout are TTY.
- Non-TTY execution path auto-falls back to non-interactive behavior.
