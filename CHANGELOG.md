# Changelog

## 0.2.0 - 2026-02-17

### Added
- PII provider modes: `local`, `rapidapi`, and `hybrid`.
- Secure RapidAPI client with endpoint validation and key-source priority:
  - `x-sentinel-rapidapi-key`
  - `SENTINEL_RAPIDAPI_KEY`
  - `pii.rapidapi.api_key`
- `sentinel doctor` command for startup readiness checks.
- Startup preflight doctor checks in `sentinel start` (can be skipped with `--skip-doctor`).
- Provider observability fields in status output:
  - `pii_provider_mode`
  - `pii_provider_fallbacks`
  - `rapidapi_error_count`
- Demo assets for fallback behavior:
  - `scripts/demo-rapidapi-fallback.sh`
  - `docs/DEMO_VIDEO_SCRIPT.md`

### Changed
- Strips all `x-sentinel-*` headers before upstream forwarding.
- BYOK documentation is now explicit for RapidAPI mode.
- Telemetry service version bumped to `0.2.0`.

### Fixed
- Ensured PII provider telemetry is initialized before provider engine usage.
- Relaxed rapidapi config validation for backward compatibility with existing configs.

## 0.1.0 - 2026-02-17

- Initial public MVP release.
