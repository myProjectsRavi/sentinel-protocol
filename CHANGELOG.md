# Changelog

## Unreleased - 2026-02-24

### Added
- New monitor-first runtime engines:
  - `runtime.behavioral_fingerprint`
  - `runtime.threat_intel_mesh`
  - `runtime.lfrl`
  - `runtime.self_healing_immune`
  - `runtime.cost_efficiency_optimizer`
  - `runtime.zk_config_validator`
  - `runtime.adversarial_eval_harness`
  - `runtime.anomaly_telemetry`
- New control-plane endpoints:
  - `GET /_sentinel/anomalies`
  - `GET /_sentinel/threat-intel`
  - `GET /_sentinel/zk-config`
  - `POST /_sentinel/adversarial-eval/run`
- New engine modules and unit coverage for the runtime controls above.
- Config profile system (`minimal|standard|paranoid`) with deterministic overlays.
- One-command bootstrap CLI flow: `sentinel bootstrap --profile <name>`.
- Lazy optional-engine loading with runtime visibility counters and status output.
- Cost optimizer memory-budget extensions:
  - hard RSS cap (`memory_hard_cap_bytes`)
  - deterministic engine shedding (`shed_on_memory_pressure`, `shed_engine_order`)
  - restore path after memory recovery.

### Changed
- Integrated new engines into live stage flow (policy + agentic + audit) with deterministic block/warn behavior.
- Extended capability introspection and MITRE ATLAS mapping for newly added engines.
- Extended config defaults + strict schema validation for all new runtime keys (unknown-key rejection preserved).
- `startServer` now supports runtime profile overlay selection before mode/vcr overrides.

### Fixed
- SSE stream stability hardening:
  - disabled provenance fallback no longer yields invalid stream proof contracts
  - SSE proof context now validates `update/finalize` contract before use
  - monitor-mode SSE path no longer escalates block-severity findings into stream termination
- CI bootstrap gate hardening:
  - `ci:bootstrap:npx` now uses robust readiness wait logic with clear early-exit diagnostics
  - config compatibility restored for `runtime.rate_limiter.enabled` in strict schema validation

### Docs
- Updated OpenAPI contract with new control-plane endpoints.
- Updated README feature map and control-plane endpoint list.
- Updated README quickstart and CLI references for bootstrap/profile flows.
- Refreshed V4 evidence doc to reflect full implemented engine set and verification focus.

## 1.0.0 - 2026-02-19

### Added
- Budget Enforcer with deterministic spend tracking and kill-switch behavior.
- Resilience Mesh routing (`runtime.upstream.resilience_mesh`) with safe failover paths.
- Sticky Canary A/B routing (`runtime.upstream.canary`) with observability headers.
- Cross-provider adapter contracts for OpenAI-compatible contract routing.
- Stream budget accounting on both stream completion and stream error paths.
- Local API key vault (`runtime.upstream.auth_vault`) with dummy-key replacement and enforce mode.
- Agent loop-breaker (`runtime.loop_breaker`) to detect and stop repeated autonomous request loops.
- Ghost mode (`runtime.upstream.ghost_mode`) for SDK telemetry/fingerprint header stripping.
- Local Parachute provider support for Ollama with OpenAI-contract adapter and failover compatibility.

### Changed
- Docker and compose defaults now preload semantic + neural ONNX models.
- README quickstart is Docker-first for a 2-minute install path.
- Built-in provider requests now scrub non-target auth headers to prevent cross-provider credential leakage.

### Fixed
- Restored backward-compatible circuit-breaker keys for direct providers (`openai|anthropic|google|custom`).
- Fixed partial-stream under-accounting by charging for streamed bytes on stream error paths.

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
