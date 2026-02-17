#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
SENTINEL_HOME_DIR="$TMP_DIR/sentinel-home"
CONFIG_PATH="$TMP_DIR/sentinel.yaml"
SENTINEL_PORT=8899
UPSTREAM_PORT=8999

mkdir -p "$SENTINEL_HOME_DIR"

cleanup() {
  if [[ -n "${SENTINEL_PID:-}" ]] && kill -0 "$SENTINEL_PID" >/dev/null 2>&1; then
    SENTINEL_HOME="$SENTINEL_HOME_DIR" node "$ROOT_DIR/cli/sentinel.js" stop >/dev/null 2>&1 || true
    kill "$SENTINEL_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "${UPSTREAM_PID:-}" ]] && kill -0 "$UPSTREAM_PID" >/dev/null 2>&1; then
    kill "$UPSTREAM_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat > "$CONFIG_PATH" <<EOF
version: 1
mode: enforce

proxy:
  host: 127.0.0.1
  port: $SENTINEL_PORT
  timeout_ms: 30000

runtime:
  fail_open: false
  scanner_error_action: allow
  telemetry:
    enabled: false
  upstream:
    retry:
      enabled: true
      max_attempts: 1
      allow_post_with_idempotency_key: false
    circuit_breaker:
      enabled: true
      window_size: 20
      min_failures_to_evaluate: 8
      failure_rate_threshold: 0.5
      consecutive_timeout_threshold: 5
      open_seconds: 20
      half_open_success_threshold: 3
    custom_targets:
      enabled: true
      allowlist:
        - 127.0.0.1
      block_private_networks: false

pii:
  enabled: true
  provider_mode: rapidapi
  max_scan_bytes: 262144
  severity_actions:
    critical: block
    high: block
    medium: redact
    low: log
  rapidapi:
    endpoint: "https://pii-firewall-edge.p.rapidapi.com/redact"
    host: "pii-firewall-edge.p.rapidapi.com"
    timeout_ms: 4000
    request_body_field: text
    fallback_to_local: true
    allow_non_rapidapi_host: false
    api_key: ""
    extra_body: {}

rules: []

whitelist:
  domains: []

logging:
  level: info
EOF

echo "[1/4] Starting mock upstream on http://127.0.0.1:$UPSTREAM_PORT"
node -e "require('http').createServer((req,res)=>{res.setHeader('content-type','application/json');res.end(JSON.stringify({ok:true,upstream:'mock'}));}).listen($UPSTREAM_PORT,'127.0.0.1')" &
UPSTREAM_PID=$!
sleep 1

echo "[2/4] Running Sentinel doctor checks"
SENTINEL_HOME="$SENTINEL_HOME_DIR" node "$ROOT_DIR/cli/sentinel.js" doctor --config "$CONFIG_PATH"

echo "[3/4] Starting Sentinel on http://127.0.0.1:$SENTINEL_PORT"
SENTINEL_HOME="$SENTINEL_HOME_DIR" node "$ROOT_DIR/cli/sentinel.js" start --config "$CONFIG_PATH" --port "$SENTINEL_PORT" >/dev/null 2>&1 &
SENTINEL_PID=$!
sleep 2

echo
echo "=== Demo A: No RapidAPI key, request still forwards via local fallback ==="
curl -si -X POST "http://127.0.0.1:$SENTINEL_PORT/v1/chat/completions" \
  -H "content-type: application/json" \
  -H "x-sentinel-target: custom" \
  -H "x-sentinel-custom-url: http://127.0.0.1:$UPSTREAM_PORT" \
  -d '{"text":"hello from agent"}' | sed -n '1,20p'

echo
echo "=== Demo B: Critical PII is blocked in enforce mode (still with local fallback) ==="
curl -si -X POST "http://127.0.0.1:$SENTINEL_PORT/v1/chat/completions" \
  -H "content-type: application/json" \
  -H "x-sentinel-target: custom" \
  -H "x-sentinel-custom-url: http://127.0.0.1:$UPSTREAM_PORT" \
  -d '{"text":"openai key sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefgh"}' | sed -n '1,20p'

echo
echo "[4/4] Status snapshot"
SENTINEL_HOME="$SENTINEL_HOME_DIR" node "$ROOT_DIR/cli/sentinel.js" status --json
