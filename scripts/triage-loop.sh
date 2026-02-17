#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-myProjectsRavi/sentinel-protocol}"
HOURS="${2:-72}"
INTERVAL_SECONDS="${3:-900}"
OUT_FILE="${4:-/Users/ravitejanekkalapu/Documents/sentinel-protocol/.tmp/triage-loop.log}"

if [[ -z "${GH_TOKEN:-}" ]]; then
  echo "GH_TOKEN is required" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT_FILE")"
end_ts=$(( $(date +%s) + HOURS * 3600 ))

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] triage loop started for $REPO (hours=$HOURS interval=${INTERVAL_SECONDS}s)" | tee -a "$OUT_FILE"

while [[ $(date +%s) -lt $end_ts ]]; do
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  issues_json="$(gh api "repos/$REPO/issues?state=open&per_page=50")"
  open_count="$(echo "$issues_json" | jq 'length')"
  stale_count="$(echo "$issues_json" | jq '[.[] | select(.pull_request|not) | select(((now - (.updated_at|fromdateiso8601)) / 3600) > 4)] | length')"

  echo "[$now] open_issues=$open_count stale_over_4h=$stale_count" | tee -a "$OUT_FILE"

  sleep "$INTERVAL_SECONDS"
done

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] triage loop completed" | tee -a "$OUT_FILE"
