#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-myProjectsRavi/sentinel-protocol}"
PACKAGE="${2:-sentinel-protocol}"
OUT_DIR="${3:-/Users/ravitejanekkalapu/Documents/sentinel-protocol/metrics}"

mkdir -p "$OUT_DIR"
stamp="$(date -u +%Y-%m-%d)"
out_file="$OUT_DIR/kpi-$stamp.json"

stars="0"
if [[ -n "${GH_TOKEN:-}" ]]; then
  stars="$(gh api "repos/$REPO" --jq '.stargazers_count' 2>/dev/null || echo 0)"
else
  stars="$(curl -fsSL "https://api.github.com/repos/$REPO" | jq '.stargazers_count' 2>/dev/null || echo 0)"
fi

npm_week_downloads="0"
if curl -fsSL "https://api.npmjs.org/downloads/point/last-week/$PACKAGE" >/tmp/npm-kpi.json 2>/dev/null; then
  npm_week_downloads="$(jq '.downloads // 0' /tmp/npm-kpi.json)"
fi

cat > "$out_file" <<JSON
{
  "timestamp_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "repo": "$REPO",
  "package": "$PACKAGE",
  "baseline_targets": {
    "stars": 150,
    "weekly_active_installs": 25,
    "testimonials": 5
  },
  "current": {
    "stars": $stars,
    "weekly_downloads_npm": $npm_week_downloads,
    "testimonials": 0
  }
}
JSON

echo "$out_file"
