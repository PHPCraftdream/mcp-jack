#!/usr/bin/env bash
# Check Go dependency licences against an allowlist file.
# Usage: check-go.sh <module-dir> <allowlist-file>
# Requires go-licenses (github.com/google/go-licenses/v2, pinned in the
# workflow) on PATH. Fails on any licence outside the allowlist, including
# licences go-licenses cannot identify.
set -euo pipefail

module_dir="${1:?usage: check-go.sh <module-dir> <allowlist-file>}"
policy="${2:?usage: check-go.sh <module-dir> <allowlist-file>}"

allowed="$(grep -Ev '^[[:space:]]*(#|$)' "$policy" | tr -d ' \t\r' | paste -sd, -)"
if [ -z "$allowed" ]; then
  echo "empty allowlist: $policy" >&2
  exit 2
fi

cd "$module_dir"
echo "go-licenses allowlist: $allowed"
exec go-licenses check ./... --include_tests --allowed_licenses="$allowed"
