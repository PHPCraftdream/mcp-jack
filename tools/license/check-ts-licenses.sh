#!/usr/bin/env bash
# Collect npm dependency licence metadata (dev dependencies included, private
# packages excluded) and decide against the allowlist with full SPDX
# expression semantics via tooling/eval.mjs (spdx-satisfies, pinned by
# tooling/package-lock.json).
# Usage: check-ts-licenses.sh <start-dir> <allowlist-file>
# Requires Node >= 24 (upstream checker engines) and tooling/node_modules
# (npm ci in tools/license/tooling).
set -euo pipefail

start_dir="${1:?usage: check-ts-licenses.sh <start-dir> <allowlist-file>}"
policy="${2:?usage: check-ts-licenses.sh <start-dir> <allowlist-file>}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -d "$here/tooling/node_modules" ]; then
  echo "licence tooling missing: run npm ci in $here/tooling" >&2
  exit 2
fi

echo "checking licence metadata in $start_dir against $policy"
json="$(mktemp)"
status=0
npx --yes license-checker-rseidelsohn@5.0.1 --start "$start_dir" \
  --excludePrivatePackages --json --out "$json" || status=$?
if [ "$status" -ne 0 ]; then
  rm -f "$json"
  exit "$status"
fi

eval_status=0
node "$here/tooling/eval.mjs" "$json" "$policy" || eval_status=$?
rm -f "$json"
exit "$eval_status"
