#!/usr/bin/env bash
# CI-only controls for the Go licence check: the fixture module must pass the
# real allowlist first, then an MIT-only list must refuse its BSD-3-Clause
# dependency with evidence naming the library and the licence. Requires the
# pinned go-licenses on PATH (installed by the workflow).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixture="$here/testdata/go-license-fixture"

(cd "$fixture" && go mod tidy)

bash "$here/check-go.sh" "$fixture" "$here/go-allowed-licenses.txt"

output="$(bash "$here/check-go.sh" "$fixture" "$here/testdata/go-license-allow-mit-only.txt" 2>&1)" && status=0 || status=$?
printf '%s\n' "$output"
if [ "$status" -eq 0 ]; then
  echo "::error title=license/go::BSD-3-Clause dependency passed an MIT-only allowlist" >&2
  exit 1
fi
for evidence in go-cmp BSD-3-Clause; do
  if ! grep -qF -- "$evidence" <<<"$output"; then
    echo "::error title=license/go::refusal output missing evidence: $evidence" >&2
    exit 1
  fi
done
echo "Go refusal control behaved as expected: refused go-cmp (BSD-3-Clause)."
