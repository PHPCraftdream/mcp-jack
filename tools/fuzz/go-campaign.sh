#!/usr/bin/env bash
# Bounded Go fuzz campaign over the trust/parse/credential boundaries: every
# target runs for a fixed fuzztime then fuzzminimizetime, so the campaign
# always finishes. Per-target execution, logging and failure-evidence
# collection live in run-target.sh. One failing target fails CI, but only
# after ALL targets have run.
#
# Deliberately NO `set -e`: a failing target must not abort the campaign
# before the final exit-status check.
set -uo pipefail

fuzztime=${1:-30s}
minimize=${2:-10s}
outdir=${3:-fuzz-artifacts}
if ! mkdir -p "$outdir"; then
  echo "::error title=go-fuzz-log::cannot create artifact directory: ${outdir}" >&2
  exit 1
fi
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# package + FuzzName pairs.
targets=(
  ". FuzzParseRequestAuth"
  ". FuzzParseResponseAuth"
  "server FuzzClassifyBody"
  "client FuzzLoadProfile"
  "userkey FuzzImportEnvelopes"
  "userkey FuzzValidateCredential"
)

failed=0
for entry in "${targets[@]}"; do
  pkg=${entry%% *}
  name=${entry##* }
  echo "=== fuzz ${pkg}/${name} (fuzztime=${fuzztime}, fuzzminimizetime=${minimize}) ==="
  bash "$script_dir/run-target.sh" "$pkg" "$name" "$fuzztime" "$minimize" "$outdir" || failed=1
done

exit "$failed"
