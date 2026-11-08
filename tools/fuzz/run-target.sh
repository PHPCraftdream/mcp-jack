#!/usr/bin/env bash
# Run ONE bounded fuzz target and preserve failure evidence.
# - Output is logged via tee and tee's exit status is checked alongside go's,
#   because a lost log means a lost diagnostic.
# - On failure, failing inputs are collected from BOTH Go's fuzz cache
#   ($(go env GOCACHE)/fuzz) and the package's testdata/fuzz corpus.
# - Copy failures propagate (never swallowed). A failing target (or any
#   evidence-collection/log failure) exits nonzero AFTER evidence collection.
#
# Usage: run-target.sh <pkg> <name> <fuzztime> <minimize> <outdir>
# Exit: 0 success, 1 failure.
#
# Deliberately NO `set -e`: failure paths are handled explicitly.
set -uo pipefail

if [ $# -ne 5 ] || [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ] || [ -z "$4" ] || [ -z "$5" ]; then
  echo "usage: $0 <pkg> <name> <fuzztime> <minimize> <outdir>" >&2
  exit 2
fi
pkg=$1
name=$2
fuzztime=$3
minimize=$4
outdir=$5

# upload-artifact@v4 silently skips dot-prefixed paths, so a "." package would
# yield names like ".-Target.log"; map it to a filesystem-safe prefix.
if [ "$pkg" = "." ]; then
  safe_pkg="rootpkg"
else
  safe_pkg="$pkg"
fi
log="$outdir/${safe_pkg}-${name}.log"
# Record before running: go may change directories internally; the testdata
# corpus lives relative to the invocation directory.
repo_dir=$PWD

rcs=()
go test -run '^$' -fuzz "^${name}$" -fuzztime "$fuzztime" -fuzzminimizetime "$minimize" "./$pkg" 2>&1 | tee "$log"
rcs=("${PIPESTATUS[@]}")

status=0
# tee failing means the log was not fully written; the log is the retained
# diagnostic, so losing it must fail the run.
if [ "${rcs[1]}" -ne 0 ]; then
  echo "::error title=go-fuzz::log write failed for ${pkg}/${name} (${log})" >&2
  status=1
fi

if [ "${rcs[0]}" -ne 0 ]; then
  # Collect every corpus directory named after the target from src_root into
  # outdir/<pkg>-<name>-reproducers/<label>. cp failures propagate.
  collect() {
    src_root=$1
    label=$2
    dest="$outdir/${safe_pkg}-${name}-reproducers/${label}"
    while IFS= read -r d; do
      mkdir -p "$dest"
      if ! cp -R "$d"/. "$dest"/; then
        echo "::error title=go-fuzz::reproducer copy failed: ${d} -> ${dest}" >&2
        status=1
      fi
    done < <(find "$src_root" -type d -name "$name" 2>/dev/null)
  }

  collect "$(go env GOCACHE)/fuzz" "gocache"
  # Go writes minimized failing inputs under the TESTED PACKAGE's
  # testdata/fuzz/<Target>/ (e.g. server/testdata/fuzz/... for ./server);
  # with pkg="." this reduces to the repository root, which is correct for
  # root-package targets.
  collect "$repo_dir/$pkg/testdata/fuzz" "testdata"

  echo "::error title=go-fuzz::${pkg}/${name} failed (log: ${log})" >&2
  status=1
fi

exit "$status"
