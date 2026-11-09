#!/usr/bin/env bash
# Run ONE bounded fuzz target, verify that Go actually discovers the exact
# target, and preserve raw execution/evidence diagnostics on failure.
# Usage: run-target.sh <pkg> <name> <fuzztime> <minimize> <outdir>
# Exit: 0 success, 1 failure, 2 usage/invalid target inputs.
# Deliberately NO `set -e`: each failure source is reported independently.
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

case "$pkg" in
  .|server|client|userkey) ;;
  *) echo "::error title=go-fuzz-discovery::unsupported package: ${pkg}" >&2; exit 2 ;;
esac
if [[ ! "$name" =~ ^Fuzz[A-Za-z0-9_]+$ ]]; then
  echo "::error title=go-fuzz-discovery::invalid fuzz target name: ${name}" >&2
  exit 2
fi

# upload-artifact@v4 silently skips dot-prefixed paths, so a "." package would
# yield hidden artifacts without this filesystem-safe prefix.
if [ "$pkg" = "." ]; then
  safe_pkg="rootpkg"
else
  safe_pkg="$pkg"
fi
if ! mkdir -p "$outdir"; then
  echo "::error title=go-fuzz-log::cannot create artifact directory: ${outdir}" >&2
  exit 1
fi
log="$outdir/${safe_pkg}-${name}.log"
discovery_log="$outdir/${safe_pkg}-${name}-discovery.log"
repo_dir=$PWD
status=0

echo "=== discover exact fuzz target ${pkg}/${name} ==="
go test -list "^${name}$" "./$pkg" 2>&1 | tee "$discovery_log"
discovery_rcs=("${PIPESTATUS[@]}")
if [ "${discovery_rcs[1]}" -ne 0 ]; then
  echo "::error title=go-fuzz-log::discovery log write failed for ${pkg}/${name} (${discovery_log})" >&2
  status=1
fi
if [ "${discovery_rcs[0]}" -ne 0 ]; then
  echo "::error title=go-fuzz-discovery::go test -list failed for ${pkg}/${name} (log: ${discovery_log})" >&2
  status=1
else
  # Match a complete output line, never a substring or a successful empty
  # `go test -run` result. The exact regexp and identifier validation above
  # also prevent user-controlled regexp syntax from broadening discovery.
  discovery_check_log="$outdir/${safe_pkg}-${name}-discovery-check.log"
  if exact_matches=$(awk -v target="$name" '$0 == target { n += 1 } END { print n + 0 }' "$discovery_log" 2>"$discovery_check_log"); then
    if [[ ! "$exact_matches" =~ ^[0-9]+$ ]]; then
      echo "::error title=go-fuzz-tool::invalid target-discovery count for ${pkg}/${name} (details: ${discovery_check_log})" >&2
      status=1
    elif [ "$exact_matches" != "1" ]; then
      echo "::error title=go-fuzz-discovery::exact target ${pkg}/${name} was not discovered exactly once (log: ${discovery_log})" >&2
      status=1
    fi
  else
    echo "::error title=go-fuzz-tool::could not inspect target-discovery log for ${pkg}/${name} (details: ${discovery_check_log})" >&2
    status=1
  fi
fi

# Never invoke the campaign command if target discovery did not prove the
# exact fuzz function exists.
if [ "$status" -ne 0 ]; then
  exit "$status"
fi

echo "=== fuzz ${pkg}/${name} (fuzztime=${fuzztime}, fuzzminimizetime=${minimize}) ==="
go test -run '^$' -fuzz "^${name}$" -fuzztime "$fuzztime" -fuzzminimizetime "$minimize" "./$pkg" 2>&1 | tee "$log"
run_rcs=("${PIPESTATUS[@]}")
run_failed=0
if [ "${run_rcs[1]}" -ne 0 ]; then
  echo "::error title=go-fuzz-log::execution log write failed for ${pkg}/${name} (${log})" >&2
  status=1
fi
if [ "${run_rcs[0]}" -ne 0 ]; then
  run_failed=1
  if grep -Eq "^--- FAIL: ${name}([[:space:]]|$)" "$log"; then
    echo "::error title=go-fuzz-target::${pkg}/${name} reported a target failure (log: ${log})" >&2
  else
    echo "::error title=go-fuzz-tool::go test fuzz execution failed without a target failure marker for ${pkg}/${name} (log: ${log})" >&2
  fi
  status=1
fi

if [ "$run_failed" -eq 1 ]; then
  # On a target/run failure, collect every matching directory from BOTH Go's
  # fuzz cache and the package testdata corpus. Scan/copy failures are never
  # swallowed; separate annotations preserve their source.
  collect() {
    src_root=$1
    label=$2
    dest="$outdir/${safe_pkg}-${name}-reproducers/${label}"
    if [ ! -d "$src_root" ]; then
      if [ "$label" = "gocache" ]; then
        err_file="$outdir/${safe_pkg}-${name}-corpus-${label}-discovery.log"
        printf 'corpus source directory does not exist: %s\n' "$src_root" >"$err_file"
        echo "::error title=go-fuzz-discovery::required corpus source missing for ${label} (${src_root}; details: ${err_file})" >&2
        status=1
      fi
      return 0
    fi

    match_file="$outdir/${safe_pkg}-${name}-corpus-${label}-matches.log"
    err_file="$outdir/${safe_pkg}-${name}-corpus-${label}-discovery.log"
    find "$src_root" -type d -name "$name" -print >"$match_file" 2>"$err_file"
    find_rc=$?
    if [ "$find_rc" -ne 0 ]; then
      echo "::error title=go-fuzz-discovery::corpus discovery failed for ${label} (${src_root}; details: ${err_file})" >&2
      status=1
    else
      rm -f "$err_file"
    fi

    copy_log="$outdir/${safe_pkg}-${name}-corpus-${label}-copy.log"
    : > "$copy_log"
    while IFS= read -r d; do
      [ -n "$d" ] || continue
      if ! mkdir -p "$dest"; then
        echo "::error title=go-fuzz-copy::cannot create reproducer destination: ${dest}" >&2
        status=1
      elif ! cp -R "$d"/. "$dest"/ 2>>"$copy_log"; then
        echo "::error title=go-fuzz-copy::reproducer copy failed: ${d} -> ${dest} (details: ${copy_log})" >&2
        status=1
      fi
    done < "$match_file"
  }

  cache_env_log="$outdir/${safe_pkg}-${name}-gocache-env.log"
  if cache_dir=$(go env GOCACHE 2>"$cache_env_log") && [ -n "$cache_dir" ]; then
    collect "$cache_dir/fuzz" "gocache"
  else
    echo "::error title=go-fuzz-tool::could not determine Go fuzz cache (details: ${cache_env_log})" >&2
    status=1
  fi
  # Go writes minimized failures below the tested package's testdata/fuzz;
  # with pkg="." the path naturally reduces to the repository root.
  collect "$repo_dir/$pkg/testdata/fuzz" "testdata"
fi

exit "$status"
