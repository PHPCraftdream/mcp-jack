#!/usr/bin/env bash
# CI-executed regression controls for run-target.sh, driven by a stub `go`
# on PATH (never a real toolchain, never network):
#   1. a succeeding target exits 0, keeps its log, collects nothing;
#   2. a failing target exits 1 AND copies planted evidence from both Go's
#      fuzz cache and the package testdata corpus, over EVERY real
#      subpackage layout (./server, ./client, ./userkey);
#   3. a reproducer copy failure propagates as exit 1 instead of being
#      ignored (source isolated via its distinct annotation);
#   4. a lost log on a succeeding target still fails observably
#      (source isolated via its distinct annotation);
#   5. a root-package target (pkg ".") uses root testdata/fuzz corpus layout
#      and nonhidden artifact names;
#   6. missing exact target discovery fails closed and never invokes fuzz;
#   7. discovery command and discovery-log failures are distinct;
#   8. fuzz tool failures without target failure markers are distinct;
#   9. corpus scans, copy, and GOCACHE lookup failures remain separately diagnosed;
#  10. duplicate discovery and discovery-log inspection failures fail closed;
#  11. empty discovery output is rejected; campaign runs all real targets after failure.
# Scratch lives under tools/fuzz/.selftest-<random> inside the worktree and
# is removed on exit (trap).
#
# Deliberately NO `set -e`: assertion failures are handled explicitly.
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d "$here/.selftest-XXXXXX")

cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT

stub_dir="$work/bin"
cache="$work/cache"
pkgroot="$work/pkg"
out="$work/out"
mkdir -p "$stub_dir" "$pkgroot" "$cache/fuzz/selftest/FuzzX" "$out"

cat > "$stub_dir/go" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = "env" ]; then
  if [ "${SELFTEST_FAIL_GOCACHE:-0}" = "1" ]; then echo "stub GOCACHE failure" >&2; exit 1; fi
  echo "$SELFTEST_CACHE"
  exit 0
fi
if [ "$1" = "test" ] && [ "$2" = "-list" ]; then
  echo "stub discovery"
  target=${SELFTEST_DISCOVERY_TARGET:-__AUTO__}
  if [ "$target" = "__AUTO__" ]; then
    target=${3#^}
    target=${target%?}
  elif [ "$target" = "__EMPTY__" ]; then
    target=""
  fi
  if [ -n "$target" ]; then
    echo "$target"
    if [ "${SELFTEST_DUPLICATE_DISCOVERY:-0}" = "1" ]; then echo "$target"; fi
  fi
  exit "${SELFTEST_DISCOVERY_STATUS:-0}"
fi
go_status=${SELFTEST_STATUS:-0}
fuzz_target=""
if [ "$1" = "test" ]; then
  previous=""
  for arg in "$@"; do
    if [ "$previous" = "-fuzz" ]; then fuzz_target=${arg#^}; fuzz_target=${fuzz_target%$}; fi
    previous="$arg"
  done
fi
if [ -n "$fuzz_target" ] && [ -n "${SELFTEST_CAMPAIGN_RUNS:-}" ]; then
  printf '%s %s\n' "$fuzz_target" "${@: -1}" >> "$SELFTEST_CAMPAIGN_RUNS"
  if [ "$fuzz_target" = "${SELFTEST_CAMPAIGN_FAIL_TARGET:-}" ]; then go_status=1; fi
fi
if [ "$1" = "test" ] || [ "$1" = "fuzz" ]; then
  echo "stub fuzz run"
  : > "$SELFTEST_RUN_MARKER"
  if [ "$go_status" -eq 1 ]; then
    echo "--- FAIL: ${fuzz_target:-FuzzX} (0.00s)"
  elif [ "$go_status" -ne 0 ]; then
    echo "stub go test tool failure"
  fi
fi
if [ -n "${SELFTEST_PLANT:-}" ]; then
  echo "cache-evidence" > "$SELFTEST_CACHE/fuzz/selftest/FuzzX/input"
  mkdir -p "${SELFTEST_PKG}/${SELFTEST_PKG_SUBPATH}/testdata/fuzz/FuzzX"
  echo "testdata-evidence" > "${SELFTEST_PKG}/${SELFTEST_PKG_SUBPATH}/testdata/fuzz/FuzzX/failing"
fi
exit "$go_status"
EOF
cat > "$stub_dir/cp" <<'EOF'
#!/usr/bin/env bash
if [ "${SELFTEST_FAIL_COPY:-0}" = "1" ]; then
  echo "stub cp failure" >&2
  exit 1
fi
PATH=${PATH#*:}
export PATH
exec cp "$@"
EOF
cat > "$stub_dir/tee" <<'EOF'
#!/usr/bin/env bash
for arg in "$@"; do
  if [ "${SELFTEST_FAIL_DISCOVERY_TEE:-0}" = "1" ] && [[ "$arg" == *server-FuzzX-discovery.log ]]; then
    echo "stub discovery tee failure" >&2
    exit 1
  fi
  if [ "${SELFTEST_FAIL_TEE:-0}" = "1" ] && [[ "$arg" == *server-FuzzX.log ]]; then
    echo "stub tee failure" >&2
    exit 1
  fi
done
PATH=${PATH#*:}
export PATH
exec tee "$@"
EOF
cat > "$stub_dir/awk" <<'EOF'
#!/usr/bin/env bash
if [ "${SELFTEST_FAIL_DISCOVERY_CHECK:-0}" = "1" ]; then
  echo "stub discovery inspection failure" >&2
  cat >/dev/null
  exit 1
fi
PATH=${PATH#*:}
export PATH
exec awk "$@"
EOF
cat > "$stub_dir/find" <<'EOF'
#!/usr/bin/env bash
if [ "${SELFTEST_FAIL_FIND:-0}" = "1" ]; then
  echo "stub corpus discovery failure" >&2
  exit 1
fi
PATH=${PATH#*:}
export PATH
exec find "$@"
EOF
chmod +x "$stub_dir/go" "$stub_dir/cp" "$stub_dir/tee" "$stub_dir/awk" "$stub_dir/find"

fail() {
  echo "FAIL: $1"
  exit 1
}

expect_status() { # $1 = desc, $2 = actual numeric status, $3 = expected
  if [ "$2" -ne "$3" ]; then
    echo "FAIL: $1 (exit $2, expected $3)"
    exit 1
  fi
  echo "PASS: $1"
}

expect_annotation() { # $1 = desc, $2 = grep pattern in case_err
  if ! grep -q "$2" "$case_err"; then
    echo "FAIL: $1 (annotation not found: $2)"
    exit 1
  fi
  echo "PASS: $1"
}

expect_no_annotation() { # $1 = desc, $2 = pattern that must NOT appear
  if grep -q "$2" "$case_err"; then
    echo "FAIL: $1 (unexpected annotation: $2)"
    exit 1
  fi
  echo "PASS: $1"
}

case_out="$work/case.out"
case_err="$work/case.err"
# Deliberately global: read by the caller after run_case returns, never
# captured via command substitution (that would lose the subshell status).
run_case() { # status, plant, pkg, discovered name, discovery status, fail-copy, fail-execution-tee, fail-find, duplicate-discovery, fail-GOCACHE, fail-discovery-tee, fail-discovery-check
  (
    cd "$pkgroot" || exit 99
    export PATH="$stub_dir:$PATH"
    export SELFTEST_CACHE="$cache"
    export SELFTEST_PKG="$pkgroot"
    export SELFTEST_STATUS="$1"
    export SELFTEST_RUN_MARKER="$work/run-marker"
    rm -f "$SELFTEST_RUN_MARKER"
    if [ -n "$2" ]; then export SELFTEST_PLANT="$2"; else unset SELFTEST_PLANT; fi
    # The stub plants the package corpus under the SAME package-relative
    # layout run-target.sh collects from: "server"/"client"/"userkey"
    # mirror the real subpackage dirs, "." reduces to the repository root.
    export SELFTEST_PKG_SUBPATH="$3"
    if [ "${4+x}" = x ]; then export SELFTEST_DISCOVERY_TARGET="$4"; else export SELFTEST_DISCOVERY_TARGET="FuzzX"; fi
    export SELFTEST_DISCOVERY_STATUS="${5:-0}"
    export SELFTEST_FAIL_COPY="${6:-0}"
    export SELFTEST_FAIL_TEE="${7:-0}"
    export SELFTEST_FAIL_DISCOVERY_TEE="${11:-0}"
    export SELFTEST_FAIL_DISCOVERY_CHECK="${12:-0}"
    export SELFTEST_FAIL_FIND="${8:-0}"
    export SELFTEST_DUPLICATE_DISCOVERY="${9:-0}"
    export SELFTEST_FAIL_GOCACHE="${10:-0}"
    bash "$here/run-target.sh" "$3" FuzzX 1s 1s "$out"
  ) >"$case_out" 2>"$case_err"
  case_status=$?
}

# Scenario 1: succeeding target over a real subpackage -> exit 0, log kept,
# nothing collected.
rm -f "$out/server-FuzzX.log"
rm -rf "$out/server-FuzzX-reproducers" "$out/client-FuzzX-reproducers" "$out/userkey-FuzzX-reproducers" "$out/rootpkg-FuzzX-reproducers"
run_case "0" "" "server"
expect_status "scenario 1: succeeding target exits 0 (real status)" "$case_status" 0
[ -s "$out/server-FuzzX.log" ] || fail "scenario 1: log missing or empty"
[ ! -e "$out/server-FuzzX-reproducers" ] || fail "scenario 1: reproducers collected on success"
expect_no_annotation "scenario 1: no ::error annotation" "::error"

# Scenario 2: failing target -> exit 1 and evidence from both corpora,
# mirrored over the ACTUAL ./server, ./client and ./userkey corpus layouts.
for pkg in server client userkey; do
  run_case "1" "1" "$pkg"
  expect_status "scenario 2 ($pkg): failing target exits 1 (real status)" "$case_status" 1
  [ -f "$out/$pkg-FuzzX-reproducers/gocache/input" ] || fail "scenario 2 ($pkg): gocache evidence missing"
  [ -f "$out/$pkg-FuzzX-reproducers/testdata/failing" ] || fail "scenario 2 ($pkg): testdata evidence missing"
  expect_annotation "scenario 2 ($pkg): target-failure annotation present" "reported a target failure (log:"
  expect_no_annotation "scenario 2 ($pkg): no copy-failure annotation" "reproducer copy failed"
  expect_no_annotation "scenario 2 ($pkg): no log-write annotation" "log write failed"
done

# Scenario 3: reproducer copy failure propagates (stub cp fails on all corpus
# copies while the log remains writable) — isolates collection as the failure source.
rm -f "$out/client-FuzzX.log"
rm -rf "$out/client-FuzzX-reproducers"
run_case "1" "1" "client" "FuzzX" "0" "1"
expect_status "scenario 3: copy failure propagates as exit 1" "$case_status" 1
expect_annotation "scenario 3: copy-failure annotation (isolated source)" "reproducer copy failed"
[ -s "$out/client-FuzzX.log" ] || fail "scenario 3: log lost (tee failed, wrong source)"
expect_annotation "scenario 3: target genuinely failed" "reported a target failure (log:"
expect_no_annotation "scenario 3: no log-write annotation" "log write failed"

# Scenario 4: lost log on a succeeding target still fails. A tee shim rejects
# only the execution log, leaving discovery logging intact; no evidence collection ran.
rm -f "$out/server-FuzzX.log"
run_case "0" "" "server" "FuzzX" "0" "0" "1"
expect_status "scenario 4: lost log fails a succeeding target" "$case_status" 1
expect_annotation "scenario 4: log-write annotation (isolated source)" "log write failed"
expect_no_annotation "scenario 4: no copy-failure annotation" "reproducer copy failed"
expect_no_annotation "scenario 4: no target-failure annotation" "reported a target failure"

# Scenario 5: root-package layout (pkg ".") -> root testdata/fuzz corpus and
# nonhidden artifact names.
rm -f "$out/rootpkg-FuzzX.log"
run_case "1" "1" "."
expect_status "scenario 5: root-package failing target exits 1" "$case_status" 1
[ -f "$out/rootpkg-FuzzX-reproducers/testdata/failing" ] || fail "scenario 5: root-layout testdata evidence missing"
[ -f "$out/rootpkg-FuzzX.log" ] || fail "scenario 5: nonhidden log missing"

# Scenario 6: an absent exact target fails closed before any fuzz invocation.
rm -f "$work/run-marker"
run_case "0" "" "server" "FuzzXExtra" "0"
expect_status "scenario 6: missing exact target fails closed" "$case_status" 1
expect_annotation "scenario 6: target discovery failure is distinct" "exact target server/FuzzX was not discovered"
[ ! -e "$work/run-marker" ] || fail "scenario 6: fuzz command ran after failed discovery"
expect_no_annotation "scenario 6: not a target execution failure" "reported a target failure"

# Scenario 7: discovery-log failure must fail closed before campaign execution.
rm -f "$out/server-FuzzX-discovery.log"
run_case "0" "" "server" "FuzzX" "0" "0" "0" "0" "0" "0" "1"
expect_status "scenario 7: discovery log failure fails closed" "$case_status" 1
expect_annotation "scenario 7: discovery log failure is distinct" "discovery log write failed"
[ ! -e "$out/server-FuzzX-discovery.log" ] || fail "scenario 7: discovery log was unexpectedly retained after simulated tee failure"
expect_no_annotation "scenario 7: target not run after lost discovery log" "execution failed without a target failure marker"

# Scenario 8: discovery command failure is reported as a tool/discovery source,
# rather than being mistaken for an absent target or fuzz execution failure.
run_case "0" "" "server" "FuzzX" "7"
expect_status "scenario 8: discovery-tool failure fails closed" "$case_status" 1
expect_annotation "scenario 8: discovery command failure is distinct" "go test -list failed"
[ ! -e "$work/run-marker" ] || fail "scenario 8: fuzz command ran after discovery-tool failure"
expect_no_annotation "scenario 8: not a target execution failure" "reported a target failure"

# Scenario 9: a failing fuzz command without a target-failure marker is
# reported as a tool failure, not misattributed to the fuzz target.
run_case "7" "" "server"
expect_status "scenario 9: fuzz-tool failure fails" "$case_status" 1
expect_annotation "scenario 9: fuzz-tool failure is distinct" "execution failed without a target failure marker"
expect_no_annotation "scenario 9: not a target failure" "reported a target failure"
expect_no_annotation "scenario 9: log write succeeded" "log write failed"

# Scenario 10: corpus discovery failures are reported and their raw diagnostics
# are retained separately from fuzz tool, target and copy failures.
run_case "1" "1" "client" "FuzzX" "0" "0" "0" "1"
expect_status "scenario 10: corpus discovery failure fails" "$case_status" 1
expect_annotation "scenario 10: gocache discovery failure is distinct" "corpus discovery failed for gocache"
expect_annotation "scenario 10: testdata discovery failure is distinct" "corpus discovery failed for testdata"
[ -s "$out/client-FuzzX-corpus-gocache-discovery.log" ] || fail "scenario 10: gocache discovery diagnostics missing"
[ -s "$out/client-FuzzX-corpus-testdata-discovery.log" ] || fail "scenario 10: testdata discovery diagnostics missing"
expect_no_annotation "scenario 10: no copy failure" "reproducer copy failed"

# Scenario 11: failure to query Go's cache is reported independently of corpus
# discovery and copy; its raw stderr is retained for diagnosis.
run_case "1" "1" "client" "FuzzX" "0" "0" "0" "0" "0" "1"
expect_status "scenario 11: GOCACHE query failure fails" "$case_status" 1
expect_annotation "scenario 11: cache-query failure is distinct" "could not determine Go fuzz cache"
[ -s "$out/client-FuzzX-gocache-env.log" ] || fail "scenario 11: GOCACHE diagnostic log missing"
expect_no_annotation "scenario 11: no copy failure" "reproducer copy failed"

# Scenario 12: duplicate exact discovery output is rejected; discovery must
# establish exactly one target instead of accepting ambiguous evidence.
run_case "0" "" "server" "FuzzX" "0" "0" "0" "0" "1"
expect_status "scenario 12: duplicate discovery rejected" "$case_status" 1
expect_annotation "scenario 12: exact-once validation is explicit" "was not discovered exactly once"
[ ! -e "$work/run-marker" ] || fail "scenario 12: fuzz command ran after ambiguous discovery"

# Scenario 13: failure to inspect discovery output fails closed with raw stderr.
run_case "0" "" "server" "FuzzX" "0" "0" "0" "0" "0" "0" "0" "1"
expect_status "scenario 13: discovery log inspection failure fails closed" "$case_status" 1
expect_annotation "scenario 13: inspection failure is distinct" "could not inspect target-discovery log"
[ -s "$out/server-FuzzX-discovery-check.log" ] || fail "scenario 13: discovery inspection diagnostic missing"
[ ! -e "$work/run-marker" ] || fail "scenario 13: fuzz command ran after inspection failure"

# Scenario 14: empty successful discovery output is rejected as a missing target.
run_case "0" "" "server" "__EMPTY__" "0"
expect_status "scenario 14: empty discovery fails closed" "$case_status" 1
expect_annotation "scenario 14: empty result is a missing exact target" "exact target server/FuzzX was not discovered exactly once"
[ ! -e "$work/run-marker" ] || fail "scenario 14: fuzz command ran after empty discovery"

# Scenario 15: a failed target does not abort the bounded campaign; all six
# current real targets are invoked and the aggregate campaign status is nonzero.
campaign_runs="$work/campaign-runs.log"
rm -f "$campaign_runs"
(
  cd "$pkgroot" || exit 99
  export PATH="$stub_dir:$PATH"
  export SELFTEST_CACHE="$cache"
  export SELFTEST_STATUS=0
  export SELFTEST_DISCOVERY_TARGET="__AUTO__"
  export SELFTEST_RUN_MARKER="$work/run-marker"
  export SELFTEST_CAMPAIGN_RUNS="$campaign_runs"
  export SELFTEST_CAMPAIGN_FAIL_TARGET=FuzzClassifyBody
  bash "$here/go-campaign.sh" 1s 1s "$work/campaign-out"
) >"$case_out" 2>"$case_err"
case_status=$?
expect_status "scenario 15: campaign preserves failure status" "$case_status" 1
campaign_count=$(awk 'END { print NR + 0 }' "$campaign_runs")
expect_status "scenario 15: all six targets run despite a failure" "$campaign_count" 6
for target in FuzzParseRequestAuth FuzzParseResponseAuth FuzzClassifyBody FuzzLoadProfile FuzzImportEnvelopes FuzzValidateCredential; do
  if ! awk -v target="$target" '$1 == target { found = 1 } END { exit !found }' "$campaign_runs"; then
    fail "scenario 15: campaign omitted $target"
  fi
done

echo "PASS: all campaign self-test scenarios"
exit 0
