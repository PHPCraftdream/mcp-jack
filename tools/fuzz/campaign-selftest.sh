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
#      and nonhidden artifact names.
# Scratch lives under tools/fuzz/.selftest-<random> inside the worktree and
# is removed on exit (trap).
#
# Deliberately NO `set -e`: assertion failures are handled explicitly.
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d "$here/.selftest-XXXXXX")

cleanup() {
  # Best-effort restore of every permission-guarded path before removal.
  chmod 755 "$work/out" 2>/dev/null || true
  chmod u+w "$work/out/client-FuzzX-reproducers/gocache" 2>/dev/null || true
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
  echo "$SELFTEST_CACHE"
  exit 0
fi
if [ "$1" = "test" ] || [ "$1" = "fuzz" ]; then
  echo "stub fuzz run"
fi
if [ -n "${SELFTEST_PLANT:-}" ]; then
  echo "cache-evidence" > "$SELFTEST_CACHE/fuzz/selftest/FuzzX/input"
  mkdir -p "${SELFTEST_PKG}/${SELFTEST_PKG_SUBPATH}/testdata/fuzz/FuzzX"
  echo "testdata-evidence" > "${SELFTEST_PKG}/${SELFTEST_PKG_SUBPATH}/testdata/fuzz/FuzzX/failing"
fi
exit "${SELFTEST_STATUS:-0}"
EOF
chmod +x "$stub_dir/go"

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
run_case() { # $1 = SELFTEST_STATUS, $2 = SELFTEST_PLANT (empty = unset), $3 = pkg (one of the real package names or ".")
  (
    cd "$pkgroot" || exit 99
    export PATH="$stub_dir:$PATH"
    export SELFTEST_CACHE="$cache"
    export SELFTEST_PKG="$pkgroot"
    export SELFTEST_STATUS="$1"
    if [ -n "$2" ]; then export SELFTEST_PLANT="$2"; else unset SELFTEST_PLANT; fi
    # The stub plants the package corpus under the SAME package-relative
    # layout run-target.sh collects from: "server"/"client"/"userkey"
    # mirror the real subpackage dirs, "." reduces to the repository root.
    export SELFTEST_PKG_SUBPATH="$3"
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
  expect_annotation "scenario 2 ($pkg): target-failure annotation present" "failed (log:"
  expect_no_annotation "scenario 2 ($pkg): no copy-failure annotation" "reproducer copy failed"
  expect_no_annotation "scenario 2 ($pkg): no log-write annotation" "log write failed"
done

# Scenario 3: reproducer copy failure propagates (gocache copy dest
# read-only, log still writable) — isolates the copy as the failure source.
rm -f "$out/client-FuzzX.log"
rm -rf "$out/client-FuzzX-reproducers"
mkdir -p "$out/client-FuzzX-reproducers/gocache"
chmod a-w "$out/client-FuzzX-reproducers/gocache"
run_case "1" "1" "client"
chmod u+w "$out/client-FuzzX-reproducers/gocache"
expect_status "scenario 3: copy failure propagates as exit 1" "$case_status" 1
expect_annotation "scenario 3: copy-failure annotation (isolated source)" "reproducer copy failed"
[ -s "$out/client-FuzzX.log" ] || fail "scenario 3: log lost (tee failed, wrong source)"
expect_annotation "scenario 3: target genuinely failed" "failed (log:"
expect_no_annotation "scenario 3: no log-write annotation" "log write failed"

# Scenario 4: lost log on a succeeding target still fails — the pre-existing
# log is removed FIRST, then $out made read-only, so tee must CREATE the log
# inside a directory without write permission (which fails); isolates the
# tee/log-write source; no evidence collection ran.
rm -f "$out/server-FuzzX.log"
chmod a-w "$out"
run_case "0" "" "server"
chmod 755 "$out"
expect_status "scenario 4: lost log fails a succeeding target" "$case_status" 1
expect_annotation "scenario 4: log-write annotation (isolated source)" "log write failed"
expect_no_annotation "scenario 4: no copy-failure annotation" "reproducer copy failed"
expect_no_annotation "scenario 4: no target-failure annotation" "failed (log:"

# Scenario 5: root-package layout (pkg ".") -> root testdata/fuzz corpus and
# nonhidden artifact names.
rm -f "$out/rootpkg-FuzzX.log"
run_case "1" "1" "."
expect_status "scenario 5: root-package failing target exits 1" "$case_status" 1
[ -f "$out/rootpkg-FuzzX-reproducers/testdata/failing" ] || fail "scenario 5: root-layout testdata evidence missing"
[ -f "$out/rootpkg-FuzzX.log" ] || fail "scenario 5: nonhidden log missing"

echo "PASS: all campaign self-test scenarios"
exit 0
