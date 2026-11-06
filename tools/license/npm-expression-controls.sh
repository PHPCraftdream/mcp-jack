#!/usr/bin/env bash
# CI-only controls for SPDX expression handling: nested OR/AND, plain OR,
# plain AND, unknown identifier, undetermined licence, and ambiguous array
# metadata. Fixture data is tracked JSON; each case materializes a temporary
# installed tree, runs the pinned wrapper, asserts the outcome with evidence,
# and removes the temporary tree. Requires tooling/node_modules and Node >= 24.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixture="$here/testdata/npm-fixture"
tmp=""
status=0
output=""

cleanup() {
  if [ -n "$tmp" ] && [ -d "$tmp" ]; then
    rm -rf "$tmp"
  fi
}
trap cleanup EXIT

die() {
  echo "::error title=license/ts::$1" >&2
  exit 1
}

expect_evidence() { # <output> <evidence>...
  local evidence
  for evidence in "${@:2}"; do
    if ! grep -qF -- "$evidence" <<<"$1"; then
      die "refusal output missing evidence: $evidence"
    fi
  done
}

# Build a temporary installed tree from tracked fixture data.
materialize() { # <dep>...
  cleanup
  tmp="$(mktemp -d)"
  cp "$fixture/fixture-package.json" "$tmp/package.json"
  mkdir -p "$tmp/node_modules"
  local dep
  for dep in "$@"; do
    mkdir -p "$tmp/node_modules/$dep"
    cp "$fixture/deps/$dep/package.json" "$tmp/node_modules/$dep/package.json"
  done
}

expect_pass() { # <allowlist-file>
  bash "$here/check-ts-licenses.sh" "$tmp" "$1"
}

expect_refusal() { # <allowlist-file> <evidence>...
  output="$(bash "$here/check-ts-licenses.sh" "$tmp" "$1" 2>&1)" && status=0 || status=$?
  printf '%s\n' "$output"
  if [ "$status" -eq 0 ]; then
    die "fixture was expected to fail the allowlist"
  fi
  expect_evidence "$output" "${@:2}"
}

# Nested: (MIT AND GPL-3.0-only) OR Apache-2.0 is satisfied by the real
# allowlist through its Apache-2.0 branch and refused without it.
materialize license-fixture-dep-nested
expect_pass "$here/npm-allowed-licenses.txt"
materialize license-fixture-dep-nested
expect_refusal "$here/testdata/npm-allow-mit-only.txt" license-fixture-dep-nested Apache-2.0

# AND: every branch must be allowed; the real allowlist lacks GPL-3.0-only.
materialize license-fixture-dep-and
expect_refusal "$here/npm-allowed-licenses.txt" license-fixture-dep-and GPL-3.0-only

# OR: one allowed branch suffices even with a copyleft branch.
materialize license-fixture-dep-or
expect_pass "$here/testdata/npm-allow-mit-only.txt"

# The scanner maps NotMIT to UNKNOWN; require the named package's refusal.
materialize license-fixture-dep-notmit
expect_refusal "$here/testdata/npm-allow-mit-only.txt" license-fixture-dep-notmit "no licence could be determined"

# Undetermined licence: refused.
materialize license-fixture-dep-unknown
expect_refusal "$here/testdata/npm-allow-mit-only.txt" license-fixture-dep-unknown "no licence"

# Ambiguous array metadata: refused.
materialize license-fixture-dep-array
expect_refusal "$here/testdata/npm-allow-mit-only.txt" license-fixture-dep-array ambiguous

# Private packages: the checker rewrites every private-marked package's
# licence to UNLICENSED and tooling/reconcile-licenses.mjs restores declared
# licences from the installed manifests, so a valid private root must pass,
# and private-marked dependencies must still be evaluated (disallowed or
# missing licences refuse with evidence).
materialize
expect_pass "$here/npm-allowed-licenses.txt"
materialize license-fixture-dep-private-gpl
expect_refusal "$here/npm-allowed-licenses.txt" license-fixture-dep-private-gpl GPL-3.0-only
materialize license-fixture-dep-private-unlicensed
expect_refusal "$here/npm-allowed-licenses.txt" license-fixture-dep-private-unlicensed UNLICENSED

echo "npm SPDX controls behaved as expected."
