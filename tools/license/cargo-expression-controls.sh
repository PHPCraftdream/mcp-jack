#!/usr/bin/env bash
# CI-only controls proving cargo-deny evaluates SPDX expressions: the OR
# fixture passes the production policy and an MIT-only allowlist, the same
# branches joined by AND are refused naming the crate and licence, and a
# crate without a licence field is refused. Requires the pinned cargo-deny on
# PATH (installed by the workflow).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mit_only="$here/testdata/deny-mit-only.toml"
status=0
out=""

run_deny() { # <fixture-dir> <config-path>
  out="$(cd "$1" && cargo deny --config "$2" check licenses 2>&1)" && status=0 || status=$?
  printf '%s\n' "$out"
}

# The fixture path must succeed under the production policy first.
run_deny "$here/testdata/cargo-or" "$here/../../rust/deny.toml"
if [ "$status" -ne 0 ]; then
  echo "::error title=license/rust::OR fixture failed the production policy" >&2
  exit 1
fi

run_deny "$here/testdata/cargo-or" "$mit_only"
if [ "$status" -ne 0 ]; then
  echo "::error title=license/rust::GPL-3.0-only OR MIT must pass an MIT-only allowlist" >&2
  exit 1
fi

run_deny "$here/testdata/cargo-and" "$mit_only"
if [ "$status" -eq 0 ]; then
  echo "::error title=license/rust::GPL-3.0-only AND MIT must be refused" >&2
  exit 1
fi
for evidence in license-fixture-and GPL-3.0-only; do
  if ! grep -qF -- "$evidence" <<<"$out"; then
    echo "::error title=license/rust::refusal output missing evidence: $evidence" >&2
    exit 1
  fi
done

run_deny "$here/testdata/cargo-unlicensed" "$mit_only"
if [ "$status" -eq 0 ]; then
  echo "::error title=license/rust::crate without a licence must be refused" >&2
  exit 1
fi
for evidence in license-fixture-unlicensed unlicensed; do
  if ! grep -qF -- "$evidence" <<<"$out"; then
    echo "::error title=license/rust::refusal output missing evidence: $evidence" >&2
    exit 1
  fi
done

echo "cargo-deny expression controls behaved as expected."
