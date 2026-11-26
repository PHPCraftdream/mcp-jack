#!/usr/bin/env bash
# Write SHA256SUMS and rc-manifest.json for the release-candidate bundle.
#
# Usage: rc-checksums.sh <bundle-dir> <sha> <commit-time-rfc3339-utc>
#
# <bundle-dir> must contain exactly the seven RC artifact files (four CLI
# binaries, TypeScript tarball, Rust crate, Go module archive) and nothing
# else. SHA256SUMS is sha256sum -c compatible, sorted by name, and covers
# exactly that artifact set. rc-manifest.json records the SHA, the UTC commit
# time, and per-artifact name, size, and SHA-256; it contains only relative
# artifact names, no machine-private paths.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <bundle-dir> <sha> <commit-time-rfc3339-utc>" >&2
  exit 2
fi
if ! printf '%s' "$2" | grep -Eq '^[0-9a-f]{40}$'; then
  echo "invalid sha argument" >&2
  exit 2
fi
if ! printf '%s' "$3" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'; then
  echo "invalid commit time argument" >&2
  exit 2
fi

bundle="$1"
sha="$2"
commit_time="$3"

cd "$bundle"

# The RC artifact set, C-locale sorted by name.
names="$(printf '%s\n' \
  go-module-snapshot.tgz \
  jack-darwin-amd64 \
  jack-darwin-arm64 \
  jack-linux-amd64 \
  jack-linux-arm64 \
  mcp-jack-0.1.0.tgz \
  mcp-jack-0.1.0.crate \
  | LC_ALL=C sort)"

# Nothing else may have landed in the bundle: no extra files, no directories.
extra="$(find . -mindepth 1 -maxdepth 1 ! -type f -print)"
actual="$(find . -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort)"
if [ -n "$extra" ] || [ "$actual" != "$names" ]; then
  echo "bundle contents differ from the expected RC artifact set" >&2
  diff <(printf '%s\n' "$names") <(printf '%s\n' "$actual") >&2 || true
  exit 1
fi

: > SHA256SUMS
for name in $names; do
  sha256sum "$name" >> SHA256SUMS
done

# Machine-readable manifest; relative artifact names only.
{
  printf '{\n'
  printf '  "schema_version": 1,\n'
  printf '  "sha": "%s",\n' "$sha"
  printf '  "commit_time_utc": "%s",\n' "$commit_time"
  printf '  "artifacts": ['
  first=true
  while read -r digest name; do
    size="$(stat -c %s "$name")"
    if $first; then
      first=false
    else
      printf ','
    fi
    printf '\n    {"name": "%s", "sha256": "%s", "size": %s}' "$name" "$digest" "$size"
  done < SHA256SUMS
  printf '\n  ]\n}\n'
} > rc-manifest.json

echo "SHA256SUMS and rc-manifest.json written for $(wc -l < SHA256SUMS) artifacts"
