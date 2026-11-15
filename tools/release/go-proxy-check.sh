#!/usr/bin/env bash
# Prove that what the Go ecosystem would serve for this commit is the real
# source: request the computed proxy pseudo-version for
# github.com/PHPCraftdream/mcp-jack with bounded retries and compare the
# served module zip with the committed tree.
#
# Usage: go-proxy-check.sh <sha>     (run from a checkout of the same sha)
#
# The pseudo-version is v0.0.0-<UTC commit time YYYYMMDDHHMMSS>-<first 12 hex
# of the sha>. The first request makes proxy.golang.org fetch the commit, so
# both requests retry at most 10 times, 30 s apart, before failing with a
# clear message. The v0.0.0 base assumes no semver tag is reachable from
# this commit.
#
# Module-zip inclusion rule (the golang.org/x/mod/zip walk used by cmd/go):
# every tracked file of the root module EXCEPT
#   - files under a directory named .bzr, .git, .hg, or .svn (VCS metadata),
#   - files under a nested module (any subdirectory containing its own
#     go.mod; the root go.mod is the module's own and stays),
#   - files under a directory named vendor at any depth (the root go.mod
#     declares go 1.25.0, so the whole vendor tree is skipped),
#   - irregular files such as symlinks (none are tracked).
# Expected to fail until the commit is on the public default branch.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <sha>" >&2
  exit 2
fi
sha="$1"
if ! printf '%s' "$sha" | grep -Eq '^[0-9a-f]{40}$'; then
  echo "invalid sha argument" >&2
  exit 2
fi

module="github.com/PHPCraftdream/mcp-jack"
proxy="https://proxy.golang.org/$module/@v"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

stamp="$(date -u -d "@$(git show -s --format=%ct "$sha")" +%Y%m%d%H%M%S)"
pseudo="v0.0.0-$stamp-${sha:0:12}"
echo "pseudo-version: $pseudo"

# Bounded retry: 404s are expected until the proxy has fetched the commit.
fetch() {
  local url="$1" destination="$2" attempt
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS --max-time 60 -o "$destination" "$url"; then
      return 0
    fi
    if [ "$attempt" -eq 10 ]; then
      break
    fi
    echo "proxy attempt $attempt/10 failed; retrying in 30 s" >&2
    sleep 30
  done
  echo "::error::proxy.golang.org did not serve $url after 10 attempts; the commit must be public on the default branch" >&2
  return 1
}

fetch "$proxy/$pseudo.info" "$work/info.json"
info_version="$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["Version"])' "$work/info.json")"
info_time="$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["Time"])' "$work/info.json")"
if [ "$info_version" != "$pseudo" ]; then
  echo "::error::proxy .info version $info_version differs from the computed $pseudo" >&2
  exit 1
fi
if [ "$(date -u -d "$info_time" +%Y%m%d%H%M%S)" != "$stamp" ]; then
  echo "::error::proxy .info time $info_time differs from the commit time $stamp" >&2
  exit 1
fi

fetch "$proxy/$pseudo.zip" "$work/module.zip"
unzip -q "$work/module.zip" -d "$work/zip"
prefix="$module@$pseudo/"

# Zip member names under the single expected prefix, sorted.
while IFS= read -r entry; do
  [ -n "$entry" ] || continue
  case "$entry" in
    "$prefix"*) printf '%s\n' "${entry#"$prefix"}" ;;
    *) echo "::error::unexpected zip entry: $entry" >&2; exit 1 ;;
  esac
done < <(unzip -Z1 "$work/module.zip") | LC_ALL=C sort > "$work/zip-names.txt"
if ! grep -qx "go.mod" "$work/zip-names.txt"; then
  echo "::error::module zip does not contain go.mod" >&2
  exit 1
fi

# Committed tree filtered by the module-zip inclusion rule from the header.
git ls-tree -r --name-only "$sha" > "$work/tree-names.txt"
sed -n 's#^\(.*\)/go\.mod$#\1#p' "$work/tree-names.txt" > "$work/nested-modules.txt"
while IFS= read -r path; do
  [ -n "$path" ] || continue
  case "$path" in
    */.git/*|*/.hg/*|*/.svn/*|*/.bzr/*) continue ;;
    */vendor/*|vendor/*) continue ;;
  esac
  skip=false
  while IFS= read -r nested; do
    case "$path" in
      "$nested"/*) skip=true; break ;;
    esac
  done < "$work/nested-modules.txt"
  if ! "$skip"; then
    printf '%s\n' "$path"
  fi
done < "$work/tree-names.txt" | LC_ALL=C sort > "$work/expected-names.txt"

# Exact file list equality: no extra or missing file.
if ! diff -u "$work/expected-names.txt" "$work/zip-names.txt"; then
  echo "::error::module zip file list differs from the filtered commit tree" >&2
  exit 1
fi

# Byte comparison of every file.
mkdir "$work/tree"
git archive --format=tar "$sha" | tar -x -C "$work/tree"
while IFS= read -r name; do
  committed="$(sha256sum "$work/tree/$name" | cut -d' ' -f1)"
  served="$(sha256sum "$work/zip/$prefix$name" | cut -d' ' -f1)"
  if [ "$committed" != "$served" ]; then
    echo "::error::content differs between the commit and the module zip: $name" >&2
    exit 1
  fi
done < "$work/expected-names.txt"

count="$(wc -l < "$work/expected-names.txt")"
echo "Go proxy pseudo-version $pseudo reports the commit time $stamp." >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
echo "Module zip matches the commit tree: $count files, byte-identical." >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
