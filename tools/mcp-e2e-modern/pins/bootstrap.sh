#!/usr/bin/env bash
set -uo pipefail
out=${1:-pins-bootstrap}
mkdir -p "$out/go" "$out/ts" "$out/logs" || exit 1
report="$out/report.json"
printf '{"go":{},"typescript":{},"failures":[],"optional_gaps":[]}' > "$report"
work="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/mcp-pins-$$"
mkdir -p "$work/go" "$work/ts" || exit 1
fail=0
go_locks_ok=false
ts_locks_ok=false
logrun() { local n=$1; shift; "$@" >"$out/logs/$n.log" 2>&1; local rc=$?; printf '%s\n' "$rc" >"$out/logs/$n.exit"; return "$rc"; }
record() { local key=$1 name=$2 msg=$3; printf '%s\n' "$msg" >>"$out/logs/$name.log"; set_report --arg n "$name" --arg m "$msg" ".${key} += [{name:\$n,message:\$m}]" || fail=1; }
required_fail() { record failures "$1" "$2"; fail=1; }
optional_gap() { record optional_gaps "$1" "$2"; }
set_report() { local t="$report.tmp"; jq "$@" "$report" >"$t" && jq -e . "$t" >/dev/null && mv "$t" "$report" || { rm -f "$t"; printf '%s\n' 'report update failed' >>"$out/logs/report-write.log"; fail=1; return 1; }; }
require_file() { local src=$1 dst=$2 name=$3; if [[ -f $src ]] && cp "$src" "$dst"; then return 0; fi; required_fail "$name" "file copy failed: $src"; return 1; }
validate() { jq -e . "$2" >/dev/null 2>&1 || { required_fail "$1" "invalid JSON: $2"; return 1; }; }
json_string() { jq -Rn --arg v "$1" '$v'; }
gh_tag_commit() {
  local repo=$1 tag=$2 obj sha type depth=0
  obj=$(curl -fsSL "https://api.github.com/repos/$repo/git/ref/tags/$tag" 2>/dev/null) || return 1
  while (( depth < 8 )); do
    type=$(jq -r '.object.type // empty' <<<"$obj"); sha=$(jq -r '.object.sha // empty' <<<"$obj")
    [[ $sha =~ ^[0-9a-f]{40}$ ]] || return 1
    [[ $type == commit ]] && { printf '%s' "$sha"; return 0; }
    [[ $type == tag ]] || return 1
    obj=$(curl -fsSL "https://api.github.com/repos/$repo/git/tags/$sha" 2>/dev/null) || return 1; depth=$((depth+1))
  done
  return 1
}
resolve_go() {
  local f="$out/go/releases.json"
  if ! curl -fsSL 'https://api.github.com/repos/modelcontextprotocol/go-sdk/releases?per_page=20&page=1' -o "$f" || ! validate go-release-json "$f"; then required_fail go-latest 'latest Go release metadata unavailable'; return; fi
  mapfile -t go_tags < <(jq -r '.[]|select(.draft==false and .prerelease==false)|.tag_name' "$f" | head -20)
  if ((${#go_tags[@]}==0)); then required_fail go-latest 'no stable Go release'; return; fi
  local latest=${go_tags[0]} commit=null; if c=$(gh_tag_commit modelcontextprotocol/go-sdk "$latest"); then commit=$(json_string "$c"); else required_fail go-latest 'latest release tag unresolved'; fi
  walk_go_candidates "$latest" "$commit" "${go_tags[@]}"
}
walk_go_candidates() {
  local latest=$1 lc=$2 tag ver count=0 selected=$1 latest_status=unknown latest_reason=no_probe latest_kind=unknown latest_lines='[]' selected_status=unknown selected_reason=no_probe selected_kind=unknown selected_lines='[]' selected_commit=null
  local gomodcache; gomodcache=$(go env GOMODCACHE)
  shift 2
  for tag in "$@"; do
    ((count+=1)); ((count>10)) && break
    [[ $tag == v* ]] || continue
    ver=$tag
    printf 'module pins-bootstrap\n\ngo 1.25\n\nrequire github.com/modelcontextprotocol/go-sdk %s\n' "$ver" >"$work/go/go.mod"
    [[ -s $work/go/go.mod ]] || { required_fail "go-manifest-$count" 'go.mod missing'; break; }
    if ! logrun "go-download-$count" bash -c 'cd "$1" && go mod download' _ "$work/go"; then [[ $count == 1 ]] && { latest_status=unknown; latest_reason=download_failed; latest_kind=unknown; }; optional_gap "go-download-$count" 'download failed'; continue; fi
    local src="$gomodcache/github.com/modelcontextprotocol/go-sdk@${ver#v}" log="$out/logs/go-protocol-$count.log" rc kind=source_literal lines
    grep -rnF '2026-07-28' "$src" --include='*.go' >"$log" 2>&1; rc=$?
    if (( rc == 1 )); then [[ $count == 1 ]] && { latest_status=absent; latest_reason=no_literal; latest_kind=absent; selected_status=absent; selected_reason=no_literal; selected_kind=absent; }; continue
    elif (( rc >= 2 )); then [[ $count == 1 ]] && { latest_status=unknown; latest_reason=search_error; latest_kind=unknown; }; optional_gap "go-protocol-$count" 'search error'; continue; fi
    lines=$(jq -Rsc 'split("\n")|map(select(length>0))|.[0:5]' "$log")
    grep -rnE '2025-11-25.*2026-07-28|2026-07-28.*2025-11-25' "$src" --include='*.go' >"$out/logs/go-declared-$count.log" 2>/dev/null; rc=$?
    if (( rc == 0 )); then kind=declared; lines=$(jq -Rsc 'split("\n")|map(select(length>0))|.[0:5]' "$out/logs/go-declared-$count.log"); elif (( rc >= 2 )); then optional_gap "go-declared-$count" 'search error'; fi
    if [[ $count == 1 ]]; then latest_status=$kind; latest_kind=$kind; latest_lines=$lines; fi
    selected=$tag; selected_status=$kind; selected_kind=$kind; selected_lines=$lines
    break
  done
  if [[ $selected_status == unknown ]]; then optional_gap go-fallback 'no protocol-support candidate could be verified'; fi
  printf 'module pins-bootstrap\n\ngo 1.25\n\nrequire github.com/modelcontextprotocol/go-sdk %s\n' "$selected" >"$work/go/go.mod"
  [[ -s $work/go/go.mod ]] || { required_fail go-lock-manifest 'go.mod missing'; return; }
  if logrun go-lock bash -c 'cd "$1" && go mod download' _ "$work/go"; then
    require_file "$work/go/go.mod" "$out/go/go.mod" go-mod-copy && require_file "$work/go/go.sum" "$out/go/go.sum" go-sum-copy && go_locks_ok=true
  else required_fail go-lock 'Go lock generation failed'; fi
  if c=$(gh_tag_commit modelcontextprotocol/go-sdk "$selected"); then selected_commit=$(json_string "$c"); fi
  local latest_evidence selected_evidence
  if [[ $latest_status == absent ]]; then latest_evidence='{"kind":"absent","reason":"no_literal"}'; else latest_evidence=$(jq -cn --arg k "$latest_kind" --argjson l "$latest_lines" '{kind:$k,lines:$l}'); fi
  if [[ $selected_status == unknown ]]; then selected_evidence='{"kind":"unknown","reason":"no_probe"}'; else selected_evidence=$(jq -cn --arg k "$selected_kind" --argjson l "$selected_lines" '{kind:$k,lines:$l}'); fi
  set_report --arg lv "$latest" --arg sv "$selected" --argjson lc "$lc" --argjson sc "$selected_commit" --arg ls "$latest_status" --arg ss "$selected_status" --argjson le "$latest_evidence" --argjson se "$selected_evidence" '.go={latest:{version:$lv,commit:$lc,protocol_status:$ls,evidence:$le},selected:{version:$sv,commit:$sc,protocol_status:$ss,evidence:$se}}'
}
resolve_ts_package() {
  local pkg=$1 required=$2 safe=${1##*/} meta="$out/ts/registry-${1##*/}.json" latest selected status=unknown ev=download_failed probe evidence_file
  safe=${safe//-/_}
  if ! curl -fsSL "https://registry.npmjs.org/$pkg" -o "$meta" || ! validate "npm-json-$safe" "$meta"; then
    if [[ $required == true ]]; then required_fail "npm-$safe" 'registry metadata unavailable'; else optional_gap "npm-$safe" 'umbrella package unavailable'; fi; return
  fi
  latest=$(jq -r '."dist-tags".latest // empty' "$meta"); if [[ -z $latest ]]; then if [[ $required == true ]]; then required_fail "npm-$safe" 'latest version missing'; else optional_gap "npm-$safe" 'latest version missing'; fi; return; fi
  selected=$latest
  probe=$(npm_source_match "$pkg" "$latest" "$safe" latest)
  evidence_file="$out/logs/npm-source-$safe-latest.json"
  case $probe in
    match) status=source_literal; ev=$(jq -cn --argjson l "$(<"$evidence_file")" --arg log "logs/npm-source-$safe-latest.log" '{kind:"source_literal",lines:$l,log:$log}') ;;
    declared) status=declared; ev=$(jq -cn --argjson l "$(<"$out/logs/npm-declared-$safe-latest.json")" --arg log "logs/npm-declared-$safe-latest.log" '{kind:"declared",lines:$l,log:$log}') ;;
    miss) status=absent; ev='{"kind":"absent","reason":"no_literal"}' ;;
    search_error) status=unknown; ev='{"kind":"unknown","reason":"source_search_error"}' ;;
    *) status=unknown; ev='{"kind":"unknown","reason":"download_failed"}' ;;
  esac
  local latest_status=$status latest_ev=$ev
  if [[ $status != source_literal && $status != declared ]]; then
    local count=0 ver fallback_probe fallback_status fallback_ev
    while IFS= read -r ver; do
      [[ -n $ver && $ver != *-* && $ver != "$latest" && $(printf '%s\n%s\n' "$ver" "$latest" | sort -V | tail -1) == "$latest" ]] || continue
      ((count+=1)); ((count>10)) && break
      fallback_probe=$(npm_source_match "$pkg" "$ver" "$safe" "fallback-$count")
      case $fallback_probe in
        match|declared) selected=$ver; status=$fallback_probe; evidence_file="$out/logs/npm-source-$safe-fallback-$count.json"; [[ $fallback_probe == declared ]] && evidence_file="$out/logs/npm-declared-$safe-fallback-$count.json"; ev=$(jq -cn --arg k "$fallback_probe" --argjson l "$(<"$evidence_file")" --arg log "logs/${evidence_file##*/}" '{kind:$k,lines:$l,log:$log}'); break ;;
        miss) ;;
        search_error) optional_gap "npm-search-$safe-fallback-$count" 'search error' ;;
        *) ;;
      esac
    done < <(jq -r '.versions|keys[]' "$meta" | sort -Vr)
    [[ $status == source_literal || $status == declared ]] || optional_gap "npm-fallback-$safe" 'no verified protocol-support candidate'
  fi
  verify_ts_provenance "$meta" "$latest" "$safe-latest"
  if [[ $PROV_COMMIT == null && $required == true ]]; then optional_gap "npm-latest-$safe" 'latest provenance unverified'; fi
  local latest_commit=$PROV_COMMIT latest_url=$PROV_URL
  verify_ts_provenance "$meta" "$selected" "$safe"
  local prov_commit=$PROV_COMMIT prov_url=$PROV_URL prov_ev=$PROV_EVIDENCE role=informational
  [[ $pkg == @modelcontextprotocol/client ]] && role=client
  [[ $pkg == @modelcontextprotocol/server ]] && role=server
  [[ $pkg == @modelcontextprotocol/node ]] && role=tooling
  set_report --arg p "$pkg" --arg role "$role" --arg lv "$latest" --arg sv "$selected" --arg ls "$latest_status" --argjson le "$latest_ev" --arg ss "$status" --argjson se "$ev" --argjson lc "$latest_commit" --argjson lu "$latest_url" --argjson commit "$prov_commit" --argjson url "$prov_url" --arg pe "$prov_ev" '.typescript.packages[$p]={role:$role,latest:{version:$lv,protocol_status:$ls,evidence:$le,commit:$lc,verified_release_url:$lu},selected:{version:$sv,protocol_status:$ss,evidence:$se,commit:$commit,verified_release_url:$url,provenance:$pe}}'
}
npm_source_match() {
  local pkg=$1 ver=$2 safe=$3 label=$4 dir="$work/ts/node_modules/$pkg" logfile="$out/logs/npm-source-$3-$4.log" rc lines tag
  printf '{"name":"pins-bootstrap","private":true,"dependencies":{"%s":"%s"}}\n' "$pkg" "$ver" >"$work/ts/package.json"
  [[ -s $work/ts/package.json ]] || { printf 'install_failed'; return 0; }
  if ! logrun "npm-$safe-$label" bash -c 'cd "$1" && npm install --no-audit --no-fund' _ "$work/ts"; then printf 'install_failed'; return 0; fi
  grep -rlF '2026-07-28' "$dir" >/dev/null 2>&1; rc=$?
  if (( rc == 0 )); then
    grep -rnF '2026-07-28' "$dir" >"$logfile" 2>&1; rc=$?
    (( rc == 0 )) || { printf 'search_error'; return 0; }
    jq -Rsc 'split("\n")|map(select(length>0))|.[0:5]' "$logfile" >"$out/logs/npm-source-$safe-$label.json"
    grep -rnE '2025-11-25.*2026-07-28|2026-07-28.*2025-11-25' "$dir" >"$out/logs/npm-declared-$safe-$label.log" 2>/dev/null; rc=$?
    if (( rc == 0 )); then jq -Rsc 'split("\n")|map(select(length>0))|.[0:5]' "$out/logs/npm-declared-$safe-$label.log" >"$out/logs/npm-declared-$safe-$label.json"; printf 'declared'; else printf 'match'; fi
  elif (( rc == 1 )); then printf 'miss'; else printf 'search_error'; fi
  return 0
}
verify_ts_provenance() {
  local meta=$1 ver=$2 safe=$3 githead tag found=null url=null rel matched='' name page tagsfile="$out/logs/tags-$3.json"
  githead=$(jq -r --arg v "$ver" '.versions[$v].gitHead // empty' "$meta")
  for tag in "v$ver" "$ver"; do
    if c=$(gh_tag_commit modelcontextprotocol/typescript-sdk "$tag") && [[ $c == "$githead" && $githead =~ ^[0-9a-f]{40}$ ]]; then matched=$tag; found=$(json_string "$c"); break; fi
  done
  if [[ $found == null ]]; then
    name=${meta##*/registry-}; name=${name%.json}
    for page in 1 2; do
      if curl -fsSL "https://api.github.com/repos/modelcontextprotocol/typescript-sdk/tags?per_page=100&page=$page" -o "$tagsfile"; then
        matched=$(jq -r --arg p "@modelcontextprotocol/$name@$ver" '[.[]|select(.name|contains($p))][0].name // empty' "$tagsfile")
        [[ -n $matched ]] || matched=$(jq -r --arg n "$name@$ver" '[.[]|select(.name|contains($n))][0].name // empty' "$tagsfile")
        [[ -n $matched ]] || matched=$(jq -r --arg v "v$ver" --arg ver "$ver" '[.[]|select(.name==$v or .name==$ver)][0].name // empty' "$tagsfile")
        [[ -n $matched ]] && break
      fi
    done
    if [[ -n $matched ]] && c=$(gh_tag_commit modelcontextprotocol/typescript-sdk "$matched"); then found=$(json_string "$c"); fi
  fi
  if [[ $found != null ]]; then
    rel="https://api.github.com/repos/modelcontextprotocol/typescript-sdk/releases/tags/$matched"
    if curl -fsSL "$rel" -o "$out/logs/release-$safe.json" && jq -e --arg t "$matched" '.tag_name==$t' "$out/logs/release-$safe.json" >/dev/null 2>&1; then url=$(json_string "https://github.com/modelcontextprotocol/typescript-sdk/releases/tag/$matched"); else :; # Keep tag-verified commit without optional release URL.
    fi
  fi
  PROV_COMMIT=$found; PROV_URL=$url; PROV_EVIDENCE=unverified
  [[ $found != null ]] && PROV_EVIDENCE=verified
}
write_ts_lock() {
  local client server node
  client=$(jq -r '.typescript.packages["@modelcontextprotocol/client"].selected.version // empty' "$report")
  server=$(jq -r '.typescript.packages["@modelcontextprotocol/server"].selected.version // empty' "$report")
  node=$(jq -r '.typescript.packages["@modelcontextprotocol/node"].selected.version // empty' "$report")
  if [[ -z $client || -z $server || -z $node ]]; then required_fail ts-lock 'selected split package version missing'; return; fi
  jq -n --arg c "$client" --arg s "$server" --arg n "$node" '{name:"pins-bootstrap",private:true,dependencies:{"@modelcontextprotocol/client":$c,"@modelcontextprotocol/server":$s,"@modelcontextprotocol/node":$n}}' >"$work/ts/package.json"
  validate ts-lock-manifest "$work/ts/package.json" || return
  if logrun ts-lock bash -c 'cd "$1" && npm install --no-audit --no-fund' _ "$work/ts"; then
    require_file "$work/ts/package.json" "$out/ts/package.json" ts-package-copy && require_file "$work/ts/package-lock.json" "$out/ts/package-lock.json" ts-lock-copy && ts_locks_ok=true
  else required_fail ts-lock 'npm lock generation failed'; fi
}
run_probes() {
  local src="$(dirname "$0")" go_ok=false ts_ok=false
  if [[ -f $src/probe_go.go ]] && cp "$src/probe_go.go" "$work/go/probe_go.go"; then
    if logrun go-tidy bash -c 'cd "$1" && GOFLAGS=-mod=mod go mod tidy' _ "$work/go"; then
      if logrun go-probes bash -c 'cd "$1" && go run probe_go.go' _ "$work/go"; then go_ok=true; require_file "$work/go/go.mod" "$out/go/go.mod" go-probe-mod; require_file "$work/go/go.sum" "$out/go/go.sum" go-probe-sum; else optional_gap go-probe 'compile or run failed'; fi
    else optional_gap go-tidy 'go mod tidy failed'; fi
  else optional_gap go-probe 'probe file missing or copy failed'; fi
  if [[ -f $src/probe_ts.mjs ]] && cp "$src/probe_ts.mjs" "$work/ts/probe_ts.mjs"; then
    if logrun ts-probes bash -c 'cd "$1" && node probe_ts.mjs' _ "$work/ts"; then ts_ok=true; else optional_gap ts-probe 'run failed'; fi
  else optional_gap ts-probe 'probe file missing or copy failed'; fi
  [[ -f $out/logs/go-probes.log ]] || : >"$out/logs/go-probes.log"
  [[ -f $out/logs/ts-probes.log ]] || : >"$out/logs/ts-probes.log"
  merge_caps go "$out/logs/go-probes.log" "$go_ok"
  merge_caps typescript "$out/logs/ts-probes.log" "$ts_ok"
}
merge_caps() {
  local section=$1 logfile=$2 ok=$3 caps
  caps=$(jq -sR --argjson keys '["protocol_2026_07_28","client_stdio_transport","server_streamable_http_transport","stateless_server_mode","progress_notifications_tool_call","client_cancellation_api","subscriptions_listen","server_discover"]' --arg log "${logfile#"$out"/}" --arg ok "$ok" --arg tail "$(tail -n 5 "$logfile" 2>/dev/null)" '
    (split("\n")|map(try fromjson catch null)|map(select(type=="object" and (.capability|type)=="string"))) as $r |
    reduce $keys[] as $k ({}; .[$k]=([ $r[]|select(.capability==$k)]|last) as $x |
      if $ok!="true" then {status:"unknown",reason:"probe_failed",evidence:{kind:"probe",detail:$tail,log:$log}}
      elif $x==null then {status:"unknown",reason:"no_probe",evidence:{kind:"probe",detail:$tail,log:$log}}
      elif $x.ok==true then {status:"supported",evidence:{kind:"probe",detail:($x.detail//""),log:$log}}
      elif $x.detail=="no_probe" then {status:"unknown",reason:"no_probe",evidence:{kind:"probe",detail:"no_probe",log:$log}}
      else {status:"unknown",reason:"probe_failed",evidence:{kind:"probe",detail:($x.detail//$tail),log:$log}} end)
  ' "$logfile") || { required_fail "${section}-caps" 'capability merge failed'; return; }
  printf '%s\n' "$caps" >"$out/logs/${section}-caps.json"; validate "${section}-caps-json" "$out/logs/${section}-caps.json" || return
  set_report --argjson caps "$caps" ".$section.capabilities=\$caps"
}
write_references() {
  { echo '# Verified source references'; echo; jq -r '"Go latest: \(.go.latest.version // "unknown"), selected: \(.go.selected.version // "unknown")."' "$report"; jq -r '.typescript.packages|to_entries[]|"\(.key): latest \(.value.latest.version), selected \(.value.selected.version), commit \(.value.selected.commit // "unverified"), release \(.value.selected.verified_release_url // "unverified")"' "$report"; } >"$out/SOURCE_REFERENCES.md" || required_fail references 'reference write failed'
}
write_summary() {
  local ts_ok go_status ts_status gl gs tl ts
  ts_ok=$(jq -r '[.typescript.packages["@modelcontextprotocol/client"].selected.provenance,.typescript.packages["@modelcontextprotocol/server"].selected.provenance,.typescript.packages["@modelcontextprotocol/node"].selected.provenance]|all(.=="verified")' "$report")
  go_status=$(jq -r '.go.selected.protocol_status // "unknown"' "$report"); ts_status=$(jq -r '[.typescript.packages["@modelcontextprotocol/client"].selected.protocol_status,.typescript.packages["@modelcontextprotocol/server"].selected.protocol_status,.typescript.packages["@modelcontextprotocol/node"].selected.protocol_status]|join(",")' "$report")
  gl=$(jq -r '.go.latest.version // ""' "$report"); gs=$(jq -r '.go.selected.version // ""' "$report")
  tl=$(jq -r '[.typescript.packages["@modelcontextprotocol/client"].selected.version,.typescript.packages["@modelcontextprotocol/server"].selected.version,.typescript.packages["@modelcontextprotocol/node"].selected.version]|join(",")' "$report"); ts=$tl
  set_report --arg gl "$gl" --arg gs "$gs" --arg tl "$tl" --arg ts "$ts" --arg gp "$go_status" --arg tp "$ts_status" --argjson go_locks "$go_locks_ok" --argjson ts_locks "$ts_locks_ok" --argjson tpv "$ts_ok" '.summary={go:{latest:$gl,selected:$gs,protocol_status:$gp,ready_for_pinning:(($gp=="source_literal" or $gp=="declared") and .go.selected.commit!=null and $go_locks)},typescript:{latest:$tl,selected:$ts,protocol_status:$tp,ready_for_pinning:(($tp|split(",")|all(.=="source_literal" or .=="declared")) and $tpv and $ts_locks)}}'
}
set_report '.typescript={packages:{}}'
resolve_go
resolve_ts_package @modelcontextprotocol/client true
resolve_ts_package @modelcontextprotocol/server true
resolve_ts_package @modelcontextprotocol/node true
resolve_ts_package @modelcontextprotocol/sdk false
write_ts_lock
run_probes
write_summary
write_references
validate report-json "$report"
exit "$fail"
