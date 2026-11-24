# Signed-stream executable contract

Normative wire rules are [`../../spec/05-signed-streams.md`](../../spec/05-signed-streams.md); request authentication and signed refusals are [`../../spec/01-authentication.md`](../../spec/01-authentication.md); modern request metadata/mirrors are [`../../spec/04-modern-profile.md`](../../spec/04-modern-profile.md), especially S4/S5/S6 and `spec/tests/modern/CASES.md`. Rotation and durable lifecycle mechanics below mirror [`../rotation.mjs`](../rotation.mjs) and [`../durable.mjs`](../durable.mjs). This documents the executable contract and current status, not passing SDK evidence. The concurrency runner holds stream A, verifies an independent signed refusal for stream B, releases A, and audits both request rows and distinct nonces. Rotation explicitly fails before client startup because successor reopen/key-resolver IPC is absent. Durable branches attempt exact raw replay and verify request-log evidence, but remain partial and can fail on response/state contract mismatch. Self-test exercises stream scenarios and Linux fake durable scenarios, and explicitly asserts the rotation contract gap; it is not SDK evidence. No scenarios are reported as executed here.

## Driver commands, results and process protocol

Node >=20, built-ins only:

```sh
node interop/stream.mjs [--matrix stream|rotation-stream|durable-stream] [--targets <file>] [--servers <l,l,...>] [--clients <l,l,...>] [--scenario <id[,id...]>] [--list] [--self-test]
node interop/stream.mjs --list
node interop/stream.mjs --self-test
node interop/stream.mjs
node interop/stream.mjs --matrix rotation-stream
node interop/stream.mjs --matrix durable-stream
node interop/stream.mjs --servers go --clients go --scenario progress-final
```

Matrix defaults to `stream`; omitted language selections mean every language in target document. `--scenario` accepts comma-separated IDs; `--list` prints selected matrix IDs and exits 0; `--list` with `--self-test` is usage error. Driver exit 0 means all selected cases pass; 1 means scenario/cell failure; 2 means invocation, target, input, or harness error. Scenario outputs include matrix/pair headings, PASS/FAIL, counts and final `INTEROP-SUMMARY`. Child executable exits: 0 completed the protocol action (a protocol refusal is still a completed action); 1 local/network inability; 2 invalid invocation. Diagnostics only on stderr.

For every selected (client,server,scenario), the driver creates one temporary fixture state and clock/log, starts the selected stream server on loopback, checks ready identity against pinned fixture `svc`, then starts the client. A configured relay is between client and server and the client receives the relay's actual port. Driver terminates only children it started. `stream_options` values are passed as matching `--<hyphenated-option>` flags to server and client when present; `idleTimeoutMs` becomes `--idle-timeout-ms` on both. Server and client receive `--profile modern`. Only `durable-stream` is explicitly restricted to Linux by the runner; rotation has no runner platform gate.

Server exact invocation (selected target argv, followed by):

```text
--profile modern --matrix NAME --scenario ID --aud AUD --state PATH --server-seed-hex HEX --clock-file PATH --request-log PATH --port 0
[--frame-max-bytes N] [--max-concurrent-streams N] [--max-stream-duration-ms N] [--heartbeat-ms N] [--idle-timeout-ms N]
[--ring-seed ring-1=HEX --successor-activation UNIX_SECONDS --rotation-store PATH]
[--durable-dir PATH]
```

`AUD` is `https://svc.example.test`, from `spec/fixtures/registry.json`. `PATH` state is version 1 `{version:1,keys:registry.keys,invites:[]}`. Server seed is fixture `svc` seed. It binds 127.0.0.1; `--port 0` means choose available port. Its first nonblank stdout JSONL line is exactly shaped `{"ready":true,"port":N,"server_public_key":"B64U","server_kid":"kid"}`; the public key and kid must equal `svc` fixture. Stderr is diagnostics. Server stdin is control JSONL where applicable: rotation announcement `{ "op":"announce", "reference":"ring-1", "kid":"<successor kid>" }`; response must report `{announced:true,ordinal:1,head_ordinal:1,published_at:P,activates_at:A,head_hash:<string>}`. Max-duration control `{action:"clock_advanced",clock:T,start:P,duration_ms:D}` is acknowledged `{control:"clock_advanced",clock:T}`. A hold producer is released by `{action:"release"}` and must acknowledge on stdout with `{control:"released",sid:<held stream sid>}`; the driver keeps the held state until this acknowledgement, then awaits and independently verifies the held client's complete JSONL stream. EOF cleanly stops server (exit 0); signal termination is cleanup, not evidence of successful lifecycle.

Client exact base invocation:

```text
--profile modern --matrix NAME --scenario ID --url URL --aud AUD --clock-file PATH --server-public-key B64U --seed-hex HEX --request-log PATH --nonce B64U --sid B64U --request-body-json JSON --jack-accept s1 --modern-version 2026-07-28 --mirror-headers-json JSON
[--action cancel|hold|once] [--frame-max-bytes N] [--max-concurrent-streams N] [--max-stream-duration-ms N] [--heartbeat-ms N] [--idle-timeout-ms N]
[--successor-activation UNIX_SECONDS --rotation-store PATH] [--durable-dir PATH]
```

For `opt-in-required`, `--jack-accept ''` omits opt-in; otherwise `s1`. Alice fixture signs; pinned verifier key is `svc`. `--mirror-headers-json` is an ordered array of name/value pairs built by driver. One stdout JSON object per line, newline terminated; no chatter on stdout. Each delivered MCP message is recorded before exactly one terminal record. Client action `hold` leaves stream open after first message for concurrency/durable orchestration; `cancel` closes after first notification; `once` is the independent refusal request.

Client JSONL actual schema: each message record includes `{type:"message",scenario,stream_index,request_method,request_target,request_body_b64u,request_headers,request_sig,request_ts,open:{sid,kid,ts,sig},frames:[{kind,sid,kid,seq,ts,data,sig}],data?,message?}`. The raw request evidence fields are included in every message record. `data` is exact signed UTF-8 string and/or `message` its parsed object, tied to a signed frame. Terminal records are `{type:"terminal",scenario,outcome:"complete|error|cancelled|refused",code,http_status,http_code,frames_verified,request_id,mcp_complete,terminal_frame,request_sig,v1_evidence,open?,frames?,failure_frame?,successor_activation?}` with nullable fields emitted as null where applicable. Complete terminal includes `terminal_frame:{kind:"end",sig:<final frame signature>}`. Stream errors retain verified open/frame evidence and `failure_frame` where applicable. Signed 429/501 refusal terminal carries exact v1 response evidence `{status,kid,ts,sig,body_b64u,request_sig}`; unsigned 401 replay refusal has `v1_evidence:null`. Driver verifies evidence independently and does not trust client `verified` assertions. Actual scenario comparison is `{messages:[parsed delivered message objects],terminal:<terminal>}`; expected objects are recursive subsets, arrays exact length/order.

## Modern request and wire evidence

Each POST is modern profile. JSON body is `{jsonrpc:"2.0",id:request_id,method:request_method,params:{...request_params,_meta:{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"mcp-jack-interop-stream-client","version":"1.0.0"}}}}`. `_meta` is inside `params`, never root. Every request has the protocolVersion and clientCapabilities mirrors; version is exactly `2026-07-28`; `Mcp-Method` exactly body method; `Mcp-Name` only when spec 04 S6 names a source (`tools/call`, events stream, etc.), not `subscriptions/listen`, `tools/list`, or `events/list`. Any name is sourced from body `params.name` or `params.uri`, byte-equal. `subscriptions/listen` specifically carries `params.notifications:["notifications/events/list_changed"]` to opt into that notification, while having no `Mcp-Name`. Valid `Mcp-Param-*` mirrors follow C5/C6 order; none of these cases currently defines annotated arguments. S4 requires present well-formed equal modern version header and `_meta`; S5 requires `Mcp-Method`; S6 forbids `Mcp-Name` where no source applies. Headers are unsigned mirrors, never part of signature; exact request body remains signed.

The v1 request signing string is eight LF-separated UTF-8 fields, no trailing LF: `mcp-jack/v1/request`, method, exact origin-form target, audience, Alice kid, canonical decimal Unix seconds, canonical unpadded base64url 16-byte nonce, canonical base64url SHA-256 of exact body bytes. Header Jack-Auth has actual request signature. V1 response string is `mcp-jack/v1/response\n<status>\n<request-sig>\n<server-kid>\n<ts>\n<base64url(SHA-256(exact raw body bytes))>`; signed 429/501 evidence must bind its status, raw body, request signature, server kid, timestamp and signature exactly.

Open signing string is `mcp-jack/stream1/open\n200\n<request-sig>\n<kid>\n<ts>\n<sid>`. Frame signing string is `mcp-jack/stream1/frame\n<sid>\n<seq>\n<ts>\n<prev>\n<base64url(SHA-256(UTF8(data)))>`. `seq` starts 0, `prev` is open signature then previous frame signature. End has empty data and counts as verified. For oversize, signal is verified and counted but never delivered; client stops there, does not require or count following end. `mcp_complete` is true only when complete signed end and last message is matching JSON-RPC response (same id, jsonrpc 2.0, exactly result or error, no method). A final notification followed by end—including list-changed last—has `mcp_complete:false`.

Driver chooses fixed protocol clock default `1800000000`; rotation matrix time `1767052810`, activation default `1767225610`. It writes decimal Unix seconds to clock file; languages must consult it for each signature/verification timestamp and not wall clock. For duration driver advances by `ceil(durationMs/1000)`; for idle it leaves clock fixed while transport stays open. Scenario nonce and sid are canonical 16-byte base64url test values supplied via flags. Respect them where API allows; where not, record actual values and explicitly do not claim deterministic generation. Any second independent concurrency request uses first 16 bytes SHA-256 of UTF-8 `<value>\nsecond`, base64url. A normal production `sid` MUST remain unique CSPRNG 16 bytes per spec 05; fixture injection is test-only.

## Request log and producer obligations

Request log is append-only JSONL, each line one observed event object, flushed at lifecycle evidence boundaries. For authenticated requests it must expose at least `request_verified:true`, `request_sig`, `request_method`, exact `body`, `request_params` (including `_meta`), `nonce`, `mirror_protocol_version`, `mirror_method`, `mirror_name` (null/absent if not applicable), and projected mirror fields where present. Preserve event-specific facts: cancellation via `handler_cancelled`/`request_cancelled` or `handler_cancelled:true`; duration `clock_changed` then `duration_elapsed` or equivalent `clock_observed` with change flag; granted heartbeat via heartbeat-grant event/field; durable `nonce_committed_before_first_byte:true`/`nonce_committed` before `stream_open`/first byte; replay row event `replayed_nonce`. Do not assert lifecycle from absent log events.

Producers and required behavior (spec 05): progress-final emits `notifications/progress`, matching final response, signed end; subscriptions/listen sends acknowledged first, only opted-in list_changed, matching final response/end for test; tools/list final followed by `notifications/tools/list_changed` and end; events/stream active first, then event, heartbeat, terminated, no final response; cancel blocks after first notification until client closes and handler observes cancellation. concurrency hold keeps same Alice stream live at limit while independent signed request gets signed v1 429 before any stream bytes. `max-duration` emits an initial `notifications/progress` message with `{progress:1}`, holds until the controlled clock advance, then emits the matching final response and signed end. Oversize sends data value exceeding `frameMaxBytes`, suppresses that MCP message/final response, sends canonical signed `notifications/jack/stream_error` transport signal with configured limit, then end; client stops after signal. No opt-in produces signed v1 501 `streaming_unsupported`. Relay cases are real raw TCP transforms: drop seq 1, reverse 0/1, mutate UTF-8 data without resigning, truncate before end, splice foreign-sid frame, duplicate seq 0. Idle holds connection open with frozen time and no valid frame until timeout.

## Scenario oracle

`stream-scenarios.json` owns exact messages and terminal expectation subsets and operation metadata. IDs and essential expectations:

- `progress-final`: progress then id=1 result; complete, 3 frames, end, `mcp_complete:true`.
- `subscriptions-listen`: request params filter is exactly `notifications:["notifications/events/list_changed"]` (the fake expects this opt-in); acknowledged first with `subscriptionId:2`, opted-in list_changed, final response; complete, 4 frames, true.
- `list-changed`: tools/list response is `{tools:[]}`, then `notifications/tools/list_changed` last; complete/end, `mcp_complete:false`.
- `events-stream`: request `params:{name:"demo",arguments:{}}`, mirror name `demo`, and `heartbeatMs:15000`; messages are active `{state:"active"}`, event `{event:"event"}`, heartbeat `{event:"heartbeat",heartbeatMs:15000}`, terminated `{state:"terminated}`; terminal complete/end, `mcp_complete:false`.
- `cancel`: one progress delivered, cancelled; request log must prove handler cancellation.
- `concurrency-limit`: driver holds first stream, launches independent second client, verifies signed v1 429 `stream_limit_exceeded` without open/frame, releases and verifies first stream completion; audits each request signature against its exact row/body and verifies distinct first/second nonces; the compared oracle terminal is the second refusal.
- `max-duration`: delivers the initial progress notification `{jsonrpc:"2.0",method:"notifications/progress",params:{progress:1}}`, then after controlled advance delivers the matching final response and signed end; complete, true.
- `oversize`: zero delivered messages; one verified signal counted (`frames_verified:1`), error `stream_frame_too_large`, false; no end consumption required.
- `opt-in-required`: signed 501 `streaming_unsupported`, v1 evidence.
- `relay-drop`, `relay-reorder`, `relay-edit-data`, `relay-truncate`, `relay-splice`, `relay-replay`: respectively `stream_out_of_order`, `stream_out_of_order`, `stream_bad_signature`, `stream_truncated`, `stream_bad_signature`, `stream_out_of_order`, preserving only messages verified before the failing observation.
- `idle`: open then silence; `stream_idle`, no messages, false.
- `rotation-cutoff-reopen`: predecessor opens before activation and ends before cutoff; inject signed predecessor-chain frame exactly at activation and require `stream_after_cutoff`; then reopen same logical request as successor. Per `rotation.mjs`, announce `ring-1` with successor fixture Erin, require ordinal/head ordinal 1, `published_at=P`, `activates_at=A`, hash; clock must be set before startup/announcement. Do not claim this lifecycle works without actual successor reopen evidence.
- `durable-live-replay`: first signed request opens and holds after durable commit; replay identical raw method, target, body bytes and Jack-Auth while open, require HTTP 401 JSON body `replayed_nonce`, and prove the log's replay row follows `stream_open` for the same signature/nonce; retain the first stream message and verify its terminal after stopping the held client. The response may omit Jack-Auth; if present, it must verify against the exact status/body/request signature. The current oracle expects unsigned refusal evidence.
- `durable-restart-replay`: capture the same exact raw evidence, prove commit precedes stream open in the log; cleanly stop by stdin EOF and require exit 0; restart with identical durable directory/state and identity; replay exact method/target/body/header and require HTTP 401 JSON body `replayed_nonce`. A response Jack-Auth is optional; if present, verify it against exact status/body/request signature. Confirm the original request and replay rows retain matching signature/nonce/body. `durable.mjs` initializes durable state out-of-band with the normal `--aud AUD --state PATH --server-seed-hex HEX` arguments plus `--durable-dir DIR --durable-init` (exactly one stdout `{"durable_initialized":true}`, exit 0); a configured non-default window may use `--durable-window W`. Reopen must preserve nonce commitment; process crash/fail-closed handling is a distinct durable.mjs test, not this clean-restart scenario. Linux only.

Rotation store is independently initialized/opened by server/client SDK mechanisms, not a fabricated memory map. `rotation.mjs` lifecycle uses fixed published/activation clock values, control-pipe announce with ring reference and successor kid, validates returned chain-head ordinal/hash/times, then polls/refreshes client trust state as applicable before successor use. Stream cutoff must be strictly before activation (`ts < A`); equality is rejected. Server ends old stream before cutoff, never signs old-key frame at/after A. Client must use known activation map to reject equality and reopen using successor key only after verification. A stream never switches signing key midstream.

## Limits, APIs, targets and platform gaps

Server defaults: `frameMaxBytes=1048576` bytes of data value (minimum 1024); `maxConcurrentStreams=4` per authenticated identity; `maxStreamDurationMs=3600000`; heartbeat default 15000ms for `W=30s`, grant MUST be `<= floor(W*500)` and clamp suggestion; client `idleTimeoutMs=90000`, configurable. Keep-alive comments do not reset idle; only verified frames do. Duration expiration sends final response if needed and writable then signed end. Cancellation closes/cancels handler: Go context; Rust request extension / `StreamCancellation` framework mechanism (not a common extension API); TypeScript `AbortSignal` in `JackStreamContext`. A client-side cancel is connection close, not `notifications/cancelled`.

Known public API limits, not promises of APIs: Go client `Transport.OpenStream` and `client/stream`; server `HandlerConfig.Streams`, `StreamFromContext`; public Go has no deterministic SID source. Rust client `SigningTransport.open_stream` / `open_stream_as`; rotation requires caller-owned `VerifiedStream::from_response` resolver/key map. Rust server `StreamLayer`; cancellation/heartbeat are request extensions (`StreamCancellation`, `StreamHeartbeat`), not shared APIs. TypeScript `openSignedStream`, `JackStreamContext`; successor activation/key resolver and SID test hook exist on relevant configured surfaces. Do not invent a uniform API or pretend fixture hook exists in Go.

`interop/targets.json` roles: Go `interop/bin/go-stream-server`, `interop/bin/go-stream-client`; Rust `interop/rust/target/release/interop-server --mode stream-server`, `interop/rust/target/release/interop-client --mode stream-client`; TypeScript `node ts/dist/interop/stream/server.js`, `node ts/dist/interop/stream/client.js`. Go future source paths `interop/go/streamserver` and `interop/go/streamclient`, TS future sources `ts/src/interop/stream/server.ts` and `client.ts` are not present; Rust uses existing interop crate modes. Build commands (plans, not run):

```sh
go build -o interop/bin/go-stream-server ./interop/go/streamserver
go build -o interop/bin/go-stream-client ./interop/go/streamclient
cargo build --manifest-path interop/rust/Cargo.toml --locked --release
npm --prefix ts run build
```

`stream_options` include client idle timeout and are passed to both executable roles by the runner. Rotation remains unsupported and fails after announcement before client launch because successor reopen/key-resolver IPC is unavailable. Durable cases attempt exact raw replay and validate the 401 body, optionally verify a signed response header, and check replay/request log evidence; partial control/evidence compatibility means response/state mismatches remain contract gaps. Self-test runs the stream fake scenarios and Linux fake durable scenarios, and explicitly asserts the rotation contract gap; these are harness checks, not SDK evidence. No scenarios were executed for this documentation update.

<!--
CI NOTE for parent PR only; no workflow edited. Model after webhook-interop; Linux-only lifecycle jobs.

  stream-interop:
    name: signed-stream interop matrix
    runs-on: ubuntu-latest
    needs: [go, rust, ts, fixtures]
    planned: common Go/Rust/cache/Node 22 setup; build Go stream binaries, `cargo build --locked --release` in interop/rust, npm ci/build in ts; run `node interop/stream.mjs --self-test`, then `node interop/stream.mjs`.
  rotation-stream-interop:
    name: signed-stream rotation interop matrix
    runs-on: ubuntu-latest
    needs: [go, rust, ts, fixtures]
    planned: same setup/build; run `node interop/stream.mjs --matrix rotation-stream`.
  durable-stream-interop:
    name: signed-stream durable interop matrix
    runs-on: ubuntu-latest
    needs: [go, rust, ts, fixtures]
    planned: same setup/build; run `node interop/stream.mjs --matrix durable-stream`.

No workflow edits and no test/build execution are asserted. Do not enable lifecycle jobs as passing until orchestration is implemented.
-->
