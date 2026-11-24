# Signed-stream executable contract

Normative wire rules are [`../../spec/05-signed-streams.md`](../../spec/05-signed-streams.md); authentication/refusals are [`../../spec/01-authentication.md`](../../spec/01-authentication.md); modern metadata/mirrors are [`../../spec/04-modern-profile.md`](../../spec/04-modern-profile.md) S4/S5/S6 and `spec/tests/modern/CASES.md`. [`../stream-scenarios.json`](../stream-scenarios.json) is the source of the active and deferred oracles. This is the executable contract and current status, not passing SDK evidence. Active `matrices.stream` has exactly nine cases. Deferred entries are not listed, counted, or run by default. Concurrency and durable raw replay remain deferred; rotation lacks successor reopen/key-resolver IPC. Do not overstate implementation. No scenario execution is asserted here.

## Driver commands and process protocol

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

Omitted matrix means `stream`; omitted language selections mean all languages in targets. `--scenario` selects comma-separated IDs. `--list` prints active IDs for the selected matrix and exits 0; deferred rows are never included. `--list` with `--self-test` is a usage error. The two lifecycle matrix names `rotation-stream` and `durable-stream` print `deferred` and exit 2 without running rows. Exit 0 means selected cases passed, 1 scenario/cell failure, 2 invocation/target/input/harness error. The driver prints pair headings, PASS/FAIL, counts and `INTEROP-SUMMARY`; diagnostics are stderr. CI comments should refer only to stream self-test and default stream runner, not lifecycle jobs.

For each selected client/server/scenario, the driver creates temporary fixture state, fixed clock and request log; starts the server on loopback, verifies its ready identity against pinned fixture `svc`, and starts the client. Relay cases interpose the relay and provide its actual port. Only owned children are terminated. `stream_options` become matching `--<hyphenated-option>` flags when applicable; `idleTimeoutMs` maps to `--idle-timeout-ms`. Both roles receive `--profile modern`.

### Server argv and stdout

The selected server target argv is followed by:

```text
--profile modern --matrix NAME --scenario ID --aud AUD --state PATH --server-seed-hex HEX --clock-file PATH --request-log PATH --port 0
[--frame-max-bytes N] [--max-concurrent-streams N] [--max-stream-duration-ms N] [--heartbeat-ms N] [--idle-timeout-ms N]
[--ring-seed ring-1=HEX --successor-activation UNIX_SECONDS --rotation-store PATH]
[--durable-dir PATH]
```

`AUD` is `https://svc.example.test` from `spec/fixtures/registry.json`; state is version 1 `{version:1,keys:registry.keys,invites:[]}` and server seed is fixture `svc`. Server binds `127.0.0.1`; port 0 chooses an available port. Its first nonblank stdout JSONL line is `{"ready":true,"port":N,"server_public_key":"B64U","server_kid":"kid"}` and public key/kid must equal fixture `svc`. Stderr is diagnostic. Request-log output is append-only JSONL with one event object per line, flushed at lifecycle evidence boundaries.

Server stdin control JSONL when used: rotation announcement input `{ "op":"announce", "reference":"ring-1", "kid":"<successor kid>" }` and reply `{announced:true,ordinal:1,head_ordinal:1,published_at:P,activates_at:A,head_hash:<string>}`; controlled duration input `{action:"clock_advanced",clock:T,start:P,duration_ms:D}` and acknowledgement `{control:"clock_advanced",clock:T}`; held stream release input `{action:"release"}` and acknowledgement `{control:"released",sid:<held stream sid>}`. EOF cleanly stops server (exit 0); signals are cleanup, not lifecycle evidence. Rotation/durable operations remain deferred as specified above.

### Client argv and stdout

Base client invocation:

```text
--profile modern --matrix NAME --scenario ID --url URL --aud AUD --clock-file PATH --server-public-key B64U --seed-hex HEX --request-log PATH --nonce B64U --sid B64U --request-body-json JSON --jack-accept s1 --modern-version 2026-07-28 --mirror-headers-json JSON
[--action cancel|hold|once] [--frame-max-bytes N] [--max-concurrent-streams N] [--max-stream-duration-ms N] [--heartbeat-ms N] [--idle-timeout-ms N]
[--successor-activation UNIX_SECONDS --rotation-store PATH] [--durable-dir PATH]
```

`--url` is a bare origin (`http://127.0.0.1:PORT`); the signed and sent request target is always `/mcp`. For `opt-in-required`, empty `--jack-accept` omits streaming opt-in; otherwise it is `s1`. Alice fixture signs; `svc` is the pinned verifier key. `--mirror-headers-json` is an ordered array of name/value pairs. One JSON object per newline-terminated stdout line; no chatter on stdout. Each delivered MCP message is recorded before exactly one terminal record. `hold` retains a stream after first message; `cancel` closes after first notification; `once` denotes independent refusal request.

Message record fields are `type:"message"`, `scenario`, `stream_index`, `request_method`, `request_target`, `request_body_b64u`, ordered `request_headers`, `request_sig`, `request_ts`, `nonce`, signed `open`, verified `frames`, exact signed UTF-8 `data`, and parsed `message`. Example:

```json
{"type":"message","scenario":"progress-final","stream_index":0,"request_method":"POST","request_target":"/mcp","request_body_b64u":"<canonical-base64url-raw-body>","request_headers":[["Jack-Auth","v1 kid=<alice-kid>,ts=1800000000,nonce=<nonce>,sig=<request-signature>"],["Content-Length","<byte-length>"]],"request_sig":"<request-signature>","request_ts":1800000000,"nonce":"<nonce>","open":{"sid":"<sid>","kid":"<svc-kid>","ts":1800000000,"sig":"<open-signature>"},"frames":[{"kind":"message","sid":"<sid>","kid":"<svc-kid>","seq":0,"ts":1800000000,"data":"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}","sig":"<frame-signature>"}],"data":"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}","message":{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}}
```

Exactly one terminal record follows delivered messages. Terminal records carry the applicable schema fields; inapplicable values are null or omitted, and `frames` is an array when present. Stream terminal records with `outcome:"complete"` or `outcome:"error"` require a non-null signed `open`, a 64-byte `request_sig`, and a `frames` array (including an empty array when no frames were verified). Example complete terminal:

```json
{"type":"terminal","scenario":"progress-final","outcome":"complete","code":null,"http_status":null,"http_code":null,"frames_verified":3,"request_id":1,"mcp_complete":true,"terminal_frame":{"kind":"end","sig":"<end-signature>"},"request_sig":"<request-signature>","v1_evidence":null,"open":{"sid":"<sid>","kid":"<svc-kid>","ts":1800000000,"sig":"<open-signature>"},"frames":[{"kind":"message","sid":"<sid>","kid":"<svc-kid>","seq":0,"ts":1800000000,"data":"<signed-message-data>","sig":"<frame-signature>"},{"kind":"end","sid":"<sid>","kid":"<svc-kid>","seq":1,"ts":1800000000,"data":"","sig":"<end-signature>"}],"failure_frame":null,"successor_activation":null}
```

Stream error uses the same fields, `outcome:"error"`, non-null code, open and request signature, and every verified frame. Example relay truncation has `code:"stream_truncated"`, `frames_verified:2` if two messages verified, `mcp_complete:false`, null terminal frame and no end in frames. A separately evidenced failure frame follows the corresponding protocol definition.

Refusal is a separate model: `outcome:"refused"`; `mcp_complete:false`; `request_sig` is required and must be a 64-byte signature. It is not a stream: `open` is null or omitted, `frames` is empty or omitted, and `terminal_frame`, `failure_frame`, and `successor_activation` are null or omitted. A signed refusal requires non-null `v1_evidence`, independently verified against the request signature and pinned server key; the signature binds HTTP status and exact raw response body, whose JSON `error.code` (the 01 section 4 body shape `{"error":{"code":...,"message":...}}`, not a JSON-RPC envelope; the SDK body is used unchanged) must equal any terminal `code`/`http_code`. Signed refusal example has HTTP 501 `streaming_unsupported` with status/kid/time/signature/exact raw body in v1 evidence. The only permitted unsigned refusal is HTTP 401 `replayed_nonce`, with `v1_evidence:null`; `http_status` and `code` or `http_code` identify that exact status/code, and when `http_body_b64u` is present it must contain the exact raw JSON response body identifying `replayed_nonce`. Exact request evidence remains on its message record. Refusals return no stream evidence messages. `complete` and `error` require non-null open/request_sig and frame arrays. No undocumented keys are defined. Driver compares `{messages:[parsed delivered message objects],terminal:<terminal>}` as recursive expected subsets, with arrays exact length/order.

## Modern requests and cryptographic evidence

Each POST body is `{jsonrpc:"2.0",id:request_id,method:request_method,params:{...request_params,_meta:{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"mcp-jack-interop-stream-client","version":"1.0.0"}}}}`; `_meta` is inside params. Mirrors include protocol version and `Mcp-Method`; `Mcp-Name` only applies where S6 has a `params.name`/`params.uri` source and is byte-equal. `subscriptions/listen` has no `Mcp-Name` and carries `params.notifications:["notifications/events/list_changed"]` to opt in. No active row defines annotated arguments. S4 requires equal well-formed version mirror and `_meta`; S5 requires method mirror; S6 forbids an unsourced name mirror. Mirrors are unsigned; exact body is signed.

Request signature input is eight LF-separated UTF-8 fields, no trailing LF: `mcp-jack/v1/request`, method, exact origin-form target, audience, Alice kid, decimal Unix seconds, canonical unpadded base64url 16-byte nonce, canonical base64url SHA-256 of exact body bytes. Jack-Auth contains the actual signature. V1 response input is `mcp-jack/v1/response\n<status>\n<request-sig>\n<server-kid>\n<ts>\n<base64url(SHA-256(exact raw body bytes))>`; signed refusal evidence binds status, bytes and signature. Stream open input: `mcp-jack/stream1/open\n200\n<request-sig>\n<kid>\n<ts>\n<sid>`. Frame input: `mcp-jack/stream1/frame\n<sid>\n<seq>\n<ts>\n<prev>\n<base64url(SHA-256(UTF8(data)))>`. Sequence begins at 0 and prev is open signature then previous frame signature. End has empty data and is verified. `mcp_complete:true` only if verified end follows matching JSON-RPC final response (same id, jsonrpc 2.0, exactly result or error, no method). Notification-last does not complete MCP.

Driver clock defaults to 1800000000. Duration control advances by ceil(durationMs/1000); idle (deferred) holds fixed clock. Scenario nonce/sid are fixed 16-byte base64url test inputs. A hypothetical second independent concurrency request derives its nonce/sid from first 16 SHA-256 bytes of UTF-8 `<value>\nsecond`; this is not in the active matrix. Production sid remains unique CSPRNG 16 bytes.

## Request log and producer obligations

Authenticated log events expose at least `request_verified:true`, `request_sig`, method, exact body, params including `_meta`, nonce, protocol-version and method mirror, `mirror_name` null/absent as appropriate, and projected mirror fields. Cancellation evidence uses `handler_cancelled`/`request_cancelled`; duration evidence orders `clock_changed` then `duration_elapsed` or equivalent observed change; heartbeat evidence identifies grant. These are evidence requirements for relevant behavior, not claims about inactive/deferred scenarios.

Active producer behavior: `progress-final` emits progress, matching response and signed end. Active `list-changed` is producer `subscriptions-listen`: acknowledges first, emits only opted-in events/list_changed, then matching response and end. `events-stream` emits active, event, heartbeat, terminated, end; no final response. `cancel` blocks after first notification until client close and handler cancellation evidence. `max-duration` is an `events/stream` request (name `demo`, id 7): the handler writes one progress notification and then holds; the driver writes the advanced clock file and sends the `clock_advanced` control line; the SERVER SDK duration timer (spec 05 3.4 and 6.3) then writes the final `events/stream` response `{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":7}}}` and the signed end (the application must not write that final itself). The SDK timer may fire before the control line is read, so the executable logs `clock_changed` when it reads the control line and logs `duration_elapsed` only after it has logged `clock_changed` AND observed the handler cancellation, in that order. `opt-in-required` without `s1` gives signed v1 501 `streaming_unsupported`. Active relay cases: `relay-drop` drops seq 1; `relay-edit-data` changes a UTF-8 data byte without resigning; `relay-truncate` removes signed end. Deferred producer behaviors are recorded only in deferred scenario rows and are not default contract runs.

## Active and deferred oracle

Exactly these nine IDs are in default active matrix, in order: `progress-final`, `list-changed`, `events-stream`, `cancel`, `opt-in-required`, `max-duration`, `relay-drop`, `relay-edit-data`, `relay-truncate`. `list-changed` has id `list-changed`, request method `subscriptions/listen`, producer `subscriptions-listen`, request id 3, opt-in notification filter, unique nonce/sid, acknowledged/list_changed/final messages, and complete end. The old tools/list notification-last scenario is deferred under a distinct ID.

The deferred IDs are `concurrency-limit`, `oversize`, `relay-reorder`, `relay-splice`, `relay-replay`, `idle`, `list-changed-tools-list`, `rotation-cutoff-reopen`, `durable-live-replay`, `durable-restart-replay`. All have explicit deferred status and reason in `stream-scenarios.json`; none appears in active `matrices.stream`. Rotation is unavailable without successor reopen/key resolver. Partial durable raw replay does not establish durable lifecycle success. Concurrency orchestration is deferred and not implemented as an active case. Self-test and default-runner claims must not imply deferred cases run; fakes are not SDK evidence.

## Limits, API boundaries and targets

Defaults: frameMaxBytes 1048576 data-value bytes (minimum 1024), maxConcurrentStreams 4 per identity, maxStreamDurationMs 3600000, heartbeat default 15000ms for verification window W=30 seconds and grant <= floor(W*500), idleTimeoutMs 90000. These options are not all active scenarios. Cancellation uses Go context, Rust request extension/framework mechanism, TS AbortSignal in `JackStreamContext`; no common extension API is implied. APIs are language-specific: Go `Transport.OpenStream`/`client/stream`, `HandlerConfig.Streams`/`StreamFromContext`; Rust `SigningTransport.open_stream`/`open_stream_as`, `StreamLayer`; TS `openSignedStream`, `JackStreamContext`. Do not imply Go deterministic SID hook exists.

Targets: Go `interop/bin/go-stream-server` and `interop/bin/go-stream-client`; Rust `interop/rust/target/release/interop-server --mode stream-server` and `interop-client --mode stream-client`; TypeScript `node ts/dist/interop/stream/server.js` and `node ts/dist/interop/stream/client.js`. These are output paths, not claims binaries exist. Future Go source paths `interop/go/streamserver`, `interop/go/streamclient` and TS sources `ts/src/interop/stream/server.ts`, `client.ts` are absent; Rust uses the interop crate modes. Build plans (not executed):

```sh
go build -o interop/bin/go-stream-server ./interop/go/streamserver
go build -o interop/bin/go-stream-client ./interop/go/streamclient
cargo build --manifest-path interop/rust/Cargo.toml --locked --release
npm --prefix ts run build
```

<!-- CI NOTE for parent PR only; no workflow edited. Use stream self-test and default stream runner only: `node interop/stream.mjs --self-test`, then `node interop/stream.mjs`. Do not schedule deferred lifecycle matrix jobs. No tests/builds were run for this documentation update. -->
