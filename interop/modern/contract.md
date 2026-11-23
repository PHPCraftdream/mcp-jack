# Modern matrix executable contract

Status: normative for the `modern_server` and `modern_client` executables that `interop/modern.mjs` launches, and for the self-test fakes, dated 2026-11-23. Sources: [`spec/04-modern-profile.md`](../../spec/04-modern-profile.md) for the era, mirror header, refusal and client rules; `interop/README.md` section 14 for the harness; [`interop/modern-scenarios.json`](../modern-scenarios.json) for the exact expected outcomes. The driver treats every statement here as a test oracle, so an executable that disagrees with this document fails the matrix.

## 1. Roles

For every (client language, server language, scenario) triple the driver runs:

1. one server process (`modern_server` target) bound to a loopback port the driver chooses;
2. optionally one tamper proxy inside the driver process, between client and server; the client is then given the proxy's URL instead of the server's;
3. one client process (`modern_client` target) that performs the scenario's request sequence and prints one result line.

Nothing here adds SDK API. The executables configure the SDK with the deployment profile, the fixture identity, the fixed clock and the nonce source; the wrapped handler and the request log are the executables' own code. Ordinary MCP traffic passes through the SDK wrapper unchanged, so the handler only sees authenticated requests.

## 2. Conventions shared by both roles

- **Line discipline.** stdout carries only the lines this document defines, one JSON object per line, newline-terminated. Diagnostics, startup failures and any logging go to stderr. No other stdout output, ever.
- **Exit codes.** `0` the process completed its role (the result line is the verdict; a protocol refusal is never an exit code); `1` the process could not complete (invalid flag, bind failure, unreadable clock/state file, connection failure) with a one-line stderr diagnostic and no result line; `2` reserved for usage errors.
- **Fixed clock.** Both roles read one decimal integer from `--clock-file` every time they need "now", for the request timestamp, the freshness window, response signing and response verification. The wall clock is never consulted for those. The driver always writes `1800000000`, so every timestamp in a run is exactly `1800000000`.
- **Deterministic nonces.** For the 0-based index `i` of each distinct signed request the client sends in a scenario, the nonce is the first 16 bytes of `sha256(utf8("mcp-jack-interop-modern/nonce/" + <scenario id> + "/" + <i>))`, sent as canonical unpadded base64url (22 characters). The index increments once per new request. A replayed request is not a new request: it reuses the source request's exact bytes, signature and nonce. Nonces are never random.
- **Values supplied by the driver.** The audience `https://svc.example.test`; the client seed (fixture `alice`, 64 hex characters); the pinned server public key (fixture `svc`, base64url); the server seed (fixture `svc`); and a state file that is the fixture registry document `{"version":1,"keys":[...],"invites":[]}` (the same strict `FileState` document `interop-server` reads, i.e. `spec/fixtures/registry.json` without the top-level `aud` member). The executables never read `spec/fixtures/` themselves.
- **Response trust.** The client verifies every response against `--anchor` only: no TOFU, no learned key, no trusted body. The spec 01 section 5 unsigned-allowed 401 family is the only response that may lack `Jack-Auth`.
- **Headers.** Header names are case-insensitive, values case-sensitive (RFC 9110). The client must put the mirror headers on the wire as separate header lines, in the order below; no HTTP library may fold or reorder them.

## 3. Server executable (`modern_server`)

### 3.1 Invocation

```text
modern_server --profile <legacy|modern|both> --aud <aud> --state <file>
              --server-seed-hex <64 hex> --clock-file <file> --port <n>
              [--request-log <file>]
              [--supported-versions <v1,v2,...>]
              [--discover-version-mode <supported|refuse-first|refuse-always>]
```

`--profile` is the SDK deployment profile of spec 04 section 3. `--port` binds `127.0.0.1:<n>` (`0` means any free port). `--supported-versions` defaults to `2026-07-28,2025-11-25`. `--discover-version-mode` defaults to `supported`. Every flag is required except the three optional ones.

### 3.2 Ready line

Exactly one newline-terminated JSON object on stdout, then no further stdout output:

```json
{"ready":true,"port":<n>,"server_public_key":"<b64u>","server_kid":"<kid>","profile":"<legacy|modern|both>"}
```

`server_public_key` and `server_kid` are derived from `--server-seed-hex`. The driver compares them with the fixture `svc` identity and fails the pair on a mismatch. A startup error exits 1 with nothing on stdout. SIGTERM, SIGINT or stdin EOF stops the server with exit 0.

### 3.3 Request log

With `--request-log <file>` the server appends, and flushes before writing the response, one newline-terminated JSON object per request the **wrapped handler answered**, in order:

```json
{"method":"<body method>","http_status":<handler status>}
```

Only handler-dispatched requests are logged. A request the wrapper itself refuses (for example `400 -32020`), a GET or HEAD refused with `405`, and a protocol-native `jack.*` call are never logged. A request the handler answers with 405 (the legacy `server/discover`), 200 or 202 is logged. The driver truncates the file before each run, so the log holds exactly one scenario.

### 3.4 Wrapped handler

The handler is fixed by this contract; it is what the matrix tests through. Status codes and body members are pinned; JSON member order and insignificant whitespace are free, because the signature covers whatever bytes the executable sends. `<id>` is the request's JSON-RPC `id` echo, `null` when the request had no id.

**(a) `server/discover`, process profile `modern` or `both`:**

```json
200 {"jsonrpc":"2.0","id":<id>,"result":{"resultType":"complete","supportedVersions":["2026-07-28","2025-11-25"],"capabilities":{},"serverInfo":{"name":"mcp-jack-interop-modern","version":"1.0.0"}}}
```

`supportedVersions` is the configured `--supported-versions` list in the configured order. `capabilities` is an empty object, so no extension (in particular no events extension) is advertised. `resultType` is `"complete"` and `serverInfo` has exactly the two members above.

**(b) `server/discover`, process profile `legacy`:**

```json
405 {"error":{"code":"method_not_allowed","message":"server/discover is not available in the legacy profile"}}
```

This is the spec 01 section 4 envelope: no `jsonrpc`, no `id`, so it is not a modern-era signal and a C9 client falls back to `initialize`.

**(c) `server/discover` refused by `--discover-version-mode` (see 3.5):**

```json
400 {"jsonrpc":"2.0","id":<id>,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":[...],"requested":"<requested version>"}}}
```

**(d) `tools/list`:**

```json
200 {"jsonrpc":"2.0","id":<id>,"result":{"tools":[{"name":"region.echo","inputSchema":{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}},"required":["region"]}}]}}
```

**(e) `tools/call` of `region.echo`:**

```json
200 {"jsonrpc":"2.0","id":<id>,"result":{"content":[{"type":"text","text":"<echo>"}]}}
```

`<echo>` is one line per header instance the handler received, `"<name>: <value>"`, lines joined with a single LF and no trailing newline, in the order the handler received them. A framework that hands the handler an unordered map renders a deterministic order of its own. Names keep whatever casing the framework delivered. The matrix compares names case-insensitively and values exactly, so a header the wrapper stripped (`Mcp-Session-Id` and `Last-Event-ID` in the modern era) can never appear, and repeated instances appear once per instance.

**(f) `initialize`, legacy era:**

```json
200 {"jsonrpc":"2.0","id":<id>,"result":{"protocolVersion":"<negotiated>","capabilities":{},"serverInfo":{"name":"mcp-jack-interop-modern","version":"1.0.0"}}}
```

`<negotiated>` is the requested `params.protocolVersion` when it is in `--supported-versions`, otherwise `2025-11-25`. The response also carries the header `Mcp-Session-Id: sess-1`; the server never mints any other session id.

**(g) `notifications/initialized`:** status `202` with an empty body.

**(h) Any other method, and `tools/call` of any other tool:**

```json
200 {"jsonrpc":"2.0","id":<id>,"error":{"code":-32601,"message":"method not found"}}
```

Protocol-native `jack.*` tools never reach the handler: the SDK answers them before dispatch, with `resultType` and `serverInfo` added in the modern era (spec 04 C7).

The handler is era-neutral apart from (a), (b), (c) and (f): it is constructed with the process profile and the two version switches, and it never inspects the per-request era.

### 3.5 Version control for the retry scenario

`--supported-versions` defines the `supportedVersions` list of (a), the `data.supported` list of (c), and the `initialize` echo rule of (f). `--discover-version-mode` decides when (a) is refused:

| Mode | Behaviour |
|---|---|
| `supported` | (a) when the requested `params._meta["io.modelcontextprotocol/protocolVersion"]` is in the list, otherwise (c) with `requested` set to that value |
| `refuse-first` | the first `server/discover` of the process answers (c) whatever the requested version is; later ones follow `supported` |
| `refuse-always` | every `server/discover` answers (c) with `requested` set to the version asked for |

The mode is per process, so the driver starts a dedicated server for the scenario that needs it.

### 3.6 Free implementation choices

How the executable wires the SDK (Go `server.NewHandler`/`server.NewVerifier`, Rust `JackLayer::with_profile`, the TypeScript `profile` option), how it renders the echo order, and any stderr logging are free. The wrapper's own era handling, mirror validation, refusals and forwarding are the SDK's job and must not be reimplemented in the executable.

## 4. Client executable (`modern_client`)

### 4.1 Invocation

```text
modern_client --url <base-url> --aud <aud> --seed-hex <64 hex> --anchor <b64u>
              --scenario <id> --era <legacy|modern|auto> --clock-file <file>
              [--probe-version <v>] [--json-id <text>]
```

`--url` is the endpoint the driver gives: the server's `http://127.0.0.1:<port>`, or the tamper proxy's address in the scenarios that use one. `--anchor` is the pinned server public key. `--era legacy` sends 0.1.x bytes only (no `_meta`, no mirror headers, no handshake). `--era modern` sends MCP 2026-07-28 requests: `params._meta` with `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities`, plus the mirror headers `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` where the method has a source field, then the projected `Mcp-Param-*`. `--era auto` is C9. `--probe-version` defaults to `2026-07-28` and is the version a C9 probe asks for. `--json-id` defaults to `1` and is the text inserted verbatim as the JSON-RPC `id` member, so the driver can pass `1`, `"abc"` or `null`.

The clock and the nonce source are the SDK's injection points (Go `client.Config.Now`/`Nonce`, the Rust signing transport's clock/nonce sources, the TypeScript transport's clock and nonce source); they must be fed from `--clock-file` and section 2's derivation.

Some pinned requests have no high-level SDK helper — `server/discover`, the GET and HEAD refusals, the replay of stored bytes, and the four id forms. The executable sends those through the SDK's own signing transport (Go `client.NewTransport`, the Rust signing transport, the TypeScript signing fetch) with hand-built bodies and mirrors, so requests are still signed and responses still verified by the SDK; it must not reimplement signing or response verification, and it must not add a request the scenario's row in 4.4 does not list.

### 4.2 Result line

Exactly one JSON object as the final non-empty stdout line; exit 0.

```json
{"scenario":"<id>","outcome":"ok|rejected|client_error","http_status":<int|null>,"code":<string|int|null>,"data":{"era":"modern|legacy","steps":[<step>,...]}}
```

Each `step`:

```json
{"name":"<step name>","http_method":"POST|GET|HEAD","http_target":"/mcp",
 "jsonrpc_method":"<body method>|null","http_status":<int|null>,"id":<parsed JSON-RPC id or null>,
 "request_headers":[["<name>","<value>"],...],"request_body_b64u":"<...>",
 "request_sig":"<b64u signature from the request Jack-Auth>",
 "response_auth":"<exact response Jack-Auth value>|null","response_content_type":"<value>|null",
 "response_allow":"<value>|null","response_session_id":"<value>|null",
 "response_body_b64u":"<exact response body bytes>"}
```

Every member is present, `null` where not applicable, and byte fields are unpadded base64url of the exact bytes. `request_headers` lists the headers the executable itself put on the wire (application, mirror and `Jack-Auth` headers) in send order with the casing it used; framing headers owned by the HTTP library may be omitted. A step exists for every request actually sent, in order, including refused ones, and a replay is a separate step with byte-identical `request_body_b64u` and `request_sig`. `response_body_b64u` is the empty string when no body arrived.

The top-level `http_status` is the last step's status. `outcome` and `code` describe the last response:

- `ok`: the last response was a verified 200 or 202 and the operation completed.
- `rejected`: the last response was a verified non-2xx refusal, or the client itself stopped after a verified answer with one of its own codes (`unsupported_version_no_overlap`); `http_status` is that status.
- `client_error`: the response could not be verified or a local step failed before an answer was trusted; `http_status` is null and `code` is the client code (`missing_auth`, `malformed_auth`, `unsupported_version`, `unknown_key`, `key_inactive`, `timestamp_out_of_window`, `bad_signature`, `unknown_server_key`).

`code` derivation, identical in every language: when the body parses as JSON and has `"jsonrpc":"2.0"` and an `error` object whose `code` is an integer, that integer; otherwise when it has an `error` object whose `code` is a string (the spec 01 section 4 envelope), that string; otherwise `null`. A client-side refusal reports its own code.

`data.era` is the era of the last request sent: `modern` or `legacy`, and for a C9 client the era it settled on (a client that aborted on `-32022` reports `modern`, because the verified `-32022` selected it).

Exit 1 (with no result line) only when the scenario cannot be run at all: unreadable clock file, connection refused, invalid flags. A refused operation is always a result line.

### 4.3 C9 era detection as the matrix pins it

The client sends one probe `server/discover` at `--probe-version` first; the probe never executes the user operation. The decision uses the verified response only:

| Verified answer | Era |
|---|---|
| 2xx | modern |
| `400` carrying a JSON-RPC error `-32020`, `-32021` or `-32022` | modern |
| `404` carrying a JSON-RPC error `-32601` | modern |
| any other `400`, `404` or `405` | legacy: fall back to `initialize` |
| unverified, unsigned, malformed, or a network error | no era: `client_error`, the operation fails |

A recognized JSON-RPC error is an object with `jsonrpc` exactly `"2.0"`, an `id` member present (`null` allowed) and an `error` object with an integer `code` and a string `message`. Jack's own `{"error":{"code":"..."}}` envelope has no `jsonrpc` member and never selects the modern era.

For `-32022`, `error.data.supported` must be an array whose elements are all strings. The client picks the first element that it implements (`2026-07-28`, `2025-11-25`, `2025-06-18`) and that differs from the version just attempted, and retries exactly once: a modern pick (`>= 2026-07-28`) is retried with a new `server/discover` at that version, a legacy pick runs the legacy handshake at that version and then the operation. If there is no such element, or the single retry is answered `-32022` again, the client stops and reports `"outcome":"rejected"`, `"code":"unsupported_version_no_overlap"`. There is never a second retry.

Legacy fallback: `initialize` with `params {"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"mcp-jack-interop-modern-client","version":"1.0.0"}}` and **no** mirror headers, then `notifications/initialized` with empty `params`, carrying the negotiated version in `MCP-Protocol-Version` and the session id from the `initialize` response in `Mcp-Session-Id`, then the legacy operation. The settled era is `legacy`.

### 4.4 Scenario to operation

Each row is the complete request sequence for that `--scenario`, nothing more and nothing less. `<id>` is `--json-id`, nonce indices run from 0.

| Scenario | Requests, in order |
|---|---|
| `modern-discover` | `server/discover` (modern era) |
| `modern-call-projection` | 1. `tools/list`; 2. `tools/call` `region.echo` with `arguments {"region":"us-west1"}` and `Mcp-Param-Region: us-west1` |
| `modern-mismatch-name` | 1. the `tools/call` of `modern-call-projection` step 2 (nonce index 0); 2. those exact request bytes again, unchanged, same signature and nonce |
| `modern-repeated-version` | the same single `tools/call` |
| `modern-get-405` | `GET /mcp`, empty body, `Jack-Auth` signed over the empty body, header `MCP-Protocol-Version: 2026-07-28` |
| `modern-head-405` | `HEAD /mcp`, empty body, `Jack-Auth` signed over the empty body, the same header |
| `modern-session-stripped` | the same single `tools/call` |
| `era-auto-modern` | C9 probe (index 0), then the `tools/call` of `modern-call-projection` (index 1) |
| `era-auto-legacy` | C9 probe, `initialize`, `notifications/initialized`, legacy `tools/call` `region.echo` `{"region":"us-west1"}` |
| `era-retry-version` | C9 with the retry rule of 4.3 |
| `legacy-both-parity` | legacy `tools/call` `region.echo` `{"region":"us-west1"}` |
| `native-era-shape` | `tools/call` `jack.whoami` in the era the driver passes |
| `refusal-id-forms` | four `tools/call` `region.echo` requests with ids `"abc"`, `7`, `null`, `1.5` (verbatim JSON text), each carrying the modern mirrors **minus** `Mcp-Name` |

Step names, in order, are part of the contract because the driver matches steps positionally:

| Scenario | Step names |
|---|---|
| `modern-discover` | `discover` |
| `modern-call-projection` | `list`, `call` |
| `modern-mismatch-name` | `call`, `replay` |
| `modern-repeated-version` | `call` |
| `modern-get-405` | `get` |
| `modern-head-405` | `head` |
| `modern-session-stripped` | `call` |
| `era-auto-modern` | `probe`, `call` |
| `era-auto-legacy` | `probe`, `initialize`, `initialized`, `call` |
| `era-retry-version`, retry run | `probe`, `initialize`, `initialized`, `call` |
| `era-retry-version`, abort run | `probe`, `probe-retry` |
| `legacy-both-parity` | `call` |
| `native-era-shape` | `whoami` |
| `refusal-id-forms` | `id-string`, `id-integer`, `id-null`, `id-fractional` |

## 5. Determinism rules

Two runs of one client language against one endpoint produce byte-identical requests: the clock is fixed, nonces are derived from the scenario and the request index, and the JSON-RPC id comes from `--json-id`. That is what `legacy-both-parity` compares: the driver starts both servers on the same port, so even the `Host` header is equal, and it compares the response body bytes and statuses of the two runs.

Reference bodies (member order inside a body is free; the header order is not):

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"region.echo","arguments":{"region":"us-west1"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"mcp-jack-interop-modern-client","version":"1.0.0"}}}}
```

with the request headers, in this order after `Jack-Auth`: `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method: tools/call`, `Mcp-Name: region.echo`, `Mcp-Param-Region: us-west1`.

- `server/discover`: `{"jsonrpc":"2.0","id":<id>,"method":"server/discover","params":{"_meta":{...protocolVersion, clientCapabilities, clientInfo...}}}`, mirrors `MCP-Protocol-Version: <probe version>` then `Mcp-Method: server/discover`, and no `Mcp-Name` (the method has no source field).
- Legacy `tools/call`: `{"jsonrpc":"2.0","id":<id>,"method":"tools/call","params":{"name":"region.echo","arguments":{"region":"us-west1"}}}`, no `_meta`, no mirror headers, plus `MCP-Protocol-Version` and `Mcp-Session-Id` only after a handshake.
- `jack.whoami`: the same shape with `params.name` `"jack.whoami"` and `arguments {}`; in the modern era it carries `_meta`, `Mcp-Method: tools/call` and `Mcp-Name: jack.whoami`.

## 6. Scenario table and expected outcomes

The expected outcomes live in `interop/modern-scenarios.json`; this table is the human summary. Every verification of a server response is done with the independently pinned fixture `svc` key.

| # | Scenario | Server | Client | Expected |
|---|---|---|---|---|
| 1 | `modern-discover` | `both` | modern | `ok`, 200; result `resultType: "complete"`, `supportedVersions: ["2026-07-28","2025-11-25"]`, `capabilities: {}` without `extensions`, the pinned `serverInfo` |
| 2 | `modern-call-projection` | `both` | modern | `ok`, 200; `tools/list` returns `region.echo` with `x-mcp-header: "Region"`; the echo shows `Mcp-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, `Mcp-Param-Region` once each and no session headers |
| 3 | `modern-mismatch-name` | `both`, proxy rewrites `Mcp-Name` after signing | modern | step 1 signed `400` `-32020` `name_header_mismatch` with the handler never called; the replay of the identical bytes `401` `replayed_nonce` (unsigned); the nonce was consumed |
| 4 | `modern-repeated-version` | `both`, proxy duplicates `MCP-Protocol-Version` | modern | signed `400` `-32020`, message "Header mismatch: a request metadata header appears more than once", handler never called |
| 5 | `modern-get-405` | `both` | modern | signed `405`, JSON-RPC `-32600` "HTTP method not allowed", `Allow: POST`, handler never called |
| 6 | `modern-head-405` | `both` | modern | signed `405` with `Allow: POST` and `Content-Type: application/json`, **no body**: the signature covers the empty bytes the client receives |
| 7 | `modern-session-stripped` | `both`, proxy adds `Mcp-Session-Id` and `Last-Event-ID` | modern | `ok`, 200; the echo shows neither header, the mirrors are still there |
| 8 | `era-auto-modern` | `both` | auto | `ok`, 200, era modern; the request log is exactly `server/discover`, `tools/call` |
| 9 | `era-auto-legacy` | `legacy` | auto | probe answered `405` (legacy signal), then `initialize` without `MCP-Protocol-Version`, at `2025-11-25`, then `notifications/initialized` with `MCP-Protocol-Version: 2025-11-25` and `Mcp-Session-Id: sess-1`, then the legacy call; `ok`, 200, era legacy; the log pins the four methods in order |
| 10 | `era-retry-version` | run 1 `both` with `--supported-versions 2025-11-25 --discover-version-mode refuse-first`; run 2 `both` with `--supported-versions 2026-07-28 --discover-version-mode refuse-always` | auto, probe `2026-08-01` in run 2 | run 1: `-32022` with `data.supported ["2025-11-25"]`, retry once with the older version, `initialize`, `initialized`, call; `ok`. Run 2: `-32022` twice, no second retry; `rejected` 400 `unsupported_version_no_overlap` |
| 11 | `legacy-both-parity` | `legacy` and `both`, same port | legacy | `ok`, 200 in both runs; response bodies and statuses byte-identical |
| 12 | `native-era-shape` | `both` and `legacy` | modern, then legacy | modern: `resultType: "complete"` and `result._meta["io.modelcontextprotocol/serverInfo"]`; legacy: neither, byte-identical to 0.1.x. Native calls are never in the request log |
| 13 | `refusal-id-forms` | `both` | modern | four signed `400` `-32020` `name_header_missing` refusals whose `id` echoes `"abc"`, `7`, `null`, `null` |

## 7. What the driver checks

For every run the driver:

1. verifies every response itself with the pinned fixture key: the signing string `mcp-jack/v1/response`, the status, the request signature the client reports, the `kid`, the timestamp and the SHA-256 of the exact body bytes; the `kid` must be the fixture `svc` kid. Only the unsigned-allowed 401 family may lack a signature, and a signature that is present is verified even there.
2. re-parses the response bytes of every step, so a client's own claims cannot mask a wrong body; `expected.steps` is matched positionally as a recursive subset over the client's step plus the driver-derived `signed`, `result`, `error` and `id`.
3. compares the top-level `outcome`, `http_status`, `code` and `era`, and cross-checks the client's `http_status` and `code` against its own parse of the last response. The single exception is the client-side code `unsupported_version_no_overlap`, which reports a client decision rather than a wire code; the driver accepts it exactly where its own parse of the last response yields `-32022`.
4. evaluates `header_echo` (`contains`, `absent`, `counts`) over the last step's echo text, `request_headers` per step name, `absent_paths` over the last step's result, and `server_request_log` against the server's log file.
5. evaluates the scenario invariants: `identical_request_bytes` (every step's request body and signature equal) and `identical_response_body_across_runs` (the two runs' last response bodies and statuses equal).
6. fails the pair on any harness-level problem: a missing ready line, an identity mismatch, a nonzero client exit, a missing or malformed result line, an unexpected step name or count.

## 8. Self-test fakes

`interop/tools/fakes/modern/` holds an independent implementation of this contract that uses no SDK: `jack-sign.mjs` (Ed25519 signing and response verification over `node:crypto`), `fake-modern-server.mjs` and `fake-modern-client.mjs`. They follow sections 3 to 5 exactly and are never SDK evidence. `node interop/modern.mjs --self-test` runs the matrix against them, checks the tamper proxy with its own controls, and proves that the tamper scenarios fail when the proxy is disabled.