# Design: cross-language interoperability tests

Status: implemented; kept as the design record, with the decisions as built pinned in [../../interop/README.md](../../interop/README.md). Scope: Go, Rust and TypeScript, client and server.

## 1. Goal and acceptance

Every client SDK works against every server SDK. With three languages that is a 3 x 3 matrix of (client, server) pairs, including the same-language diagonal.

Acceptance:

1. A harness runs every scenario of section 4 for every pair and fails on the first deviation from the expected outcome.
2. A byte-exactness check proves that the three SDKs produce identical signed bytes for identical inputs (section 5), so a future fourth implementation can be checked without running a pair.
3. CI runs the matrix on Linux; each failing pair is named in the output.

Non-goals: performance, long-running soak tests, interop with third-party MCP clients, streaming (refused with 501 in v0.1).

## 2. What is needed first

Design-time note: when this was written only a Go client existed; the Rust and TypeScript client SDKs have since been built (see `rust/README.md` and `ts/README.md`). The matrix needed a Rust client SDK and a TypeScript client SDK, both mirroring `client/` (signer, request signing, response verification, typed native-tool calls, connection profile). Client SDK scope is the Go client's: no stdio bridge, no gateway.

## 3. Contract between the harness and the SDKs

Each language ships two small executables, built from its SDK and living outside the library API:

- `interop-server`: a server built from the SDK `NewHandler`/`JackLayer`/`jackFetchHandler` in front of a fixed, trivial MCP handler (below).
- `interop-client`: a client built from the SDK that runs one named scenario and prints a result.

The harness (`interop/run.mjs`, Node, no dependencies) builds nothing itself: CI builds the six executables first, then the harness spawns them from paths given on the command line or in `interop/targets.json` (relative paths, no machine paths).

### 3.1 interop-server

```
interop-server --aud <aud> --policy <file> --state <file> --server-seed-hex <64 hex> [--bootstrap-ttl <seconds>] [--verify-only]
```

- Listens on `127.0.0.1:0` (plain HTTP; TLS is the environment's job) and prints exactly one line to stdout when ready: `{"ready":true,"port":<n>,"server_public_key":"<b64u>","server_kid":"<kid>"}`. Nothing else on stdout.
- The state file is a copy of `spec/fixtures/registry.json` in the SDK's `FileState` format, written by the harness into a fresh temp directory per run (no shared state between runs). The on-disk format is pinned: `{"version":1,"keys":[...],"invites":[]}` — registry entries as in `registry.json` but without any `aud` field (the aud travels via `--aud`); the server loads it strictly like `server/statefile.go` (unknown fields, duplicate kid/name, invalid entries rejected at load). The harness composes the policy file as `spec/fixtures/policy.json` plus one inserted allow-any rule for the tool `echo` (without it the echo scenario is denied by the fixture policy). The server uses the spec default time window (30 s).
- `--verify-only` (no listening): reads exactly one JSON object from stdin `{"method":"POST","target":"/mcp","jack_auth":"v1 kid=...,ts=...,nonce=...,sig=...","body_b64u":"..."}`, checks request-auth steps 1-4 and 7 of spec 01 section 4 (grammar, version, kid lookup, strict Ed25519 signature over exact body bytes) and skips steps 5/6/8 (validity, time window, nonce) because the sign cases use fixed `ts` values 0 and 999999999999. Prints one stdout line `{"verify":"accept","kid":"<kid>"}` or `{"verify":"reject","code":"<code>"}` and exits 0 either way. Exit codes: 0 on SIGTERM/stdin close, nonzero on startup failure (bad flags, unreadable state/policy).
- When `--bootstrap-ttl` is given, the server creates an admin invite through the SDK's `BootstrapAdmin` and prints it on stderr as `{"bootstrap_invite":"<code>"}`; the harness does not use the bootstrap invite; scenarios mint invites through the protocol (an admin signs `jack.admin.invite.create`).
- The wrapped MCP handler is the same in every language and fixed by this document; every answer is a full JSON-RPC envelope. `POST` with a JSON-RPC body answers by method: `ping` -> `{"jsonrpc":"2.0","id":<id>,"result":{}}`; `tools/list` -> `{"jsonrpc":"2.0","id":<id>,"result":{"tools":[{"name":"echo"}]}}`; `tools/call` of `echo` -> `{"jsonrpc":"2.0","id":<id>,"result":{"content":[{"type":"text","text":<arguments.text verbatim>}]}}`; `tools/call` of `logs.tail` and `config.set` -> `{"jsonrpc":"2.0","id":<id>,"result":{"content":[{"type":"text","text":"ok"}]}}` (policy decides who may call them); anything else -> JSON-RPC error `-32601`. A `GET /sse` is finite: the wrapped handler answers `Content-Type: text/event-stream`, writes exactly one SSE event (`data: hello` plus a blank line) and closes within 1 second; the wrapper refuses the event-stream answer and responds instead with the signed `501 {"error":{"code":"streaming_unsupported",...}}`.
- Exits on SIGTERM/stdin close; the harness kills only the PID it spawned.

### 3.2 interop-client

```
interop-client --url <base> --seed-hex <64 hex> --server-public-key <b64u> --aud <aud> --scenario <name> [--seeds <file>] [--ts <n>] [--nonce <b64u>] [--arg k=v ...]
```

Prints one JSON object to stdout and exits 0 on a completed scenario, whether the scenario's outcome is success or an expected protocol rejection; exit 1 only for a harness-level failure (cannot connect, crash). The object is `{"scenario":"<name>","outcome":"ok"|"rejected"|"client_error","http_status":<n|null>,"code":"<code|null>","data":<json|null>}`. Outcome semantics: `ok` = accepted with a verified response signature (`data` = the JSON-RPC `result` member verbatim); `rejected` = server rejection (`http_status`/`code` from the wire, `data` null; the client verifies the response signature of every response except answers to requests that failed authentication — only the 401 family with the spec 01 section 4 codes may be unsigned, every 2xx and 400/403/404/409/501 must carry a valid signature, and a missing or invalid signature there is `client_error`, with an absent header being `missing_auth` per spec 01 section 5); `client_error` = client-side response-verification failure per spec 01 section 5 (`http_status` null, `data` null). `--seeds` is always passed by the harness (the path of `spec/fixtures/keys.json` itself, opened read-only; nothing is copied) so multi-step scenarios can sign individual steps with non-primary identities; `--seed-hex` is the primary identity. `--ts`/`--nonce` are sign-only only; `sign-only` never touches the network and its output `data` is `{"signing_string":...,"jack_auth":...,"kid":...}`. In a multi-step scenario a failing intermediate step yields `client_error` with that step's status/code and `data` `{"step":<0-based index>}`, still exit 0; the final step's result is compared.

## 4. Scenarios (the same list for every pair)

Expected outcomes live in `interop/scenarios.json`, which is normative; each scenario cites its source (request/admin vectors, spec sections, fixtures). Full list, in `scenario_order`: 

| Scenario | What it proves | Expected |
|---|---|---|
| `ping` | signed request and signed response round trip, unmodified MCP passes through | ok |
| `echo` | body bytes with non-ASCII text hash identically | ok, text equals input |
| `whoami` | native tool, `structuredContent` shape | ok, kid and scopes as registered |
| `denied-tool` | a `read` key calls `svc.config.set` | rejected, 403 `insufficient_scope` |
| `unmapped-tool` | a tool matching no policy rule | rejected, 403 `operation_denied` |
| `unknown-key` | a key not in the registry | rejected, 401 `unknown_key` |
| `replay` | the client re-sends the exact bytes of an accepted request | second answer rejected, 401 `replayed_nonce` (needs a client `--replay` mode that re-sends raw bytes) |
| `clock-skew` | the client signs with `ts` 120 s in the past | rejected, 401 `timestamp_out_of_window` |
| `tampered-body` | the client changes one body byte after signing | rejected, 401 `bad_signature` |
| `bad-server-key` | the client pins a wrong server key | `client_error`, response not trusted |
| `expired-key` | registry entry with `not_after` in the past | rejected, 401 `key_inactive` |
| `key-not-yet-valid` | `not_before` shifted to now + 3600 s via `registry_overrides` (dedicated server) | rejected, 401 `key_inactive` |
| `stream` | `GET /sse` | rejected, 501 `streaming_unsupported` |
| `agent-admin` | an agent key calls an admin native tool | rejected, 403 `insufficient_scope` |
| `invalid-request` | valid signature, unparseable body | rejected, 400 `invalid_request` |
| `unknown-native-tool` | an undefined `jack.`-prefixed tool | rejected, 403 `operation_denied` |
| `enroll` (fresh) | invite -> new key enrolls -> whoami with the new key | ok |
| `enroll-used-invite` (fresh) | re-using a consumed invite | rejected, 403 `invalid_invite` |
| `rotate` (fresh) | key rotation with proof, old key dead, new key works | ok |
| `admin-create` (fresh) | admin creates a user and an invite, the new user enrolls | ok |
| `revoke-key` (fresh) | admin revokes a key, the key is dead | rejected, 401 `unknown_key` |
| `last-admin` (fresh) | demoting the last admin | rejected, 409 `last_admin` (code exactly as in spec 03) |

A scenario is fresh (runs against a pristine server) exactly when its steps expect a state change: `enroll`, `enroll-used-invite`, `rotate`, `admin-create`, `revoke-key`, `last-admin`. A scenario with `registry_overrides` (currently `key-not-yet-valid`) also runs against a dedicated pristine server, so the overrides are baked into that server's state file. Scenarios that need an admin start from the registry admin key of the fixtures.

## 5. Byte-exactness check

`interop-client --scenario sign-only` with fixed `--ts`, `--nonce`, method, target, body and seed prints the request `Jack-Auth` header and the signing string as the JSON `data` triple `{signing_string, jack_auth, kid}`. Ed25519 is deterministic, so all three SDKs must print identical bytes. The harness compares every output against the oracle in `interop/sign-cases.json` (8 cases: empty body, ASCII body, multibyte body, body with NUL and newline, percent-encoded query target, long target, `ts` 0 and `ts` 999999999999; generated by `interop/tools/gen-sign-cases.mjs`, which has a `--check` mode). The harness also cross-verifies every (signing, verifying) language pair through `interop-server`'s `--verify-only` flag (prints accept/reject for a header+body without serving), including one tampered-body control per pair (the final body byte XOR 0x01 must reject with `bad_signature`). This catches drift that the fixtures cannot: fixtures pin outcomes, this pins bytes.

## 6. Layout

```
interop/
  README.md          how to run, how to add a language
  scenarios.json     expected outcomes (normative)
  sign-cases.json    byte-exactness inputs (generated by tools/gen-sign-cases.mjs)
  run.mjs            matrix harness (also --self-test)
  tools/             gen-sign-cases.mjs, fake-server.mjs, fake-client.mjs (self-test fakes)
  go/        cmd mains (package main under the Go module)
  rust/      bin target(s) in the crate or a tiny sibling crate path-depending on it
  ts/        two scripts compiled with the package
```

Go: `interop/go/server/main.go`, `interop/go/client/main.go` inside the existing module (imports the SDK packages). Rust: `rust/src/bin/` behind a cargo feature `interop` so `cargo build` for library users is unaffected. TypeScript: `ts/src/interop/{server,client}.ts`, compiled by the package build, run with `node`.

## 7. CI

One job `interop` on ubuntu, as built in `.github/workflows/ci.yml`: build the Go executables, `cargo build --locked --release --features interop` (`interop` enables `http`), `npm ci --no-audit --no-fund` + `npm run build` for the TypeScript package, then `node interop/run.mjs`. Before building the SDKs, CI (and any implementer) can run the harness's dependency-free self-test: `node interop/run.mjs --self-test`. The job declares `needs: [go, rust, ts, fixtures]`, so a unit-test or fixture failure is reported first.

## 8. Risks and decisions

- Adding Rust and TypeScript client SDKs enlarges scope; they are necessary, a pair matrix without them reduces to Go-client x three servers.
- HTTP client for the Rust `interop-client`: `ureq` as an optional dependency of the `interop` feature only (blocking, small, no async runtime), not in the library's default dependencies. TypeScript uses the built-in `fetch`; Go uses `net/http`.
- Scenario `replay` and `tampered-body` need raw-byte control in the client; the SDK clients expose a low-level `sign_request` for this, and the interop client uses it directly instead of its high-level transport.
- Determinism: nonces and timestamps are injected in `sign-only`; in live scenarios real clocks and random nonces are used, and all processes run on the same machine clock.
- Ports and temp directories are per run; nothing is shared between scenarios, so the matrix can later run in parallel.

## 9. Client URL policy

Spec 01 section 1 requires HTTPS for every non-loopback connection. The Go, Rust and TypeScript client SDKs enforce one conservative, literal-only policy on the destination URL, pinned by `spec/fixtures/client-url-policy.json` (a table of `{name, url, allow}` cases, with an optional `parse_reject` field, that all three SDK test suites run). The table is the normative test oracle for the SDK URL policy, but it is hand-maintained: it is not a generated protocol vector, is not produced by `spec/tools/gen-fixtures.mjs` and is not covered by its `--check`. This section is its prose.

The policy is a pure function of the raw URL string. It is applied before any URL-library parsing or normalisation and only accepts or refuses: it never rewrites the URL.

1. Refuse if the string is empty, contains any byte `<= 0x20`, `0x7f` or `>= 0x80`, or contains a backslash anywhere.
2. The scheme must be `http` or `https` (ASCII case-insensitive), followed by `://`.
3. The authority is the text after `://` up to the first `/`, `?` or `#` (or the end). Refuse if it is empty, contains `@` (no userinfo, for any scheme) or contains `%` (no percent escapes in the authority; this also refuses zone IDs such as `[fe80::1%25eth0]`). Percent-encoded path or query bytes (e.g. `/a%20b?x=%2F`) are not affected.
4. Host and port. With a leading `[`: exactly one `]`, directly after a non-empty IPv6 literal made only of `[0-9A-Fa-f:.]`, followed by the end or `:` plus a port; no other `[` or `]`. Without a leading `[`: no `[` or `]`, at most one `:` (more means unbracketed IPv6), and a non-empty host made only of `[A-Za-z0-9._-]`. A port, if a `:` is present, is 1 to 5 ASCII digits with value 1..65535 (`host:`, `0` and `65536` are refused; leading zeros within 5 digits are fine).
5. `https` is accepted for any host passing 1-4, remote or loopback. The host is used literally; the policy performs no DNS.
6. `http` is accepted only for a literal loopback host: canonical dotted-decimal IPv4 (exactly four decimal octets 0..255, no leading zeros, first octet exactly 127), or bracketed IPv6 whose content is exactly `::1` (hex case irrelevant, no other spelling). Everything else over `http` is refused, including `localhost` and any `*.localhost`, `127.1`, `127.0.1`, `0x7f.0.0.1`, `2130706433`, `0177.0.0.1`, `127.000.000.001`, `0.0.0.0`, `[::]`, `[::ffff:127.0.0.1]`, `[0:0:0:0:0:0:0:1]`, `127.0.0.1.nip.io` and every userinfo trick (`evil.example#@127.0.0.1` has the authority `evil.example`, so it is a remote host).
7. Path, query and fragment are not inspected beyond rule 1 (so `@` and `%` after the authority are fine, a space is not). Their bytes are untouched and signed as before; the fragment is never signed.

### 9.1 Why literal-only

- No DNS and no alias list: `localhost` can resolve to anything, and a resolve-then-connect check would leave a time-of-check/time-of-use gap between the address checked and the address connected. Judging only the literal string leaves nothing to race.
- Userinfo, percent escapes in the authority, backslashes and zone IDs are refused, not normalised. Percent-encoded path and query bytes stay accepted and are signed exactly as given. Different URL parsers disagree on them (which host a backslash or `@` selects, whether `%31%32%37` is `127`), and a parser disagreement between the check and the transport is the classic downgrade vector. Refusing keeps one reading of the string.
- Refusal happens locally, before signing and before any injected transport, `fetch` or network call. A refused URL produces no signature and no packet.
- The signed target bytes are unaffected: the policy changes nothing about what is signed, it only decides whether signing and sending proceed. The standalone pure signing helpers, which take no destination URL, are unchanged and not subject to the policy.

### 9.2 Redirects and TLS

- SDK-owned sending clients never follow redirects. They refuse exactly the redirect statuses 301, 302, 303, 307 and 308 (the ones HTTP clients follow) locally as an error, before verification and without surfacing `Location`, in all three SDKs. Other 3xx statuses, notably 304 Not Modified, are not redirects: they go through normal signature verification like any other answer (a correctly signed 304 with an empty body is returned; unsigned or tampered ones fail verification).
- Redirect refusal is a no-follow/no-downgrade guard: a signed request is never replayed or verified against another origin. It is not TLS enforcement.
- TLS certificate validation stays with the platform transport and is never weakened; there is no insecure or skip-verify option.

### 9.3 Remaining boundary

A caller-injected transport (Rust `Transport` trait, TypeScript `fetchImpl`, Go `Config.HTTP` or a base `RoundTripper`) is outside the SDK's control. It must use TLS for `https` URLs, connect to exactly the URL it is given, and not follow redirects. The SDKs cannot police arbitrary custom transport behaviour. In Go, `Config.HTTP` is always wrapped by the SDK signing/verifying transport; the caller's transport remains responsible for TLS and not following redirects.

### 9.4 Fixture contract

Rows are `{name, url, allow}` plus the optional `parse_reject` (array of SDK ids; only `"go"` is used). `allow=true` means the security policy accepts the URL. `parse_reject: ["go"]` on an `allow=true` row (only `allow-https-percent-in-fragment`, `https://svc.example.test#%`) means the policy still accepts it (the fragment is never sent or signed and is not inspected), but that SDK's platform URL parser (Go `net/url` rejects the invalid escape `%` in the fragment) additionally rejects it at the public constructors and profile loaders with the generic "must be an absolute http/https URL" error, which is not a policy error, and `http.NewRequest` cannot build it. Every other `allow=true` row is accepted by every public constructor and profile loader in all three SDKs, with no exception.

Per row, each runner exercises three entry paths:

1. Policy function on the raw string: `allow=true` must pass; `allow=false` must be refused with the policy error.
2. Public constructors and profile loaders (Go `NewClient`/`LoadProfile`/`NewClientFromProfile`, Rust `Client::new`/`load_profile`/`from_profile`, TS `new Client`/`loadProfile`/`validateProfile`/`clientFromProfile`): `allow=false` must be refused with the policy error before any signing or transport call; `allow=true` must succeed, except rows listing that SDK in `parse_reject`, which must fail with a non-policy (generic parse) error.
3. Low-level signing transport (Go `Transport.RoundTrip`, Rust `SigningTransport::round_trip`, TS `createSigningFetch`): `allow=false` means zero signer uses and zero inner transport/fetch calls; `allow=true` reaches the inner spy exactly once.

Go limitation: `Transport` sees only the already-parsed `req.URL`, so rows the Go parser rejects (`http.NewRequest` fails) or normalises (percent-decoded host, dropped or escaped path or fragment bytes) cannot be presented to `RoundTrip` as the raw string. The Go runner classifies each row explicitly as parser-rejected, refused-at-transport or parser-normalised, and asserts that the pre-parser policy rejects the raw string in every `allow=false` case. TS `createSigningFetch` checks URL and Request inputs on their WHATWG-normalised `href` (a string input is checked as given).

Fragments are never signed. In TS, the comparison of the response URL against the request URL ignores the fragment.
