# Design: cross-language interoperability tests

Status: draft, not implemented. Scope: Go, Rust and TypeScript, client and server.

## 1. Goal and acceptance

Every client SDK works against every server SDK. With three languages that is a 3 x 3 matrix of (client, server) pairs, including the same-language diagonal.

Acceptance:

1. A harness runs every scenario of section 4 for every pair and fails on the first deviation from the expected outcome.
2. A byte-exactness check proves that the three SDKs produce identical signed bytes for identical inputs (section 5), so a future fourth implementation can be checked without running a pair.
3. CI runs the matrix on Linux; each failing pair is named in the output.

Non-goals: performance, long-running soak tests, interop with third-party MCP clients, streaming (refused with 501 in v0.1).

## 2. What is needed first

Only a Go client exists today. The matrix needs a Rust client SDK and a TypeScript client SDK, both mirroring `client/` (signer, request signing, response verification, typed native-tool calls, connection profile). They are separate tasks and use the same fixtures for conformance. Client SDK scope is the Go client's: no stdio bridge, no gateway.

## 3. Contract between the harness and the SDKs

Each language ships two small executables, built from its SDK and living outside the library API:

- `interop-server`: a server built from the SDK `NewHandler`/`JackLayer`/`jackFetchHandler` in front of a fixed, trivial MCP handler (below).
- `interop-client`: a client built from the SDK that runs one named scenario and prints a result.

The harness (`interop/run.mjs`, Node, no dependencies) builds nothing itself: CI builds the six executables first, then the harness spawns them from paths given on the command line or in `interop/targets.json` (relative paths, no machine paths).

### 3.1 interop-server

```
interop-server --aud <aud> --policy <file> --state <file> --server-seed-hex <64 hex> --bootstrap-ttl <seconds>
```

- Listens on `127.0.0.1:0` (plain HTTP; TLS is the environment's job) and prints exactly one line to stdout when ready: `{"ready":true,"port":<n>,"server_public_key":"<b64u>","server_kid":"<kid>"}`. Nothing else on stdout.
- The state file is a copy of `spec/fixtures/registry.json` in the SDK's `FileState` format, written by the harness into a fresh temp directory per run (no shared state between runs).
- When `--bootstrap-ttl` is given, the server creates an admin invite through the SDK's `BootstrapAdmin` and prints it on stderr as `{"bootstrap_invite":"<code>"}`; the harness reads it for the enrollment scenarios.
- The wrapped MCP handler is the same in every language and fixed by this document: `POST` with a JSON-RPC body answers by method: `ping` -> `{"jsonrpc":"2.0","id":<id>,"result":{}}`; `tools/list` -> one tool `echo`; `tools/call` of `echo` -> a `CallToolResult` whose text content is the `text` argument; `tools/call` of `logs.tail` and `config.set` -> `{"content":[{"type":"text","text":"ok"}]}` (policy decides who may call them); anything else -> JSON-RPC error `-32601`. A `GET /sse` answers `text/event-stream` (to exercise the 501 path).
- Exits on SIGTERM/stdin close; the harness kills only the PID it spawned.

### 3.2 interop-client

```
interop-client --url <base> --seed-hex <64 hex> --server-public-key <b64u> --aud <aud> --scenario <name> [--arg k=v ...]
```

Prints one JSON object to stdout and exits 0 on a completed scenario, whether the scenario's outcome is success or an expected protocol rejection; exit 1 only for a harness-level failure (cannot connect, crash). The object is `{"scenario":"<name>","outcome":"ok"|"rejected"|"client_error","http_status":<n|null>,"code":"<code|null>","data":<json|null>}`.

## 4. Scenarios (the same list for every pair)

Expected outcomes live in `interop/scenarios.json`, validated by the harness, derived from the spec and the shared fixtures (keys, registry, policy). Initial list:

| Scenario | What it proves | Expected |
|---|---|---|
| `ping` | signed request and signed response round trip, unmodified MCP passes through | ok |
| `echo` | body bytes with non-ASCII text hash identically | ok, text equals input |
| `whoami` | native tool, `structuredContent` shape | ok, kid and scopes as registered |
| `denied-tool` | a `read` key calls `config.set` | rejected, 403 `insufficient_scope` |
| `unknown-key` | a key not in the registry | rejected, 401 `unknown_key` |
| `replay` | the client re-sends the exact bytes of an accepted request | second answer rejected, 401 `replayed_nonce` (needs a client `--replay` mode that re-sends raw bytes) |
| `clock-skew` | the client signs with `ts` 120 s in the past | rejected, 401 `timestamp_out_of_window` |
| `tampered-body` | the client changes one body byte after signing | rejected, 401 `bad_signature` |
| `bad-server-key` | the client pins a wrong server key | `client_error`, response not trusted |
| `enroll` | invite -> new key enrolls -> whoami with the new key | ok |
| `rotate` | key rotation with proof, old key dead, new key works | ok |
| `admin-create` | admin creates a user and an invite, the new user enrolls | ok |
| `last-admin` | demoting the last admin | rejected, 409 `last_admin` (code exactly as in spec 03) |
| `stream` | `GET /sse` | rejected, 501 `streaming_unsupported` |

Scenarios that need an admin start from the registry admin key of the fixtures. Scenarios that change state run against a fresh server instance (the harness starts one per scenario that mutates state).

## 5. Byte-exactness check

`interop-client --scenario sign-only` with fixed `--ts`, `--nonce`, method, target, body and seed prints the request `Jack-Auth` header and the signing string. Ed25519 is deterministic, so all three SDKs must print identical bytes. The harness compares the three outputs for each case of a small table (`interop/sign-cases.json`: empty body, ASCII body, multibyte body, long target with a query string) and also verifies each with the other SDKs' verifier through `interop-server`'s `--verify-only` flag (prints accept/reject for a header+body without serving). This catches drift that the fixtures cannot: fixtures pin outcomes, this pins bytes.

## 6. Layout

```
interop/
  README.md          how to run, how to add a language
  scenarios.json     expected outcomes
  sign-cases.json    byte-exactness inputs
  run.mjs            matrix harness
  go/        cmd mains (package main under the Go module)
  rust/      bin target(s) in the crate or a tiny sibling crate path-depending on it
  ts/        two scripts compiled with the package
```

Go: `interop/go/server/main.go`, `interop/go/client/main.go` inside the existing module (imports the SDK packages). Rust: `rust/src/bin/` behind a cargo feature `interop` so `cargo build` for library users is unaffected. TypeScript: `ts/src/interop/{server,client}.ts`, compiled by the package build, run with `node`.

## 7. CI

One job `interop` on ubuntu: build the Go executables, `cargo build --release --features interop,http`, `npm install` + build the TypeScript package, then `node interop/run.mjs`. It needs the Go, Rust and TypeScript jobs' sources only; it runs after them (`needs`) so a unit-test failure is reported first.

## 8. Risks and decisions

- Adding Rust and TypeScript client SDKs enlarges scope; they are necessary, a pair matrix without them reduces to Go-client x three servers.
- HTTP client for the Rust `interop-client`: `ureq` as an optional dependency of the `interop` feature only (blocking, small, no async runtime), not in the library's default dependencies. TypeScript uses the built-in `fetch`; Go uses `net/http`.
- Scenario `replay` and `tampered-body` need raw-byte control in the client; the SDK clients expose a low-level `sign_request` for this, and the interop client uses it directly instead of its high-level transport.
- Determinism: nonces and timestamps are injected in `sign-only`; in live scenarios real clocks and random nonces are used, and all processes run on the same machine clock.
- Ports and temp directories are per run; nothing is shared between scenarios, so the matrix can later run in parallel.
