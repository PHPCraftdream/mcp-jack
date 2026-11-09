# mcp-jack interop harness

**Baseline `b13b972`: SDK contract migrated; shared interop matrix acceptance was verified in GitHub CI on `444c69b`.** This document describes the current harness contract and test obligations; actual CI results for integrated `444c69b` are recorded in readiness. The current scenario oracle is [`scenarios.json`](scenarios.json); the independent credential-transfer oracle is `spec/fixtures/user-key-transfer.json`.

Current protocol contract: authenticate the exact request, then forward authenticated ordinary MCP traffic unchanged with the immutable verified identity `{kid, name, admin}` available to the application handler. Protocol `admin` gates reserved `jack.admin.*` tools only; ordinary MCP authorization belongs to the application. Legacy user/state `kind` and `scopes` fields are rejected without migration or rewrite. There is no policy engine or policy-file input. Do not use retired policy/scopes examples as current behavior.

## 1. Purpose

The request matrix checks Go, Rust and TypeScript clients against each server language. It preserves exact signing parity, live freshness and replay checks, independently pinned server-key verification, signatures on authenticated answers, identity forwarding, native admin behavior, and last-active-admin protection. The transfer matrix in section 11 is a separate, local credential import/export contract; it is not a request scenario or network issuance feature.

Normative protocol sources are `spec/01-authentication.md`, `spec/02-authorization.md`, and `spec/03-user-management.md`. This README pins executable harness details; `docs/design/interop.md` records the current boundary and pending status.

## 2. Layout

```text
interop/
  README.md                         this contract
  scenarios.json                    current request scenarios and expected outcomes
  sign-cases.json                   8 exact signing-byte oracle cases
  run.mjs                           request matrix, sign/verify phases, fake self-test
  targets.json                      Go, Rust and TypeScript executable argv
  transfer.mjs                      independent credential-transfer matrix
  transfer-{checks,fixtures,matrix,public,refusals,trust,process}.mjs
  transfer-{self-test,lifecycle-test}.mjs
  tools/gen-sign-cases.mjs           signing-vector generator/checker (not run here)
  tools/fake-{client,server}.mjs     request-harness self-test only; not SDKs
  tools/transfer-child.mjs           transfer lifecycle self-test child
  go/{server,client,transfer}/       Go integration executable sources
  ../rust/src/bin/interop*.rs        Rust integration executable sources
  ../ts/src/interop/*.ts             TypeScript integration executable sources
```

`targets.json` currently maps Go to `interop/bin/go-{server,client,transfer}`, Rust to `rust/target/release/interop-{server,client,transfer}`, and TypeScript to `node ts/dist/interop/{server,client,transfer}.js`. These are build/output paths, not claims that binaries currently exist. On Windows, the request harness tries `.exe` for a missing binary path. Target-file relative paths resolve from the repository root; a bare command is resolved on `PATH`.

Build instructions (not executed for this documentation update):

```sh
go build -o interop/bin/go-server ./interop/go/server
go build -o interop/bin/go-client ./interop/go/client
go build -o interop/bin/go-transfer ./interop/go/transfer
cargo build --manifest-path rust/Cargo.toml --locked --release --features interop --bin interop-server --bin interop-client --bin interop-transfer
npm --prefix ts run build
```

Rust's `interop` feature enables the interop binaries/dependencies; the transfer binary is behind that feature. TypeScript output is built from `ts/src/interop/`. Go outputs must be placed where `targets.json` points (or the targets file adjusted).

## 3. Running

Request harness (Node >= 20, no external runtime dependencies):

```sh
node interop/run.mjs [--targets <file>] [--servers <l,l,...>] [--clients <l,l,...>]
                     [--scenario <id>] [--list] [--self-test]
```

- `--targets <file>` selects a targets document; default is `interop/targets.json`.
- `--servers` and `--clients` take comma-separated language names; defaults are all target languages.
- `--scenario <id>` runs just that scenario and skips sign/verify phases.
- `--list` prints current scenario IDs with freshness and expected outcome/code, then the signing-case IDs; it exits 0.
- `--self-test` exercises the harness using bundled fakes. It is not SDK evidence.

Examples (instructions only):

```sh
node interop/run.mjs
node interop/run.mjs --clients go --servers rust
node interop/run.mjs --scenario identity-forward
node interop/run.mjs --self-test
```

The harness starts one shared server per client/server pair for non-fresh scenarios. Fresh state-changing cases and cases with `registry_overrides` receive a dedicated pristine server/state file. Legacy-state rejection cases launch a server directly with a deliberately modified state document. The harness kills only child PIDs it started; it does not kill processes by image name. Captured child output is classified after `close` (pipes drained), not merely `exit`.

Request harness exit codes: `0` all selected scenarios and, when enabled, sign/verify checks pass; `1` a scenario/sign/verify failure; `2` harness/usage/contract error (including unknown language/scenario, invalid contract input, or missing target; the diagnostic identifies the role and resolved target path). A client nonzero exit is a harness failure even if it printed a matching result. Scenario client calls have a 20-second deadline; server readiness is 10 seconds; verify-only calls have a 10-second deadline. Output includes `== pair client=<c> server=<s> ==`, one `PASS`/`FAIL <id>` per case, pair counts, sign/verify phase headings, a matrix table, and a final summary. A `--scenario` run does not run signing parity phases.

The separate transfer harness is described in section 11; its direct entry points are `node interop/transfer.mjs` and `node interop/transfer.mjs --self-test` (instructions only).

## 4. `interop-server` contract

Invocation:

```text
interop-server --aud <aud> --state <file> --server-seed-hex <64 hex>
               [--bootstrap-ttl <seconds>] [--verify-only]
```

There is no `--policy` flag. Required values are the audience, SDK state path, and 32-byte server Ed25519 seed as 64 hex characters. Diagnostics go to stderr; the only normal stdout line is the serve-mode ready object or verify-only verdict. Startup errors exit nonzero and do not emit a partial ready line.

Every live request signs the UTF-8 string of eight LF-separated lines, with no final LF: `mcp-jack/v1/request`, HTTP method, origin-form target, configured audience, client kid, decimal Unix timestamp seconds, canonical base64url nonce, and canonical base64url SHA-256 of the exact body bytes. The nonce is 16 random bytes and fresh per request except controlled replay/fixed vectors. The server's default accepted timestamp skew is 30 seconds. Authentication checks header presence/grammar/version, key lookup and validity, freshness, strict Ed25519 signature, then replay nonce; a valid signature must not be reused.

Every response following successful authentication signs six LF-separated lines without a trailing LF: `mcp-jack/v1/response`, decimal HTTP status, request signature, server kid, response timestamp, and SHA-256 of exact response bytes. The client verifies the configured pinned server key, timestamp and strict signature before acting on a response. The unsigned-allowed 401 family in section 5 is the only exception. For protocol details and error ordering see `spec/01-authentication.md` sections 3–5; exact request-signing oracle cases and verification-phase wiring are section 7.

### Serve mode and readiness

The server binds plain HTTP to `127.0.0.1` on an available port. It prints exactly one newline-terminated JSON object to stdout:

```json
{"ready":true,"port":<n>,"server_public_key":"<b64u>","server_kid":"<kid>"}
```

The server public key and kid are derived from the supplied seed. The harness accepts a complete non-empty JSON line, tolerates preceding blank lines, and waits up to 10 seconds. Stderr may carry diagnostics. In serve mode, SIGTERM/SIGINT or stdin EOF stops the server; normal stop exits 0. A malformed flag, seed, state file, verifier setup, or bind failure is a startup error.

Optional `--bootstrap-ttl` asks the SDK's local `BootstrapAdmin` operation to create an administrator invite; the invite is printed as `{"bootstrap_invite":"<code>"}` to stderr. The harness does not use bootstrap mode; scenario setup and protocol-native invite creation are used instead.

### State file

The server reads the SDK's strict `FileState` document:

```json
{"version":1,"keys":[<registry entries without aud>],"invites":[]}
```

The top-level member set is exactly `version`, `keys`, and `invites`; version is integer 1 and both collections are arrays. Each key entry permits exactly `kid`, `public_key`, `name`, optional `admin`, optional `not_before`, and optional `not_after`. `admin` defaults false when absent and, when present, is only the JSON boolean `true` or `false`; it is not truthy-coerced. Name is unique, 1–64 characters from `[A-Za-z0-9._-]`; public key is canonical base64url for 32 bytes, strictly valid Ed25519, and `kid` must equal base64url(SHA-256(public-key bytes)). Time bounds are nonnegative integer seconds or null, and when both set `not_before < not_after`.

Each invite record permits exactly `invite_id`, optional strict-boolean `admin`, `created_by`, `created_at`, `expires_at`, and optional `key_ttl_seconds`. ID/creator are non-empty strings; timestamps are nonnegative integers with created_at <= expires_at; key TTL is absent or an integer in 1..31536000, never null. Invite IDs are unique. Unknown fields, duplicate key/name/invite IDs, invalid keys/entries, and invalid state are rejected at load; a missing file means an empty store. For ordinary scenarios, the harness builds state from `spec/fixtures/registry.json` and supplies the audience separately via `--aud`.

Legacy rejection applies at the key/invite record level too: any `kind` or `scopes` field causes startup rejection, the error names the offending field, and the harness confirms the state bytes were not rewritten. The two current controls are `legacy-stored-kind` and `legacy-stored-scopes`; neither is migration behavior.

### Fixed MCP handler

As current migrated APIs, the relevant operations are `jack.whoami`, `jack.enroll`, `jack.key.rotate`, `jack.admin.user.list`, `jack.admin.user.get`, `jack.admin.user.create`, `jack.admin.user.set_admin`, `jack.admin.user.revoke`, and `jack.admin.invite.{create,list,revoke}`. User records report `{kid, public_key, name, admin, not_before, not_after}`; `admin` defaults false if omitted in create/invite input and is always present in returned identity. There is no `kind`, `scopes`, `set_scopes`, policy mapping, or policy-derived result. The protocol admin gate applies to `jack.admin.*` only. Native tool arguments and errors follow `spec/03-user-management.md`; in particular `set_admin` requires a strict boolean including explicit false. The scenario matrix checks false, missing, null, string, number, and last-active-admin behavior.

The wrapped ordinary handler is a fixed minimal example, not a protocol policy engine:

| Authenticated input | Handler behavior |
|---|---|
| `ping` | JSON-RPC `result: {}` |
| `tools/list` | JSON-RPC `result: {"tools":[{"name":"echo"}]}`; no broader list shape is pinned |
| `tools/call` `echo` | Returns the `arguments.text` value in one text content item |
| `tools/call` `app.identity` | JSON-RPC result contains one text item `identity`, `structuredContent` `{kid,name,admin,body_b64u,method,target}`, and `isError:false`; forged identity arguments are ignored |
| `tools/call` `svc.config.set` or `config.set` | Fixture identity `bob` receives result content `[{"type":"text","text":"ok"}]`; others receive HTTP 403 `{"error":{"code":"application_permission_denied",...}}` |
| `tools/call` `logs.tail` | Returns result content `[{"type":"text","text":"ok"}]`; it is ordinary MCP, not an admin/policy mapping |
| Other methods/tools | JSON-RPC `-32601`, `method not found` |
| Authenticated GET `/identity` or `/a/../identity` | JSON-RPC result has `id:null` and identity structured content; exercised with `/identity?x=%2F` and `/a/../identity?x=%2F` |
| Authenticated GET `/sse` | Handler offers one finite `data: hello\\n\\n` SSE event; wrapper refuses event-stream with signed HTTP 501 `streaming_unsupported` |
| Other authenticated GET | JSON-RPC `{"jsonrpc":"2.0","id":null,"result":{}}` |

Reserved `jack.*` tools are dispatched by the SDK before the wrapped handler. Defined `jack.admin.*` operations require a verified `admin: true` identity; undefined `jack.` tools are denied with `operation_denied`. This is independent of the example application's `svc.config.set` decision. Every response after successful authentication—including application errors and protocol denials—must be signed. Responses to authentication failures may be unsigned.

### `--verify-only`

This mode does not listen. It reads stdin through EOF as one JSON object with `method`, `target`, `jack_auth`, and `body_b64u` fields, decodes the body, and checks header grammar/version, key lookup in the state, and strict Ed25519 signature against the signing string constructed with configured `--aud`, method, exact target, and exact body bytes. It skips key-validity, timestamp-window, and nonce checks because fixed oracle timestamps include `0` and `999999999999`; it does not replace live freshness/replay tests.

It prints one line, then exits 0 for either verdict:

```json
{"verify":"accept","kid":"<kid>"}
{"verify":"reject","code":"<code>"}
```

Malformed input/setup is a harness/server error; an ordinary signature rejection is a verdict, not a nonzero exit.

## 5. `interop-client` contract

Invocation:

```text
interop-client --url <base-url> --seed-hex <64 hex> --server-public-key <b64u>
               --aud <aud> --scenario <name> [--seeds <file>] [--ts <n>]
               [--nonce <b64u>] [--arg k=v]...
```

`--url`, `--seed-hex`, `--server-public-key`, `--aud`, and `--scenario` are used for live scenarios; `--seeds <file>` supplies fixture identities for multi-step scenarios. Repeatable `--arg k=v` carries scenario inputs (split at the first `=`). `sign-only` uses `--ts <n>`, `--nonce <b64u>`, and `--arg method=...`, `--arg target=...`, optionally `--arg body-b64u=...`; it does no network I/O and ignores URL/server-key values. Timestamp zero is valid when explicitly supplied; empty `body-b64u` denotes an empty byte string. Its `data` contains the complete signing string, `Jack-Auth` value, and kid. For live calls, Go and Rust clients use a 15-second HTTP transport timeout. The TypeScript interop client's raw dot-target request uses Node HTTP with its own explicit, clearable 15-second deadline timer (not an `AbortSignal`); expiration destroys the request/socket, and the deadline spans response headers and body. Its ordinary Fetch path has no explicit transport timeout. The request harness's 20-second per-scenario deadline governs all client calls.

A completed client scenario prints one JSON object as its final non-empty stdout line and exits 0:

```json
{"scenario":"<id>","outcome":"ok|rejected|client_error","http_status":<n|null>,"code":"<string|null>","data":<object|null>}
```

- `ok`: a successful result (HTTP 200 for live cases) with verified response signature; `code` is null and `data` is the JSON-RPC `result` member.
- `rejected`: a wire-level protocol or application rejection; reports wire HTTP status and error code, and null data. A verified non-2xx response remains a rejection; JSON-RPC errors in HTTP 200 are represented as rejected with status 200.
- `client_error`: response trust/verification failed; status and data are null and `code` is the client-side verification code. It must never convert an unsigned/unverifiable response to `ok`.

The only unsigned-allowed responses are HTTP 401 answers to requests that failed authentication, with one of `missing_auth`, `malformed_auth`, `unsupported_version`, `unknown_key`, `key_inactive`, `timestamp_out_of_window`, `bad_signature`, or `replayed_nonce`. If an allowed 401 includes a response signature, clients still verify it. Every other response—including every 2xx and authenticated 400/403/404/409/501 application/protocol error—requires a valid signature from the independently pinned server key. A missing signature outside the allowed family is a client-side `missing_auth` error; a wrong pinned key is `unknown_server_key`.

Exit 1 is reserved for client/harness-level inability to complete (connection, crash, invalid local inputs); diagnostics go to stderr. A failing intermediate step of a multi-step scenario emits `client_error`, the failing step's status/code when on-wire (or its client-side code), and `data: {"step":<zero-based index>}`; it exits 0 as a completed scenario so the harness can compare and fail the pair. If intermediates succeed, the final step is compared to the scenario's declared expectation.

For ordinary requests the wrapper forwards exact body bytes and the verified identity. The Node HTTP adapter captures raw origin-form `req.url` before constructing a Fetch `Request` and attaches it as adapter metadata on the existing exported `RAW_TARGET_SYMBOL`; this metadata is not SDK-private identity storage. The adapter also preserves repeated `Jack-Auth` header values. A pure Fetch `Request` URL is already parsed/normalized: the fallback `pathname + search` cannot recover original wire spelling or dot segments. Therefore exact raw-target claims apply when the Node adapter supplies raw metadata, not to arbitrary Fetch callers. The current `identity-get` scenario pins `/identity?x=%2F`; `identity-dot-target` pins `/a/../identity?x=%2F` through the raw adapter and tests preservation. These cases are not a claim that a pure Fetch handler reconstructs original raw target bytes.

The focused TypeScript raw-path integration controls are in `ts/test/interop-client-raw-path.test.ts` and run automatically through `npm test` in the TypeScript CI job. They cover acceptance of exactly 1 MiB and rejection of the next byte, deadline destruction for no-response and stalled-body peers, truncation and the production incomplete-response finalizer, and literal-path/signature controls. The testable integration-module exports are not public SDK API; the package exports only the SDK root and excludes interop files. These controls are CI-wired, not executed for this documentation update.

## 6. Scenarios

[`scenarios.json`](scenarios.json) is the current scenario source of truth (33 ordered scenario IDs). Expected objects are recursively matched subsets; arrays are exact; `$kid` resolves from `spec/fixtures/keys.json`, and `$base64url` resolves the exact UTF-8 string bytes. The table below reports the current expected outcome/status/code; identity forwarding, application decisions, and administrative controls are distinct:

| Current scenario IDs | Expected result |
|---|---|
| `ping` | `ok`, HTTP 200, result `{}` |
| `echo` | `ok`, HTTP 200; result contains the exact non-ASCII text content |
| `whoami` | Alice reports `{kid,name:"alice",admin:false,not_before:null,not_after:null}` |
| `admin-identity` | Root reports `{kid,name:"root",admin:true,not_before:null,not_after:null}` |
| `identity-forward` | `app.identity` returns Alice's verified identity, exact POST `/mcp`, and exact noncanonical body bytes as base64url; forged identity arguments do not override it |
| `identity-get` | `GET /identity?x=%2F` returns Alice identity, empty body, method and target |
| `identity-dot-target` | `GET /a/../identity?x=%2F` returns Alice identity, empty body, method and exact raw target |
| `app-permission-allowed` | `ok`, HTTP 200; app result contains text `ok` |
| `app-permission-denied` | `rejected`, HTTP 403 `application_permission_denied` (signed) |
| `admin-required` | `rejected`, HTTP 403 `admin_required` (signed) |
| `set-admin-false` | `ok`, HTTP 200; Alice's returned structured entry has `admin:false` (fresh scenario starts Alice admin while root remains admin) |
| `set-admin-missing`, `set-admin-null`, `set-admin-string`, `set-admin-number` | `rejected`, HTTP 400 `invalid_params` (signed) |
| `unknown-key` | `rejected`, HTTP 401 `unknown_key` |
| `replay` | `rejected`, HTTP 401 `replayed_nonce` |
| `clock-skew` | `rejected`, HTTP 401 `timestamp_out_of_window` |
| `tampered-body` | `rejected`, HTTP 401 `bad_signature` |
| `bad-server-key` | `client_error`, status null, `unknown_server_key` |
| `expired-key`, `key-not-yet-valid` | `rejected`, HTTP 401 `key_inactive` |
| `stream` | `rejected`, HTTP 501 `streaming_unsupported` (signed) |
| `invalid-request` | `rejected`, HTTP 400 `invalid_request` (signed) |
| `unknown-native-tool` | `rejected`, HTTP 403 `operation_denied` (signed) |
| `enroll` | `ok`, HTTP 200; newly enrolled identity has `admin:false` |
| `enroll-used-invite` | `rejected`, HTTP 403 `invalid_invite` (signed) |
| `rotate` | `ok`, HTTP 200; new key retains Alice name and `admin:false` |
| `admin-create` | `ok`, HTTP 200; newbie2 key is reported as Dave with `admin:false` |
| `revoke-key` | `rejected`, HTTP 401 `unknown_key` after revocation |
| `last-admin` | `rejected`, HTTP 409 `last_admin` (signed) |
| `legacy-stored-kind`, `legacy-stored-scopes` | startup rejection `state_corrupt`; offending field named and state bytes remain unchanged |

Current coverage includes non-admin and admin identity reports; ordinary MCP forwarding with forged identity arguments and noncanonical body whitespace; authenticated GET identity handoff; app-allowed and app-denied ordinary tool calls; native admin gate; typed `admin=false` plus raw omitted/null/string/number invalid controls; authentication, freshness and replay controls; and enrollment/rotation/revocation/last-admin lifecycle. Do not restore retired scenarios such as policy-based `denied-tool`, `unmapped-tool`, or old `agent-admin` as current cases.

State-changing `fresh` cases use a pristine state file. A scenario with `registry_overrides` also gets a dedicated server (the current `key-not-yet-valid` override sets Erin's `not_before` to now + 3600 seconds). Other live scenarios share the pair's server. `replay` signs once, sends the exact same request bytes/header twice, and reports the second response. `clock-skew` signs 120 seconds in the past against the default 30-second server window. `tampered-body` changes the final `}` byte to `|` after signing. `bad-server-key` pins Mallory's key to force a client-side verification error.

Multi-step mechanics are normative through the scenario steps and expected result:

- `enroll`: root creates a default (non-admin) invite; the new identity enrolls with its own key; that identity calls `jack.whoami`.
- `enroll-used-invite`: create one default invite, enroll `newbie`, then attempt to enroll `newbie2` with the same code; the final step must be `invalid_invite`.
- `rotate`: Alice proves possession of the new key; the old Alice key must then be rejected as `unknown_key`; the new key reports Alice's name and non-admin status.
- `admin-create`: root creates a default invite and creates `dave` with `admin` omitted; `newbie` enrolls; the primary fixture key reports the registered name `dave`.
- `revoke-key`: root revokes Bob, then Bob's next request is `unknown_key`.

`set-admin-false` is fresh and starts with Alice already `admin=true` while root remains an active admin; the typed SDK call sets Alice's admin to the actual boolean `false` and confirms the returned entry. The scenario MUST then authenticate again as Alice and assert with a fresh typed `jack.whoami` call that `admin=false`; this is required before the scenario passes. The four malformed controls call `jack.admin.user.set_admin` as root with the member omitted or set to null, string, or number; each must be `invalid_params`. `last-admin` requests demotion of root and must preserve the last-active-admin invariant.

## 7. Byte-exactness phase

`sign-cases.json` pins eight cases across fixture identities Alice, Bob and Carol: `empty-body`, `ascii-body`, `utf8-body`, `nul-newline-body`, `query-target`, `long-target`, `ts-min` (`ts=0`), and `ts-max` (`ts=999999999999`). Each case pins identity, method, exact target, audience, timestamp, nonce, body bytes as base64url, kid, the eight-line signing string, and complete `Jack-Auth` header. Oracle source/provenance is recorded in the file and generated from `interop/tools/gen-sign-cases.mjs`; no generator was run for this documentation change.

For each selected language the sign phase invokes `sign-only` for all eight cases and requires exact oracle equality for `signing_string`, `jack_auth`, and `kid`. The verify phase feeds each signer language's exact header/body to each selected server's `--verify-only`, requiring acceptance and the expected kid. Per signer/server pair it also flips the final ASCII-body byte without changing the header; this control must reject with `bad_signature`. Verification-only vectors deliberately skip live timestamp, key-validity and nonce checks; the ordinary live scenario phase covers those independently.

## 8. Self-test

```sh
node interop/run.mjs --self-test
```

The request self-test currently has 18 assertions. Its expected labels/conditions are:

1. Fake matrix plus sign and verify phases report zero failures.
2. Exactly three servers are spawned: shared plus fresh last-admin plus dedicated key-not-yet-valid override.
3. Sign phase reports one pseudo-language and eight cases.
4. Sign phase performs eight sign-only invocations (one language × eight vectors).
5. Removing the key-not-yet-valid registry override makes that scenario fail.
6. The deliberate deviating-client negative control exits 1.
7. That negative control prints `FAIL`.
8. A client that prints a matching result but exits 2 is treated as failure (harness child exits 1).
9. The exit-2 control prints `FAIL`.
10. A verify-only fake that prints the right verdict but exits 2 makes the harness exit 1.
11. That verify control prints `FAIL verify`.
12. An unsigned authenticated 403 makes the harness exit 1.
13. That response is reported as `client_error`, not pass.
14. Its client error code is `missing_auth`.
15. Blank-line-before-ready mode exits 0.
16. The blank-ready control prints `PASS ping`.
17. Exit-before-drain mode exits 0 when output is written after child exit by a pipe-holding grandchild.
18. That drain-aware control prints `PASS ping`.

The assertions describe what a future invocation checks; they are not results from this documentation work. The two ordinary readiness modes include split-chunk delivery in the in-process fake run and a leading blank line in the subprocess control. The subprocess checks use fakes only; neither proves SDK behavior.

## 9. How to add a language

1. Implement the server, client, and transfer probe against this contract and `spec/01`–`03`; ordinary MCP must pass through and app decisions must use SDK-provided verified identity.
2. Add server/client/transfer argv to `interop/targets.json`. Relative paths resolve from repository root; executable commands may be on `PATH`.
3. Build the language targets using the appropriate instructions in section 2; do not infer a passing result from a successful build.
4. Exercise the request harness self-test, then the selected language pair and signing parity; run the independent transfer self-test and matrix for transfer changes.
5. CI builds language binaries and runs the shared jobs. For baseline `b13b972`, shared interop, transfer-matrix, consumer, coverage/fuzz evidence was verified on `444c69b`; final merge and post-merge verification are separate gates.

## 10. Determinism notes

Live request cases use the real clock and fresh random 16-byte nonces, except deliberately fixed or replayed values. All processes share the machine clock; server freshness is the default 30 seconds. `clock-skew` is 120 seconds old. `sign-only` injects timestamp and nonce from the fixed oracle. Ports and temporary state directories are per run. Fixture keys are test-only. The request harness removes its temporary directory and terminates only children it owns. The current `key-not-yet-valid` registry fixture's absolute `not_before` value is historical; the harness overrides it to runtime now + 3600 seconds. Transfer issuance uses fixed fixture seeds only in the test probe; this does not constrain production randomness.

The raw-target fidelity case `identity-dot-target` pins `/a/../identity?x=%2F`; Go and Rust run their supplied raw target in the request transport, and the TypeScript Node adapter must keep the original target alongside the normalized Fetch URL. The Fetch-only fallback cannot recover the dot segment. The case is a cross-language target-preservation expectation, but URL parsing behavior must not be described as recovering raw bytes from a pure Fetch `Request`.

## 11. Credential-transfer matrix

This is independent of the request scenarios and implements the local user-key transfer contract in [`docs/design/user-keys.md`](../docs/design/user-keys.md), with shared fixture inputs at `spec/fixtures/user-key-transfer.json`. Its transfer-envelope `type` discriminator is unrelated to removed user/state `kind`. The contract does not add network issuance, protocol changes, packaging, or fuzzing guarantees. Transfer implementation and fixture expectations are not evidence of parent CI acceptance.

### 11.1 Roles, documents and security boundary

The asymmetric role split is normative:

- Client role may generate locally; import private material from its own credential/backup; import public envelopes as verify-only; import a credential; export public envelopes only. There is no client private-export API, flag, or signer method.
- Server role may import public envelopes and locally issue a new client keypair via a dedicated pure helper. Issuance returns a client credential plus a public identity for normal public-only registration. Registry/state/profile records never store a seed; server signing-key configuration is unchanged and is not exported.
- An imported public key cannot reveal its private seed. Public-only records cannot sign or recover private material; a private/import operation against them returns `not_private`. No escrow or upgrade path exists.

Version-1 public/private envelopes are exact canonical UTF-8 JSON without whitespace, BOM, or newline:

```json
{"crv":"Ed25519","kid":"<KID43>","kty":"OKP","type":"user-key/public","v":1,"x":"<PUB43>"}
{"crv":"Ed25519","d":"<SEED43>","kid":"<KID43>","kty":"OKP","type":"user-key/private","v":1,"x":"<PUB43>"}
```

`x` is the 32-byte Ed25519 public key; private `d` is the 32-byte seed; `kid` is base64url(SHA-256(raw public key)). Base64url is canonical and unpadded. The credential is an exact canonical JSON document with fields `aud`, `client_key` (the exact private-envelope string), `server_kid`, `server_public_key`, `type:"user-key/credential/client"`, `url`, and `v:1`. It contains the server public identity as data, never the server private key. The credential's decoded audience preserves exact UTF-8 bytes; canonical string escaping and field order follow the user-key design. URL policy is applied literally; no normalization, DNS lookup, redirect, or silent pin rewrite is implied.

Imports are strict: maximum document size 4096 bytes; valid UTF-8/JSON object and supported version/type; exact member sets and types; canonical base64url; strict Ed25519 public-key validity; seed/public/kid consistency; nested private-envelope validation for credentials; and byte-for-byte canonical reserialization. The ordered first-failure checks are: size; UTF-8/escape/JSON; object root; version; known and sink-compatible type (including server public-sink private-material refusal); exact member set; envelope literals; string fields/non-empty credential audience; credential URL; base64url lengths/decoding; strict public-key validity; seed/public match; kid match; nested private import; canonical bytes. Credential trust comparison happens only after this pipeline succeeds. Unknown members are not stripped, malformed or alternate spellings are not repaired, and duplicate keys are never accepted (last parsed occurrence is checked normally; a consistent duplicate fails canonical bytes, while an inconsistent last value may fail an earlier semantic check). Error classes are closed and shared: `malformed_json`, `wrong_root_type`, `oversized_envelope`, `unknown_version`, `unknown_type`, `bad_member_set`, `wrong_field_type`, `bad_encoding`, `bad_url`, `invalid_public_key`, `seed_pub_mismatch`, `kid_mismatch`, `non_canonical_bytes`, `wrong_envelope_type`, `private_material_rejected`, `not_private`, `server_identity_mismatch`.

### 11.2 Trust and local API behavior

A credential's server identity is untrusted data, not a trust anchor. Client credential import requires a separately trusted expected tuple `{url, aud, server_public_key, server_kid}` (for example, an existing pin or an out-of-band operator-verified identity). No TOFU, trust-on-first-import, boolean “accept whatever arrived,” or silent pin replacement is permitted. The tuple is compared exactly by decoded UTF-8 values after the document passes structural/cryptographic validation. Missing, null, incomplete, invalid, or conflicting expected identity yields `server_identity_mismatch` and returns no signer/configuration. Existing caller-owned pins/state remain unchanged. HTTPS certificate validation and signed pinned-server response verification are unchanged.

Credential URL validation uses the pure literal URL policy in `docs/design/interop.md`: reject empty values, bytes `<= 0x20`, DEL, non-ASCII, and backslashes; accept only `http://` or `https://`; reject empty/malformed authority, userinfo, percent escapes in authority (including IPv6 zone IDs), malformed/unbracketed IPv6, invalid host characters, and ports outside 1..65535. HTTPS permits any otherwise valid literal host and does no DNS lookup in the policy check. HTTP permits only canonical dotted-decimal `127.x.y.z` IPv4 or bracketed `[::1]`; `localhost`, aliases, abbreviated/alternate numeric IPv4 and other loopback spellings are refused. Path/query percent escapes are allowed and are not rewritten; fragments are not part of the request target. Passing this pure policy is not proof that a platform URL parser or transport will accept/connect to the same string.

The role API obligations are language-neutral: client `importPublicEnvelope`, `importPrivateEnvelope`, `importCredential(bytes, expected)` and public export; server `importPublicEnvelope` and `issueUserKey(config, random_source)`. Issuance is local and pure, does not mutate a registry or persist anything, and deterministic under injected deterministic randomness. Its result has exactly a credential export accessor and `public_identity`; export returns a fresh owned copy on each call, is reusable (not consumed), and the issuance result redacts secret bytes from default display/debug/string/JSON forms. Caller-owned byte arrays/slices cannot mutate SDK/signer state. Client and server APIs do not log or implicitly persist secrets; plaintext credentials are unencrypted and no zeroization guarantee is implied.

### 11.3 Transfer probe IPC and lifecycle

The transfer executable targets are listed alongside request targets in `targets.json`. Probe IPC is exactly one JSON line followed by EOF:

```json
{"operations":[{"id":"...","op":"..."}]}
```

The transfer harness validates target-language entries and requires exactly one JSON response line, strict UTF-8/JSON, and one result per operation in original order. Each result ID must match its operation ID; duplicate/missing/extra IDs and extra output are rejected. A failed operation returns exactly `{"id":"...","ok":false,"class":"<transfer-class>"}`; a success must match that operation's exact result shape and canonical base64url byte fields. Operation input objects also reject unknown members. Missing/null/incomplete expected identity values remain a refusal and are tested at the SDK boundary, not trusted from the credential.

Probe process limits: 2 MiB maximum serialized IPC input and maximum captured stdout, 1024 operations, at most 16 messages with each message at most 4096 bytes, and a 30-second default deadline. The harness uses shell-free child spawn, writes stdin then closes it, drains stderr without displaying it, validates strict UTF-8 and a single newline-terminated JSON output, validates result count/order/shape, and waits for `close` so trailing output is retained. Timeout, malformed/truncated/extra output, invalid UTF-8, child failure, or cleanup deadline are distinct harness failures. Cleanup kills/reaps only children started by the transfer process harness; normal probes do not spawn descendants. Diagnostics use fixed safe labels and do not expose raw secret material. Plaintext test IPC credentials are not a claim about SDK logging or zeroization. The IPC stdout cap is also 2 MiB; each probe operation has exact allowed input members and returned result objects have exact per-operation member sets.

### 11.4 Matrix scope and expected checks

Credential issuance is deterministic under fixture-seeded randomness in these probes (not a claim of deterministic production randomness); each issued credential is checked against independently composed fixture bytes. The shared table has 14 positive cases, 51 negative cases and one structural/trust context case (66 total). Seven issued credentials are `cred-alice`, `cred-bob`, and the five audience controls `cred-aud-html-sensitive`, `cred-aud-codepoints`, `cred-aud-control`, `cred-aud-separators`, and `cred-aud-replacement-char`. The exact message set is empty bytes, ASCII text, UTF-8 text, bytes `00 0a ff`, and 4096 ASCII `a` bytes. The user-key design documents exact JCS-style string escaping (including `<>&`, controls, U+2028/U+2029, replacement character, and surrogate validation), duplicate-member precedence, strict raw UTF-8 handling, and canonical-byte requirements.

- 9 issuer-to-client language pairs and 7 deterministic credential cases (63 handoffs), checking credential issuance, fresh-copy export, cross-language import, matching public key/kid, and signatures over five exact messages.
- 66 shared transfer fixture cases per each of 9 probe pairs (594 case visits), covering positive, negative, and trust-context outcomes.
- 9 client-to-server public-import pairs with 25 public-key records each (225 exports): one OS-generated, three seed-derived, and 21 imported from the seven credential cases per client. Ten signature verdicts per record (five valid, five invalid) produce 2,250 verification checks. The expected key tuple is separately supplied and checked.
The refusal matrix supplies 17 expected-identity variants: wrong URL/audience/server key/kid, substituted server pin, omitted/null/empty/incomplete tuple, invalid HTTP URL, empty audience, malformed public key/kid, and strict-invalid public key; every one must fail `server_identity_mismatch`. Each issuer/client pair also checks a matching tuple, wrong-server context, all credential negative classes at both import and validation sinks, server/client wrong-sink behavior, inner-before-outer version precedence, document-before-trust ordering, exact Unicode audience (no normalization), and exact expected URL comparison.

Fixtures pin seed/public/kid triples independently, include RFC 8032 test material and invalid-public-key vectors, and require exact canonical envelope/credential bytes. Positives check deterministic signature bytes and verification; negative inputs are checked for the named first-failure class. The current scope also checks public-only imports cannot sign, private material is rejected at server public-import sinks, credentials never carry server-private material, and result arrays/identity values are not silently accepted or taken from credential contents.

### 11.5 Transfer self-test and status

```sh
node interop/transfer.mjs --self-test
```

The transfer self-test uses actual SDK probes for positive issuance/import/public verification before running refusal and lifecycle controls. Its expectations include exact fixture credential bytes; signature verification against independently pinned key material; wrong identity, signature, message, envelope, connection, issued bytes, and export-freshness mutations; all-accept/all-reject verifier controls; rejection-class and result-shape controls; and child truncation, extra output, invalid UTF-8, overflow, timeout, spawn failure, secret-safe diagnostics, synthetic post-exit stdout, cleanup timeout, and owned-child accounting. Lifecycle controls specifically expect success for normal and final-chunk output; classify exit-2, truncated, malformed, no-newline, extra-line, invalid-UTF-8, overflow, stderr-secret, timeout, and spawn-failure probes; reject invalid timeout options; retain stdout emitted after `exit` until `close`; and kill/reap the owned PID within bounded cleanup, including reporting `cleanup_timeout` if a synthetic child cannot close. These are specified controls, not reported outcomes; no test was run here. For the current baseline, transfer matrix and self-test acceptance were verified in GitHub CI on `444c69b` (see readiness evidence).

Transfer design references: [`docs/design/user-keys.md`](../docs/design/user-keys.md) is normative for exact credential canonicalization, import ordering, trust comparison, result redaction, mutability, and language-role API obligations; `spec/fixtures/user-key-transfer.json` is the hand-maintained case source. Transfer envelope `type` is a document discriminator, not legacy user `kind`.
