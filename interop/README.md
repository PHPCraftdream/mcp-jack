# mcp-jack interop harness

Normative artifacts: `scenarios.json` (22 expected outcomes) and `sign-cases.json`
(8 byte-exactness cases). The design contract is `docs/design/interop.md`; where
the design leaves a decision open, this README pins the decision as built.
Harness: `run.mjs` — Node >= 20, no dependencies.

## 1. Purpose

The matrix proves, for every (client, server) language pair:

- a signed request is accepted, verified and answered with a signed response
  (design doc sections 1, 4, 5);
- the three SDKs produce byte-identical signing strings, signatures and headers
  for identical inputs, and each verifier accepts every other signer's bytes;
- protocol behavior (denials, expiry, replay, streaming refusal, native tools,
  enrollment/rotation/revocation) matches the spec and the fixtures.

## 2. Layout

```
interop/
  README.md              this file
  scenarios.json         22 normative scenarios (expected outcomes, sources)
  sign-cases.json        8 byte-exactness cases with oracle values (generated)
  run.mjs                matrix harness (matrix + sign phase + verify phase + self-test)
  targets.json           per-language target argv (placeholder: go, rust, typescript)
  tools/gen-sign-cases.mjs  generates sign-cases.json (--check verifies it is up to date)
  tools/fake-server.mjs  self-test-only fake server (NOT a reference implementation)
  tools/fake-client.mjs  self-test-only fake client (NOT a reference implementation)
  .gitignore             ignores bin/
```

The six executables come from CI builds:

| Language | Server | Client | Built with |
|---|---|---|---|
| Go | `interop/bin/go-server` | `interop/bin/go-client` | `interop/go/server/main.go`, `interop/go/client/main.go` |
| Rust | `rust/target/release/interop-server` | `rust/target/release/interop-client` | `cargo build --locked --release --features interop` (`interop` enables `http`; as in CI) |
| TypeScript | `node ts/dist/interop/server.js` | `node ts/dist/interop/client.js` | the package's build (`ts/src/interop/*.ts`) |

On Windows the harness appends `.exe` to a plain binary path automatically when
the plain path is missing.

## 3. Running

```
node interop/run.mjs [--targets <file>] [--servers <l,l,...>] [--clients <l,l,...>]
                     [--scenario <id>] [--list] [--self-test]
```

- `--targets <file>` — targets file; default `interop/targets.json`. Run from
  anywhere: relative paths in the targets file resolve against the repo root.
- `--servers` / `--clients` — comma-separated language lists; default: all keys
  of the targets file.
- `--scenario <id>` — run one matrix scenario only (skips the sign/verify phases).
- `--list` — print every scenario id (with `fresh` and expected outcome/code)
  and every sign-case id, then exit 0.
- `--self-test` — validate the harness with the bundled fakes (section 8).

Exit codes: `0` everything passed; `1` any scenario/sign/verify failure;
`2` harness error (usage, missing or invalid contract files, unknown language or
scenario, missing target binary — the message names the pair role, e.g.
`client=go`, and the resolved path, including the Windows `.exe` resolution).

Output: a `== pair client=<c> server=<s> ==` header, then one `PASS <id>` or
`FAIL <id>` line per scenario; on failure a detail block (scenario, pair,
expected, actual, client exit code, stderr tail). After each pair a
`pair <label>: <passed>/<total>` summary. Then `== sign phase ==` and
`== verify phase ==` lines, a final matrix table (`pass` / `fail:<n>` per cell),
and `matrix: all pairs pass` or a failure count across pairs.

Examples:

```
node interop/run.mjs                       # full matrix, all pairs
node interop/run.mjs --clients go --servers rust
node interop/run.mjs --scenario ping
```

Kill semantics: the harness kills only the child PIDs it spawned (via
`child.kill()`), never processes by image name.

## 4. `interop-server` contract

```
interop-server --aud <aud> --policy <file> --state <file> --server-seed-hex <64 hex>
               [--bootstrap-ttl <seconds>] [--verify-only]
```

Readiness: the server binds `127.0.0.1:0` (plain HTTP) and prints exactly one
stdout line
`{"ready":true,"port":<n>,"server_public_key":"<b64u>","server_kid":"<kid>"}`
— parse-ready JSON, nothing else on stdout ever; stderr is free-form. The
harness ready-timeout is 10 s.

Lifecycle: exit 0 on SIGTERM or stdin EOF; nonzero on startup failure (bad
flags, unreadable state or policy file).

State file: the SDK `FileState` on-disk format
`{"version":1,"keys":[<registry entries as in spec/fixtures/registry.json,
without any aud field>],"invites":[]}`. The harness converts
`spec/fixtures/registry.json` to this shape per run; the aud travels via
`--aud`. The server loads it strictly like `server/statefile.go`: unknown
fields, duplicate kid/name and invalid entries are rejected at load.

Policy file: the harness writes `spec/fixtures/policy.json` with exactly one
additional rule inserted at index 2:

```json
{ "match": { "method": "tools/call", "tool": "echo" }, "scope": null }
```

Without it the `echo` tool is denied by the fixture policy. The composed file is
the fixture policy with that rule spliced in; all other rules unchanged. The
server MUST use the spec default time window (30 s).

`--bootstrap-ttl`: creates one admin invite via the SDK's `BootstrapAdmin` and
prints `{"bootstrap_invite":"<code>"}` on stderr. The harness does NOT use it —
scenarios create invites through the protocol (root signs
`jack.admin.invite.create`).

Fixed MCP handler (same in every language), exact bodies:

| Input | Response body |
|---|---|
| `ping` | `{"jsonrpc":"2.0","id":<id>,"result":{}}` |
| `tools/list` | `{"jsonrpc":"2.0","id":<id>,"result":{"tools":[{"name":"echo"}]}}` (the shape beyond the single `echo` entry is unpinned; no scenario calls `tools/list`) |
| `tools/call` of `echo` | `{"jsonrpc":"2.0","id":<id>,"result":{"content":[{"type":"text","text":<arguments.text verbatim>}]}}` |
| `tools/call` of `logs.tail` or `config.set` | `{"jsonrpc":"2.0","id":<id>,"result":{"content":[{"type":"text","text":"ok"}]}}` (both are unmapped by the harness policy, so they answer `403 operation_denied` before reaching this code — they exist to prove deny-by-default) |
| any other method | `{"jsonrpc":"2.0","id":<id|null>,"error":{"code":-32601,"message":"method not found"}}` |
| `GET /sse` | the wrapped handler answers `Content-Type: text/event-stream`, writes exactly one SSE event (`data: hello` followed by a blank line) and closes the connection within 1 second; the wrapper refuses the event-stream answer and responds instead with the signed `501 {"error":{"code":"streaming_unsupported",...}}` |
| any other signed GET | accepted by authentication, answered with `{"jsonrpc":"2.0","id":null,"result":{}}` (not exercised by scenarios) |

Response signing: every response after successful authentication carries the
spec 01 section 5 response `Jack-Auth` header — including authorization
rejections, 400/403/404/409 tool errors, the 501 streaming refusal, and
`-32601` answers. Responses to requests that failed authentication (steps 1–8)
may be unsigned (spec 01 section 5; clients tolerate both).

`--verify-only` (no listening): reads exactly one JSON object from stdin
`{"method":"POST","target":"/mcp","jack_auth":"v1 kid=...,ts=...,nonce=...,sig=...","body_b64u":"..."}`
and performs request-auth steps 1–4 and 7 of spec 01 section 4 (header grammar,
version, kid lookup in the state file, strict Ed25519 signature over the
signing string built from `--aud`, method, target, exact body bytes). Steps
5/6/8 (key validity, time window, nonce) are skipped because the sign cases use
fixed `ts` values 0 and 999999999999. It prints one stdout line
`{"verify":"accept","kid":"<kid>"}` or `{"verify":"reject","code":"<code>"}`
and exits 0 either way.

## 5. `interop-client` contract

```
interop-client --url <base-url> --seed-hex <64 hex> --server-public-key <b64u>
               --aud <aud> --scenario <name> [--seeds <file>] [--ts <n>]
               [--nonce <b64u>] [--arg k=v]...
```

Exactly one JSON object as the last stdout line, exit 0 on a completed
scenario:

```json
{"scenario":...,"outcome":"ok"|"rejected"|"client_error","http_status":<n|null>,"code":"<string|null>","data":<object|null>}
```

- `ok` — server accepted and the response signature verified: http_status 200,
  code null, data = the JSON-RPC `result` member verbatim.
- `rejected` — server rejected: http_status and code from the wire, data null.
  The client MUST verify the response signature of EVERY response EXCEPT
  answers to requests that failed authentication; the unsigned-allowed set is
  exactly the 401 family with the authentication codes of spec 01 section 4
  (`missing_auth`, `malformed_auth`, `unsupported_version`, `unknown_key`,
  `key_inactive`, `timestamp_out_of_window`, `bad_signature`,
  `replayed_nonce`). Any other response — every 2xx, and 400/403/404/409/501 —
  MUST carry a valid signature; a missing or invalid signature there is a
  `client_error` (per spec 01 section 5, an absent header is `missing_auth`).
  Non-2xx with a verified signature still reports the wire status and the code
  from the `{"error":{"code"}}` body.
- `client_error` — client-side response verification failure per spec 01
  section 5: http_status null, code = the client-side code, data null. The
  client MUST NOT treat an unsigned or unverifiable response as `ok`.

Exit 1 only for harness-level failure (cannot connect, crash): reason on
stderr, no JSON.

- `--seeds <file>` — the harness always passes the path of
  `spec/fixtures/keys.json` itself (read-only; it is not copied); multi-step scenarios sign individual steps with
  identities from that file. `--seed-hex` is the PRIMARY identity and matches
  the scenario's `identity` in `scenarios.json`.
- `--ts <n>`, `--nonce <b64u>`, and `--arg method=.. --arg target=..
  --arg body-b64u=..` are used only by `sign-only`, which never touches the
  network and ignores `--url` / `--server-public-key`. Its output is outcome
  `ok`, http_status null, code null, and
  `data = {"signing_string":<8 LF-joined lines>,"jack_auth":"v1 ...","kid":"..."}`.

Multi-step scenarios: steps run in the order documented in `scenarios.json`
`steps`. A failing INTERMEDIATE step yields outcome `client_error` with that
step's http_status/code and `data = {"step":<0-based index>}`, still exit 0
(the harness compares and fails the pair). The FINAL step's result is what the
harness compares against the scenario's `expected`.

## 6. Scenarios

`scenarios.json` is normative. `fresh` scenarios (state change expected) run
against a server started from a pristine per-scenario state file; a scenario
with `registry_overrides` (key-not-yet-valid) also gets a dedicated server,
because the override must be baked into that server's state file; all others
share one server per (client, server) pair.

| Scenario | fresh | Identity | Outcome | HTTP | Code | Proves |
|---|---|---|---|---|---|---|
| `ping` | no | alice | ok | 200 | null | signed request/response round trip |
| `echo` | no | alice | ok | 200 | null | non-ASCII body bytes hash and round-trip identically |
| `whoami` | no | alice | ok | 200 | null | native-tool `structuredContent` shape |
| `denied-tool` | no | alice | rejected | 403 | insufficient_scope | a `read` key calls `svc.config.set` |
| `unmapped-tool` | no | alice | rejected | 403 | operation_denied | tool matching no policy rule is denied by default |
| `unknown-key` | no | mallory | rejected | 401 | unknown_key | valid key not in the registry |
| `replay` | no | alice | rejected | 401 | replayed_nonce | exact re-send of accepted bytes |
| `clock-skew` | no | alice | rejected | 401 | timestamp_out_of_window | ts = now − 120 s (30 s window) |
| `tampered-body` | no | alice | rejected | 401 | bad_signature | one body byte changed after signing |
| `bad-server-key` | no | alice | client_error | null | unknown_server_key | client pins a wrong server key, response untrusted |
| `expired-key` | no | frank | rejected | 401 | key_inactive | registry entry with `not_after` in the past |
| `key-not-yet-valid` | no | erin | rejected | 401 | key_inactive | `not_before` shifted to now + 3600 s via `registry_overrides` |
| `stream` | no | alice | rejected | 501 | streaming_unsupported | `GET /sse` refused |
| `agent-admin` | no | agentx | rejected | 403 | insufficient_scope | agent key calls an admin native tool |
| `invalid-request` | no | alice | rejected | 400 | invalid_request | valid signature, unparseable body |
| `unknown-native-tool` | no | root | rejected | 403 | operation_denied | undefined `jack.`-prefixed tool |
| `enroll` | yes | newbie | ok | 200 | null | invite → enroll → whoami with the new key |
| `enroll-used-invite` | yes | newbie2 | rejected | 403 | invalid_invite | single-use invite |
| `rotate` | yes | alice | ok | 200 | null | rotation with proof, old key dead, new key works |
| `admin-create` | yes | newbie2 | ok | 200 | null | admin creates user + invite, new user enrolls |
| `revoke-key` | yes | bob | rejected | 401 | unknown_key | revoked key is removed from the registry |
| `last-admin` | yes | root | rejected | 409 | last_admin | demoting the last admin |

### Multi-step scenarios

Every step with its signing identity (all identities are names from
`spec/fixtures/keys.json`); steps marked *intermediate* must succeed — a
failing one yields `client_error` with that step's status/code:

- `enroll` (fresh; primary identity `newbie`):
  1. `root` signs `jack.admin.invite.create` `{"scopes":["read"]}` — must
     succeed (intermediate); the client takes `result.structuredContent.code`.
  2. `newbie` (its NEW key) signs `jack.enroll`
     `{"code":<code>,"name":"newbie","public_key":<newbie public key>}` — must
     succeed (intermediate).
  3. `newbie` signs `jack.whoami` (reported).
- `enroll-used-invite` (fresh; primary identity `newbie2`):
  1. `root` signs `jack.admin.invite.create` `{"scopes":["read"]}` → code
     (intermediate).
  2. `newbie` signs `jack.enroll` with that code, name `"newbie"` — must
     succeed (intermediate; consumes the invite).
  3. `newbie2` signs `jack.enroll` with the SAME code, name `"newbie2"`
     (reported; must be 403 `invalid_invite`).
- `rotate` (fresh; primary identity `alice`):
  1. `alice` signs `jack.key.rotate`
     `{"public_key":<newbie public key>,"proof":<newbie's Ed25519 signature
     over `mcp-jack/v1/rotate`, aud, alice kid, newbie kid, header ts,
     LF-joined, no trailing LF>}` — must succeed (intermediate).
  2. the OLD alice key signs `jack.whoami` — must be rejected 401
     `unknown_key` (intermediate).
  3. the NEW key (newbie seed) signs `jack.whoami` (reported; name/scopes
     kept).
- `admin-create` (fresh; primary identity `newbie2`):
  1. `root` signs `jack.admin.invite.create` `{"scopes":["read"]}` → code
     (intermediate).
  2. `root` signs `jack.admin.user.create`
     `{"name":"dave","public_key":<newbie2 public key>,"scopes":["read"]}` —
     must succeed (intermediate).
  3. `newbie` signs `jack.enroll` with the code, name `"newbie"` — must
     succeed (intermediate).
  4. `newbie2` seed signs `jack.whoami` (reported; registered as `dave`).
- `revoke-key` (fresh; primary identity `bob`):
  1. `root` signs `jack.admin.user.revoke` `{"kid":<bob kid>}` — must succeed
     (intermediate).
  2. `bob` signs `jack.whoami` (reported; must be 401 `unknown_key`).

Single-step scenarios with internal mechanics: `replay` re-sends the exact
accepted request bytes and reports the SECOND response; `tampered-body` signs
the `svc.restart` body then replaces the final byte `0x7D` with `0x7C`;
`clock-skew` signs with `ts = now − 120 s`; `bad-server-key` pins mallory's
public key (scenario field `server_public_key`) and reports the client-side
verification failure.

Notes:

- `registry_overrides` is used only by `key-not-yet-valid`:
  `{"erin":{"not_before":"now+3600"}}`; the harness computes now + 3600 s at
  run time and writes a dedicated state file for that scenario.
- `server_public_key` defaults to the ready line's key; `bad-server-key` sets
  it to `mallory` so the client fails response verification client-side.
- Expected `data` is matched as a subset: objects must recursively contain
  every expected key with an equal value, arrays must deep-equal, null is
  exact. An expected string `{"$kid":"<name>"}` resolves at run time to that
  fixture identity's kid.

## 7. Byte-exactness phase

`sign-cases.json` holds 8 cases — `empty-body`, `ascii-body`, `utf8-body`,
`nul-newline-body`, `query-target`, `long-target`, `ts-min` (`ts=0`),
`ts-max` (`ts=999999999999`) — across identities alice/bob/carol, with fixed
nonces. Each case pins `id`, `identity`, `method`, `target`, `aud`, `ts`,
`nonce`, `body_b64u` and `expected {kid, signing_string, jack_auth}`. The
oracle is generated by `node interop/tools/gen-sign-cases.mjs`; `--check`
verifies the file is up to date (like `spec/tools/gen-fixtures.mjs`).

The harness runs:

1. **Sign phase**: `--scenario sign-only` for every case × every selected
   language, requiring exact equality with the oracle and across languages.
2. **Verify phase**: for every (signing language, verifying server language)
   pair, each case is fed through the server's `--verify-only` expecting
   `accept` with the oracle kid, plus one tampered control per pair
   (`ascii-body` with its final body byte XOR 0x01, same header), which must
   reject with `bad_signature`.

## 8. Self-test

```
node interop/run.mjs --self-test
```

Validates the harness without any SDK, using `tools/fake-server.mjs` and
`tools/fake-client.mjs` as a pseudo-language `fake`. It prints one
`self-test: <what>` line per check, then `self-test: ok (16 checks)`, and
exits 0:

1. `self-test: matrix+sign+verify phases pass with fakes (0 failures)`
2. `self-test: exactly 3 servers spawned (shared + fresh last-admin + dedicated override key-not-yet-valid), got 3`
3. `self-test: sign phase ran for 1 language, 8 cases`
4. `self-test: sign phase ran 8 sign-only invocations (1 language x 8 cases)`
5. `self-test: override negative control: without registry_overrides key-not-yet-valid fails`
6. `self-test: negative control exits 1 (got 1)`
7. `self-test: negative control prints FAIL`
8. `self-test: exit-2 control exits 1 (got 1)`
9. `self-test: exit-2 control prints FAIL`
10. `self-test: verify-exit-2 control exits 1 (got 1)`
11. `self-test: verify-exit-2 control prints FAIL verify`
12. `self-test: unsigned-403 control exits 1 (got 1)`
13. `self-test: unsigned-403 control reports client_error`
14. `self-test: unsigned-403 control reports missing_auth`
15. `self-test: blank-ready control exits 0 (got 0)`
16. `self-test: blank-ready control prints PASS ping`

Checks 6–16 are negative controls run in subprocesses: the deviating fake
client (check 6–7) and the exit-2 client (8–9, a matching JSON result with a
nonzero exit must still be a harness failure) are driven by env hooks, as is
the verify-only server that prints a correct verdict but exits 2 (10–11) and
the unsigned authenticated 403 (12–14: an authenticated 403 without a
signature must surface as `client_error`/`missing_auth` and fail the pair).
Checks 15–16 feed the ready line through the blank-line mode.

The fakes implement a deliberate subset (fake-client: real signed round trips
for `ping`, `denied-tool` and `key-not-yet-valid` — the latter's outcome
depends on the `not_before` the fake server reports from its state file,
threshold now + 300 s — plus hardcoded `last-admin` and `sign-only` with real
crypto; fake-server: answers `jack.whoami` from its state file, signed 403s
`svc.config.set`, always-ok otherwise, real response signing, real
`--verify-only`). They are NOT reference implementations.

The env hooks `JACK_READY_MODE` (`split`/`blank`), `JACK_SELFTEST_EXIT2`,
`JACK_SELFTEST_VERIFY_EXIT2`, `JACK_UNSIGNED_403` and
`JACK_SELFTEST_DEVIATE` exist only to drive these controls. The self-test
runs with `JACK_READY_MODE='split'`, so ready lines are exercised as two
chunks.

## 9. How to add a language

1. Implement `interop-server` and `interop-client` from sections 4, 5, 6 and 7
   against your SDK.
2. Add a `targets.json` entry: `"<lang>": {"server":[...], "client":[...]}`.
   Relative paths resolve against the repo root; bare commands are looked up on
   PATH.
3. Run `node interop/run.mjs --self-test` first, then your pair
   (`--clients <lang> --servers <lang>`).
4. CI builds the six executables then runs `node interop/run.mjs` (one job
   `interop` after the language jobs, per design doc section 7).

## 10. Determinism notes

- Live scenarios use real clocks and random nonces; all processes share the
  machine clock, and the server window is the spec default 30 s. `clock-skew`
  signs with `ts = now − 120 s`.
- `sign-only` injects fixed `ts` and `nonce` from `sign-cases.json`.
- Ports and temp directories are per run; the harness never stores key material
  outside what it reads from `spec/fixtures` at run time.
