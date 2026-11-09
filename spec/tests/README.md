# Conformance tests

An implementation (Go, Rust, TypeScript) conforms to spec v0.1 when its test runner passes every case in the files below. [CASES.md](CASES.md) is the generated index of all cases.

| File | What it checks |
|---|---|
| `fixtures/request-vectors.json` | One request through authentication and dispatch, including protocol-native tools and the verified caller identity on forwarded accepts |
| `fixtures/admin-vectors.json` | Ordered sequences of requests that change state: enrollment, key rotation, users, invites |
| `fixtures/response-vectors.json` | Client-side verification of signed responses |
| `fixtures/key-vectors.json` | Public-key validity (strict Ed25519 keys) |
| `fixtures/load-vectors.json` | Load-time validation of registry documents |
| `fixtures/state-file-vectors.json` | Load-time validation of the server state file, including explicit rejection of legacy `kind`/`scopes` documents |
| `fixtures/keys.json` | Test keys: `seed_hex`, `public_key`, `kid` |
| `fixtures/registry.json` | Default document referenced by the request vectors |

## Runner rules

- **Inject the clock.** `state.now` is the current time in every case. Never read the wall clock.
- **Cases are independent.** Rebuild state for every case. Within a sequence the steps share state in order.
- **Bytes are exact.** `body_b64u` is the request body, unpadded base64url. `body_text` and `debug` are informative only.
- **Duplicate members are normative.** Some bodies repeat a member name (the `dup-*`, `invite-create-arguments-dup-*` and `invite-create-ttl-dup-*` cases). The expected outcome assumes the last occurrence wins and the occurrences are not merged (02 section 2); a first-wins or merging parser fails them. The signature still covers the duplicate-bearing bytes exactly as sent.
- **Header names are case-insensitive**; `headers` is a list of `[name, value]` pairs so repeated headers are representable.
- **Identity on forwarded accepts.** When a request is forwarded to the wrapped handler — ordinary MCP methods, `tools/list`, `ping`, notifications, response objects, and `GET` — an accept carries `expect.identity` `{kid, name, admin}`: the verified caller identity the server SDK MUST hand to the wrapped handler (02 section 3), the snapshot as of verification. Accepts of native `jack.*` tool calls carry `kid` and `structured` and no identity. A runner with a wrapped-handler hook compares the identity its implementation handed off.

## Request vectors

File shape: `{ "registry": "registry.json", "cases": [...] }`. The registry is the file named at the top.

| Case field | Meaning |
|---|---|
| `state` | `now`, `window_seconds`, `aud` and `nonce_cache`: entries `{kid, nonce, retain_until}` already present. Invites start empty. |
| `request` | `method`, `target`, `headers`, `body_b64u`. |
| `expect` | See below. |
| `debug` | The signing string the generator signed, line by line. In tamper cases it differs from what a verifier recomputes; that is the point of the case. |

`expect`:

- `result`: `accept` or `reject`.
- On accept: `kid` (the caller); `structured` when the request was a protocol-native tool call (the `structuredContent` of its result); and `identity` `{kid, name, admin}` when the request was forwarded to the wrapped handler — the verified caller identity (02 section 3).
- On reject: `http_status` and `code`; both MUST match exactly.
- `nonce_recorded`: `true` when this request caused a new `(kid, nonce)` entry to be stored, which is when authentication succeeded, including requests rejected at the admin gate. `false` for earlier failures and for replays.
- `audit`, present for `jack.admin.*`, `jack.enroll` and `jack.key.rotate` calls that reached the tool: `{tool, outcome: "success" | "failure", code, actor_kid}`. A runner needs an audit hook in the implementation under test to compare it.

## Sequences (`admin-vectors.json`)

Each case has an initial `state` (`registry` as a list of entries, `invites` as stored invite records, `nonce_cache`, clock and `aud`) and ordered `steps`. Run the steps in order against the same state. Each step has `request` and `expect` as above plus `after`, a summary of the state after the step:

- `users`: every registry entry as a full entry `{kid, public_key, name, admin, not_before, not_after}`, sorted by `name`;
- `invites`: the stored invite records `{invite_id, admin, created_by, created_at, expires_at, key_ttl_seconds?}`, sorted by the invite_id text (implementation-created ids appear as the `"<b64u43>"` placeholder), then `created_at`.

Every step carries `after`; a rejected step's `after` equals the state before it: rejections do not mutate.

Invite codes are random in real servers, so expectations never contain them. A string in `structured` — and in `after` alike — equal to `"<b64u43>"` matches any canonical base64url string of 43 characters. Pre-seeded invites use fixed codes, derived in the generator as `base64url(SHA-256("seeded invite <label>"))`; their `invite_id` is `base64url(SHA-256(code_bytes))`.

A step with a repeated request (`enroll-replay`) re-sends the exact same bytes, so its nonce is the same as in the earlier step.

## Public-key vectors

`key-vectors.json`: `{ "cases": [{ "id", "public_key_hex", "expect": "valid" | "rejected", "reason" }] }`. Run the key validity check of 03-user-management section 2 on the raw bytes. `reason` is informative. The cases include non-canonical encodings, a point not on the curve, small-order points, a mixed-order point and wrong lengths.

## Load vectors

`load-vectors.json`: `{ "registries": [...] }`; each case has `document` and `expect: "valid" | "invalid"`, with an informative `reason`. A conforming loader rejects every `invalid` document and accepts every `valid` one. The invalid set includes the legacy rejections: an entry containing `kind` or `scopes` MUST be rejected with an error that names the offending member, and `admin` MUST be a strict JSON boolean (`true` or `false`) when present (02 section 1).

## State-file vectors

`state-file-vectors.json`: `{ "cases": [{ "id", "document", "expect": "valid" | "invalid", "reason?" }] }`. Run the load rules of 03-user-management section 10: a conforming server state-file loader accepts every `valid` document and rejects every `invalid` one. For the `legacy-*` cases the rejection MUST name the offending member and MUST NOT migrate, strip, reset or rewrite the file (03 section 10). `reason` is informative. A default invite (no `key_ttl_seconds`) persists and reloads; a record with `key_ttl_seconds` null is invalid. Boundary vectors cover a key TTL at the maximum, below the minimum, above it, absent, and null.

## Response vectors

Each case has `state` (`now`, `window_seconds`, `pinned_server_kid`, `pinned_server_public_key`, `request_sig`), `response` (`status`, `headers`, `body_b64u`) and `expect` (`accept`, or `reject` with `code`). `request_sig` is the `sig` of the request being answered.

## Key and signature checks

For every key in `keys.json` a runner MUST confirm that the Ed25519 public key derived from `seed_hex` equals `public_key` and that `kid` equals `base64url(SHA-256(public_key))`.

Ed25519 signatures are deterministic (RFC 8032), so a runner SHOULD also re-sign `debug.signing_string_lines` (joined with LF) of every `accept-*` request case with the key named by the header `kid` and compare with the `sig` in the header. Byte-identical signatures across Go, Rust and TypeScript are the strongest interoperability check.

## Adding a case

Add it to `tools/gen-fixtures.mjs` with the expected outcome. The generator builds the full expectation — result, `kid`, `structured`, `identity`, `audit`, `nonce_recorded` and `after` — from its own model of the case and requires the reference verifier to agree on every field; it refuses to write fixtures on any disagreement. After a sequence the generator also serializes the final durable state to state-file JSON text, decodes that text again, and requires the reference state-file reader to accept the decoded document; a rejected step must additionally leave the raw durable data — member presence included — unchanged. Regenerate, run `node tools/gen-fixtures.mjs --check`, and commit all generated files together.

## Where the runners live

| Language | Runners |
|---|---|
| Go | `spec/*_test.go` and the package tests in `server/` and `client/` |
| Rust | `rust/tests/*conformance.rs`, `rust/tests/state_file.rs` (state-file vectors), `rust/tests/client_*.rs` |
| TypeScript | `ts/test/*.test.ts` (fixtures are read from `spec/fixtures`) |

Cross-language behavior (every client against every server) is covered separately by [../../interop/README.md](../../interop/README.md).
