# Conformance tests

The current top-level v0.1 case index is [`CASES.md`](CASES.md). Passing cases is a contract definition, not evidence that these docs or this worktree passed tests. The existing Jack 3×3 interop matrices cover SDK request/response and credential transfer; they are distinct from candidate runner/generator machinery and the future official MCP integration profile.

Task57 candidate profile prose is [`../candidate/README.md`](../candidate/README.md), [`../candidate/durable-nonces.md`](../candidate/durable-nonces.md) and [`../candidate/server-key-rotation.md`](../candidate/server-key-rotation.md). Its separate fixture/test/generator/index/CI routes do not feed this current runner contract. Candidate fixture expectations are source-stated data, not current conformance or cryptographic proof. No executable checks were run for this docs change.

| Top-level current v0.1 file | What it checks |
|---|---|
| `fixtures/request-vectors.json` | One request through authentication and dispatch, including protocol-native tools and verified caller identity on forwarded accepts |
| `fixtures/admin-vectors.json` | Ordered state-changing sequences: enrollment, user-key rotation, users and invites |
| `fixtures/response-vectors.json` | Client verification of signed responses against the configured static server pin |
| `fixtures/key-vectors.json` | Public-key validity (strict Ed25519 keys) |
| `fixtures/load-vectors.json` | Load-time validation of registry documents |
| `fixtures/state-file-vectors.json` | Load-time validation of current state files, including explicit rejection of legacy `kind`/`scopes` documents |
| `fixtures/keys.json` | Test-only keys: `seed_hex`, `public_key`, `kid` |
| `fixtures/registry.json` | Default registry referenced by request vectors |

## Runner rules

The rules and tables below describe only the current top-level v0.1 runner contract. Nested candidate fixtures and candidate test files are outside this case set.

- **Inject the clock.** `state.now` is the current time in every case. Never read the wall clock.
- **Cases are independent.** Rebuild state for every case. Within a sequence, steps share state in order.
- **Bytes are exact.** `body_b64u` is the request body, unpadded base64url. `body_text` and `debug` are informative only.
- **Duplicate members are normative.** Some request bodies repeat a member name, including `dup-*`, `invite-create-arguments-dup-*` and `invite-create-ttl-dup-*` cases. The last occurrence wins; occurrences are not merged (02 section 2). The signature still covers the exact duplicate-bearing bytes.
- **Header names are case-insensitive.** `headers` is a list of `[name, value]` pairs so repeated headers are representable.
- **Identity on forwarded accepts.** An accept forwarded to the wrapped handler carries `expect.identity` `{kid, name, admin}`, the verified identity snapshot required by 02 section 3. Native `jack.*` calls carry native result data, not forwarded identity. A runner with a wrapped-handler hook compares the identity actually handed off.
- **Current nonce model.** `state.nonce_cache` supplies in-memory entries `{kid, nonce, retain_until}`. A request that passes authentication consumes its nonce before later authorization/dispatch refusal; malformed/authentication failures and live replays do not record a new nonce. These vectors do not assert durable storage or restart protection.

## Request vectors

File shape: `{ "registry": "registry.json", "cases": [...] }`.

| Case field | Meaning |
|---|---|
| `state` | `now`, `window_seconds`, `aud` and initial `nonce_cache` entries `{kid, nonce, retain_until}`. Invites start empty. |
| `request` | `method`, `target`, `headers`, `body_b64u`. |
| `expect` | `result` (`accept` or `reject`); accepts include `kid`, native `structured` content and/or forwarded `identity` where applicable; rejects include exact `http_status` and `code`. |
| `debug` | Informative signing string, line by line. Tamper cases intentionally differ from the string recomputed by a verifier. |
| `nonce_recorded` | Whether this request inserted a new current in-memory nonce. Post-authentication native/dispatch refusals consume it; earlier failures and replays do not. |
| `audit` | For a native call that reached an audited tool: `{tool, outcome, code, actor_kid}`; compare using an implementation audit hook. |

## Sequences (`admin-vectors.json`)

Each sequence in the top-level current-v0.1 `admin-vectors.json` starts from registry entries, stored invite records, in-memory `nonce_cache`, clock and `aud`. Run its ordered steps against shared state. Each step has a request, expectation and `after` summary:


- `users`: full registry entries `{kid, public_key, name, admin, not_before, not_after}`, sorted by `name`;
- `invites`: stored records `{invite_id, admin, created_by, created_at, expires_at, key_ttl_seconds?}`, sorted by invite-id text then `created_at` (implementation-created IDs use `"<b64u43>"` placeholder).

The `after` summary covers registry/invite state only. A rejected step leaves that state unchanged; this does not imply nonce rollback: a successful-authentication refusal consumes the in-memory nonce under current runner rules. Random implementation-created invite codes use `"<b64u43>"`; seeded invite codes are deterministic. `enroll-replay` resends identical request bytes and nonce. Current top-level fixtures and `CASES.md` were not changed by this documentation update.

## Public-key, registry and state-file vectors

`key-vectors.json` has `{ "cases": [...] }` for current top-level v0.1 public-key admission; reasons are informative and cases include noncanonical/off-curve/small-order/mixed-order/wrong-length keys. `load-vectors.json` checks current registry-document validity, including named legacy `kind`/`scopes` rejection and strict boolean `admin`.

## Response vectors (current v0.1)

`response-vectors.json` uses a fixed configured server pin; it does not model rotation or pin updates. Each top-level case has state (`now`, `window_seconds`, `pinned_server_kid`, `pinned_server_public_key`, `request_sig`), a response (`status`, `headers`, `body_b64u`), and expected accept/reject. Candidate response/rotation payloads are separate inputs and are not covered by this schema.

## Current key and signature checks

For every key in the top-level `keys.json`, a runner MUST confirm the Ed25519 public key derived from `seed_hex` equals `public_key` and `kid` equals `base64url(SHA-256(public_key))`. Fixture keys derive from public strings and are test-only. Ed25519 signatures are deterministic; a runner SHOULD re-sign `debug.signing_string_lines` (joined with LF) for accepted request cases and compare the header `sig`. Byte-identical signatures are useful cross-language evidence, but these key vectors alone do not demonstrate all verifier edge-case agreement. Preserve the strict Ed25519 contract.

## Adding cases

The existing top-level `tools/gen-fixtures.mjs` and `tests/CASES.md` are the current v0.1 generator/index route. The separate Task57 candidate generator/checker writes nested `fixtures/candidate/` data and has a generated candidate-index destination under `tests/candidate/`; its source-stated outcomes are not current fixture vectors or generated cryptographic proof. The existing v0.1 generator/check was not run for this documentation update. No top-level v0.1 cases or fixture files were changed.

## Current top-level runners

| Language | Runners |
|---|---|
| Go | `spec/*_test.go` and package tests in `server/` and `client/` |
| Rust | `rust/tests/*conformance.rs`, `rust/tests/state_file.rs` and `rust/tests/client_*.rs` |
| TypeScript | `ts/test/*.test.ts` (current vectors read from top-level `spec/fixtures`) |

The current Jack 3×3 request/response and credential-transfer matrices are existing SDK interop surfaces. They are separate from Task57 candidate machinery and proposed official MCP client → bridge → gateway → server compatibility. Neither surface is test evidence for these documentation edits.
