# Scope reduction: implementation plan (2026-11-08)

Companion to [scope-review-2026-11-08.md](scope-review-2026-11-08.md). The review decided the direction; the specification, the fixture generator, the reference tools and the conformance docs are authored against it, while the generated fixture bytes remain parent-owned CI materialization, pending. This document is the implementable plan for the remaining SDK, interop and consumer tasks.

## 1. What this task authored

Work-plan step 1 of section 6 of the scope review: the reduced contract is written into the normative text, the fixture generator and the reference tools; the generated fixture files themselves are not written yet — CI materializes them from the generator and that integration is pending. Deleted: `spec/04-service-management-profile.md`, `spec/fixtures/policy.json`, `spec/fixtures/policy-wildcard.json`, `spec/fixtures/pattern-vectors.json`.

- `spec/01-authentication.md`, `spec/02-authorization.md`, `spec/03-user-management.md`, `spec/README.md` — the reduced contract (no `kind`, scopes or policy engine; the `admin` flag; verified caller identity hand-off).
- `spec/tools/reference-verifier.mjs`, `spec/tools/gen-fixtures.mjs` — reference verifier and generator for the reduced contract; the generator builds full independent expectations and requires the reference verifier to agree on every field.
- `spec/fixtures/`: the generator authors `keys.json`, `registry.json`, `request-vectors.json`, `admin-vectors.json`, `response-vectors.json`, `key-vectors.json`, `load-vectors.json` (registries only) and the new `state-file-vectors.json`; the on-disk bytes are still the pre-reduction ones until the parent integrates the CI materialization.
- `spec/tests/README.md` — the conformance runner contract for the new fixture set (including the `expect.identity` rule).
- `.github/workflows/spec-fixtures.yml` — CI-only materialization of the generated fixtures (ci.yml untouched).

## 2. Owner-decided directions

From the scope review only; no further decisions are introduced here.

- Removals: user `kind`, scopes (grammar and the reserved `admin` scope), the policy engine (document, patterns, `tools/list` filtering), the service-management profile (`spec/04`, README principle 8), README principle 7 (agents and log scopes).
- One strict boolean `admin` per user gates only the `jack.admin.*` tools and nothing else; ordinary MCP traffic is never gated.
- `jack.admin.user.set_scopes` is replaced by `jack.admin.user.set_admin {kid, admin}`.
- `jack.admin.user.create` and `jack.admin.invite.create` carry an optional `admin` flag (default `false`) instead of `scopes` and `kind`; enrollment inherits the invite's flag.
- Identity hand-off `{kid, name, admin}` to the wrapped handler exists in Go (request context), Rust (request extension) and TypeScript (request property).
- No compatibility window: v0.x, no release, no known deployment. Legacy state files with `kind` or `scopes` are rejected, never migrated.
- Server key rotation is decided (announced next key signed by the current key); design pending, NOT this task.
- The v0.2 session channel direction, and the Q1 reasoning record: message AUTHENTICATION (per-request Ed25519 signature plus nonce, what v0.1 does) and CONFIDENTIALITY (TLS today) are distinct properties; ChaCha20-Poly1305 over a Noise-style handshake is the chosen future direction. It is NOT implemented and NOT sufficiently specified in this task. No channel, cluster or server-key-rotation implementation belongs to this task.

## 3. Minimal design choices made here

- `403 admin_required` replaces `insufficient_scope` for the admin gate: the old name references removed scopes; the new name discriminates old implementations.
- Any administrator may administer any entry; the only protection is last-admin: the scope-holding target and escalation rules had no meaning without scopes.
- Unknown tool-argument members are inert while known mistyped members fail closed: this matches the last-wins argument model and cannot escalate (a stale `scopes` member does nothing; a mistyped `admin` is `400 invalid_params`).
- `admin` is optional and defaults to `false` in documents and arguments, REQUIRED and strict-boolean in `set_admin`, and always present in tool results.
- Registry and state-file legacy rejection names the offending member and never rewrites the file (02 section 1, 03 section 10).
- The v0.1 `501 streaming_unsupported` refusal is now stated in the spec itself (02 section 2) instead of only in interop and product docs.
- Request vectors carry `expect.identity` only on forwarded accepts; native `jack.*` accepts carry `kid` and `structured` without identity, since native calls never reach the wrapped handler.
- Fixture enrollment flows use seeded invites only (fixed codes, exact bytes), so no runner-side code substitution exists.

## 4. Non-goals of this task

- No channel, cluster or server-key-rotation implementation.
- No product Go, Rust or TypeScript SDK, interop, consumer, manifest or dependency edits.
- No shared CI check edits; `ci.yml` is untouched.
- No release, tag or publication.
- No MSRV, Go or Node version changes.

## 5. Acceptance map

Each contract requirement, its normative home, and the vectors that discriminate it. All ids are generated case ids in the fixture files.

| Requirement | Normative home | Discriminating vectors |
|---|---|---|
| `admin` defaults to false when omitted | 02 s1 | `registry.json` omits `admin` for non-admins; `valid-admin-omitted`; the `whoami-nonadmin`/`whoami-admin` request cases |
| Strict boolean / null / string admin | 02 s1, 03 s3 | load `invalid-admin-number`, `invalid-admin-string`, `invalid-admin-null`; `admin-set-admin-invalid-params`; `admin-create-admin-mistyped`; statefile `statefile-invalid-admin-string` |
| Unknown/mistyped fields cannot escalate | 03 s3 | `admin-create-stale-members-inert`; the `dup-*` argument cases; load/statefile unknown-field cases |
| Non-admin denial with `admin_required` | 02 s2, 03 s7 | `admin-gate-nonadmin`; `admin-user-list-requires-admin` |
| Invite privilege inheritance | 03 s3.2 | `enroll-admin-invite`; `invite-create-admin-invite`; `enroll-ok` (default false) |
| Rotation preserves admin | 03 s3.1 | `rotate-preserves-admin` |
| Last-admin protection, incl. serialized concurrent semantics | 03 s4, s9 | `admin-set-admin-last-admin`; `admin-set-admin-serialized-strip`; `admin-revoke-last-admin`; `admin-last-admin-counts-active-only` |
| Malformed RPC, UTF-8 and duplicates preserved | 01, 02 s2 | `malformed-*`; `request-*`; `dup-*`; `sig-*`; `replay-*` |
| Ordinary MCP pass-through (counterfactual to the old deny-by-default) | 02 s2 | `accept-ordinary-tool-any-key`; `accept-unmapped-tool-forwarded`; `accept-unmapped-method-forwarded`; `accept-proto-tool-name-forwarded` |
| Reserved native dispatch incl. undefined refusal | 02 s2, 03 intro | `unknown-native-tool` (also `admin-unknown-native-tool`) → `operation_denied` |
| Identity hand-off on forwarded accepts | 02 s3; `spec/tests/README.md` runner rules | the `expect.identity` rule; `accept-admin-identity` and the other forwarded accepts |
| Legacy state-file rejection, no migration | 03 s10 | `statefile-invalid-legacy-kind-entry`, `statefile-invalid-legacy-scopes-entry`, `statefile-invalid-legacy-kind-invite` |
| Response and key vectors unchanged | 01 | `res-*`; `valid-*` / `reject-*` |
| Independently trusted credential import untouched | `docs/design/user-keys.md` | `spec/fixtures/user-key-transfer.json` is hand-maintained; its envelope `kind` is a different field, unaffected |
| Independent expectation postconditions (identity, structured, audit, nonce, state; rejection nonmutation) | `spec/tests/README.md` runner rules; generator expectation model (full durable registry/invite state) | every sequence step's `after` (rejected steps' `after` equals the pre-step state); `expect.identity`/`structured`/`audit` compared field-by-field, not snapshot-copied |
| Default-invite persistence round trip (key_ttl_seconds absent vs null) | 03 s3.3, s10 | `statefile-valid-default-invite`; `statefile-invalid-invite-ttl-null`; serialize-decode-reader persistence check on every sequence; `statefile-valid-invite-ttl-max`, `statefile-invalid-invite-ttl-zero`, `statefile-invalid-invite-ttl-above-max` |
| Q1 corrected: authentication and confidentiality distinct, channel future | scope review section 3 Q1 | the corrected analysis paragraph; plan section 2 Q1 record |

## 6. Cross-scope consequences (named, not edited here)

The concrete list for the SDK, interop and consumer tasks. Until the SDK tasks land, the Go, Rust, TS, interop and consumer jobs and the spec package tests are expected to be red. No green claim is made here: the generator has not been run locally (by design), and CI materialization, the `--check` gate and all validation are parent-owned and pending.

- **Go** — `spec/spec.go` typed loaders (`PolicyDocument`/`PatternCases`/`Kind`/`Scopes` fields must go; add state-file case loading for `state-file-vectors.json`); `spec/fixtures_test.go` and `spec/statefile_loader_test.go`; delete `server/policy.go` and the scope/pattern helpers in the root package; `server/native.go` (`set_scopes` → `set_admin`, the `admin_required` gate, `whoami`/enroll/admin results without `kind`/scopes); `server/state.go` and `server/statefile.go` (legacy rejection per 03 s10); `client/tools.go`; the affected Go tests: `server/policy_test.go`, `server/middleware_test.go`, `server/verify_test.go`, `server/response_cap_test.go`, and `client/*_test.go` files that reference policy fixtures.
- **Rust** — delete `rust/src/server/policy.rs`; `native.rs`, `state.rs`, the client tools; remove `tests/policy_conformance.rs` and `tests/patterns_conformance.rs`; `tests/state_file.rs` now consumes `state-file-vectors.json`; also `rust/tests/fixtures_load.rs`, `rust/tests/common/fixtures.rs`, `rust/tests/admin_conformance.rs`, `rust/tests/http_layer.rs`.
- **TypeScript** — `ts/src/server/policy.ts`, `native.ts`, `state.ts` (+ `state-file.ts`), the client tools; `ts/test/policy.test.ts`, `ts/test/native.test.ts` and the other affected tests; also the ts/test files that load policy/pattern fixtures (`ts/test/policy.test.ts`, `ts/test/fixtures-load.test.ts` and any other test reading the removed files).
- **Interop** — the scenarios `denied-tool`, `unmapped-tool` and `agent-admin` are removed or replaced; the policy files and the interop registry copy are dropped; `whoami` expectations lose `scopes`; new identity-hand-off scenarios (the state file in `interop.md` section 4 is `registry.json` without `aud` — the loader rules change with 03 s10); also `interop/run.mjs`, `interop/README.md` and `interop/scenarios.json` (the harness composes `spec/fixtures/policy.json`, which no longer exists).
- **Consumers** — the `tools/consumer/verify-*.mjs` scripts that reference admin tool names or scopes.
- **Docs** — `docs/readiness.md` and `docs/design/interop.md`/`rust-ts-server-sdks.md`/`user-keys.md` still describe draft v0.1 behavior (policy, scopes, `kind`); their remaining staleness is owned by the respective follow-up tasks, except the three section citations fixed alongside this plan (02 section 4 -> 02 section 2).

## 7. Parent CI materialization step

The generated bytes of this task were NOT produced locally (execution constraint), so they are unverified until CI materializes them. Procedure:

1. Run the `spec fixtures` workflow (`.github/workflows/spec-fixtures.yml`) on this branch.
2. Download the `spec-generated-fixtures` artifact.
3. Copy the eight JSON files over `spec/fixtures/` (`keys.json`, `registry.json`, `request-vectors.json`, `admin-vectors.json`, `response-vectors.json`, `key-vectors.json`, `load-vectors.json`, `state-file-vectors.json`), leaving `client-url-policy.json` and `user-key-transfer.json` untouched, and copy `CASES.md` over `spec/tests/CASES.md`.
4. Confirm the existing `ci.yml` `fixtures` job (`node spec/tools/gen-fixtures.mjs --check`) passes.

## 8. Still open

- Q1 channel details: transport, relationship with TLS, session lifetime and rekeying, replay protection inside a session.
- Q3 rotation details: announcement format and delivery, client persistence.
- Q5 clusters and cluster management.
- The README questions not covered by the review: local-only or remote services, third-party clients, service discovery.

The scope-review's "exact shape of the `admin` flag in tools and invites" item is settled by this contract: optional, default `false`, strict boolean in documents and arguments; REQUIRED and strict boolean in `set_admin`; always present in results and in invite records.
