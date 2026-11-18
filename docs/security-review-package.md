# Security review package (v0.1.0)

**Status: internal, AI-assisted pre-review. This is NOT an independent audit.** The
release has not been independently audited. This document hands an external
reviewer the scope, the coverage of the internal pre-review, its findings with the
maintainers' disposition, the known divergences between the three SDKs, and the
open questions. Nothing here is a security guarantee.

A separate historical AI source review of later durable-store changes is recorded in [the independent-review document](independent-review.md#second-independent-review-historical-pre-fix-source-review). It was source-only, not a human or third-party audit; no project builds or tests were run, and the report discloses one interpreter invocation. Its coverage table records substantial unreviewed areas and the review did not read every test body; consult its coverage and dispositions, not a blanket audit claim.

How to read it:

- The pre-review was a read-only study of source and documents at commit
  `1822634` (before the documentation refresh). Nothing was built, run or fuzzed.
  Statements about third-party libraries (bbolt, serde_json, the `http` crate,
  OpenSSL, V8) and all cost figures are hypotheses, not measurements.
- Findings are the pre-reviewer's claims. The maintainers re-read the code for
  F-01, F-04 and F-07 and confirmed them; the others have not been re-verified.
- No critical or high finding was reported: no authentication bypass, response
  forgery or replay in the Go durable profile was found. The remaining risk is
  mainly availability and divergence between the SDKs.

## 1. Coverage of the pre-review

| Area | Read fully | Read partly | Not reached |
|---|---|---|---|
| Specification | `spec/01`, `spec/02`, `spec/03`, `spec/candidate/durable-nonces.md`, `spec/candidate/server-key-rotation.md`, `docs/protocol-transition.md`, `docs/threat-model.md`, `SECURITY.md` | `spec/candidate/README.md` | `docs/design/server-key-rotation.md`, `docs/design/durable-nonce-backend.md` |
| Go root, `server/`, `rotation/`, `durable/`, `client/`, `client/rotation/` | almost all (not `durable/layout.go`) | `client/rpc.go` (start) | `client/{tools,profile,errors}.go`, rest of `client/rpc.go`, `userkey/{key,transfer}.go` bodies |
| Go `internal/cli/` | gateway, storage, connection, bridge, run, keys, nonce and server-key commands, admin RPC and invite file | `docs/design/cli.md` | most `admin*.go` |
| Rust | `rotation/{record,result,json_object,mod,private_file,store}.rs`, most of `rotation/server_provider.rs` | `server/verify.rs`, `server/http.rs`, `server/nonce.rs`, `auth_header.rs`, `ed25519.rs`, start of `rotation/server_key.rs` | `server/{native,state,state_file}`, `client/*`, `rotation/{chain,page,controller,trust*,server_state*,server_store*,store_format,sign}`, `user_key.rs` |
| TypeScript | none in full | `ed25519.ts`, `auth-header.ts`, `json-raw.ts`, `server/{verify,fetch,node}.ts`, `rotation-file.ts`, `server/server-key-tool.ts` | `client/*`, other `rotation-*`, `server/{native,state,state-file,nonce}`, `user-key*` |
| Tests, fixtures, tooling | none | list of CI jobs only | all tests, `spec/fixtures/**`, `spec/tests/**`, `interop/**`, `tools/**`, CI results |

An external review should cover at least everything in the "not reached" column
and the Rust and TypeScript rotation controllers and store formats, which the
pre-review did not read against the Go reference. The Rust server durable-nonce
sources (`rust/src/server/durable_store.rs`, `durable_format.rs`,
`durable_recovery.rs`, `durable_admission.rs`) and the TypeScript counterparts
(`ts/src/server/durable-store.ts`, `durable-format.ts`, `durable-admission.ts`)
landed after the reviewed commit and were re-read in this tree; the reviewed
commit `1822634` predates them.

Three defects in those durable stores were found by CI during development and
fixed before merge, stated here as fact: (a) the Rust store lost an
operation-index entry at intent-to-live conversion, so every restart after a
commit failed the strict loader (fixed in `rust/src/server/durable_store.rs`);
(b) the Rust store fenced on definite refusals (`capacity_exhausted`,
`state_changed`) where Go does not, now fixed — current code in both SDKs
fences only on non-definite outcomes; (c) the TypeScript store validated the
prepared receipt against the pre-transaction high water, rejecting every
admission whose clock had moved since the last durable high-water write (fixed
in `ts/src/server/durable-store.ts`).

Serving-open in all three SDKs refuses dirty/unsafe state, unresolved intents or 64 tombstones; Rust uses canonical binary bytes and TypeScript canonical JSON. Recovery binds deployment and window; TypeScript additionally uses exclusive ownership, private-file, no-follow and bounded-read checks ([operations](operations.md); [cross-language conformance](cross-language-conformance.md)). Go and Rust drain leases outside the mutex; fenced close reports `RecoveryRequired` and releases the backend owner unless I/O fails. TypeScript leased close throws while remaining retryable after caller stop-ingress/drain; a fenced close reports recovery-required and releases its marker, as in Go and Rust. Rust fences when a poisoned lock is next acquired (`rust/src/server/durable_store.rs:704-711`); TypeScript fences on unexpected non-`JackError` reserve failure (`ts/src/server/durable-store.ts:430-446`). These current-source notes are separate from the historical pre-review; no builds or tests were run for this cleanup.

## 2. Findings and disposition

Severity is the pre-reviewer's. "Open" means the maintainers want the external
reviewer's opinion before deciding.

| Id | Severity | Finding | Disposition |
|---|---|---|---|
| F-01 | Medium | (Fixed: the exception now requires a live invite, checked read-only before the signature and the nonce; the finding as reviewed follows.) A self-signed `jack.enroll` request from an unknown `kid` reserves a nonce before the invite is checked, so unauthenticated traffic can occupy nonce capacity. A slot lives up to `2*window + 1` seconds; the gateway admits at most 64 requests per second against 4096 slots, which is exhausted at a window above 31. The reviewed text of `spec/01-authentication.md` said unauthenticated requests cannot fill the cache; that was wrong for this path and the specification now states the exception and the sizing rule. | Mitigated in the gateway: the durable `window` is capped so that the product stays below capacity (default 30 gives 3904 of 4096). The protocol rule itself is unchanged. Open: should unknown `kid`s get a separate budget, or should the invite be checked before reservation (a change to the order in the durable-nonce spec)? |
| F-02 | Medium | Each signed response in the rotation profile re-verifies the whole server-key chain several times and performs at least two fsyncs; cost grows linearly with the ring length. Estimated, not measured. | Accepted for 0.1.0, documented. There is no spacing rule between announcements (see L-4 of the independent review), so keep rotations rare and the ring short. Open: verify once at open and after each CAS; add a benchmark gate. |
| F-03 | Medium | A single forward clock jump raises the store high-water mark `H`; when the clock returns, the nonce store, the server ring and every client trust store latch `unsafe` for good. There is no recovery command in 0.1. | Documented limitation with operator and client procedure in `docs/operations.md`. Open: requirements on the time source, a plausibility threshold before advancing `H`. |
| F-04 | Medium, conditional | The bridge signed and forwarded `tools/call` for `jack.*` tools from the stdio side. With `native_admin` enabled and an administrator key in the bridge, a prompt-injected agent could create administrators. | Fixed: the bridge refuses `jack.*` tool calls locally and never signs them. |
| F-05 | Low | The same signed body gets different verdicts in Go, Rust and TypeScript (lone surrogates, nesting depth, GET with a body). See section 3. | Fixed for the rows that changed a verdict (1, 2, 3, 5, 9): all three SDKs now agree and the shared corpus proves it. The remaining rows (target forms, response bytes, signer panic, lease timing) were investigated and are open for the reviewer; see section 3. |
| F-06 | Low | Ed25519: Rust uses strict verification and rejects a signature whose `R` is a small-order point; Go and TypeScript accepted it. A malicious server-key holder could publish a rotation record that Go and TypeScript clients accept and Rust clients reject. | Fixed: Go and TypeScript reject a signature whose `R` is one of the eight small-order encodings and the specification states the rule; regression tests build the crafted signatures at test time. The shared corpus has the vector. A small-order public key at direct `Verify` time is still accepted by Go and TypeScript and rejected by Rust; all three reject such keys at admission. |
| F-07 | Low | Expired invites are never removed; at 1024 stored invites `invite.create` fails and a gateway with 1025 does not start. | Fixed: expired invites are removed in the same atomic state edit that creates, enrolls with or revokes an invite, in all three SDKs; the gateway cap is evaluated after the purge. |
| F-08 | Low | The announce limit (1153 keys) and the retired-key limit (1024) differ, so a long-lived deployment could eventually refuse to sign. Compaction is not implemented. | Fixed for the unservable state: an announcement is refused, before authorization and commit, once the ring holds more than 1024 keys (Go, Rust, TypeScript), so the ring can no longer outgrow what serving accepts. The remaining limit is by design: there is no spacing rule and no compaction, so a ring is good for at most 1024 rotations. |
| F-09 | Low | At the reviewed commit the top-level documents said that durable nonces and rotation were not implemented, and did not state that only the Go server SDK has a durable nonce store. | Updated in this tree: all three SDKs provide optional Linux-only durable nonce stores. Serving-open rejection, canonical formats and recovery/serving separation are documented in `docs/operations.md` and `docs/cross-language-conformance.md`. The historical review did not cover the later Rust/TS stores. |
| F-10 | Low | The gateway applies global rate and connection limits before authentication, so garbage traffic can deny service to everyone. | Documented in the CLI design notes, the threat model and the operations guide. |
| F-11 | Low | Rust `JackLayer::new` is infallible and accepts a verifier with `jack.server.key` routing next to a static response profile, so the page is served without the final gate. | Accepted for 0.1.0: the constructor contract is documented; making it fallible is an API change. Revisit for 0.2. |
| F-12 | Low | Go `FileState`: an unknown outcome of `rename` can leave disk and memory different; every well-formed `jack.enroll` takes a deep copy of the state under the global mutex before the invite is checked. | Accepted for 0.1.0, documented. |
| F-13 | Info | The upstream response status is not validated; a `1xx` status is signed as is. | Fails closed at the client (`bad_signature`). |
| F-14 | Info | `401 timestamp_out_of_window` after a committed reservation is signed and consumes the nonce, which differed from the wording of one table in the durable-nonce spec. | Resolved in the specification: the candidate durable-nonce text now describes the post-commit clock sample (stale sample: refused, reservation kept). |
| F-15 | Info | `aud` is not checked for control characters. | Recorded; operator-controlled value. |
| F-16 | Info | Wiping of secrets is best effort (invite code copies). | Recorded. |
| F-17 | Info | The Go state-file loader is tolerant of key case and duplicates (`encoding/json`); the Rust and TypeScript loaders were not read. | Answered by the independent review: Go is the outlier (case-variant names such as `ADMIN` load); tracked for a fix. |

## 3. Divergence between Go, Rust and TypeScript on the same input

Gathered by the pre-review and then re-verified against the source (the Rust
entries for rows 1 and 2 were wrong in the original table). The Go, Rust and
TypeScript cells show the behaviour at the reviewed commit; the last column shows
the state now. Rows 1, 2, 3, 5 and 9 changed a verdict and are aligned and
covered by the shared corpus; the others are investigated, not changed.

| # | Input | Go | Rust | TypeScript | Now |
|---|---|---|---|---|---|
| 1 | Lone surrogate escape (`\ud800`) in `method`, `params.name` or a member name | replaced by U+FFFD, accepted | rejected only in materialized strings, accepted inside raw-captured values | accepted as is | `400 invalid_request` in all three (spec 02) |
| 2 | JSON nesting depth | rejected above 10000 | raw capture unlimited, materialized values 128 | unbounded tokenizer | more than 128 levels is `400 invalid_request` in all three (spec 02) |
| 3 | Signature with a small-order `R` | accepted | rejected | accepted | rejected in all three; vectors in the shared corpus |
| 4 | Absolute-form request target | full URI is signed | path and query only | raw `req.url` | unchanged; unreachable for a client that signs origin-form; a spec sentence is proposed |
| 5 | GET with a body | body is hashed | body is hashed | Node adapter drops the body | all three hash the exact bytes sent |
| 6 | `#fragment` in the target | kept in the signing string | dropped by `http::Uri` | kept | unchanged; a client must not send a fragment; a spec sentence is proposed |
| 7 | Non-ASCII bytes in the target | bytes as is | bytes as is | latin1 re-encoded to UTF-8, `bad_signature` | unchanged; the one remaining row where a verdict can differ for bytes the specification allows (open) |
| 8 | Fetch adapter without Node | | | WHATWG path normalisation | unchanged |
| 9 | Header `v2 <obs-text>` | `unsupported_version` | `malformed_auth` | `unsupported_version` | `unsupported_version` in all three (single header value; more than one is `malformed_auth` first) |
| 10 | Bytes of native responses | HTML-escaped, compact `id` | as is | as is | unchanged; each response is signed over its own bytes, so no verdict differs |
| 11 | Durable nonce store | yes | no | no | yes in all three SDKs now (optional, Linux-only): Go bbolt-backed private file; TypeScript a single JSON sealed document with an `.owner` marker; Rust a private-file store with an `.owner` marker |
| 12 | `jack.server.key` with a static signer | constructor refuses | allowed | constructor refuses | unchanged |
| 13 | Store format and exclusion | bbolt and flock | JSON bundle and `.owner` marker | JSON bundle and `.owner` marker, path based checks | unchanged for the Go rotation store; the Rust and TypeScript durable nonce stores (landed after the reviewed commit) use the same private-file plus `.owner` exclusion pattern |
| 14 | Serving lease released | after the physical write | before the physical write | before the physical write | unchanged; affects the latency of `close()` only |
| 15 | Panic in the signer callback | recovered, `503` | not recovered | try/catch, `503` | unchanged; not reachable from client input |

## 4. Questions for the external reviewer

1. Is it acceptable that any network party holding a key pair can spend durable
   nonce slots and cause fsyncs, within the gateway rate limit? Which window is
   acceptable at 64 requests per second and 4096 slots?
2. What is the measured cost of a signed response with a ring of 1, 10 and 100
   records, and is there a reason to re-verify the chain on every response?
3. What must the operator and the client do after the `unsafe` latch, and how is
   the time source protected?
4. The SDKs now agree on lone surrogates (400), nesting depth (128 levels) and a
   GET with a body (hashed as sent). Are these the right normative rules? Should
   the specification also say that an absolute-form target or a fragment is
   rejected before verification, and that target bytes are taken before any
   character decoding (row 7)?
5. Is rejecting a small-order `R` the right normative rule? (The shared corpus has the vector; the independent review agrees with the rule.)
6. Do read-then-rename under an `.owner` marker (Rust, TypeScript) give the same
   guarantee as a bbolt compare-and-swap when the process stops between rename
   and the directory fsync?
7. `jack.server.key` can be served with the durable nonce store in all three
   SDKs; each deployment chooses whether the served key's verifier uses it.
   Should the served-key deployment be required to select the durable store
   where the profile asks for a durable reservation, or is per-deployment
   choice acceptable?
8. Should the bridge ever pass `jack.*` tools? (Current answer: no.)

Also wanted: real power-loss and kill testing of the durable stores, races under
load, side channels, review of the dependencies (bbolt, dalek, OpenSSL, undici,
hyper), a differential run of the three verifiers and decoders over one corpus,
the gateway behind a real reverse proxy (path rewriting, absolute-form targets,
limits), and `userkey` plus credential transfer, which the pre-review did not
cover.

## 5. What the pre-review cannot give

- Behaviour under power loss, filesystem faults and `kill`; races under load;
  side channels.
- Correctness of third-party dependencies.
- CI results at the reviewed commit, the contents of fixtures, interop and E2E
  tests, and the quality of the tests themselves.
- Fuzz coverage: at the reviewed commit the Go campaign had six targets and none
  for `rotation` or `durable`; later work adds native Go fuzz targets for both.
  Rust and TypeScript have deterministic property and mutation tests and a
  shared corpus, not coverage-guided fuzzing.
