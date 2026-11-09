# Design proposal: server-key rotation (sr1)

**Status:** proposal sr1; not implemented. This is an English design-only proposal, not normative spec v0.1 and not a change to any existing SDK contract. It becomes a normative, versioned implementation contract only after parent design review and a separately versioned implementation/review. The MUST/SHOULD language below states the proposed contract, not current behavior.

**Baseline evidence:** source reviewed at `cc7318677c2e27f733320987971cc6c10c9525d7`. Parent verified the [standing post-merge CI](https://github.com/PHPCraftdream/mcp-jack/actions/runs/42625802903) and the coverage, fuzz, licence, and fixture workflows on that exact commit. Those results establish the existing baseline, not correctness of this unimplemented proposal. No local runtime checks, implementation, tests, fixtures, exports, or implementation task records are created here.

## 1. Purpose and scope

Define a bounded, signed, opt-in protocol for replacing a server response-signing Ed25519 key without silently changing the trust root. The design covers the shared contract needed by the Go, Rust, and TypeScript SDKs: server publication, client retrieval and pin state, canonical bytes, time windows, durable anti-rollback, delivery, errors, APIs, and cross-language acceptance.

This is specifically **server** response-key rotation. It is unrelated to the existing user-key operation `jack.key.rotate(user)`, which rotates a user's key in the server registry. The new proposed read-only tool name is `jack.server.key.rotation.get`; it does not alter user keys, user authorization, registry entries, invites, or user-key credentials.

All existing per-request request/response signing, TLS requirements, strict public-key/signature validation, exact-body signature verification, request replay controls, and strict credential imports remain unchanged. Rotation is an explicit capability selected with an independently trusted rotation snapshot; existing clients do not become rotating clients by receiving a new field or header. Existing `Profile.kid` remains the **user** key id. No new `server_kid` is silently inserted into or inferred from the existing profile format. The existing static profile/pin constructors retain their existing behavior.

No auto-discovery, TOFU, TLS replacement, key algorithm negotiation, remote schedule/cancel API, arbitrary R import mode, key-chain catch-up, secret-key serialization, profile migration, or changes to v0.1 status are proposed.

## 2. Source review map and observed baseline

These references are repository-relative, not private workstation paths.

| Source | Relevant observed surface |
|---|---|
| `spec/01-authentication.md` sections 2–5, 6, 7 | Ed25519, strict canonical keys/signatures and `kid`; exact signed request/response bytes; response pinning and verification precedence; existing time window; profile/security and conformance rules. |
| `spec/02-authorization.md` sections 1–2 | Registry is user-key state, not a server-response-key pin store; `jack.*` dispatch and user/admin distinction. |
| `client/profile.go` lines 14–26, 49–99 | Profile stores URL, audience, server public key, and optional `KID` documented as the client/user key id; current validation/import path. |
| `client/transport.go` lines 120–237 | Existing response buffering cap (1 MiB), redirect/stream refusal, exact response verification, and current pinned-key behavior. |
| `client/signer.go` lines 19–26 | Existing general user `Signer` interface. |
| `userkey/transfer.go` lines 47–77, 186–208, 227–291, 714–739 | Existing strict independently expected server identity and credential-import behavior; credential transfer is not a rotation pin store. |
| `server/statefile.go` lines 22–65, 264–325 | Current state file is registry/invite state; file `fsync` then rename is implemented, but that alone does not establish durable directory metadata or power-loss recovery. |
| `rust/src/client/profile.rs`, `rust/src/client/signer.rs`, `rust/src/client/http_transport.rs` | Rust profile, user signer, and transport counterparts. |
| `rust/src/server/http.rs`, `rust/src/server/state_file.rs`, `rust/src/user_key.rs` | Rust server HTTP/state and strict user-key transfer counterparts. |
| `rust/src/ed25519.rs` lines 23–49 | Rust's current generic verifier explicitly uses strict verification, rejecting noncanonical/small-order R in addition to canonical S. This source observation is not a claim that the Go and TypeScript wrappers currently enforce the same R-point rules. |
| `ts/src/client/profile.ts`, `ts/src/client/signer.ts`, `ts/src/client/transport.ts`, `ts/src/ed25519.ts` | TypeScript client/profile/transport and verifier counterparts. |
| `ts/src/server/fetch.ts`, `ts/src/server/node.ts`, `ts/src/server/state-file.ts`, `ts/src/user-key-transfer.ts` | TypeScript server adapters/state and strict user-key transfer counterpart. |
| `server/statefile.go` | Go registry/invite persistence; not a client pin store or rotation snapshot. |

The existing profile's `server_public_key` is a static server pin, while `kid` is the user's key id. Existing registry/invite stores are not pin stores. Do not repurpose either. Existing same-directory temp-file write, file sync, and rename must not be described as sufficient power-loss durability for the new trust snapshot: a separately reviewed platform durability mapping is required.

## 3. Threat model, trust, and assumptions

### 3.1 Protected properties

An opted-in client must authenticate each response with a key already independently trusted and eligible at verification time. It may accept exactly one next-key transition, only after validating the canonical statement, its old-key authorization, its next-key possession proof, exact binding, schedule, and expected generation/head. Once durably accepted, the client must not roll the transition back, resurrect the old pin, skip generations, or silently resolve a fork by arrival order. An unauthenticated body, header, URL, or credential must never establish a pin.

The network adversary may observe, alter, replay, delay, suppress, reorder, truncate, or flood messages; may serve old signed data; and may cause clients to see different validly signed views. TLS remains required for non-loopback connections and response signatures retain their existing exact-body/request-sig binding. The public rotation statement adds authenticated continuity, not secrecy.

### 3.2 Required trust and operational assumptions

- Initial trust is established by an operator through an independent channel: exact endpoint URL, audience, server id, current key, generation/head checkpoint, and time/checkpoint metadata. Trust is never bootstrapped from the same HTTP response, user-key credential, registry file, invite file, or announcement being checked.
- Ed25519, SHA-256, the existing strict key/signature validation rules, the local trust-store implementation, trusted local configuration, and the clock policy are not compromised. Server signing keys are protected by their configured signer/key-custody mechanism.
- The endpoint and audience are the exact configured strings. Existing URL policy still applies. sr1 has stricter size/scalar requirements only for explicit rotation mode; unsupported bindings fail closed in that mode and do not invalidate an otherwise valid legacy profile or credential.
- The local trust store can provide the durability receipt and serialization required by section 9. If it cannot, rotation trust changes and rotation-enabled verification fail closed; there is no in-memory success fallback.
- The attacker is not assumed unable to compromise a currently trusted signing key. The effects and limits of such compromise are explicit in section 13.

### 3.3 Explicit limits

Signed forks from a legitimate current signer are indistinguishable from a single honest history until a client observes both. The protocol detects a conflicting authenticated statement only for a generation whose authorizing key is still known in the bounded snapshot. It does not prove global single-view publication. Independent OOB resolution is required for quarantine, lost state, missed transitions, or a fork that cannot be authenticated from retained data.

An attacker who can roll back or replace the local trust store, the trusted clock, or the configured OOB checkpoint is outside the protocol's protection. A state-file revision is a concurrency control, not a remote rollback oracle. Persistent independent hardware/server witness/high-water service is not defined here.

## 4. Names, binding, and exact record encoding

### 4.1 Binding tuple

A rotation binding is:

`(server_id, exact_url, exact_aud)`

- `server_id` is an independently provisioned, stable 32-byte random identifier encoded as canonical unpadded base64url (43 ASCII characters). It is not derived from the URL, audience, or a signing key. One logical deployment keeps it stable across key changes. Reusing it for a different deployment requires an explicit OOB reset.
- `exact_url` is the raw configured endpoint string, compared byte-for-byte as UTF-8; it is not reconstructed from a parsed URL. It must also pass the existing client URL policy.
- `exact_aud` is the configured audience string, compared byte-for-byte as UTF-8, with no Unicode normalization or case folding. It must be non-empty as required by existing profiles.
- `binding_ref` in local state is `base64url(SHA-256(UTF8("mcp-jack/server-key-rotation/sr1/binding\n") || UTF8(server_id) || LF || base64url(UTF8(exact_url)) || LF || base64url(UTF8(exact_aud))))`. The binding ref is a local consistency key, not an independent trust root.

For rotation mode, `exact_url` must encode to at most 2048 UTF-8 bytes and be a valid Unicode scalar string; `exact_aud` must encode to 1–1024 UTF-8 bytes and be a valid Unicode scalar string. Controls and non-normalized scalar sequences are not normalized or rejected merely for their scalar value. These limits bound the record, are not retroactive validation of legacy profiles, and must not change legacy import behavior.

### 4.2 Canonical statement bytes

`B` is exactly the following 13 ASCII lines joined by a single LF (U+000A), with no trailing LF, BOM, CR, whitespace, or alternate spelling:

```text
mcp-jack/server-key-rotation/sr1
<base64url(UTF8(exact_url))>
<base64url(UTF8(exact_aud))>
<server_id>
<generation>
<previous_statement_digest>
<current_kid>
<current_public_key>
<next_kid>
<next_public_key>
<announced_at>
<activate_at>
<retire_at>
```

Each field is a single token on one line. All byte-string fields are canonical unpadded base64url, so `B` itself is ASCII and line boundaries are unambiguous. There is no JSON/JCS step for `B` or `R`.

| Field | Exact form and meaning |
|---|---|
| `server_id` | Canonical base64url of the independently trusted 32-byte id. |
| `generation` | Canonical positive decimal integer 1 through `9007199254740991` (2^53−1), at most 16 digits, no leading zero or sign. |
| `previous_statement_digest` | `-` only for generation 1, whose predecessor is initial generation 0/head `-`; otherwise canonical base64url of SHA-256 over the complete prior canonical `R` bytes. |
| `current_kid`, `next_kid` | Existing `kid = base64url(SHA-256(raw_32_byte_public_key))`, exactly 43 characters and recomputed from the adjacent public key. |
| `current_public_key`, `next_public_key` | Canonical base64url of exactly 32 bytes; both pass the existing strict Ed25519 public-key rules. |
| `announced_at`, `activate_at`, `retire_at` | Canonical Unix seconds, whole decimal integers in `[0, 999999999999]`, at most 12 digits, no sign or leading zero except literal `0`. |

The complete record is exactly 15 ASCII lines, again LF-joined with no trailing LF:

```text
B
<base64url(proof_next)>
<base64url(old_signature)>
```

The literal `B` above means its exact 13 lines, not the characters `B`.

```text
proof_next = Ed25519_sign(next_private,
    UTF8("mcp-jack/server-key-rotation/sr1/next-proof\n") || B)

old_signature = Ed25519_sign(current_private,
    UTF8("mcp-jack/server-key-rotation/sr1/authorize\n") || B || LF ||
    ASCII(base64url(proof_next)))
R = B || LF || ASCII(base64url(proof_next)) || LF || ASCII(base64url(old_signature))
digest(R) = base64url(SHA-256(exact_R_bytes))
```

The two domain strings are exact, distinct, and never reused for request, response, user-key, or other proofs. Proof and authorization signatures are canonical base64url of exactly 64 bytes. **Announcement-specific verification requirement:** for each signature message `M`, decode `R` and `S`; require R to be the canonical encoding of a non-identity point on the curve in the prime-order subgroup, and S to be the canonical scalar with `S < L`; then require the uncofactored Ed25519 equation `[S]B = R + [k]A`, where `k = SHA-512(R_bytes || A_bytes || M) mod L`, `A` is the verified signing public key, and all encodings and byte order follow RFC 8032. The verifier MUST NOT rely on a backend's unspecified/cofactored acceptance behavior. This is an sr1-specific conformance requirement for announcement proofs, not a claim that the existing Go, Rust, and TypeScript generic verification wrappers currently implement identical R-point checks. In particular, the reviewed Rust verifier uses `verify_strict`, while the reviewed Go/TypeScript wrappers explicitly check S<L and delegate equation verification to their backends. This proposal does not change v0.1 request/response signature verification or claim to tighten its behavior. The next-key proof demonstrates possession/readiness only; it is not an external trust root and does not protect against compromise of the current key.

The two public keys must differ, and each `kid` must match its key. This does not claim an unlimited retired-key blacklist: a bounded snapshot cannot remember every historic public key. Operators MUST track key history and MUST NOT reuse any previously used server key. Clients can reject reuse where it is present in their retained records, but cannot guarantee detection of keys absent from the bounded checkpoint/history.

### 4.3 Size and parser bounds

- Decoded `R` is at most 8192 bytes; the client accepts exactly one statement, never an array, chain, redirect, fetch URL, or nested statement.
- `exact_url` is at most 2048 decoded UTF-8 bytes; `exact_aud` is 1–1024 decoded UTF-8 bytes. The supported limits are also checked when provisioning the rotating binding.
- Canonical base64url has no `=`, uses only `A-Z a-z 0-9 _ -`, has zero unused trailing bits, and round-trips through decode/re-encode identically.
- Before rotation parsing, the existing HTTP transport response-body cap remains 1 MiB. The returned tool content has its own bounded encoded-record length corresponding to 8192 decoded bytes. Neither bound changes existing non-rotation transport behavior.
- A durable rotation snapshot is at most 32768 bytes, contains at most two complete R records (pending and last), and at most two opaque UTF-8 references (`binding_ref` and server-side signer-provider reference), each at most 256 bytes. No URL is fetched from R. A parser/validator performs bounded work once per explicit refresh; no retries, chains, or unbounded signature loops are permitted.

## 5. Time schedule and key eligibility

### 5.1 Schedule constraints

All schedule arithmetic uses checked integer Unix seconds and rejects overflow before arithmetic:

```text
60 <= activate_at - announced_at <= 86400
86400 <= retire_at - activate_at <= 604800
```

Thus `retire_at - announced_at` is at most 691200 seconds (eight days). `announced_at < activate_at < retire_at` follows. `announced_at` MUST equal the server's sampled publication time. If `g>0`, the server requires `announced_at >= persisted last_retire + 86400` with checked arithmetic; it must not accept a scheduling request merely because current time is after that bound when the signed announcement time is earlier. Publication must complete durably while the sampled time remains `< activate_at`; otherwise discard the unpublished draft and prepare a new schedule. Once published, the record and its times are immutable. No cancellation, replacement, rescheduling, or extension is permitted, even before overlap begins.

Only one published pending statement exists. There is no queue, overlap chain, offline catch-up, or generation skip. A subsequent publication is permitted only after the preceding retirement and at least 86400 seconds of stabilization after the preceding `retire_at`; it is a new generation with the prior full-R digest. A private unannounced draft may be discarded. There is no remote schedule/cancel operation.

### 5.2 Clock policy

A rotating client snapshot stores `max_seen_time`. Preliminary processing may sample the clock for cheap rejection, but that sample is never authoritative for the final trust decision. After response parsing and any bounded record cryptography, the final serialized gate takes a **fresh** integer-second `sampled_wall` under the binding's exclusive state lock. It checks the sample is within the supported range and rejects `sampled_wall < max_seen_time - 30` as `rotation_clock_unsafe`; otherwise `effective_now = max(sampled_wall, max_seen_time)`. It durably advances the high-water mark to `effective_now` and materializes any due retirement before deciding key eligibility. Signed key intervals and first-acceptance schedule comparisons use `effective_now`; the existing response freshness check uses the final `sampled_wall` and unchanged rule `abs(sampled_wall - ts) <= configured_window`. The final gate rechecks the captured response-signing key's eligibility and response freshness against that final sample. No state lock is held across network I/O.

The final serialized gate takes a **fresh** integer-second `sampled_wall` under the binding's exclusive state lock. It checks the sample is within the supported range and rejects `sampled_wall < max_seen_time - 30` as `rotation_clock_unsafe`; otherwise `effective_now = max(sampled_wall, max_seen_time)`. It durably advances the high-water mark and materializes any due retirement before deciding key eligibility. Signed key intervals and first-acceptance schedule comparisons use `effective_now`; the existing response freshness check uses the final `sampled_wall` and unchanged rule `abs(sampled_wall - ts) <= configured_window`. The final gate rechecks the captured response-signing key's eligibility and response freshness against that final sample. No state lock is held across network I/O.

The final exclusive serialized gate is the trust-success linearization point: its lock covers the fresh sample, latest-state decision, and any required durable commit/revision installation. Application success is authorized at that gate, not guaranteed to remain eligible until physical return. A later quarantine cannot interleave with an earlier gate transaction's commit, but it may commit before that earlier success physically returns. Durability is required before exposing success; sr1 does not promise a physical return-time retirement guarantee. A future wall clock can cause denial of service or early retirement; sr1 has no independent trusted-time oracle. Time fields and persisted `max_seen_time` must remain within the 12-digit bound; exhaustion or an invalid/out-of-range sample fails closed. Repeated operation retries are not used to conceal clock failures.

### 5.3 Server signing intervals

| Server effective time | Key permitted for a newly completed response signature |
|---|---|
| Before publication | Current key only. |
| `[announced_at, activate_at)` | Current/old key only. |
| `[activate_at, retire_at)` (overlap) | Current/old key only, deterministically; never negotiate based on request key. |
| `>= retire_at` | Next key only. If its signer is unavailable, fail closed; never fall back to old. |

The server applies the same persistent `max_seen_time`/backward-clock policy as the client. It selects a signer before computing the response signature, then takes a fresh completion sample and applies the final guard: validate the sample and high-water mark, compute effective time, and confirm that the selected key remains eligible. If the key no longer matches the interval at that guard, discard the computed signature and fail the response; do not retry with another key. Final signing authorization is the server's emission-eligibility linearization time, not a guarantee about the time of the last network byte. The persistent high-water mark and any due server retirement are advanced under serialized state before authorization; no trust-state lock is held across network I/O. An old signing lease cannot authorize a response whose final guard is at/after retirement. Keep the old signer handle until retirement and all in-flight signing leases have been released; thereafter it may be removed from active custody. The public R remains available for audit/idempotence.

### 5.4 Client response-key intervals

| Client state | Key eligible at verification time |
|---|---|
| No accepted pending R | Settled key indefinitely, but only for signed response timestamps `ts >= settled_key_ts_not_before`. Suppression cannot force expiry. |
| Accepted R, before `activate_at` | Settled/current key only, with `settled_key_ts_not_before <= ts < retire_at`. |
| Accepted R, `[activate_at, retire_at)` | Both settled/current and next keys. Old-key responses require `settled_key_ts_not_before <= ts < retire_at`; next-key responses require `activate_at <= ts < retire_at`. |
| Accepted R, `>= retire_at` | Next key only, with `ts >= activate_at`. The client first advances its local snapshot from the accepted R; it persists `settled_key_ts_not_before = activate_at`; the old key is never resurrected. |

The client checks both key eligibility at the final verification linearization sample and signed response timestamp bounds. There is no skew grace at a schedule boundary. The inherited `settled_key_ts_not_before` is persisted for the settled key and prevents an old signed timestamp from being accepted after retirement under the new key's open-ended interval. On retirement of R, assign the next key's bound to that R's `activate_at`; the timestamp lower bound belongs to that key and is not a global numeric monotonic value to compare across different keys. An old-key response signed before retirement but reaching the final gate at/after retirement is rejected. During overlap the client may verify a next-key response, although an honest server signs with old throughout that overlap. A next key unavailable at retirement never causes fallback.

### 5.5 Acceptance timing and offline distinction

A **first acceptance** of a new R must satisfy `announced_at <= effective_now + 30` and `effective_now < retire_at`, in addition to the intrinsic checks in section 6. A generation above zero must also satisfy `announced_at >= last_retire + 86400` with checked arithmetic; receipt at a late time does not waive this signed schedule lower bound. These first-acceptance timing checks do not apply to an exact duplicate of retained pending/last R or to an authenticated conflict for a retained generation. Such records are classified only after syntax, cryptography, exact binding, and intrinsic schedule-duration validation; a retained-generation conflict is not expired merely because its schedule ended. An R not previously accepted that reaches its first-acceptance gate at `effective_now >= retire_at` is rejected as `rotation_expired`, even if its enclosing response has a valid old-key signature. A missed-R client cannot bootstrap from a response signed by the unannounced next key.

A client that already durably accepted R can advance from that stored statement while offline when it next runs at/after `retire_at`; retirement is a local deterministic transition, not a signed event. A client that missed R cannot perform that advancement. Its recovery is the explicit OOB checkpoint/replacement process, never remote reset, stale-chain catch-up, or TOFU.

## 6. Trust snapshot, replay, forks, and state transitions

### 6.1 Complete persisted snapshot

Each rotation binding has one immutable-snapshot/revision-CAS trust state with all fields below. Unneeded fields are explicitly null; implementations must not infer missing values from an untrusted network record.

| Retained field | Required invariant |
|---|---|
| `format_version` | Exactly the sr1 trust-snapshot format version. It is independent of v0.1 profile, registry, and invite formats. |
| `binding_ref` | Exact derived binding reference from section 4.1; checked against the explicit caller/server configuration on every open/use. |
| `server_id` | Exact OOB id, unchanged across the binding's rotations. |
| `settled_generation` | 0 through 2^53−1. Generation 0 means initial checkpoint only. Never decreases or wraps. |
| `settled_head` | Literal `-` iff settled generation is 0; otherwise canonical digest of the full settled statement/checkpoint. |
| `settled_kid`, `settled_public_key` | Current authoritative key; strict key validity and recomputed kid. If a pending R exists, this is its `current` key. |
| `settled_key_ts_not_before` | Inclusive lower bound on the signed response timestamp `ts` for the settled key. Generation-0 OOB initialization explicitly supplies this bound; an operator who cannot establish it MUST explicitly choose 0. On retirement of R, set it to that R's `activate_at` for the newly settled key. The bound is key-specific, not a global numeric monotonic value across different keys. |
| `pending_R` | Either null or the exact, fully validated, durably accepted complete R for `settled_generation + 1`; no second pending item. |
| `last_R` | Either null or the exact most recently retired full R for `settled_generation`, retained for duplicate/fork checks. Its old `current_public_key` may authenticate a same-generation conflict for quarantine only; it is never an eligible response pin. |
| `max_seen_time` | Monotone whole-second high-water mark, within 0–999999999999. |
| `last_retire` | Null only for initial generation 0; otherwise the trusted retirement time of the last settled transition/checkpoint. It is not reset by an announcement. A g>0 OOB checkpoint supplies it even if no previous R is present. |
| `revision` | Monotone snapshot revision in 0–2^53−1; increment exactly once for each durable snapshot change; no wrap. Exhaustion fails closed. |
| `quarantine` | Null or a durable conflict marker containing generation, reason, and canonical digest of the authenticated conflicting R; it is never cleared by a null/empty network result. |
| Opaque refs | At most two bounded references as in section 4.3. The signer-provider ref, if server-side, resolves protected key handles outside this public snapshot. |

The snapshot contains only public keys, public R records, hashes, times, metadata, and bounded opaque references. It MUST NOT contain a private seed, private key, credential, or serialized signer secret. Clients keep the rotation pin store distinct from the existing user profile and imported credential. Servers keep it distinct from registry/invite state.

### 6.2 Initial and OOB checkpoints

Initial enrollment is local and explicit. For generation 0 the trusted checkpoint contains exact binding, `server_id`, settled key/kid, head `-`, `settled_key_ts_not_before`, null `pending_R`, null `last_R`, null `last_retire`, an operator-approved initial `max_seen_time`, revision, and no quarantine. The operator supplies the inclusive settled-key signature timestamp lower bound; if it is unknown, the operator explicitly chooses 0. A network message may never create this checkpoint.

An OOB checkpoint at generation greater than zero supplies the exact binding, `server_id`, settled generation, head, settled key/kid, `settled_key_ts_not_before`, `last_retire`, and `max_seen_time`. These are exact required fields, not inferred defaults. It may include the full last R; if included, it must be canonical, match generation/head/key/binding, and pass sr1 validation. The checkpoint's `settled_key_ts_not_before` is the trusted inclusive lower bound for the current key's response-signature timestamps; if the operator cannot establish it, the operator must explicitly choose 0. A checkpoint may omit the last R and its previous authorizing key. In that case an older/same-settled-generation differing record cannot be authenticated as a fork; classify it as replay/stale without claiming it is a valid conflict. A checkpoint itself must arrive through an independently trusted operator channel.

For same-binding recovery from readable state, define the highest reserved generation as `max(settled_generation, pending_R.generation)` when pending R exists, otherwise `settled_generation`. A trusted replacement checkpoint must have `settled_generation` at least that high-water generation and must explicitly attest that its settled schedule is retired/complete (including the corresponding `last_retire`); the operator may select a different head at that same generation to resolve an authenticated fork. Never choose a head by lexicographic hash, arrival order, or numeric digest ordering. Preserve `max_seen_time` and advance `revision`, fence all prior writers, and do not lower the highest reserved generation. If pending R has not retired, same-binding recovery cannot discard it: wait for a separately trusted checkpoint attesting retirement or use an explicitly new binding/server id. For readable state, the current key's timestamp lower bound is preserved when retaining that key; it belongs to the key and is not compared numerically across different keys. If state is corrupt/lost and high-water values cannot be established, a same-binding rollback guarantee is impossible: require a separately trusted independent checkpoint/high-water source or establish a new binding/server id, and state plainly that the lost local values cannot be guaranteed not to roll back. Replacing state fences prior writers and never fetches values from the endpoint being reset.

If initialized state is missing, corrupt, rolled back in a way the backend can detect, or bound to a different binding, fail closed and require OOB action. A missing file on an explicitly new installation may only be initialized by the explicit OOB operation; it is never an implicit empty/generation-0 fallback for a previously initialized binding.

### 6.3 Ordered state transitions

| State/event | Durable action and eligibility |
|---|---|
| Initial/settled generation `g`, no pending | Keep settled key eligible indefinitely for responses whose signed `ts >= settled_key_ts_not_before`. A first new acceptance is possible only for exactly `g+1`, with head/current key matching settled state, no pending R, and all first-acceptance timing checks passed. |
| Publish/accept statement `g+1` | Atomically store the full R as pending and reserve generation `g+1` immediately. Existing key schedule continues as section 5 specifies. This is the only first-acceptance path. |
| Exact duplicate of pending R | After syntax, cryptographic, binding, and intrinsic schedule validation, no-op. It ignores first-acceptance expiry, stabilization, and current-key checks; it cannot reset times, revision, pins, high-water time (except normal final-gate advancement), or quarantine. |
| Time reaches pending `retire_at` | Before any subsequent eligibility decision, atomically set settled generation to pending generation, settled head to `digest(pending_R)`, settled key to `pending.next`, move pending R to `last_R`, set `last_retire`, clear pending; preserve max time/quarantine. Old key becomes ineligible. |
| Exact duplicate of `last_R` | After syntax, cryptographic, binding, and intrinsic schedule validation, idempotent no-op; ignores first-acceptance timing/current-key checks, never re-adds its old key to eligible pins, and never resets schedule. |
| Authenticated differing R for pending or latest retained settled generation | Verify with the retained record's stored authorizing public key and compare candidate generation, `current_public_key`, and `previous_statement_digest` with retained context. If authenticated contents differ, durably quarantine; preserve original R and schedule. Do not apply first-acceptance expiry/stabilization checks. |
| Unauthenticated differing R, or same generation without retained authorizing context | Never quarantine. After intrinsic checks, classify using the retained state as replay/stale or checkpoint-required; self-declared signatures do not establish fork evidence. |
| Any authenticated generation `< latest settled generation` | Replay/stale, no trust mutation; older history is not retained for global fork detection. |
| Generation greater than exactly expected `settled_generation+1`, or first-new candidate with wrong head/current key | Gap/stale checkpoint required; no chain fetch or skip. |
| Null/no announcement | No transition. It cannot clear a pending R, quarantine, high-water mark, retired state, or missing-checkpoint condition. |
| Quarantined binding | No automatic new rotation acceptance or schedule change. Existing accepted pending schedule still advances by time. A valid null response does not clear quarantine. Only explicit OOB replacement/resolution can clear it. |

Generation `9007199254740991` is terminal; no wrap or successor statement. Recovery requires a separately trusted checkpoint/new version. Revision exhaustion has the same fail-closed/manual-recovery character.

### 6.4 Anti-rollback, replay, and conflict authentication

A pending R reserves its generation/head as soon as the client durably accepts it, before activation. The client never accepts another R at that generation except a byte-identical duplicate; a differing candidate is a quarantine candidate only if it authenticates against retained context. It never accepts a generation gap. For a first new generation after generation zero, require the signed `announced_at >= persisted last_retire + 86400` with checked arithmetic; checking only that receipt time is late is insufficient. This stabilization test applies only to first acceptance, not exact duplicates or retained-generation conflicts. The settled head is the SHA-256 digest of the exact full prior R; no parsed/re-serialized representation is hashed.

**Intrinsic record validation is separate from state-context acceptance.** Every non-null candidate must pass canonical syntax, exact binding, strict key and signature encodings, both required signature verifications, and internally valid schedule arithmetic/durations before it can be a duplicate, conflict, replay, gap, or first-new candidate. For an exact duplicate, verify using the authorizing public key retained with that exact pending/last R, then no-op without first-acceptance freshness, stabilization, or current-key checks. For a candidate at a retained pending/latest-settled generation, use that retained record's stored authorizing public key—not the candidate's self-declared `current_public_key`—to verify the old authorization. Compare candidate generation, current key, and previous digest with the retained context; a different, authenticated record at that generation is a fork and is durably quarantined, regardless of its first-acceptance expiry or stabilization. Its next proof is checked against its declared next key before old authorization verification. Binding mismatch or any invalid intrinsic field/signature cannot quarantine.

For other generations, state context may select a trusted authorizer for a potential first acceptance; if no retained authorizer exists, a self-declared key may be used only to finish intrinsic signature validation, never as evidence for quarantine. After those validations, records outside retained authenticatable context classify as replay/stale, gap, or checkpoint-required. A first new R is accepted only when there is no pending R, its generation is exactly `settled_generation+1`, its `previous_statement_digest` equals the settled head, its `current_public_key` equals the settled key, and first-acceptance schedule checks pass. Generation mismatch, wrong head/current key, or a gap cannot be turned into a fork claim by self-signing. A conflict candidate is retained only as its canonical digest/reason in quarantine; the bounded snapshot does not accumulate arbitrary conflict records.

**Quarantine scope and fail-closed behavior:** quarantine applies to the complete `(server_id, exact_url, exact_aud)` rotation binding and every rotating client instance sharing that trust store. Every application trust success is authorized at the final exclusive serialized gate, and a quarantine decision is durably ordered at that same gate. The gate that commits a detected conflict never returns application content; no application gate that runs after quarantine commits can succeed, and such gates fail with `rotation_quarantined`. A successful application gate ordered before quarantine may physically return afterward; it was already authorized and is not revoked by the later decision. The gate lock is held through the decision and durable commit/revision installation, with no network I/O under the lock, so a later quarantine cannot interleave with an earlier gate transaction's commit even though it may precede that operation's physical return. Only an explicit `jack.server.key.rotation.get` control refresh may continue after quarantine, using a still-eligible non-retired pin and returning only rotation status/error (never application content); neither `sr1:none` nor another record clears quarantine. Only explicit OOB resolution/replacement with a separately authenticated checkpoint can clear it, after the operator selects the authoritative branch and the old writers are fenced. No remote message or user-admin privilege can clear it.

## 7. Response delivery and read-only retrieval

### 7.1 Tool behavior

Proposed tool: `jack.server.key.rotation.get`. It is a read-only protocol tool available to any currently active authenticated USER key. It is not admin-only and grants no new user privilege. It accepts an empty arguments object only. There is no schedule, publish, cancel, reset, key import, or arbitrary-R upload RPC.

The result uses the existing MCP tool result envelope and one text content item only; after normal JSON-RPC/response authentication the text is exactly one of:

```text
sr1:none
sr1:<canonical-base64url-of-one-complete-R>
```

No other content item, prefix, whitespace, multiple record, array, chain, or extra result data is accepted for this tool. `sr1:none` means only “no currently published statement to return”; it is not authority to clear any local state. It may be returned before a first publication. After publication, the server returns the same full R, including after retirement, for audit/idempotence; it never substitutes an unsigned header or an unauthenticated discovery hint. The encoded record is bounded by the 8192-byte decoded R limit. Tool JSON and enclosing response remain subject to the existing 1 MiB response cap.

A later implementation could use a different standard result representation only through a separately reviewed/versioned contract; this proposal chooses the exact text form to avoid optional-field or null ambiguity.

### 7.2 Authentication order and first-use rule

A caller explicitly invokes refresh through the ordinary existing signed HTTP request path. There is no background poll, header hint, automatic retry, redirect, or separate URL fetch. The tool call/response uses exactly the existing request signature, response signature, HTTP status, `request-sig`, body hash, time window, TLS, buffering, and no-follow rules.

**The R is never used to verify the response that carries it.** The client first verifies the entire HTTP response with a key from the pre-existing durable snapshot that is eligible at verification time. Only after that succeeds does it parse the JSON-RPC/tool result and consider its R. For first acceptance, the enclosing response must verify with the previously trusted, currently eligible settled key; for a client with an already accepted R it may verify with any key then eligible under that stored R. A not-yet-trusted next key in R is never used for its enclosing response.

Null/no announcement changes no rotation state. There is no standalone import mode: an R is considered only inside a successfully authenticated current-key response from this exact binding.

### 7.3 Do not alter existing response semantics

Existing response-authentication errors and transport errors keep their current classes and precedence. A signed HTTP response with an RPC/tool error is reported as the existing RPC/tool error; no record is parsed from an error response. Rotation result parsing happens only after a successful, fully response-authenticated tool result. Unknown unsigned headers remain ignored as today. Rotation never changes response signature bytes, response body serialization, signing key selection of an existing static client, or strict credential format.

## 8. Validation and failure precedence

The proposed local errors below are additions only to a future explicitly rotating API. Existing `missing_auth`, malformed/unsupported response auth, unknown server key, timestamp, bad signature, transport, HTTP, TLS, redirect, stream, and existing credential-import errors remain unchanged and take precedence wherever their current checks apply.

### 8.1 Refresh pipeline

One refresh operation follows this order, stopping at the first applicable failure. Preliminary processing may sample time for cheap checks, but cannot authorize key trust or state changes. Preserve outer-authentication and response-freshness failures for precedence: any R-local parsing, intrinsic-validation, or state-classification error found before the final gate is deferred until that gate runs. Do not expose content before the final gate. After the gate, return the first error according to the ordering below.

1. Validate local configuration/store binding and required initialized OOB snapshot. Missing, corrupt, unsupported-format, or binding-mismatched initialized state is `rotation_checkpoint_required`. Failure to access storage or acquire/retain its exclusive owner lock is `rotation_store_unavailable`. A possibly committed write with uncertain outcome is `rotation_outcome_unknown`; never treat it as an absent checkpoint.
2. Read and capture the current snapshot/revision. If quarantined, reject application traffic with `rotation_quarantined`; only explicit rotation-control refresh may continue, returning status/error only, never application content.
3. Send the ordinary signed request with existing transport, redirect, stream, and body-limit behavior. Never hold the trust-state lock across network I/O.
4. Process outer response authentication in the existing header/error order using only keys present in the captured pre-existing snapshot, never a key from this response's R. Unknown outer key is existing `unknown_server_key`; malformed auth, bad signature, HTTP/transport/TLS errors retain their existing errors and precedence. A preliminary wall sample may reject cheaply, but any final trust/freshness decision is deferred to step 15. No R is parsed from an outer-authentication failure or remote RPC/tool error.
5. Parse authenticated JSON-RPC/tool result. Invalid result envelope, wrong content count/type, or extra content with `sr1:none` is `rotation_bad_result`. Exact `sr1:none` is a no-record result, subject to the final gate. For an R result, preserve the existing RPC/tool error mapping and stop before R parsing for remote errors.
6. Require exact `sr1:` prefix and one encoded record. Encoded payload length greater than 10923 characters is `rotation_oversized` before alphabet checks; 10923 is `ceil(8192*8/6)`. Invalid base64url alphabet, padding, or nonzero unused trailing bits is `rotation_noncanonical`. After decoding, more than 8192 bytes is `rotation_oversized`.
7. Require the decoded R to be exactly 15 ASCII lines joined by LF, with no trailing LF, BOM, CR, whitespace, or non-ASCII; require the exact known domain `mcp-jack/server-key-rotation/sr1` and exact field count/order. Any failure here, including an unknown `srN` domain, is `rotation_malformed`.
8. Validate decimal grammar and ranges in field order: generation (positive, <= 9007199254740991, <=16 digits), then announced/activate/retire timestamps (0..999999999999, <=12 digits). Invalid spelling, leading zero, sign, or range is `rotation_noncanonical`.
9. Validate each base64url field's alphabet, canonical trailing bits, and encoded/decoded fixed length in record line order: URL bytes (<=2048), audience bytes (<=1024), 32-byte server id, previous digest (`-` only at generation 1, otherwise 32 bytes), current kid (43 chars), current key (32 bytes), next kid (43 chars), next key (32 bytes), next proof (86 chars/64 bytes), old signature (86 chars/64 bytes). Grammar or encoded-length/fixed-length violations are `rotation_noncanonical`; decoded URL/audience over-limit is `rotation_oversized`.
10. Decode URL and audience as valid Unicode scalar UTF-8; invalid UTF-8 or invalid scalar encoding is `rotation_malformed`. Empty audience, URL policy failure, or exact URL/audience/server-id/derived-binding disagreement with configured binding is `rotation_binding_mismatch` (and cannot quarantine).
11. Validate current public key strictly and recompute/check current kid; then validate next public key strictly and recompute/check next kid. Failure is `rotation_bad_key`. Equal current and next public keys are `rotation_bad_key`.
12. Validate intrinsic schedule arithmetic/durations with checked arithmetic: `60 <= activate-announced <= 86400` and `86400 <= retire-activate <= 604800`. Invalid ordering, duration, or overflow is `rotation_bad_schedule`. Do not apply first-acceptance freshness/stabilization here.
13. Select the authorizer from captured state for verification, without yet emitting a generation/state error: exact duplicate uses that retained record's stored authorizer; a candidate at a retained pending/latest-settled generation uses that context's stored authorizer; a possible first-new record uses the trusted settled key. For other records, the self-declared current key may be used only to finish intrinsic verification and can never authenticate a quarantine decision.
14. Verify `proof_next` under the declared next key first (`rotation_bad_proof`); then verify old authorization under the selected authorizer (`rotation_bad_authorization`). Only after both proofs pass classify retained duplicate/conflict/replay/gap/checkpoint versus first-new context. A different authenticated record at a retained pending/latest-settled generation is a conflict only when verified by the retained authorizer and compared against retained generation/current-key/previous-digest context. Wrong generation outside retained authenticatable context is replay/stale, gap, or checkpoint-required, never quarantine based on self-signing.
15. Acquire the binding's exclusive state lock for the final serialized gate and take a fresh integer-second `sampled_wall`. Validate its supported range and backward movement against latest `max_seen_time`; if `sampled_wall < max_seen_time - 30`, return `rotation_clock_unsafe`. Compute `effective_now = max(sampled_wall,max_seen_time)`, durably advance high-water time, materialize due retirement, and revalidate the captured response-signing key's eligibility and the existing response freshness `abs(sampled_wall - ts) <= configured_window` using this final wall sample. Existing outer key/freshness errors take precedence over any deferred R parse/classification error. A key that is no longer eligible returns the existing `unknown_server_key` error; changed captured state is revalidated once under section 8.3 or returns `rotation_revision_conflict`, with no retry loop or stale-snapshot fallback. The final sample under this lock is the trust-success linearization time; no guarantee is made that it remains valid until physical return.
16. Against the latest state, classify the candidate exactly once using the ordered table in section 8.3. Intrinsic errors from steps 5–14 precede candidate classification, but never override the final outer-authentication, quarantine, clock, or storage gate. Duplicates and authenticated retained-generation conflicts are classified before first-acceptance timing or stabilization checks. Reclassification against a concurrently installed pending/retired record is allowed only when the exact authorizing public key used for cryptographic verification remains trusted in that retained context; otherwise return `rotation_revision_conflict`. No new cryptography or retry loop runs under the gate.
17. Commit every changed snapshot durably before exposing a newly accepted pin or successful refresh result. Commit quarantine before returning `rotation_conflict` and discard the triggering operation's application content. No success precedes a durability receipt. If commit may have completed but receipt/outcome is uncertain, fence/reload/reconcile and return `rotation_outcome_unknown`; never rollback or issue a replacement. A failure to persist final high-water/retirement state is `rotation_store_unavailable`, with no stale-snapshot fallback.

The closed sr1 local error set is: `rotation_checkpoint_required`, `rotation_store_unavailable`, `rotation_quarantined`, `rotation_clock_unsafe`, `rotation_bad_result`, `rotation_oversized`, `rotation_malformed`, `rotation_noncanonical`, `rotation_binding_mismatch`, `rotation_bad_key`, `rotation_bad_schedule`, `rotation_bad_proof`, `rotation_bad_authorization`, `rotation_expired`, `rotation_too_early`, `rotation_replay`, `rotation_gap`, `rotation_conflict`, `rotation_revision_conflict`, and `rotation_outcome_unknown`. Unknown domain is `rotation_malformed`; sr1 defines no separate unsupported-version error. Existing non-rotation and outer response-auth/transport/HTTP/TLS errors retain their existing names and precedence; an ineligible outer key maps to the existing `unknown_server_key` class.

### 8.2 Multi-fault precedence examples

| Simultaneous conditions | First result |
|---|---|
| Bad/missing outer response authentication plus malformed R body | Existing outer-authentication error; R parsing cannot override it. |
| Correctly signed response from an ineligible/unknown key plus malformed R | Existing `unknown_server_key` error. |
| Authenticated response containing remote tool error and malformed-looking content | Existing remote RPC/tool error; no R parse. |
| Wrong binding plus bad old signature | `rotation_binding_mismatch` before signature verification; never quarantine. |
| Correct binding, bad `proof_next`, and wrong generation | `rotation_bad_proof` before state-generation classification. |
| Valid first-new R with correct binding/cryptography but at `effective_now >= retire_at` | `rotation_expired`; no pin change. |
| Unauthenticated differing same-generation R | `rotation_bad_authorization` or earlier intrinsic error; no durable quarantine. |
| Valid intrinsic record for a retained exact duplicate after retirement | Successful no-op; first-acceptance expiry/stabilization/current-key checks do not apply. |
| Valid authenticated different same-pending-generation R | `rotation_conflict` plus durable quarantine, original pending state/schedule preserved. |
| Valid authenticated retained-generation conflict with expired intrinsic-valid schedule | `rotation_conflict`; persist quarantine without first-acceptance expiry/stabilization checks. |
| Durable commit may have succeeded, receipt absent/late | `rotation_outcome_unknown`; reconcile, never rollback/reissue. |

### 8.3 Exact final-gate and state classification order

The final gate checks, in order: latest quarantine (application traffic fails with `rotation_quarantined`), clock range/backward safety (`rotation_clock_unsafe`), required high-water/retirement persistence (`rotation_store_unavailable`, or `rotation_outcome_unknown` when a write may have committed), outer-key eligibility (`unknown_server_key`), and response freshness (the existing timestamp-window error). For rotation-control refresh while quarantined, these outer checks still run; a valid result reports `rotation_quarantined` and cannot change the accepted schedule. Existing outer header/signature failures already found at step 4 are returned without parsing R. After a successful final outer gate, return the earliest deferred intrinsic error, then apply the following first-match table. `g` is the latest settled generation after any due retirement; `h` is the highest reserved generation (`pending.generation` if pending exists, otherwise `g`). Time/high-water advancement required by the gate is not candidate acceptance.

| First matching candidate/state condition | Exact outcome |
|---|---|
| Captured binding or verified authorizer can no longer be revalidated from latest retained trusted context | `rotation_revision_conflict`; no candidate mutation. |
| Exact bytes equal latest pending R or last R, with its retained authorizer verified | Successful no-op; no first-acceptance expiry/stabilization check. |
| Different record at a retained pending/last generation, verified by that retained authorizer | Persist quarantine, then `rotation_conflict`; no first-acceptance timing check. |
| Candidate generation `<= g`, without an authenticatable retained conflict/duplicate above | `rotation_replay`; no fork claim. |
| Pending exists and candidate generation `> h` | `rotation_gap`; cannot queue a successor before the reserved transition retires. |
| Pending exists and candidate is not covered above | `rotation_checkpoint_required`; retained context is insufficient. |
| No pending, and candidate generation `> g+1` (including successor overflow at terminal generation) | `rotation_gap`; never skip or wrap. |
| No pending, candidate is exactly `g+1`, but current key differs from settled key or previous digest differs from settled head | `rotation_checkpoint_required`; signatures do not establish continuity. |
| First-new candidate at `g+1`, `g>0`, and checked `last_retire+86400` overflows or exceeds signed `announced_at` | `rotation_bad_schedule`. |
| Otherwise-valid first-new candidate with `announced_at > effective_now+30` (checked arithmetic) | `rotation_too_early`; overflow in this comparison is `rotation_clock_unsafe`. |
| Otherwise-valid first-new candidate with `effective_now >= retire_at` | `rotation_expired`. |
| Otherwise-valid first-new candidate | Persist pending R and reserve `g+1`, then return success. |

A byte-identical duplicate newly installed by another concurrent refresh is revalidated once and reaches the duplicate row, not a spurious revision error. A differing same-generation candidate verified by the same trusted retained authorizer reaches the conflict row. A changed binding/authorizer that would need fresh cryptography returns `rotation_revision_conflict`. No hash ordering chooses an authoritative branch.

## 9. Durable publication, atomicity, and concurrency

### 9.1 Server publication

The server operator/controller prepares a next signing key and exact R privately; it validates both keys, proofs, binding, timing, history/reuse policy, and signer readiness before publication. Preparing/discarding is not externally visible. Publication atomically installs the exact immutable R and the protected next-signer handle/reference. There is no state in which a public announcement is served while next-key readiness is unrecorded. After publication, no cancellation/rescheduling/replacement is permitted, even if activation is distant or no client has seen it.

The tool returns the exact published R until superseded only after the next rotation is legally scheduled; after retirement it still returns that last R until a later valid generation is published. A future publication supersedes the audit response only after stabilization and the previous retirement. Every server process serving one binding must be the sole live owner of its state store. The owner acquires and holds an exclusive store ownership lock from startup through shutdown; a second live owner, even in another process or host, must fail startup with `rotation_store_unavailable`. This design does not support replicas sharing promises, distributed ownership, or cluster election. A process that loses ownership must stop serving rotation-enabled responses and fail closed.

### 9.2 Durable snapshot receipt and crash rules

A trust-changing operation writes a complete immutable snapshot and commits with a backend-specific durable receipt. The implementation review must map this to each supported filesystem/database/platform, including directory metadata durability after file replacement (or a platform transaction with equivalent reviewed guarantees), flush ordering, atomic visibility, and recovery. A file-data `fsync` followed by rename alone is explicitly **not** enough evidence of power-loss durability. If the platform cannot provide the required receipt, the operation must fail closed and must not report durable success.

A crash/restart may recover only the complete old snapshot (if commit was not durable) or complete new snapshot (if commit was durable); it may never accept a truncated, mixed, partially updated, or implicit-genesis snapshot. Corrupt/missing initialized data requires OOB recovery. After a write/rename/transaction with uncertain outcome, do not claim rollback: fence the binding, reload authoritative storage, reconcile by revision and exact bytes, and return `rotation_outcome_unknown` to the caller. If a server publication committed but its receipt was delayed until at/after activation, the server follows the committed schedule/key timeline; it does not roll back, reissue, or choose a new schedule. The caller gets unavailable/unknown, not success or a replacement statement.

The existing Go file store's file sync + rename is a useful atomic-write precedent but does not itself satisfy this new platform durability gate. No current durability claim is made for any SDK by this proposal.

### 9.3 CAS and concurrent requests

Snapshots are immutable values with a monotonically increasing revision. Validate expensive bounded parsing/cryptography off-lock against a captured snapshot, then serialize state decisions: acquire the binding's exclusive writer lock/transaction, reload the authoritative snapshot, take the final fresh time sample, apply monotonic time and due retirement, revalidate the captured response key and candidate against that latest state, and compare-and-swap the revision. A revision change is revalidated once using section 8.3 when the exact verified authorizer is still trusted in the latest retained context. This includes high-water advancement, due retirement, and a concurrent first acceptance that installed the same or a conflicting candidate generation. A binding/authorizer change requiring fresh cryptography returns `rotation_revision_conflict`; latest quarantine takes precedence. Never reject a safely revalidated exact duplicate solely because its first acceptance changed the revision. Do not loop/retry or fall back to stale state. One binding has one logical writer; concurrent requests within that instance linearize. A process lock alone is insufficient when multiple processes share a file; use a reviewed single-owner lock or transactional backend. Never let stale in-memory state overwrite a newer disk revision.

Do not hold the trust-state lock across network I/O. After an HTTP response arrives, the final exclusive serialized gate re-checks latest durable quarantine, eligibility, and freshness before authorizing application content or committing its R. The gate lock remains held through its decision and any durable commit/revision installation. A response may therefore be rejected if it crossed retirement before that gate; there is no physical return-time guarantee. A successful gate ordered before a later quarantine commit may physically return afterward; the later quarantine does not revoke that authorization. The operation that detects and commits quarantine never returns application content, and no application gate after that commit succeeds. Exact concurrent duplicate R operations within the single owner converge to an idempotent no-op after one commit. Different valid same-generation statements serialize; the second causes quarantine, not winner selection. When the second statement is authenticated only with a retired key retained in `last_R`, that key is strictly quarantine-only and is never included in the eligible-key result. Store failure, revision exhaustion, revision conflict, corrupt reload, or owner-lock loss fences trust changes and fails closed.

`max_seen_time` advancement and deterministic local retirement are durable before a key is considered eligible. If that update fails, no stale snapshot is used as a fallback. A trusted R accepted from the network is not exposed as a success/new pin until the exact snapshot containing it has a durability receipt.

### 9.4 Server signing leases and key custody

Server snapshots contain public metadata and opaque protected signer-provider references only. Private key bytes/seeds never enter profile, user registry, invite state, or the public rotation snapshot. The provider must prove at readiness time that its next signer corresponds to `next_public_key` and can produce `proof_next`; after crash, the server revalidates the handle/key id and readiness before serving. Missing/mismatched handles fail closed. Signer handles are leased for each operation; retire closes new old-key leases and waits for existing operations to release before removing the old handle. Key custody, zeroization, hardware integration, backups, and access control remain provider responsibilities and must not be implied by opaque references.

## 10. Credential/profile compatibility and proposed API shapes

These shapes are illustrative and are **not exports or final source signatures**. The existing general user `Signer` surface, user credential serialization, static client constructors, and profile bytes do not change.

| Language | Rotation state/refresh (illustrative) | Server controller (illustrative) |
|---|---|---|
| Go | `RotationTrustStore` with `InitializeOOB(checkpoint)`, `Snapshot()`, and explicit `Client.RefreshServerKeyRotation(ctx)`; transport receives the store only through an explicitly selected rotating constructor. | `RotationController.Snapshot()` and `Publish(expectedRevision, nextSigner, activateAt, retireAt)`; local controller only. |
| Rust | `RotationTrustStore` with equivalent OOB/snapshot methods; explicit `refresh_server_key_rotation(&context)` on a rotating client. | `RotationController::publish(expected_revision, next_signer, activate_at, retire_at)` and snapshot/advance equivalents. |
| TypeScript | `RotationTrustStore` with equivalent OOB/snapshot methods; explicit `refreshServerKeyRotation({signal})` on a rotating client. | `RotationController.publish(expectedRevision, nextSigner, activateAt, retireAt)` and snapshot/advance equivalents. |

All languages must have equivalent semantics, not necessarily identical idiomatic spelling. `ExpectedIdentityFor(kid, now)` may be an internal/read-only snapshot accessor returning the exact eligible public tuple and revision lease. No public method fabricates a trusted identity or directly overwrites pins. Do not change the general user `Signer` interface/trait or add a public/private serialization API. If server-side proof signing uses a `Signer`-like adapter, it must be a server-role proposal and must not be confused with user key issuance.

The rotating constructor is explicit and requires an independently initialized trust store matching URL/audience/server id. The legacy profile path remains static. Imported credentials continue to require an independently trusted expected identity and never initialize or update the rotation store. The independently trusted tuple is exactly `{url, aud, server_public_key, server_kid}`; decoded UTF-8 equality is required. The strict import pipeline runs before the `server_identity_mismatch` gate; a missing, null, incomplete, invalid, or conflicting expected tuple remains the existing `server_identity_mismatch` error. For rotation-enabled import, select the expected tuple separately from the rotation store by the explicitly trusted selected `kid`, never from the credential's embedded server key, and make no import mutation to that store. A connection's one server-key pin is not the authoritative rotating store: during overlap the rotating constructor trusts both scheduled pins, while an honest server continues signing with the old key. Plaintext credential secret remains only the explicit existing issuance handoff; no general signer/private-key export is added. Strict existing credential formats/import rules remain byte-for-byte unchanged.

Refresh is caller-initiated. Go and TypeScript use the caller's whole-call deadline/abort signal without creating retries. Rust's optional `client-http` feature already exposes `HttpTransportBuilder::timeout`; its default is 15 seconds and it is one absolute, transport-owned HTTP round-trip deadline, not reset per phase. The transport owns the networking round trip, not disk work or arbitrary callbacks. Go and TypeScript whole-call deadlines remain caller-owned. No language adds an automatic refresh loop, hidden key retry, extra fetch, background worker, or timeout reset. Existing static clients remain usable without any new store or new network call.

## 11. Acceptance plan for a separately authorized implementation

No tests are executed or added in this design-only task. The following are required before implementation is accepted. All tests must be deterministic, bounded, and must compare actual bytes/behavior rather than hard-code invented cryptographic outputs.

### 11.1 Positive protocol and state cases

| Case | Required result |
|---|---|
| Explicit OOB generation-0 initialization with correct binding | Initial key trusted; no network-derived trust. |
| Independently trusted generation-g checkpoint | Exact settled fields load; g>0 requires `last_retire`; omitted historical key/R prevents fork claims, not checkpoint validity. |
| Valid generation-1 record with head `-`, matching current key, valid proof/authorization and timing | Accept only from response verified by pre-existing current pin; persist full R before success. |
| Valid next generation with full prior-R digest and settled-key continuity | Accept only if the signed `announced_at >= persisted last_retire + 86400`; late receipt cannot rescue an earlier signed announcement. |
| Exact duplicate while pending, after retirement, and after process restart | Idempotent; no time reset, no revival of old pin, no duplicate R storage. |
| Client receives R before activation / in overlap / just before retirement | Correct persisted pin set and boundary eligibility; first-seen only while `< retire_at`. |
| Previously accepted client offline across activation/retirement | On return, monotonically advance locally; old key cannot be used at/after retirement. |
| Read-only tool returns `sr1:none` | No change to pending, quarantine, high-water, pins, or revision except required monotonic time update. |
| OOB recovery from missed transition or quarantined state | Only explicit operator-supplied checkpoint replaces trust; no remote reset/chain catch-up. |
| Existing non-rotation profile and existing strict credential import | Byte/behavior compatibility; no new pin mutation or `server_kid` interpretation. |

### 11.2 Negative, malformed, and precedence cases

Cover each statement field and every parser boundary: wrong line count/order/domain; trailing LF, BOM, CR, non-ASCII, whitespace, alternate decimal/base64url spelling, padding/nonzero unused bits, invalid UTF-8/scalar, too-long URL/aud, empty audience, URL policy failure, wrong binding/server id, duplicate or unknown records, malformed/overflow decimal, generation 0/overflow, 12/13-digit time, 16/17-digit generation, record 8192/8193 bytes, encoded length boundary, invalid kid/key correspondence, noncanonical/off-curve/non-subgroup/identity key, invalid signature encoding/noncanonical S, noncanonical/off-curve/small-order/identity R, cofactored-only verification acceptance, bad next proof, bad old authorization, equal keys, bad digest, missing predecessor, invalid schedule, arithmetic overflow, too-early/expired first acceptance, expired authenticated conflict, gap, replay, wrong current key, invalid result shape, multiple text items, arrays/chains, `sr1:none` plus malicious extra state, and stale/unknown profile bindings.

Verify ordered multi-fault examples in section 8.2 exactly. Mutated/unverified Rs must never advance pins, times (except local monotonic `max_seen_time` as specified), quarantine, or generation. Authenticated wrong-binding messages never quarantine. Invalid signatures cannot create durable fork state. Old R in a new-key response after retirement cannot make old key eligible.

### 11.3 Boundaries, crash, offline, and concurrency matrix

| Area | Required injected boundary/failure |
|---|---|
| Schedule | Every min/max boundary: 59/60/86400/86401 activation delay; 86399/86400/604800/604801 overlap; exact activation and exclusive retirement; 30-second early announcement edge; exact eight-day total; checked overflow. |
| Clock | Equal time, forward time, backward 30/31 seconds, fast clock, near 12-digit maximum, recovery without decreasing `max_seen_time`. |
| Generation/revision | 0/1/max-safe/max-safe+1; exact next, duplicate, old, gap; revision max/exhaustion; no wrap. |
| Persistence | Crash before temp write, during write, before flush, after data flush/before metadata flush, before/after rename/transaction commit, receipt delay, restart with old/new complete state, corrupt/truncated/missing snapshot, failed reload, owner lock loss. No implementation may claim unsupported power-loss guarantees. |
| Client response | Response starts with old key and arrives at activation/retirement; signed timestamp on either side of each boundary; valid R carried in response signed by old eligible key; R attempting to authorize its own enclosing response; body >1 MiB; explicit refresh deadline. |
| Offline | R accepted then offline over each boundary; R missed and fetched before/at/after retirement; client returns after several server generations; must not chain/catch up. |
| Concurrent client | Two exact duplicates; two different valid same-generation R values; stale revisions; due retirement racing response verification; receipt/outcome uncertainty. One linearized outcome, no stale overwrite. |
| Concurrent server (one instance) | Two publishers within one instance using the same expected revision; second live owner startup rejection; attempted replacement/cancel; duplicate publish; signer readiness/read lease racing retirement; delayed response signing across retire. No two public forks or old signature after final authorization. |
| Quarantine | Invalid/unauthenticated conflict does not persist; valid same-pending/latest-settled conflict does even after its signed schedule expires; retired last-R key is used only for quarantine; exact duplicate does not; null does not clear; application responses fail closed; OOB resolution alone clears. |

### 11.4 Key-compromise boundaries

| Key compromise | Required recovery boundary |
|---|---|
| Compromised current key before client commits R | Attacker can authorize an attacker-selected next key with valid proof; only independently trusted OOB replacement can recover trust. |
| Conflicting authenticated same-generation R observed | Persist binding-wide quarantine; fail closed all application content until OOB branch resolution/replacement fences old writers. |
| Retired old key later compromised | It may authenticate a retained-generation conflict for quarantine only; it is never an eligible HTTP response key and cannot reverse retirement. |
| Suppressed transition not yet accepted by client | That client's settled pin remains valid indefinitely; suppression is not solved. |
| Fast-forwarded clock or local store rollback | Denial of service or undetected rollback remains possible without independent trusted time/high-water. |

### 11.5 Required 3×3 language interoperability

Before release, run all nine combinations: Go producer→Go/Rust/TypeScript verifier; Rust producer→Go/Rust/TypeScript verifier; TypeScript producer→Go/Rust/TypeScript verifier. Each producer must create actual canonical `B`/`R` with deterministic test signers or shared reviewed vectors; each verifier must parse exact bytes, verify both signatures, bind exact URL/audience/server id, apply schedule/state rules, and reject the same mutation classes. No producer may use another language's serializer as its oracle. The matrix must also carry authenticated HTTP/tool-response envelopes so the enclosing-response-pin rule is exercised, not merely the inner signature function.

For each language lane test server schedule/publication, client initial/OOB state, persistence/restart, all parser boundaries, errors/precedence, credential compatibility, and the normal existing request/response signing tests unchanged. A green compile/unit suite alone is not the 3×3 evidence.

## 12. Parent-owned implementation task dependencies

This document creates no implementation task. Only the parent/orchestrator may create or assign future leaf tasks, after approving the design and separately authorizing implementation.

Suggested dependency order:

1. **Parent review gate:** approve/fix this protocol, security model, exact encoding, error precedence, OOB process, and lifecycle. No SDK coding before approval.
2. **Shared contract/vector leaf:** after gate 1, author and independently review hand-maintained canonical positive/negative inputs and cross-language acceptance oracles. Do not generate oracle crypto output from the implementation under test.
3. **Persistence/durability leaf:** after gate 1, define and review the exact snapshot schema, revision CAS, platform-specific durable receipt/metadata flush, multi-process ownership, crash recovery, and storage rollback assumptions. This is blocking for trust-changing implementation.
4. **Go SDK leaf:** depends on gates 1–3; implement Go codec/store/controller/client behavior and compatibility tests only in Go-owned scope.
5. **Rust SDK leaf:** depends on gates 1–3; may run parallel with Go; implement Rust equivalents and compatibility tests only in Rust-owned scope.
6. **TypeScript SDK leaf:** depends on gates 1–3; may run parallel with Go/Rust; implement TypeScript equivalents and compatibility tests only in TS-owned scope.
7. **3×3 integration leaf:** depends on completed 4–6 and the reviewed shared contract; run all producer/verifier and authenticated transport combinations, plus full existing language lanes.
8. **Versioned normative-doc/release gate:** depends on accepted 3×3 evidence, persistence review, security review, and parent approval. Only then update versioned protocol docs/status and decide release separately.

Task splitting, task numbers, paths, APIs, and branch scope are parent decisions; this proposal does not create child tasks or authorize sibling-worktree edits.

## 13. Residual risks and explicit review gates

- **Old-key compromise before acceptance:** old key can sign an attacker-selected next key; possession proof is not an independent approval. Recovery needs OOB trust, not sr1 alone.
- **Suppression/never-seen transition:** absent a separately trusted expiry/revocation root, a client that never learns R must keep its old pin usable indefinitely. This is a deliberate continuity/availability trade-off, not a claim that suppression is solved.
- **Fork/split view:** signatures prove authority, not uniqueness. A client observing one view cannot detect an unseen competing view. Authenticated same-generation conflict quarantines the complete binding. The triggering operation returns no application content, and no application gate ordered after quarantine commits can succeed; a success authorized by an earlier gate may physically return afterward and is not revoked. Only explicit OOB branch resolution/replacement fences old writers. Rotation-control refresh may report status only and cannot clear quarantine.
- **State rollback:** local file/database rollback by an attacker is not detected by a local revision or digest. A hardware monotonic counter, transparency service, or independent witness is outside sr1.
- **Clock trust:** fast local time may cause early rejection/retirement and denial of service. The 30-second backward check does not detect forward jumps.
- **Power-loss durability:** file-data sync and rename are not enough by themselves. Each supported platform/backend needs a reviewed directory-metadata flush or equivalent durable-transaction receipt and crash proof before implementation can claim success.
- **Storage confidentiality/integrity:** statement material is public; protected signer references still depend on external custody. State-file ACLs, signer access, multi-host locks, and backup security are implementation/platform review gates.
- **Bounded history:** keeping only pending and most recent full R bounds storage but limits authenticated fork checks to retained authorizing keys. Older statements are replay/stale, not proven forgeries or proven forks.
- **Compatibility:** explicit rotation mode may reject URL/audience values exceeding sr1 bounds; existing v0.1 static profiles, ordinary transport, and strict credential import must remain unchanged.
- **Protocol/API review:** confirm existing MCP result envelope compatibility for the chosen one-text-item representation; confirm publication readiness and operator workflow; review exact error mapping and public-snapshot exposure before implementation.
- **No current claim:** this design does not assert runtime correctness, green CI, power-loss safety, or implementation availability. The baseline source and owner-provided prior CI evidence are provenance only.

## 14. Design refinements fixed by this proposal

For a reviewable single contract, this proposal resolves choices that otherwise invite divergent SDK implementations: it chooses the 15-line LF record rather than JSON canonicalization; an independently provisioned random `server_id` and exact URL/audience binding; one text item with `sr1:none`/`sr1:<base64url(R)>`; old-key signing throughout overlap; one pending transition, no cancel/reschedule/chain; first-accept-before-retire and no self-verification of enclosing response; monotone local time and exact boundary behavior; exact persisted signed-timestamp lower bounds, including their inheritance at retirement; a persisted prior-retirement-plus-24-hours lower bound on the next signed announcement time; explicit full snapshot fields, two-record/reference bounds, revision/CAS and binding-wide fail-closed quarantine; announcement-specific strict Ed25519 R/S/equation requirements (without changing v0.1 response verification); and `rotation_outcome_unknown` for uncertain/late durable receipts. The platform metadata-flush/transaction receipt is intentionally an implementation review gate, not an asserted property of current state files.
