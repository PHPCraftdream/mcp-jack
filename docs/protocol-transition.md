# Protocol transition contract

**Status:** transition contract for v0.1.x. The durable-nonce and server-key-rotation profile is implemented and normative; the wire is frozen for the whole 0.1.x line (no wire changes within 0.1.x). Existing static pins/credentials remain valid and unchanged; adopting rotation is an explicit operator action. Independent audit, publication, and release stay separate ([`docs/versioning.md`](versioning.md)). This document records the frozen 0.1.x transition rules; it does not authorize publication or a release.

## 1. Baseline and transition matrix

The v0.1 contract documents remain normative in [`spec/01-authentication.md`](../spec/01-authentication.md), [`spec/02-authorization.md`](../spec/02-authorization.md), and [`spec/03-user-management.md`](../spec/03-user-management.md): exact v1 signing bytes/auth precedence; nonce admission defaults to a volatile in-memory store, and the durable profile is an explicitly selected, normative alternative; native argument rules; static pins/credentials; and version-1 strict registry/state loading. The table describes what happens when configurations mix static and rotation deployments.

| Existing configuration/state | Selected candidate result |
|---|---|
| Current static-pin client reaches rotation server switch | It rejects the new outer `kid` as `unknown_server_key`; no bootstrap from that response and no fallback. Provision a candidate rotation client out of band before switch or perform OOB replacement. |
| Rotation-enabled candidate client contacts a legacy server without `jack.server.key` | The legacy native dispatcher returns `403 operation_denied`; the client does not downgrade, use TOFU, or treat legacy response as rotation state. |
| Existing profile/credential embeds an expected server key | Remains an independent static expectation for its exact endpoint/audience/server-key tuple and MUST exactly agree with the OOB candidate anchor if used. It does not authorize a nonzero checkpoint, new pin, or chain head. |
| Existing v1 registry/state file | Keep its version-1 strict loader and unknown-field rules unchanged. Rotation snapshots, ClockGuard, and durable nonce state use separate versioned stores; missing initialized stores fail closed. |
| Volatile nonce cache to durable profile | Volatile nonce cache -> durable profile: require atomic handoff of all possibly-live tuples OR trusted all-history U and W bounds with raw time strictly greater than checked `U+W`; never initialize empty. |

The completed table is an at-a-glance migration/rejection matrix, not an automatic migration.

### Design baseline provenance

Delivery history is summarized in [`../CHANGELOG.md`](../CHANGELOG.md) (development history); this document records the current contract, not a receipt.

## 2. Profile selection and wire compatibility

The compatibility table above is the transition matrix. The v0.1.x profile preserves every existing `mcp-jack/v1` signing byte, domain, key-ID rule, body hash, Ed25519 validation rule, URL policy, and outer verification precedence. Existing `Profile.server_public_key`, `Profile.kid` user-key meaning, user-key `jack.key.rotate`, credentials, static pins, registry/invite state, and existing native argument rules remain unchanged. The new `jack.server.key` tool is only available in the explicitly selected profile. Any future v1 wire-byte change requires a new wire identifier and separate migration/rejection contract; never reinterpret v1.

Durable nonces and rotation are separately selectable capabilities and separately persisted/recovered state. Rotation does not make a volatile nonce cache durable: rotation mode requires the durable profile; durable nonce support alone does not rotate a static pin. If a selected deployment requires both, both must be enabled and pass their own acceptance gates. Rotation uses the durable authenticated nonce semantics for the new native tool when the deployment has selected that durable profile; do not infer support from another SDK/profile.

## 3. Public API and status summary

The exact normative text is in [`../spec/candidate/durable-nonces.md`](../spec/candidate/durable-nonces.md) and [`../spec/candidate/server-key-rotation.md`](../spec/candidate/server-key-rotation.md). This section summarizes the implemented surface.

### Durable request admission

After existing outer authentication succeeds, durable admission reserves the exact `(kid, nonce)` pair before any authorization/state mutation or handler dispatch. Freshness remains inclusive with immutable `W`; expiry is live at equality. Invalid signatures write no nonce. Unknown durable commit outcome fences, never dispatches, and never automatically retries. Durable-profile statuses are:

| HTTP | Code | Client meaning |
|---|---|---|
| 503 | `durability_unavailable` | Store/recovery/clock/fence unavailable, conflicting unresolved intent, lookup unavailable, or write/cleanup outcome unknown. Never dispatch. |
| 503 | `state_changed` | Captured owner/generation/W/key/enrollment snapshot changed; no dispatch, retry, or false claim nonce was consumed. |
| 503 | `clock_unsafe` | Clock rollback/invalid range, only after durable unsafe latch; failed/unknown latch is `durability_unavailable`. |
| 503 | `capacity_exhausted` | Capacity fails after authoritative replay lookup; live duplicate remains `401 replayed_nonce`. Never evict live/tombstone state. |

These are durable-profile failures after authentication. Existing pre-auth transport/body/rate/queue limits may reject before auth, but such refusals are not authenticated nonce-store outcomes. Current outer v1 auth precedence and `401 replayed_nonce` remain unchanged. New pre-final-reservation 503s are unsigned; current clients report `missing_auth` (or applicable missing/malformed-auth error), not status-only acceptance. Old automatic retry behavior is not asserted.

### Rotation tool

Request and result shape are summarized here; strict field/range and page rules are detailed in the rotation spec.

Native API: `jack.server.key` strict args `{"after_ordinal":0,"after_hash":"-"}` (or matching nonzero ordinal/full-record hash), and result `structuredContent:{current,records,head,complete}` mirrored semantically in one text item. The page has at most 16 total links; it may have an exact retained duplicate prefix ending at the request cursor followed by new contiguous links. Head/complete must match delivered terminal: true requires equal head; false requires head ordinal strictly greater; empty page is only cursor=head and complete=true. Current/result/head come from one latest committed server snapshot and signing-time sample, with final emission revalidation. See the rotation spec for complete envelope shapes and strict client page validation.

Native errors: `400 invalid_params`; `409 rotation_checkpoint_unavailable` (cursor/link prefix missing, pruned, or mismatched; OOB recovery); `503 rotation_state_unavailable` (fence, clock, store, or required signer unavailable). A signed native error is handled before rotation payload parsing; unsigned bodies/headers never establish trust. Outer order remains unknown outer `kid`, freshness, signature, authenticated timestamp assignment, then rotation payload. Unknown outer key always fails before chain parsing.

## 4. Selected directions, technical defaults, and implementation gates

### Owner-selected directions recorded in the read-only baselines

The owner-selected directions are a durable authenticated nonce reservation before authorization/mutation/dispatch, fail-closed/no-retry on unknown outcome, and rejection of timestamp startup floors. The 48-hour next-successor grace and unlimited pending announcements with no one-pending/cooldown restriction are also owner-selected. The logical event that samples `P_i` is a profile rule, not a separate approval. The Go gateway's durable nonce profile uses the bbolt v1.5.0-backed Linux private-file store; `go.mod` declares go 1.25.0; Rust MSRV is 1.88.

### Profile technical rules

The logical publication event defining `P_i` is the serialized authorization point; bind that sample to `R_i` and persist them atomically, with serviceability only after exact commit ACK. Delayed physical visibility does not move P/A. Arbitrarily many announcements may be pending; equal-time activations use greatest ordinal. The K1 Monday 10/K2 Monday 11 example yields K1 cutoff Wednesday 11, not an independent TTL from K1's own announcement. The codec is exact 10-line `B_i` plus two signature lines (12-line `R_i`), domain `mcp-jack/server-key-rotation/min1`, exact endpoint/audience UTF-8 binding, canonical unpadded base64url, strict existing key admission, and SHA-256 over exact complete prior `R`. Client response cutoff is strict at known successor activation; first-seen bridge uses fresh `t<A_(m+1)`. The API, errors, pagination, ClockGuard, whole-snapshot callback, and bounded capacities are profile rules, not separately owner-approved choices.

The rotation server has its own durable H/rollback latch/dirty startup gate in its rotation store; it MUST check/advance H before publication authorization, response-signer selection, and final emission. Uncertainty or rollback fences signing/publication without old-key fallback. This is distinct from nonce-store H and client ClockGuard; a self-consistent backup rollback is not locally detected.

### Implemented state and remaining gates

The profile is implemented: Go reference implementation and CLI; Rust provider traits (`ResponseSigner`/`ResponseKeys`) and server side; TypeScript client wiring; and CI jobs covering the 3x3 rotation interop matrix and the official MCP SDK end-to-end path. Remaining gates are independent audit, cross-SDK conformance review at the freeze, and release authorization. CI green alone does not approve a release, version, or publication. Versions and publication flags remain unchanged; `go.mod` is 1.25.0; Rust MSRV is 1.88.

## 5. Material compatibility limits and contradictions

The profile is the next-successor 48-hour grace with unlimited pending successors/no one-pending or cooldown rule. Its material limits are properties of the shipped profile: a static client is incompatible at a rotation switch (it rejects the new outer `kid` with no bootstrap or fallback); the suppressed-suffix limitation holds; the fixed publication time P gives no guarantee of 48-hour first visibility to a client that has never seen the predecessor; and backup rollback is not locally detected, so a restore can silently roll back rotation or nonce state (a restore is undetectable locally; recovery provisions clean state and re-anchors pins out of band). The physical-visibility limitation of P and the backup rollback caveat are detailed in the candidate specs. Hash-linked records establish local continuity, not global fork prevention or a protected server identity beyond exact URL/audience/OOB trust.
