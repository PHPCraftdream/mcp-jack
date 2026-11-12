# Candidate protocol extensions: durable replay and server-key rotation

These documents are normative only as candidate text for a future explicitly selected profile. They neither revise current v0.1 nor add SDK support/export, dependency, manifest, version, publication setting, or runtime implementation.

This directory separates: **selected owner directions** (durable authenticated nonce reservation before dispatch; arbitrary many successor announcements with the fixed 48-hour schedule); **candidate technical defaults** (codec, API, bounds, cutoff, statuses, storage rules); and **future implementation/acceptance gates**. A candidate technical default is not an additional owner approval.

## Documents

- [durable-nonces.md](durable-nonces.md) — candidate durable replay-protection semantics, storage outcomes, recovery, HTTP errors, and acceptance requirements.
- [server-key-rotation.md](server-key-rotation.md) — candidate chained server-key schedule, exact record codec, `jack.server.key` delivery, client trust snapshot, and publication/signing gates.
- [../../docs/protocol-transition.md](../../docs/protocol-transition.md) — selection, compatibility, migration, and acceptance boundary across the current v1 contract and the future profile.

## Decision boundary

The future profile is explicitly out-of-band selected; it is not negotiated by the network and does not change the existing `v1` domain or bytes. A static client remains static. Durable nonce and rotation state are separate stores/records and each requires explicit selected support. The owner-approved Go direction is a vetted transactional library; bbolt v1.5.0 is a proposed, source-reviewed candidate for future dependency/security/platform qualification. Go 1.25 is approved as the whole Go module floor; deployment builds use Go 1.26.11. Manifest/dependency migration is later work. Rust 1.88, TypeScript `private: true`, Rust `publish = false`, package versions, and publication settings remain unchanged here.

The exact logical publication authorization event defining `P_i` is a candidate default, not an independently recorded owner decision. The client also requires a separate durable ClockGuard for monotone raw time and rollback fences; ordinary response verification or an exact duplicate may advance that guard while invoking zero trust-extension callbacks. Trust and clock revisions are separate. A local guard does not detect a self-consistent backup rollback.

No runtime implementation or behavior changes are made by these documents. They add no SDK surface/export, dependency, manifest, current normative v0.1 spec, or baseline design-document changes. The accompanying fixture sources and additive CI job validate the candidate only. Fixture/vector source preparation is authorized in Task 57 and is not by itself acceptance. Later exact-head production acceptance requires independent Go, Rust, and TypeScript references, all three conformance runners, MCP integration, and security/backend qualification; no such acceptance is claimed here.
