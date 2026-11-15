# Candidate protocol extensions: durable replay and server-key rotation

These documents are normative for the v0.1.x durable-nonce and server-key-rotation profile. The profile is explicitly selected per deployment (out of band, never negotiated on the wire) and is frozen on the wire for the whole 0.1.x line: no wire changes within 0.1.x. It neither changes existing `mcp-jack/v1` bytes nor adds publication, version bumps, or release authorization.

This directory separates: **selected owner directions** (durable authenticated nonce reservation before dispatch; arbitrary many successor announcements with the fixed 48-hour schedule); **profile technical defaults** (codec, API, bounds, cutoff, statuses, storage rules); and **remaining acceptance gates**. A technical default is not an additional owner approval. The directions and defaults are implemented and exercised in CI; this document does not claim a runtime result beyond that.

## Documents

- [durable-nonces.md](durable-nonces.md) — candidate durable replay-protection semantics, storage outcomes, recovery, HTTP errors, and acceptance requirements.
- [server-key-rotation.md](server-key-rotation.md) — candidate chained server-key schedule, exact record codec, `jack.server.key` delivery, client trust snapshot, and publication/signing gates.
- [../../docs/protocol-transition.md](../../docs/protocol-transition.md) — selection, compatibility, migration, and acceptance boundary across the current v1 contract and the future profile.

## Decision boundary

The profile is explicitly out-of-band selected; it is not negotiated by the network and does not change the existing `v1` domain or bytes. A static client remains static. Durable nonce and rotation state are separate stores/records and each requires explicit selected support. The Go gateway's durable nonce profile uses the bbolt v1.5.0-backed Linux private-file store; `go.mod` declares go 1.25.0; Rust MSRV is 1.88; TypeScript stays private/unpublished. Versions and publication flags are unchanged.

The exact logical publication authorization event defining `P_i` is a profile rule: it is sampled once and immutable, and it is not an independently recorded owner decision. The client also requires a separate durable ClockGuard for monotone raw time and rollback fences; ordinary response verification or an exact duplicate may advance that guard while invoking zero trust-extension callbacks. Trust and clock revisions are separate. A local guard does not detect a self-consistent backup rollback.

The profile is implemented: Go is the reference implementation, with Rust and TypeScript client sides and the Rust/Go server sides, CLI server-key commands, and CI exercise including the rotation interop 3x3 matrix. Independent audit, publication, and release remain separate decisions.
