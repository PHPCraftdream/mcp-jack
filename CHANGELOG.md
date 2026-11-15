# Changelog

This file records repository history. The `0.1.0 (unreleased)` section describes what ships in the upcoming release. No release has been made, nothing is published, and entries here are not release authorization.

## 0.1.0 (unreleased)

### What ships

- Authenticated transport contract: Ed25519 request and response signatures, replay protection, strict canonical encoding, implemented across the Go, Rust and TypeScript SDKs.
- User management with user-key rotation and a single strict-boolean admin flag.
- Optional durable nonce admission with a bbolt-backed Go backend and fail-closed handling of unknown outcomes.
- Server response-key rotation: `jack.server.key` delivery, fixed publication time P plus 48 h activation, overlap of both keys, strict cutoff on activation, and explicit single-page client refresh — in all three SDKs plus the Go CLI.
- Candidate `jack.server.key` result decoding matches the response `id` canonically in Go, Rust and TypeScript: a numeric id must be the canonical JSON text of the expected value (`7.0`, `7e0`, `+7`, `07` fail with `rotation_result_invalid`).
- Go CLI (`jack`): keygen/bootstrap/enroll/gateway/bridge, user and invite admin commands, nonce and server-key commands.
- 3x3 interop matrices: request/response, rotation, and credential transfer.
- Official MCP SDK end-to-end CI job over the bounded legacy 2025-11-25 stdio profile.
- Ed25519 verification is equally strict in all three SDKs: a signature whose R encodes a small-order point is rejected alongside the S < L rule, so the Go and TypeScript verifiers match Rust on crafted small-order-R signatures.
- Expired invites are purged in the same atomic state edit that creates, enrolls with or revokes an invite, and in first-admin bootstrap, in the Go, Rust and TypeScript SDKs; the gateway's 1024-invite cap is evaluated after the purge, so a deployment full of expired invites can create a new invite. The document format, load rules and every wire response are unchanged, and a rejected update leaves the stored document untouched.
- The Go, Rust and TypeScript server SDKs give the same verdict on these inputs (remaining differences are listed in `docs/independent-review.md`): lone surrogate `\uXXXX` escapes and bodies nested deeper than 128 levels are `400 invalid_request`, the TypeScript node adapter verifies a GET with a body over the exact bytes sent, and a `v2` scheme is `unsupported_version` even with non-ASCII parameters (spec 01 section 3, spec 02 section 2).
- The reference verifier rejects small-order R encodings like the SDKs, and the shared corpus gains vectors for the small-order-R signature (request and response), surrogate escapes, the nesting-depth boundary and the GET body.
- Go CLI hardening from the internal pre-review: the stdio bridge refuses `jack.*` tool calls locally and never signs them, and the gateway durable nonce profile rejects a `window` above 30 seconds so that unauthenticated enrollment attempts cannot fill the nonce capacity.
- The audience `aud` must be non-empty and must not contain a byte below 0x20 or the byte 0x7f: the Go, Rust and TypeScript servers and clients refuse such a configuration (the signing string is LF-joined, so a control character would make it ambiguous; spec 01 section 3.1).
- The TypeScript verifier and nonce store fail closed on an invalid injected clock or window (`NaN`, `undefined`, negative, infinite): the request is answered `500 internal_error`, no nonce is recorded and nothing is dispatched.
- TypeScript `acceptRefresh` reports a refresh that committed before a late final-gate failure (`RotationRefreshCommittedError` carries the committed outcome), like Go and Rust.
- Unknown-key `jack.enroll`: Rust reads only the arguments the exception needs, so an unrelated member such as `"x":1e999` no longer turns the request into `401 unknown_key`; the enrollment name reaches the audit target only after validation in all three SDKs (spec 03 section 3.2).
- A body that starts with a UTF-8 byte order mark is `400 invalid_request` in all three SDKs and in the reference verifier (spec 02 section 2).
- The TypeScript state-file and registry loaders decide integer-ness on the lexeme: `1.0`, `1e3` and other non-integer spellings are rejected like in Go and Rust, with shared vectors.
- Candidate `jack.server.key` response ids are compared by exact decimal arithmetic in Go and Rust (no float64 rounding at or above 2^53); the TypeScript decoder accepts a `bigint` expected id; the shared rotation corpus covers ids beyond 2^53.
- The client refuses a stream whenever any comma-joined Content-Type member has the media type `text/event-stream` (text before the first `;`, SP and HTAB trimmed, ASCII case-insensitive), identically in Go, Rust and TypeScript, pinned by the shared table `spec/fixtures/client-streaming-refusal.json`.
- A rotation announcement is refused, before authorization and commit, once the ring holds more than 1024 keys (Go, Rust, TypeScript): serving refuses more than 1024 retired keys, so a longer ring could become unservable by the passage of time alone. A ring is good for at most 1024 rotations; the candidate specification states that `P` is chosen by the signer and that the 172800 s interval is an overlap, not a notice period.
- Each verifier keeps the highest clock sample it has seen and uses max(sample, highest seen) for freshness and the volatile nonce store, so a wall-clock step back cannot revive a purged nonce within a process; response timestamps keep the raw sample and the durable profile still latches its own clock (spec 01 section 4).
- The signed request target is the origin-form target exactly as received and consists only of the bytes 0x21 to 0x7E; absolute-, authority- and asterisk-form targets and any other byte are refused before verification with an unsigned `400 invalid_request` in the Go, Rust and TypeScript adapters (node:http may answer a bare 400 itself), and a fragment (the first `#` and everything after it) is dropped before verification. The TypeScript node adapter signs the wire bytes; the TypeScript fetch adapter, which cannot see raw bytes, accepts only targets that survive WHATWG parsing unchanged and answers `malformed_auth` for two `Jack-Auth` lines. Five new 3x3 interop scenarios prove the rule (spec 01 section 3.1).
- The enrollment exception requires a live invite: an unregistered `kid` passes authentication only for a self-signed `jack.enroll` whose `code` names a live invite, looked up read-only before the signature and before any nonce is recorded; otherwise the answer is the ordinary unsigned `401 unknown_key`, with no nonce and no audit event (a bad public key without a live invite is now `401 unknown_key`, not `400 key_rejected`). `403 invalid_invite` remains for the race between the check and the consumption. The state interfaces gain a read-only invite lookup and `jack enroll` explains a 401.
- A request body in which any JSON object has two members with the same name (compared after unescaping) is `400 invalid_request` after authentication, in all three SDKs and the reference verifier; last-wins handling is removed (spec 02 section 2).
- Internal, non-independent security pre-review package for an external reviewer: `docs/security-review-package.md`.
- Bounded Go fuzz campaign (15 native targets, including the server-key-rotation parsers and the durable store codecs), coverage lanes, and packaged-consumer lanes.
- Deterministic property/mutation tests and a shared corpus for the Rust and TypeScript rotation layers.

### Known limitations

- No operator recovery command after an abnormal stop (kill, OOM, power loss): stores stay dirty/unknown, every entry point refuses to serve (fail closed), recovery is a manual operator procedure.
- One owner of the nonce/ring state per deployment; no cluster or HA mode.
- Upstream SSE answers are unsupported; the gateway closes the stream and answers a signed 501.
- Bounded MCP profile: legacy Streamable HTTP 2025-11-25 via stdio, one JSON-RPC object per POST, no sessions, no GET stream.
- Signatures do not cover arbitrary headers and provide no confidentiality; TLS is the transport's job.
- On Windows the CLI stores fail closed by design (durable private-file stores are Linux-only; SDKs are tested on Windows).
- Audit delivery is best effort.
- Rust and TypeScript have property/mutation tests and a shared corpus but no coverage-guided fuzzing (Go has a bounded fuzz campaign).
- Only the Go SDK and the CLI gateway have the durable nonce store; Rust and TypeScript servers keep nonces in memory.
- A forward clock jump latches the durable stores unsafe permanently and there is no recovery command; unauthenticated load is bounded only by the gateway's global admission limits. See `docs/operations.md` and `docs/security-review-package.md`.
- The release is not independently audited.

## Development history

- Contract reduction and foundations (#14, #15, #16, #19, #22): admin-only wrapper with verified caller identity, sr1 server-key-rotation proposal document, foundations policy, security design and contract integration.
- Go CLI and durable backend (#17, #20, #21, #24): CLI integration, backpressure, admission, durable nonce stores and CLI commands.
- Server rotation provider and Rust/TypeScript SDK (#25, #33, #34, #35, #36, #37, #38): Rust/TS SDK delivery, Go server store and provider (#33, #34), TS server wiring, Rust server provider, Rust rotation refresh HTTP client, property/mutation tests with a shared corpus; crash-limitation documentation (#39).
- Interop and end-to-end (#40, #41, #42) plus packaging and spec fixtures (#18, #23): 3x3 rotation interop, official MCP SDK end-to-end, UNIX-socket stdio bridging for Node clients, packaging delivery, spec fixtures.

Earlier project history is in git log; this list is a summary, not a receipt.

No versioned release entries exist yet. A future release entry requires authorized release actions.
