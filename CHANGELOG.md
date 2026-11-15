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
- The release is not independently audited.

## Development history

- Contract reduction and foundations (#14, #15, #16, #19, #22): admin-only wrapper with verified caller identity, sr1 server-key-rotation proposal document, foundations policy, security design and contract integration.
- Go CLI and durable backend (#17, #20, #21, #24): CLI integration, backpressure, admission, durable nonce stores and CLI commands.
- Server rotation provider and Rust/TypeScript SDK (#25, #33, #34, #35, #36, #37, #38): Rust/TS SDK delivery, Go server store and provider (#33, #34), TS server wiring, Rust server provider, Rust rotation refresh HTTP client, property/mutation tests with a shared corpus; crash-limitation documentation (#39).
- Interop and end-to-end (#40, #41, #42) plus packaging and spec fixtures (#18, #23): 3x3 rotation interop, official MCP SDK end-to-end, UNIX-socket stdio bridging for Node clients, packaging delivery, spec fixtures.

Earlier project history is in git log; this list is a summary, not a receipt.

No versioned release entries exist yet. A future release entry requires authorized release actions.
