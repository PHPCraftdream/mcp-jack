# Security policy

The protocol ships as v0.1.x with the durable-nonce and server-response-key-rotation profile implemented. It becomes normative and wire-frozen for the 0.1.x line only when the freeze is accepted on an exact commit, not before; see the [protocol transition policy](docs/protocol-transition.md). The release is **not independently audited** and nothing is published. Source includes Go, Rust and TypeScript SDKs plus the Go CLI, gateway and stdio bridge. See the [threat model](docs/threat-model.md), [versioning and release policy](docs/versioning.md), and [candidate documents](spec/candidate/README.md).

What is implemented now: bbolt-backed durable nonce reservation before authorization, state mutation and dispatch; an unknown durable-write outcome fails closed and is never automatically retried; server-key rotation with one fixed publication time `P` per announced key, activation `A = P + 172800` seconds, both keys valid during the overlap, a strict cutoff at the successor's activation, and explicit single-page client refresh with no hidden retry or reset. Volatile in-memory nonce stores remain the SDK default when a deployment does not select the durable profile; the CLI gateway selects it via the optional `durable_nonces` profile.

## Known limitations

- No operator recovery command after an abnormal stop (kill, OOM, power loss): nonce and ring stores stay dirty/unknown and every entry point refuses to serve until a manual recovery procedure completes ([threat model](docs/threat-model.md), [operations](docs/operations.md)).
- One owner of nonce/ring state per deployment; no cluster or high-availability mode.
- Upstream SSE answers are unsupported: the gateway closes the stream and answers a signed 501 (the official TypeScript MCP server 2.4.0 answers `initialize` with `text/event-stream` even in JSON mode).
- Bounded MCP profile: legacy Streamable HTTP 2025-11-25 over stdio, one JSON-RPC object per POST, no sessions, no GET stream.
- Signatures cover only their defined fields and provide no confidentiality; TLS is the transport's job.
- On Windows the CLI's private-file stores fail closed by design; the SDKs are tested on Windows in CI, and the durable private-file stores are Linux-only.
- Audit delivery is best effort.
- Rust/TypeScript are covered by deterministic property/mutation tests plus a shared corpus, not coverage-guided fuzzing (Go has a bounded fuzz campaign).
- The release is not independently audited.

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Include the affected component (specification section, Go, Rust or TypeScript SDK, CLI), a description, and a reproduction if you have one.

You can expect an acknowledgement within a few days. Fixes are developed privately and disclosed together with the advisory.

## Scope

In scope: authentication and signature validation; nonce, freshness and replay behavior (including restart and durable-backend behavior); server response-key rotation and client pin transitions; enrollment, user-key rotation and protocol-admin checks; parser or serialization differences across SDKs; the `Jack-Auth` header and canonical encoding rules; CLI/gateway/stdio bridge boundaries; and credential handling. Report suspected issues in ordinary MCP authorization too, but note that the protocol does not supply a policy engine: authorization for ordinary MCP operations is application-owned. The protocol's `admin` privilege gates only native administrative tools.

Out of scope as secrets: the deterministic test keys in `spec/fixtures/keys.json`, public keys/vectors, and sample state documents under `spec/fixtures/`. They are public test material and must never be used outside tests. Findings involving their test-only status are not production credential compromise.

No test, build, runtime probe, scan or audit is claimed for this documentation edit; verification happens in the project's CI workflows.
