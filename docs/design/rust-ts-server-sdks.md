# Design: Rust and TypeScript SDKs

The SDK migration in baseline `b13b972` implements the current reduced contract in Go, Rust, and TypeScript. Authenticated ordinary MCP requests pass through unchanged; the wrapped application receives immutable verified identity `{kid, name, admin}` and performs its own authorization. The protocol's `admin` flag gates only reserved `jack.admin.*` tools. Legacy user/state `kind` or `scopes` data is rejected without migration or rewrite.

This is a design and source inventory, not a test result. GitHub CI verified shared interop, packaged consumers, coverage, and fuzzing on `444c69b`. Q1's authenticated session channel is future v0.2 design work; Q3 server-key rotation is separate future work requiring an exact design. Neither is implemented.

## Repository and package boundaries

- The Go module is at the repository root. Root package `jack` contains shared primitives, not client or server APIs. `client/` provides signing and response-verifying transport, profiles, and typed protocol calls. `server/` provides verifier, middleware, immutable identity hand-off, state/nonce, native tools, and audit. `userkey/` supplies role-specific user-key and transfer utilities. `spec/` provides fixture loaders and conformance data.
- Rust is one `mcp-jack` crate in `rust/`, with client, server, protocol primitives, and user-key modules. Its Tower HTTP adapter is behind `http`; optional client HTTP transport is behind `client-http`; interop executables are behind `interop`. Default features remain empty.
- TypeScript is one ESM `mcp-jack` package in `ts/`. The root export provides shared primitives, server APIs, user-key transfer and the namespaced client API. Server adapters are Fetch and `node:http`; interop executables live under `src/interop/`. The package targets Node 20+, is `private: true`, and has no runtime dependencies.

These boundaries keep common cryptographic and wire primitives separate from client transport, server integration, and independent user-key transfer. The Go `spec` package embeds fixture JSON via `go:embed`; Rust and TypeScript test suites load shared fixtures in place, not as embedded runtime-library data.

## Current behavior to preserve

- Requests are authenticated with strict Ed25519 verification, freshness checks and replay protection. The exact request body bytes are verified; middleware restores the body before forwarding.
- Defined protocol-native tools are handled by the wrapper. Only `jack.admin.*` requires protocol `admin`; ordinary MCP calls and methods are forwarded without policy filtering. The verified identity is immutable and cannot be constructed from request data.
- Protocol operations are audited. State updates preserve atomicity and last-active-admin protection; state loading rejects unknown/legacy fields rather than rewriting input.
- Responses are signed, including authenticated application errors. Streaming responses are refused with 501 in v0.1. Request and response limits bound bytes, not elapsed time; an application deadline must wrap the full handler if needed.
- Client destination policy is literal-only: HTTPS for valid hosts and HTTP only for canonical literal loopback. SDK-owned clients refuse redirects and retain TLS validation. Caller-injected transports remain responsible for connecting to the exact supplied URL, TLS for HTTPS, and no redirects.
- User-key transfer remains a separate, role-asymmetric contract: client role has no private-export API; server issuance exposes public registration identity separately from an explicit credential hand-off; credential trust requires an independently pinned server identity. See [user-keys.md](user-keys.md).

## Current test-source inventory

The shared fixtures in `spec/fixtures/` include authentication, keys, requests, responses, administration, state loading, URL policy, and user-key transfer. Go tests live beside root primitives and under `client/`, `server/`, and `userkey/`; Rust integration tests are under `rust/tests/`; TypeScript tests are under `ts/test/`. These are source inventories only and make no claim that the baseline has passed them.

The current interop scenario source is [`interop/scenarios.json`](../../interop/scenarios.json). It includes identity-forwarding, exact request-byte preservation, forged-identity rejection, and strict-boolean admin-control cases. CI acceptance passed on `444c69b`. Preserve signing-byte parity, trust, freshness/replay, signed authenticated errors, and last-active-admin coverage; the integrated shared harness passed on `444c69b`.

## Historical CI boundary

Workflow definitions describe Go vet/tests and race tests; Rust formatting, clippy, tests, feature isolation and MSRV checks; TypeScript typecheck/tests; fixture freshness; interop and transfer harnesses; consumers; coverage; fuzzing; and licence checks. The source inventory is separate from execution receipts for the integrated candidate. Coverage, fuzz, packaged-consumer and shared interop evidence are recorded for `444c69b` in readiness evidence.

The original design-time requirement was fixture parity on Linux and Windows, with shared fixtures consumed in place. Current CI definitions and all baseline outcomes must be assessed by parent CI; readiness records exact green CI evidence for `444c69b`.

See [interop design](interop.md), [scope review](scope-review-2026-11-08.md), and [readiness](../readiness.md) for the separately owned harness boundary, scope decisions, and commit-specific metrics.
