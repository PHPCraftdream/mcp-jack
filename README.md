# mcp-jack

[![ci](https://github.com/PHPCraftdream/mcp-jack/actions/workflows/ci.yml/badge.svg)](https://github.com/PHPCraftdream/mcp-jack/actions/workflows/ci.yml)

mcp-jack wraps ordinary MCP over HTTP with signed, replay-protected messages, key management, protocol auditing, and SDKs for Go, Rust, and TypeScript. The reduced contract and SDK migration are represented by baseline `b13b972`; the integrated candidate `444c69b` passed the checks recorded in readiness. Shared interop matrix acceptance, packaged-consumer evidence, and coverage/fuzz evidence were verified in GitHub CI on `444c69b` (see readiness evidence). No release has been made and nothing has been audited.

## Contract

Authenticated ordinary MCP requests pass through unchanged. The application authorizes them using the immutable verified caller identity `{kid, name, admin}` supplied by the server SDK; request headers and bodies cannot supply that identity. The strict-boolean `admin` flag (false by default) gates reserved `jack.admin.*` tools only. Protocol operations are audited. User `kind`, scopes, and the policy engine are removed; legacy registry/state records containing `kind` or `scopes` are rejected without migration or rewrite.

An authenticated session channel is a future v0.2 direction, not an implemented feature. Server-key rotation is separate future work requiring an exact design. See [the scope review](docs/design/scope-review-2026-11-08.md).

## Why

MCP has a good "tool plus description" model, but the practice around it is weak for privileged operations:

- clients keep tokens and keys in config files and environment variables in plain text;
- the stdio transport has no authorization: access is whoever launched the process;
- common server implementations offer one shared, optional token with no scopes, lifetime or audit trail.

Example: the embedded MCP server of `process-compose` (Apache-2.0) protects its SSE port with Host and Origin checks and an optional shared token (`PC_API_TOKEN`). There are no roles, scopes, TLS or call log. Before version 1.120.0 there was not even a Host check, so any website could drive local processes through DNS rebinding (GHSA-5gm3-9crp-6g3v).

Operations such as restart or a configuration change need more than "whoever reached the port".

## Design principles (hypotheses under review)

1. **Transport wrapper, not a new tool model.** Ordinary MCP messages travel over HTTP unchanged.
2. **No bearer tokens.** Each request is signed with Ed25519 and bound to the target server, a time window, and a fresh nonce; responses also carry Ed25519 signatures. TLS provides confidentiality.
3. **Application-owned authorization.** The application authorizes requests using the immutable verified caller identity `{kid, name, admin}` supplied by the server SDK; the wrapper does not add scopes or a policy engine.
4. **User key management proves possession.** Native user and invite tools support administrator management. Enrollment proves possession of the corresponding private key; key lifecycle is distinct from application authorization.
5. **Private keys stay out of config files.** Prefer OS keystores, signer agents, or hardware signers; SDKs expose a signer interface.
6. **Audit protocol operations accurately.** Record the verified caller and operation observed, distinguishing protocol activity from application-level effects.
7. **Logs are untrusted input.** Treat log content as data, not instructions to an agent.

## Implementations

| Language | Location | Main components |
|---|---|---|
| Go | repository root | `client/`, `server/`, `userkey/`, `spec/` |
| Rust | [rust/](rust/README.md) | `mcp-jack` crate; client and server SDKs; optional client HTTP transport |
| TypeScript | [ts/](ts/README.md) | `mcp-jack` package; client, Fetch and `node:http` server adapters |

The repository-root Go package `jack` contains shared protocol primitives only; it is not the client or server SDK. `client/` owns signing/verification transport, connection profiles, and typed native-tool calls. `server/` owns verification, middleware, identity hand-off, nonce/state stores, native tools, and audit sinks. `userkey/` provides role-specific key and transfer utilities independently of the client package. `spec/` supplies fixture loaders and conformance data. This separation is intentional.

## Checks and integration status

The workflow definitions specify Go vet/tests and race tests; Rust formatting, clippy, tests, feature-isolation and MSRV checks; TypeScript typecheck/tests on supported Node and OS lanes; and fixture freshness checks. These are standing checks, not results claimed for `b13b972`.

Package-isolation consumers install the actual npm tarball (`private: true`), Rust `.crate` (`publish = false`), and a Go module snapshot separately. The pinned baseline is TypeScript 5.9, Go 1.22, Rust 1.85, and Node 20/22. These are baseline pins, not new measurements or green results; no versions are changed here.

The interop and credential-transfer harnesses, packaged consumers, coverage reports, and bounded Go fuzz campaign have workflow definitions in this repository. Matrix acceptance, packaged-consumer checks, coverage, and fuzz evidence for this baseline were verified in GitHub CI on `444c69b` (see readiness evidence). The current interop scenario source of truth is [`interop/scenarios.json`](interop/scenarios.json). Historical readiness measurements are explicitly tied to their earlier commit in [docs/readiness.md](docs/readiness.md).

## Specification and future work

The contract and shared fixtures live in [spec/](spec/README.md). Q1's authenticated session channel is future v0.2 design work. Q3 server-key rotation requires a separate exact design. Service discovery remains open.

## Licence

Licensed under either the [Apache License, Version 2.0](LICENSE-APACHE) or the [MIT licence](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work, as defined in the Apache-2.0 licence, shall be dual licensed as above, without any additional terms or conditions.

## Name

The name `mcp-jack` was checked on 2026-11-05: no package with that name exists on npm, crates.io or PyPI, GitHub has no user or organisation `mcp-jack` and no repository with that exact name, and a web search found no exact match.
