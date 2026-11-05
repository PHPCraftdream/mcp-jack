# mcp-jack

[![ci](https://github.com/PHPCraftdream/mcp-jack/actions/workflows/ci.yml/badge.svg)](https://github.com/PHPCraftdream/mcp-jack/actions/workflows/ci.yml)

Status: early draft. The specification, the normative test fixtures and SDKs for Go, Rust and TypeScript exist. CI runs the unit and conformance tests of all three on Linux and Windows and a cross-language interop matrix of every client against every server (3 × 3). No release has been made and nothing has been audited.

## Intent

mcp-jack is a **secure transport protocol that wraps plain MCP**. Ordinary MCP messages (JSON-RPC) travel inside it unchanged; mcp-jack adds the protection MCP lacks: who is calling, what they may do, and a record of what they did.

A service embeds an mcp-jack server (or sits behind an mcp-jack gateway). Other programs and agents connect and can, subject to policy:

- read logs and statistics;
- read and change settings;
- `reload` and `restart`;
- manage users and their keys, through the protocol itself.

## Why

MCP has a good "tool plus description" model, but the practice around it is weak for privileged operations:

- clients keep tokens and keys in config files and environment variables in plain text;
- the stdio transport has no authorization: access is whoever launched the process;
- common server implementations offer one shared, optional token with no scopes, lifetime or audit trail.

Example: the embedded MCP server of `process-compose` (Apache-2.0) protects its SSE port with Host and Origin checks and an optional shared token (`PC_API_TOKEN`). There are no roles, scopes, TLS or call log. Before version 1.120.0 there was not even a Host check, so any website could drive local processes through DNS rebinding (GHSA-5gm3-9crp-6g3v).

Operations such as restart or a configuration change need more than "whoever reached the port".

## Design principles (hypotheses under review)

1. **Transport wrapper, not a new tool model.** The protocol carries unmodified MCP over HTTP. Three roles: a gateway in front of an unmodified MCP server, a local stdio bridge for MCP clients that know nothing about mcp-jack, and an embeddable library.
2. **No bearer tokens.** Every request and response is signed with Ed25519, bound to the target server, a time window and a fresh nonce. Confidentiality is delegated to TLS.
3. **Authorization is server policy.** Rules map MCP methods and tools to flat scopes (for example `read`, `config:write`, `lifecycle`, `admin`); everything else is denied.
4. **User management is part of the protocol.** Administrators create users and invites through MCP tools; any party may generate a key pair; enrollment proves possession of the key. Servers and clients get this from the SDKs.
5. **Private keys stay out of config files.** OS key stores, signer agents or hardware tokens; the SDKs expose a signer interface.
6. **Audit everything.** Each call and each administrative change records the caller's key identity.
7. **Logs are untrusted input.** A log line can contain instructions for an agent, so agents that read logs are never granted write or admin scopes.
8. **Do not reinvent metrics and logs.** Use Prometheus and OpenTelemetry formats; the protocol only carries the request.

## Implementations

| Language | Location | Content | Status |
|---|---|---|---|
| Go | module at the repository root (`server/`, `client/`) | server middleware, client, native tools | tests and interop green in CI |
| Rust | [rust/](rust/README.md), crate `mcp-jack` (MSRV 1.85) | server verifier and tower layer, client, native tools | tests and interop green in CI; builds on Rust 1.85 |
| TypeScript | [ts/](ts/README.md), npm package (Node 20+, no runtime dependencies) | server verifier with Fetch and `node:http` adapters, client, native tools | tests and interop green in CI (Node 20 and 22) |

All implementations are checked against the same normative test vectors so they cannot drift apart. [interop/](interop/README.md) adds cross-language tests: a Node harness starts one server and one client executable per language and runs every scenario for all 3 × 3 server and client pairs, plus byte-exact signing checks.

### Go layout

| Package | Content |
|---|---|
| `jack` (repository root) | Shared primitives: strict base64url, key ids, signing strings, `Jack-Auth` parsing, strict Ed25519 verification, public-key validation, scope and pattern matching, protocol errors |
| `spec` | The embedded fixtures and strict typed loaders; conformance tests import it |
| `server` | Request verifier, policy engine, `net/http` middleware, native tools (enrollment, key rotation, user and invite administration), `BootstrapAdmin`, and the nonce, state and audit stores |
| `client` | Signer abstraction, signing and verifying `http.RoundTripper`, connection profile, typed calls for the native tools |

Run the checks (CI does the same; the Rust, TypeScript and interop commands are in their READMEs):

```
go vet ./...
go test -race ./...
node spec/tools/gen-fixtures.mjs --check
node interop/run.mjs --self-test
```

## Specification

The draft lives in [spec/](spec/README.md): authentication, authorization, user management, an optional service-management profile, test fixtures and a reference verifier.

## Open questions

- Whether services will be local only or also remote.
- Whether clients will be only our own agents or also third-party programs.
- How services discover each other (registry or a well-known address on each).

## Licence

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT licence](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work, as defined in the Apache-2.0 licence, shall be dual licensed as above, without any additional terms or conditions.

## Name

The name `mcp-jack` was checked on 2026-11-05: no package with that name exists on npm, crates.io or PyPI, GitHub has no user or organisation `mcp-jack` and no repository with that exact name, and a web search found no exact match.
