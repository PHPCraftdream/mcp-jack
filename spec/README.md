# mcp-jack specification

Status: draft v0.1. The first slice covers authentication and authorization. Management methods, streaming and delegation come later.

## Layout

| Path | Content |
|---|---|
| [01-authentication.md](01-authentication.md) | Keys, signed requests and responses, verification order, replay protection |
| [02-authorization.md](02-authorization.md) | Key registry, scopes, operation-to-scope mapping, deny-by-default evaluation |
| `fixtures/` | Deterministic test keys, registry and request/response vectors (normative) |
| `tests/` | Conformance runner contract and the generated case index |
| `tools/` | Fixture generator and the reference verifier used to cross-check them |

## Conventions

- Test vectors are normative: an implementation conforms when it produces the expected result for every vector.
- Fixtures are generated, not hand-written. Keys are derived from public strings, so they are reproducible and **test only**.
- The reference verifier (`tools/reference-verifier.mjs`) exists to validate the spec text and the fixtures. It is not an SDK.

```
node spec/tools/gen-fixtures.mjs          # regenerate
node spec/tools/gen-fixtures.mjs --check  # fail if files on disk are stale
```

## Decisions in this draft

| # | Decision | Why |
|---|---|---|
| D1 | A profile of MCP over HTTP (JSON-RPC bodies, `tools/call`). stdio and WebSocket are out of scope. | Keeps existing MCP clients usable. stdio is local and relies on OS trust. WebSocket is not part of the MCP specification. |
| D2 | Ed25519 only, a single protocol version, no negotiation. | No downgrade surface; identical results across Go, Rust and JS. |
| D3 | A small custom signing format over raw bytes instead of RFC 9421 (HTTP Message Signatures). | A plain newline-joined string is easy to reproduce bit-for-bit in three languages and to test with vectors. Trade-off: not a standard; see Q7. |
| D4 | Per-request signature with a nonce cache, no session. | Matches the stateless transport of the 2026-07-28 MCP specification; no session state to steal or to synchronise. |
| D5 | TLS provides confidentiality; signatures provide authentication, integrity, replay protection and an audit identity. | Do not reinvent channel encryption. |
| D6 | Deny by default; scopes are flat and not hierarchical. | Small and auditable; a read-only agent can never be upgraded implicitly. |

## Open questions

- **Q1.** Streaming responses (event streams of logs and stats): per-chunk signatures or a hash chain.
- **Q2.** Delegation: short-lived certificates from a human key to an agent key, with scopes and TTL.
- **Q3.** Server key pinning and rotation on the client side.
- **Q4.** Registry distribution format, hot reload and revocation latency.
- **Q5.** Nonce cache for multi-instance servers: shared store versus per-`kid` routing.
- **Q6.** How a client learns `aud` and the server public key (configuration, well-known document, both).
- **Q7.** Whether to adopt RFC 9421 plus RFC 9530 (`Content-Digest`) instead of the custom format (D3).
- **Q8.** Human approval for destructive operations and the two-step change flow.
- **Q9.** Licence.
