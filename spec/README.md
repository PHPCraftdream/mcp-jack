# mcp-jack specification

Status: draft v0.1. Authentication, authorization and user management are specified; streaming and delegation come later.

## Layout

| Path | Content |
|---|---|
| [01-authentication.md](01-authentication.md) | Keys, signed requests and responses, verification order, replay protection |
| [02-authorization.md](02-authorization.md) | Key registry, scopes, server policy, deny-by-default evaluation |
| [03-user-management.md](03-user-management.md) | Protocol-native tools for users, invites, enrollment and key rotation |
| [04-service-management-profile.md](04-service-management-profile.md) | Optional profile: ordinary MCP tools for operating a service |
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
| D1 | mcp-jack is a **transport wrapper** around unmodified MCP over HTTP: JSON-RPC bodies pass through untouched, protection is added around them. Roles: gateway in front of an unmodified MCP server, local stdio bridge for MCP clients that do not know mcp-jack, embeddable library. stdio and WebSocket are not protocol transports in v0.1. | Keeps every existing MCP server and client usable. stdio is local and relies on OS trust. WebSocket is not part of the MCP specification. |
| D2 | Ed25519 only, a single protocol version, no negotiation. | No downgrade surface; identical results across Go, Rust and JS. |
| D3 | A small custom signing format over raw bytes instead of RFC 9421 (HTTP Message Signatures). | A plain newline-joined string is easy to reproduce bit-for-bit in three languages and to test with vectors. Trade-off: not a standard; see Q7. |
| D4 | Per-request signature with a nonce cache, no session. | Matches the stateless transport of the 2026-07-28 MCP specification; no session state to steal or to synchronise. |
| D5 | TLS provides confidentiality; signatures provide authentication, integrity, replay protection and an audit identity. | Do not reinvent channel encryption. |
| D6 | Authorization is a **server-owned policy** (method/tool pattern to scope, first match wins, deny by default); scopes are flat. | The wrapper cannot know the tools of the server it protects, so no tool table is hardcoded in the protocol. A read-only agent is never upgraded implicitly. |
| D7 | The `jack.` tool-name prefix is reserved for protocol-native tools and never reaches the policy. | A misconfigured policy cannot open or close user management. |
| D8 | Service operation tools (`svc.*`) are an optional profile, not part of the transport. | Keeps the protocol small and generic. |
| D9 | Users, invites, enrollment and key rotation are protocol-native MCP tools (`jack.*`), so administrators, SDKs and agents manage keys over the same authenticated channel. | Any party can generate a key pair; the server only ever sees public keys. |
| D10 | Enrollment is the single exception to "unknown key is rejected": the request is signed by the new key, which proves possession, and carries a single-use invite. | An invite is a bearer secret for exactly one purpose, so it is single-use, short-lived and limited to the scopes it names; proof of possession stops anyone registering a key they do not control. |
| D11 | No privilege escalation (grant only scopes you hold), the last administrator cannot be removed, and `agent` keys can never hold `admin`. | Limits the blast radius of a compromised or prompt-injected agent; the first administrator is created out of band. |
| D12 | Strict Ed25519: canonical prime-order-subgroup public keys only, and signatures with S >= L are invalid. | Verifiers in Go, Rust and JS otherwise disagree on edge cases, and a small-order key can verify for many messages. |

## Open questions

- **Q1.** Streaming responses (event streams of logs and stats): per-chunk signatures or a hash chain.
- **Q2.** Delegation: short-lived certificates from a human key to an agent key, with scopes and TTL.
- **Q3.** Server key pinning and rotation on the client side.
- **Q4.** Registry and policy distribution format, hot reload and revocation latency.
- **Q5.** Nonce cache for multi-instance servers: shared store versus per-`kid` routing.
- **Q6.** How a client learns `aud` and the server public key (configuration, well-known document, both).
- **Q7.** Whether to adopt RFC 9421 plus RFC 9530 (`Content-Digest`) instead of the custom format (D3).
- **Q8.** Human approval for destructive operations and the two-step change flow.
- **Q9.** Licence.
- **Q10.** Policy matching beyond methods and tool names (resource URIs, prompt names, argument conditions).
