# mcp-jack specification

Status: draft v0.1. The scope reduction of 2026-11-08 is applied in this text and in the fixture generator and reference tools; the generated fixture files are materialized from the generator in CI and are pending that integration. The scope review ([docs/design/scope-review-2026-11-08.md](../docs/design/scope-review-2026-11-08.md)) decided the direction; this spec now implements it, and the Go, Rust and TypeScript SDKs follow it in the next tasks.

## Layout

| Path | Content |
|---|---|
| [01-authentication.md](01-authentication.md) | Keys, signed requests and responses, verification order, replay protection |
| [02-authorization.md](02-authorization.md) | Key registry, the `admin` flag, evaluation and dispatch, verified caller identity hand-off |
| [03-user-management.md](03-user-management.md) | Protocol-native tools for users, invites, enrollment, rotation and administration; the state file |
| `fixtures/` | Deterministic test keys, documents and vectors: requests, state-changing sequences, keys, registry and state-file loading, responses (normative, generated), plus the hand-maintained `client-url-policy.json` (SDK client URL test table, not a protocol vector) |
| `tests/` | Conformance runner contract and the generated case index |
| `tools/` | Fixture generator and the reference verifier used to cross-check them |

## Conventions

- Test vectors are normative: an implementation conforms when it produces the expected result for every vector.
- All vectors except `fixtures/client-url-policy.json` are generated, not hand-written, and are normative protocol vectors. `fixtures/client-url-policy.json` is a manually maintained SDK client-side destination-policy test table: it is not a protocol vector, is not produced by `gen-fixtures.mjs` and is not covered by `--check`. Edit it by hand and keep the Go, Rust and TS runners in sync. Keys are derived from public strings, so they are reproducible and **test only**.
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
| D4 | *To be revisited in v0.2 (session channel, Q1).* Per-request signature with a nonce cache, no session. | Matches the stateless transport of the 2026-07-28 MCP specification; no session state to steal or to synchronise. |
| D5 | *To be revisited in v0.2: an authenticated, encrypted session channel (Q1).* TLS provides confidentiality; signatures provide authentication, integrity, replay protection and an audit identity. | Do not reinvent channel encryption. |
| D6 | No policy engine. Ordinary MCP of an authenticated caller passes through unchanged; what it may do inside MCP is decided by the consumers of the SDK from the verified caller identity (`kid`, `name`, `admin`) the server SDK hands them (02 section 3). | The wrapper cannot know the tools of the server it protects; a protocol-side access model would be policy by another name. The `admin` flag (D11) is the only protocol-enforced privilege and it gates only the protocol's own tools. |
| D7 | The `jack.` tool-name prefix is reserved for protocol-native tools; requests for them are dispatched by the protocol layer and never reach the wrapped handler. | Consumer access rules can neither open nor close user management. |
| D8 | No service-management profile. The tools a service exposes inside MCP, and who may call them, are the service's own concern; the protocol neither names nor scopes them. | Outside the protocol's responsibility (2026-11-08 scope review). |
| D9 | Users, invites, enrollment and key rotation are protocol-native MCP tools (`jack.*`), so administrators, SDKs and agents manage keys over the same authenticated channel. | Any party can generate a key pair; the server only ever sees public keys. |
| D10 | Enrollment is the single exception to "unknown key is rejected": the request is signed by the new key, which proves possession, and carries a single-use invite. | An invite is a bearer secret for exactly one purpose, so it is single-use, short-lived and carries one fixed admin flag; proof of possession stops anyone registering a key they do not control. |
| D11 | One strict boolean `admin` per user, default false, granted only through the administration tools; any administrator may administer any entry; the last active administrator cannot be removed or demoted. | One flag keeps the protocol's own privilege model auditable; the first administrator is created out of band (03 section 5). |
| D12 | Strict Ed25519: canonical prime-order-subgroup public keys only, and signatures with S >= L are invalid. | Verifiers in Go, Rust and JS otherwise disagree on edge cases, and a small-order key can verify for many messages. |
| D13 | Duplicate member names inside one JSON object of a request body keep the **last** occurrence: the parsed object has one member per distinct name, holding the last occurrence's value in document order — the occurrences are **not** merged. It applies to the JSON-RPC body (and so to `params` and `params.arguments`) and to protocol-native tool argument objects; authentication still covers the exact original body bytes. Registry and state-file documents are **not** covered by this rule. | Go, `serde_json` and `JSON.parse` all keep the last value, so one normative sentence buys identical behavior in every SDK; rejecting duplicates would break pass-through of ordinary MCP traffic. The scope stays narrow so the operator-facing document formats keep their own load-time rules. |
| D14 | Verified caller identity hand-off: after authentication the server SDK exposes `{kid, name, admin}` to the wrapped MCP handler (Go request context, Rust request extension, TypeScript request property behind an accessor). | Consumers need the authenticated identity to write their own access rules; the snapshot is server-authenticated, immutable to consumers and unspoofable by request headers or body (02 section 3). |

## Open questions

Status after the scope review of 2026-11-08 ([docs/design/scope-review-2026-11-08.md](../docs/design/scope-review-2026-11-08.md)):

- **Q1.** Streaming responses. *Direction:* authenticate once at a handshake, then an authenticated, encrypted session channel (ChaCha20-Poly1305, an established Noise handshake pattern), which also carries streams. Design pending; target v0.2.
- **Q2.** ~~Delegation from a human key to an agent key~~ — closed: the protocol knows only users; `kind` and delegation are not protocol features.
- **Q3.** Server key rotation. [Proposal under review](../docs/design/server-key-rotation.md) records a candidate contract; it is not accepted as normative v0.1 or implemented. Review and separately versioned implementation remain required.
- **Q4.** ~~Registry and policy distribution~~ — closed: nothing is distributed; users are created on the server; the policy engine is removed.
- **Q5.** Multi-instance servers (shared nonce cache) and cluster management. Open, deferred beyond the MVP: one server instance per state store until then.
- **Q6.** ~~How a client learns `aud` and the server key~~ — closed: out of band, by hand; not part of the protocol.
- **Q7.** ~~RFC 9421 plus RFC 9530 instead of the custom format~~ — closed: no; D3 stays.
- **Q8.** ~~Human approval for destructive operations~~ — closed: not part of the protocol or the SDK.
- **Q9.** ~~Licence~~ — resolved: the project is dual licensed under MIT OR Apache-2.0 ([LICENSE-MIT](../LICENSE-MIT), [LICENSE-APACHE](../LICENSE-APACHE)); the same terms apply to contributions ([CONTRIBUTING.md](../CONTRIBUTING.md)) and are stated in the [README](../README.md).
- **Q10.** ~~Policy matching beyond methods and tool names~~ — closed: authorization inside MCP belongs to SDK users; the policy engine is removed.
