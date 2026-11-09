# Scope review: what mcp-jack is responsible for (2026-11-08)

Status: **decided; SDK migration baseline `b13b972`.** The specification and Go, Rust, and TypeScript SDKs implement the reduced admin-only identity contract: unchanged ordinary MCP pass-through, immutable verified identity `{kid, name, admin}`, and `admin` gating only reserved `jack.admin.*` tools. Protocol operations are audited. Shared interop matrix acceptance, packaged-consumer checks, and coverage/fuzz evidence were verified in GitHub CI on `444c69b` (see readiness evidence); the exact CI runs for `444c69b` are recorded in readiness. Legacy user/state `kind` or `scopes` records are rejected without migration or rewrite. The transfer-envelope `type` discriminator is independent and unchanged.

This record covers Q1-Q8 and Q10 of [spec/README.md](../../spec/README.md) (Q9, the licence, was resolved earlier).

## 1. Responsibility boundary

mcp-jack authenticates callers and servers, protects message integrity, prevents replay, manages protocol users/keys, audits protocol operations, and hands verified caller identity to the wrapped MCP handler. User management includes creation from generated or imported public keys, invite enrollment, rotation, and revocation.

mcp-jack does not decide what a caller may do inside ordinary MCP. The application uses the verified identity for its own authorization. Users are not classified as humans or agents. Approvals, operational policy, first delivery of server identity, and cluster management are outside the current protocol.

## 2. Decisions at a glance

| # | Question (v0.1 wording, shortened) | Decision | Status |
|---|---|---|---|
| Q1 | Streaming: per-chunk signatures or a hash chain | Authenticated session channel is a future v0.2 direction; authentication and confidentiality are distinct. Exact design pending, not implemented. | Direction agreed; future v0.2 |
| Q2 | Delegation from a human key to an agent key | No human/agent distinction or delegation in the protocol; all are users. | Closed |
| Q3 | Server key pinning and rotation on the client | Rotation is separate future work; exact design and implementation remain pending. | Direction agreed; proposal under review |
| Q4 | Registry and policy distribution, hot reload | Nothing is distributed; user creation is server-side and ordinary MCP authorization is application-owned. | Closed |
| Q5 | Nonce cache for multi-instance servers | Clusters and cluster management are deferred and need separate design. | Open, deferred |
| Q6 | How a client learns `aud` and the server key | Out of band, by hand (for example SSH or a trusted browser path). | Closed |
| Q7 | RFC 9421 / RFC 9530 instead of the custom format | Keep the custom signing format (D3). | Closed |
| Q8 | Human approval for destructive operations | Not part of the protocol or SDK. | Closed |
| Q10 | Policy matching beyond methods and tool names | Application authorization is outside mcp-jack. | Closed |

## 3. Q1: session channel direction

A signature only at handshake is safe only if every later message is authenticated, for example by an AEAD tag; otherwise an on-path party can alter messages after the handshake. Authentication and confidentiality are separate properties. TLS provides confidentiality today. The future v0.2 direction is a channel providing per-message authentication and encryption together (ChaCha20-Poly1305 and Noise were discussion directions, not a specification or implementation).

Keep current per-request signed-message behavior until a separate design and versioned implementation exist. Still open for that design: transport (HTTP session identifier or long-lived stream), relationship to TLS (instead of or inside), session lifetime and rekeying, replay protection within a session, and session state across instances. No session channel is implemented.

## 4. Q3: server-key rotation is separate future design

The discussion direction was for the server to announce a next public key in a statement signed by the currently pinned key, with a transition period. A client would verify that announcement against its existing pin, hold both keys during the transition, and retire the old key after the transition. A missed transition would require manual re-pinning out of band. This does not define a protocol or commit the implementation: announcement format and delivery, pin persistence, and client/server key-set APIs remain open. Trust on first use and replacing a pin with an unauthenticated key remain rejected. Baseline `b13b972` does not implement server-key rotation.

The [server-key-rotation proposal](server-key-rotation.md) now records a candidate exact contract. It is a draft under parent design/security review; it is not accepted as normative v0.1 and is not implemented. Review must precede any separately versioned implementation.

## 5. Reduced contract

Authentication and response verification, strict Ed25519, nonce/freshness checks, exact signing, atomic registry changes, and protocol audit remain. Users are registry entries identified by `kid`, `public_key`, and `name`, with validity bounds. `jack.whoami`, `jack.key.rotate`, invite enrollment, out-of-band first-admin bootstrap, and audit of each call and administrative change remain. The `jack.` prefix is reserved for protocol-native tools.

Protocol-native administration uses one strict boolean `admin` user attribute. User/invite creation accepts optional `admin`, default false; enrollment inherits invite value; setting the attribute requires a strict boolean. Stored records and results include `admin`, including false. `admin` gates only reserved `jack.admin.*` tools and last-active-admin protection remains. After authentication, the SDK gives the wrapped handler immutable `{kid, name, admin}` identity; request headers/body cannot supply it.

Removed are user classification and delegation semantics, scope-based registry/invite/request authorization, the policy engine and ordinary-request filtering, and the service-management profile. The log-untrusted-input warning remains useful application guidance, not a protocol scope rule. Legacy user/state fields are rejected rather than migrated or rewritten.

## 6. Implementation and integration status

- The specification and three SDKs implement the reduced contract in baseline `b13b972`.
- Shared interop scenario definitions are in `interop/scenarios.json`, the current source of truth. The harness implements verified-identity forwarding through the ordinary handler and malformed required-boolean admin-input controls. Matrix acceptance was verified in GitHub CI on `444c69b` (see readiness evidence); the exact passing CI runs for `444c69b` are recorded in readiness.
- Packaged-consumer and coverage/fuzz evidence were verified in GitHub CI on `444c69b` (see readiness evidence).
- Q1 channel and Q3 server-key rotation remain future design work; multi-instance/cluster management is deferred.

## 7. Still open

- Q1 session-channel transport, TLS relationship, lifetime/rekeying, replay, and multi-instance behavior.
- Q3 review of the [server-key-rotation proposal](server-key-rotation.md).
- Q5 clusters and cluster management.
- Service discovery and whether services/clients are local-only or remote/third-party.

The transfer-envelope `type` member in [user-keys.md](user-keys.md) is not the removed user classification field and remains unchanged.
