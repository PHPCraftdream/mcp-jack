# Scope review: what mcp-jack is responsible for (2026-11-08)

Status: **decided** by the project owner on 2026-11-08. The specification (`spec/01`, `spec/02`, `spec/03`, `spec/README.md`), the fixture generator, the reference verifier (`spec/tools/`) and the conformance docs (`spec/tests/`) now carry the reduced contract — work-plan step 1 of section 6; the generated fixture bytes are materialized from the generator in CI under the parent's control and are pending that integration. The Go, Rust and TypeScript SDKs, the interop harness and the consumers still implement the draft v0.1 behavior until the later steps of section 6 land. Where this document and the v0.1 SDK behavior disagree, the specification wins.

This record covers the discussion of the open questions Q1-Q8 and Q10 of [spec/README.md](../../spec/README.md) (Q9, the licence, was resolved earlier).

## 1. The overall picture

mcp-jack is a **security wrapper around MCP**, and an SDK for that wrapper. Nothing more.

mcp-jack is responsible for:

- **Authentication** of the caller and of the server: Ed25519 signatures, the time window, replay protection, strict key and encoding rules.
- **Integrity** of every message.
- **Identity management**: users are keys. A user is created on the server, either from a key pair generated there or from an imported public key; keys can be enrolled with a single-use invite, rotated and revoked.
- **Server key rotation** as part of the protocol (section 3, Q3).
- **Audit** of protocol operations, with the caller's key identity.
- Later, an **authenticated and encrypted session channel** (section 3, Q1).

mcp-jack is **not** responsible for:

- **What a user may do inside MCP.** Users of the SDK put their own tools inside their MCP server and decide access themselves. The SDK hands them the verified identity of the caller (section 4); authorization is their code, not the protocol.
- Classifying users (humans, agents). For the protocol there are only users.
- Approvals, two-step changes, rate limits and other operational policy.
- Delivering the server identity to a client for the first time: that is a manual step outside the protocol.
- Cluster management, for now (section 3, Q5).

## 2. Decisions at a glance

| # | Question (v0.1 wording, shortened) | Decision | Status |
|---|---|---|---|
| Q1 | Streaming: per-chunk signatures or a hash chain | Authenticate once at the handshake, then a session channel protected by a session key (ChaCha20-Poly1305). Solves streaming as a side effect. | Direction agreed; design pending; target v0.2 |
| Q2 | Delegation from a human key to an agent key | No humans and agents in the protocol, only users. No delegation in the protocol. `kind` is removed. | Closed |
| Q3 | Server key pinning and rotation on the client | Rotation is part of the protocol: the server announces its next key, several keys are valid during a transition, clients that miss it re-pin manually. | Decided; design pending |
| Q4 | Registry and policy distribution, hot reload | Nothing is distributed. Users are created on the server; the policy engine is removed. | Closed |
| Q5 | Nonce cache for multi-instance servers | Each server is individual. Clusters, and cluster management, matter but are not MVP and need separate thought. | Open, deferred |
| Q6 | How a client learns `aud` and the server key | Out of band, by hand (SSH, copy from a browser). Not part of the protocol. | Closed |
| Q7 | RFC 9421 / RFC 9530 instead of the custom format | No: there is no reason to switch. D3 stays. | Closed |
| Q8 | Human approval for destructive operations | Not part of the protocol or the SDK. | Closed |
| Q10 | Policy matching beyond methods and tool names | Not our responsibility; the policy engine is removed. | Closed |

## 3. The questions in detail

### Q1. Streaming and the session channel

Owner's position: a signature is needed only at the handshake; after that the data travels as is inside the channel. Whether the channel is also encrypted was raised as a separate question, with a session key plus ChaCha as the preferred option.

Analysis agreed in the discussion: "sign only at the handshake" is safe only if every later message is authenticated — for example by the authentication tag of an AEAD such as ChaCha20-Poly1305; otherwise anyone on the path can alter a message after the handshake. Message authentication and confidentiality are distinct properties: authentication does not provide confidentiality, and the two must be decided separately. Today TLS carries the confidentiality (D5); the v0.2 direction pairs per-message authentication with encryption in one AEAD because the marginal cost is small, not because they are the same decision. ChaCha20-Poly1305 and the Noise framework are a direction to be designed, not an implemented or sufficiently specified channel.

Direction:

- A handshake authenticates both sides with their Ed25519 identities and derives a session key; every message after it is sealed with ChaCha20-Poly1305.
- The key exchange is not invented here: use an established pattern from the Noise protocol framework (X25519, ChaChaPoly, BLAKE2 or SHA-256), with the existing Ed25519 identities bound into the handshake.
- Streaming (event streams of logs and statistics) becomes ordinary channel traffic, so the v0.1 refusal of `text/event-stream` (501 `streaming_unsupported`) goes away with the channel.
- This is a move from stateless per-request signatures (D4) to sessions, and it revisits D5 ("TLS provides confidentiality"). It is a separate design and a separate version (v0.2). The v0.1 per-request signing stays until then.

Open for the v0.2 design: the transport (an HTTP session identifier or a long-lived stream), how the channel relates to TLS (instead of, or inside), session lifetime and rekeying, replay protection inside a session, and session state on multi-instance servers (Q5).

### Q2. Delegation, humans and agents

Owner's position: mcp-jack is a layer over MCP. It has no notion of agents and humans; whoever runs the system sorts that out. For mcp-jack they are all users.

Consequences: the `kind` attribute (`human` / `agent`) is removed everywhere, together with the rule "an agent key cannot hold `admin`" (`agent_admin_forbidden`, 03 section 6, the agent part of D11). Delegation is not a protocol feature.

### Q3. Server key rotation

Owner's position: the server must be able to send new keys to its clients, so rotation rules are part of the protocol. During a transition several keys must work. A client that misses the transition contacts support and re-pins by hand.

Direction (to be turned into a design):

- The server announces its next public key in a statement signed by its **current** key, with a transition period. Responses already carry the signing `kid`, so a client can tell which key signed a response.
- A client verifies the announcement with the key it has pinned and then pins the new key as well. During the transition the server answers with either key and the client accepts both.
- After the transition the old key is retired. A client that still pins only the old key fails verification and is re-pinned manually (out of band, as in Q6).
- This replaces the v0.1 rule of no automatic server-key rotation (`docs/design/user-keys.md`, sections 1 and 15) **only** for rotation authenticated by the already pinned key. Trust on first use and replacing a pin with an unauthenticated key stay rejected.

Open for the design: the format of the announcement, how it reaches the client (a response header, a protocol-native tool, or both), how clients persist the new pin, and the client and server APIs for a key set instead of one key.

### Q4. Registry and policy distribution

Owner's position: the user list is not distributed. A user is created on the server, by generating keys or by importing the user's public key, and is given the server key. How access rights are set is the business of the SDK's users: mcp-jack answers only for the wrapper protocol and the SDKs that speak it. Users of the SDK put their tools inside MCP, not into the mcp-jack protocol.

Consequences: there is no registry or policy distribution format to design. The policy engine is removed (section 5). Revocation keeps its v0.1 semantics: a change takes effect for the next request (03 section 9).

### Q5. Multi-instance servers

Owner's position: this is a cluster. Cluster management is important too, but it does not exist in the protocol; it needs serious thought. Each server is individual. It is far from MVP, but important.

Decision for now: one server instance per state store (registry, invites and nonce cache). The state store is already an interface in all three SDKs (a Go interface, a Rust trait, a TypeScript interface); the nonce store is still a concrete in-memory type in each, so a shared nonce cache needs a small SDK change but no protocol change. Cluster management, and sessions across instances (Q1), are a separate future design.

### Q6. How a client learns `aud` and the server key

Owner's position: an agent or an administrator delivers them over their own channel, such as SSH, or copies them by hand from a browser. This is an initial manual step, not part of the protocol.

This matches the current SDKs: a client credential is imported only together with an independently trusted server identity (`docs/design/user-keys.md` section 8). Nothing changes.

### Q7. RFC 9421 and RFC 9530

Owner's position: it is not clear why we would switch. The custom signing format (D3) stays.

### Q8. Approval of destructive operations

Owner's position: not part of the protocol or the SDK; mcp-jack deals with the security of the wrapper.

### Q10. Finer-grained policy

Owner's position: it is odd that we have a policy engine at all; we should not be responsible for it. Users of the SDK decide what happens inside the wrapper.

Consequence: the policy engine is removed, not extended (section 5).

## 4. What stays, and what is added to replace the policy

Stays unchanged:

- Authentication and response verification (spec 01), D1-D4, D12, D13, strict Ed25519, the nonce cache and the time window.
- Users as registry entries: `kid`, `public_key`, `name`, `not_before`, `not_after`.
- Self-service tools `jack.whoami` and `jack.key.rotate`; enrollment with single-use invites stored only as a hash; bootstrap of the first administrator out of band; the audit of protocol operations; atomic registry changes.
- The `jack.` prefix stays reserved for protocol-native tools.

Replaces scopes, for the protocol's own tools only:

- A single boolean **`admin`** attribute on a user. It gates the `jack.admin.*` tools and nothing else. The "last administrator cannot be removed" rule stays.
- Proposed for the spec change: `jack.admin.user.set_scopes` becomes `jack.admin.user.set_admin {kid, admin}`; `jack.admin.user.create` and `jack.admin.invite.create` take an optional `admin` flag (default `false`) instead of `scopes` and `kind`. Whether an administrator may revoke another administrator without extra conditions is settled in the spec change.

Added:

- **Identity hand-off.** After a request passes authentication, the server SDK passes the verified caller identity (`kid`, `name`, `admin`) to the wrapped MCP handler, so users of the SDK can implement their own access rules: in Go through the request context, in Rust as a request extension, in TypeScript on the request object. The v0.1 SDKs do not expose it yet.

## 5. What is removed

- **`kind`** in the registry, the state file, tool arguments and results, invites, `whoami`, `agent_admin_forbidden`, 03 section 6.
- **Scopes**: the scope grammar and the reserved `admin` scope (replaced by the `admin` flag), `scopes` in registry entries, invites and tool arguments, `jack.admin.user.set_scopes`, and the rules and codes `scope_escalation`, `forbidden_admin_target` and `insufficient_scope` for ordinary MCP calls.
- **The policy engine**: the policy document, patterns, first-match evaluation, `operation_denied` for ordinary MCP calls, `tools/list` filtering (02 sections 2-5), and the pattern and scope matching in the shared primitives.
- **The service-management profile** (`spec/04-service-management-profile.md`, D8): it suggests tools and scopes for the MCP servers of SDK users, which is outside mcp-jack's responsibility (Q4, Q8, Q10). README principle 8 (Prometheus and OpenTelemetry formats) goes with it.
- **README principle 7** (agents that read logs never get write or admin scopes): it depends on `kind` and scopes. The underlying warning, that logs are untrusted input for agents, can live on as advice to SDK users.

There is no compatibility window: v0.x, no release, no known deployment. State files with `kind` or `scopes` are not migrated.

## 6. Impact on the repository and work plan

Affected areas (inventory at `64cb770`, not exhaustive):

- Spec: `spec/02-authorization.md` shrinks to the key registry (or merges into 03), `spec/03-user-management.md` sections 1 and 3-7 change, `spec/04-service-management-profile.md` is deleted, `spec/README.md` decisions D5, D6, D8, D10 and D11 change.
- Fixtures and tools: `spec/fixtures/policy.json`, `policy-wildcard.json` and `pattern-vectors.json` go; `registry.json`, `load-vectors.json`, `request-vectors.json` and `admin-vectors.json` are regenerated; `spec/tools/gen-fixtures.mjs` and `spec/tools/reference-verifier.mjs` change. `spec/fixtures/user-key-transfer.json` is not affected (its `kind` is the envelope kind, a different field).
- Go: `server/policy.go`, scope and pattern matching in the root package, `server/native.go`, the state and statefile code, `client/tools.go`.
- Rust: `rust/src/server/policy.rs`, `native.rs`, `state.rs`, the client tools, and their tests (`policy_conformance.rs`, `patterns_conformance.rs`).
- TypeScript: `ts/src/server/policy.ts`, `native.ts`, `state.ts`, the client tools, and their tests.
- Interop: the scenarios `denied-tool`, `unmapped-tool` and `agent-admin` and the policy files of the interop servers change; the identity hand-off gets new scenarios.

Order of work:

1. Spec change for the scope reduction and the identity hand-off; fixtures regenerated; reference verifier updated.
2. The three SDKs and the interop harness follow the new spec; CI green across all jobs.
3. Server key rotation: design, then spec, fixtures, SDKs and an interop scenario.
4. v0.2: the session channel (design first).
5. Later: multi-instance servers and cluster management (design first).

## 7. Still open

- Q1 channel details: transport, relationship with TLS, session lifetime and rekeying.
- Q3 rotation details: announcement format and delivery, client persistence.
- Q5 clusters and cluster management.
- The exact shape of the `admin` flag in tools and invites (section 4).
- The README questions not covered here: local-only or remote services, third-party clients, service discovery.
