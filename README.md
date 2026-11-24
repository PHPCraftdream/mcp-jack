# mcp-jack

[![ci](https://github.com/PHPCraftdream/mcp-jack/actions/workflows/ci.yml/badge.svg)](https://github.com/PHPCraftdream/mcp-jack/actions/workflows/ci.yml)

mcp-jack is feature-complete for v0.1.0, which is unreleased. Nothing is published: no Go module tag, no npm package, no crates.io crate, no git tag, no GitHub Release. The code has not been independently audited. This README describes the repository as it is.

Toolchain floors: Go 1.25.0 (`go.mod`), Rust 1.88 (MSRV, `rust/Cargo.toml`), Node >= 20 (TypeScript; CI runs Node 20 and 22).

## What is in the box

| Component | Location | Notes |
|---|---|---|
| Protocol | repository root | Ed25519-signed requests and responses, replay protection with an optional durable nonce store, user management, strict-boolean admin flag, verified caller identity hand-off, audit hooks |
| Go SDK | root, `client/`, `server/`, `userkey/`, `spec/`, `durable/`, `rotation/` | reference implementation, client and server SDKs |
| Go CLI | `cmd/jack`, `internal/cli/` | single binary `jack`: keygen, bootstrap, enroll, gateway, bridge, user/invite, nonce and server-key commands |
| Rust SDK | `rust/` | `mcp-jack` crate; client and server SDKs, client HTTP transport, rotation trust store and single-page refresh HTTP client (Linux) |
| TypeScript SDK | `ts/` | client, Fetch and Node server adapters, rotation trust store, bounded rotation HTTP client |
| Spec and fixtures | `spec/` | contract documents and conformance fixtures |
| Interop harnesses | `interop/` | 3x3 request/response matrix, 3x3 rotation matrix, credential-transfer matrix |
| MCP end-to-end | `tools/mcp-e2e/` | CI job against official MCP SDK clients and servers |

The repository-root Go package `jack` contains shared protocol primitives only; it is not the client or server SDK. `client/` owns signing/verification transport, connection profiles, and typed native-tool calls. `server/` owns verification, middleware, identity hand-off, nonce/state stores, native tools, and audit sinks. `userkey/` provides role-specific key and transfer utilities independently of the client package. `spec/` supplies fixture loaders and conformance data. `durable/` holds the bbolt-backed durable nonce and ring stores (Linux-only private-file backend). `rotation/` holds the rotation record/chain/page codec and the client rotation controller. This separation is intentional.

## Contract

Authenticated ordinary MCP requests pass through unchanged. The application authorizes them using the immutable verified caller identity `{kid, name, admin}` supplied by the server SDK; request headers and bodies cannot supply that identity. The strict-boolean `admin` flag (false by default) gates reserved `jack.admin.*` tools only. Protocol operations are audited by the SDKs through an optional sink; the CLI gateway writes best-effort JSON-lines audit events for audited native calls that reach the tool to process stderr (`Record`/write errors are ignored; capture stderr for retention; see [operations](docs/operations.md)). User `kind`, scopes, and the policy engine are removed; legacy registry/state records containing `kind` or `scopes` are rejected without migration or rewrite.

User-key rotation, server response-key rotation (`spec/candidate/server-key-rotation.md`), and the optional durable nonce profile are implemented. An authenticated session channel is future v0.2 direction.

## Why

MCP has a good "tool plus description" model, but the practice around it is weak for privileged operations:

- clients keep tokens and keys in config files and environment variables in plain text;
- the stdio transport has no authorization: access is whoever launched the process;
- common server implementations offer one shared, optional token with no scopes, lifetime or audit trail.

Example: the embedded MCP server of `process-compose` (Apache-2.0) protects its SSE port with Host and Origin checks and an optional shared token (`PC_API_TOKEN`). There are no roles, scopes, TLS or call log. Before version 1.120.0 there was not even a Host check, so any website could drive local processes through DNS rebinding (GHSA-5gm3-9crp-6g3v).

Operations such as restart or a configuration change need more than "whoever reached the port".

## Installation

Nothing below is published yet. Each component is versioned `0.1.0 (unreleased)`.

- **Go module** `github.com/PHPCraftdream/mcp-jack` — not in the Go module proxy. Use it as a source/replace dependency or vendor the checkout.
- **Rust crate** `mcp-jack` — `publish = false`, not on crates.io. Depend on it by path or git.
- **TypeScript package** `mcp-jack` — `private: true`, not on npm. Install from a checkout or tarball.
- **CLI** `jack` — not distributed. Build from source with `go build ./cmd/jack`.

## Quickstart: Go CLI

Full flow requires Linux: state stores use Linux-only private files and fail closed on Windows. Files must be owner-owned with mode 0600 inside mode 0700 directories. The upstream application must listen only on the configured Unix socket.

```sh
# Provision the directories first; the CLI never creates them.
# 1. Generate the server response-signing key and the admin user key.
jack keygen server --secret /etc/jack/server.seed --public /etc/jack/server.public.json
jack keygen user   --secret /etc/jack/admin-user.seed --public /etc/jack/admin-user.public.json

# 2. Bootstrap: create the state file and the first admin invite.
jack bootstrap --state /var/lib/jack/state.json --invite-file /etc/jack/invite.first

# 3. Run the gateway in front of the upstream app's Unix socket.
jack gateway --config /etc/jack/gateway.json

# 4. Enroll the admin user against the running gateway (talks to the endpoint in client.json).
jack enroll --config /etc/jack/client.json --invite-file /etc/jack/invite.first --name root

# 5. Bridge: the local stdio entry an MCP client spawns.
jack bridge --config /etc/jack/bridge.json
```

Client config used by `jack enroll` and `jack bridge` (`bridge.json` points at the gateway instead of the upstream). `server_public_key` and `server_kid` are provisioned out of band from the keygen public file (`/etc/jack/server.public.json`):

```json
{
  "version": 1,
  "endpoint": "http://127.0.0.1:8080/mcp",
  "aud": "jack-gateway",
  "server_public_key": "<base64url server public key>",
  "server_kid": "<server key id>",
  "key_file": "/etc/jack/admin-user.seed",
  "key_format": "raw-seed",
  "call_timeout_ms": 10000
}
```

Gateway config (`/etc/jack/gateway.json`; the optional `durable_nonces` profile selects the durable nonce store — omit it for the volatile in-memory store):

```json
{
  "version": 1,
  "aud": "jack-gateway",
  "server_seed_file": "/etc/jack/server.seed",
  "state_file": "/var/lib/jack/state.json",
  "listen": "127.0.0.1:8080",
  "upstream_socket": "/var/lib/jack/upstream.sock",
  "upstream_url": "http://upstream/mcp",
  "call_timeout_ms": 10000,
  "max_concurrent": 8,
  "durable_nonces": {
    "path": "/var/lib/jack/nonces.bolt",
    "deployment_id": "<deployment id>",
    "window": 30
  }
}
```

Exact schemas and all flags: [docs/design/cli.md](docs/design/cli.md). Operator guide, including recovery after an abnormal stop: [docs/operations.md](docs/operations.md).

## Quickstart: SDK client

```go
signer, err := userkey.GenerateClientKey()
// ...
c, err := client.NewClient(client.Config{
    BaseURL:   "http://127.0.0.1:8080/mcp",
    Aud:       "jack-gateway",
    Signer:    signer,
    ServerKey: serverPubKey, // serverPubKey is the independently pinned 32-byte server public key.
})
// ...
var out struct{ OK bool `json:"ok"` }
// ctx is the caller's context.
err = c.CallTool(ctx, "ping", map[string]any{}, &out)
```

Rust client: see [rust/README.md](rust/README.md). TypeScript client: see [ts/README.md](ts/README.md).

## Server-key rotation

The server can rotate its response-signing key without re-pinning clients. One `jack server-key-announce` publishes exactly one next key with a single fixed publication time P; the successor activates at A = P + 172800 s (48 h). Both keys verify during the overlap; verification cuts over strictly when the successor activates. Clients refresh explicitly by fetching a single page; ordinary traffic never triggers a refresh, and there is no hidden retry or reset. The gateway enables it via the `server_rotation_file` profile and serves the native tool `jack.server.key` (domain `mcp-jack/server-key-rotation/min1`). Runbook: [docs/operations.md](docs/operations.md). Design: [spec/candidate/server-key-rotation.md](spec/candidate/server-key-rotation.md).

## Limitations

| # | Limitation |
|---|---|
| 1 | Recovery after an abnormal stop (kill, OOM, power loss) is a manual operator procedure: nonce and ring stores stay dirty/unknown and every entry point refuses to serve (fail closed) until it completes. The Go CLI ships `nonce-inspect` and `nonce-reconcile-terminal`; Rust and TypeScript expose library recovery functions only ([docs/operations.md](docs/operations.md)). |
| 2 | One owner of the nonce/ring state per deployment; no cluster or HA mode. |
| 3 | Upstream servers that answer with SSE are unsupported: the gateway closes the stream and answers a signed 501 (the official TypeScript MCP server 2.4.0 answers initialize with text/event-stream even in JSON response mode). |
| 4 | Bounded MCP profile: legacy Streamable HTTP 2025-11-25 entered through stdio, one JSON-RPC object per POST, no sessions, no GET stream. |
| 5 | Signatures do not cover arbitrary headers and provide no confidentiality; TLS is the transport's job. |
| 6 | On Windows the CLI stores fail closed by design; SDKs are tested on Windows in CI, the durable private-file stores are Linux-only. |
| 7 | Audit delivery is best effort. |
| 8 | Rust and TypeScript are covered by deterministic property/mutation tests and a shared corpus, not coverage-guided fuzzing (Go has a bounded fuzz campaign). |
| 9 | The release has had no human or third-party audit. It has had an internal pre-review ([docs/security-review-package.md](docs/security-review-package.md)) and an independent AI review that read the source without running it ([docs/independent-review.md](docs/independent-review.md)). |
| 10 | All three SDKs ship the durable nonce store (Linux-only file-backed stores, explicit opt-in). The operator recovery CLI commands exist only in the Go `jack` CLI; Rust and TypeScript expose library recovery functions only. |
| 11 | A forward clock jump latches the durable stores unsafe for good and no command in any SDK clears the latch, and unauthenticated load is limited only by the gateway's global admission limits; see "Operational limits to plan for" in [docs/operations.md](docs/operations.md). |

See also [docs/operations.md](docs/operations.md) and [docs/threat-model.md](docs/threat-model.md).

## Documentation

| Document | Contents |
|---|---|
| [docs/operations.md](docs/operations.md) | operator guide, recovery runbook, rotation runbook |
| [docs/compatibility.md](docs/compatibility.md) | supported MCP revisions, modern profile and interop evidence scope |
| [docs/threat-model.md](docs/threat-model.md) | threat model |
| [docs/security-review-package.md](docs/security-review-package.md) | internal pre-review findings, SDK divergences and questions for an external reviewer |
| [docs/independent-review.md](docs/independent-review.md) | result of the independent AI review: findings, coverage, dispositions |
| [docs/cross-language-conformance.md](docs/cross-language-conformance.md) | audit of what proves that Go, Rust and TypeScript behave identically: rules, shared vectors, interop coverage, gaps |
| [SECURITY.md](SECURITY.md) | security policy |
| [CHANGELOG.md](CHANGELOG.md) | repository history and unreleased changes |
| [docs/versioning.md](docs/versioning.md) | versioning policy |
| [spec/README.md](spec/README.md) | contract specification and fixtures |
| [docs/design/](docs/design/) | historical design documents |
| [interop/README.md](interop/README.md) | interop harnesses and matrices |
| [tools/mcp-e2e/README.md](tools/mcp-e2e/README.md) | official MCP SDK end-to-end job |
| [ts/README.md](ts/README.md) | TypeScript SDK |
| [rust/README.md](rust/README.md) | Rust SDK |

## Modern profile

The MCP 2026-07-28 modern profile adds validated metadata mirrors, optional signed streams, and Events webhooks while preserving the existing v1 request/JSON-response bytes. See [compatibility and profile scope](docs/compatibility.md).

## Checks

Standing CI lanes: go (ubuntu+windows), go race, Go CLI binary process qualification, Go CLI native Darwin process qualification, Go CLI portable artifact qualification, fixture freshness, rust (ubuntu+windows), rust 1.88 check, ts (ubuntu+windows at node 20/22), 3x3 interop matrix, 3x3 rotation interop matrix, 3x3 credential-transfer matrix, official MCP SDK end-to-end job, consumer ts/rust/go, coverage (go/rust/ts), bounded Go fuzz campaign, licences, six vulnerability scans, and spec fixtures. These are configured checks, not claimed results.

## Licence

Licensed under either the [Apache License, Version 2.0](LICENSE-APACHE) or the [MIT licence](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work, as defined in the Apache-2.0 licence, shall be dual licensed as above, without any additional terms or conditions.

## Name

The name `mcp-jack` was checked on 2026-11-05: no package with that name exists on npm, crates.io or PyPI, GitHub has no user or organisation `mcp-jack` and no repository with that exact name, and a web search found no exact match.
