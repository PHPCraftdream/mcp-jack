# Checkpoint — 2026-11-05 10:22 [mcp-jack-go-sdk-handoff]

## Session summary

mcp-jack is a secure transport protocol that wraps plain MCP (JSON-RPC over HTTP): every request and response is signed with Ed25519, authorization is a server-owned policy, and user management (invites, enrollment, key rotation, administration) is part of the protocol as `jack.*` MCP tools. The name was checked on npm, crates.io, PyPI and GitHub and was free on 2026-11-05.

In this session the specification (`spec/01-04`), a deterministic fixture generator with a JavaScript reference verifier (242 cases in `spec/fixtures`), a CI workflow and a first Go SDK were written and committed locally. The Go SDK has four parts: the root package `jack` (shared primitives), `spec` (embedded fixtures and strict loaders), `server` (verifier, policy, `net/http` middleware, native tools, bootstrap, nonce/state/audit stores) and `client` (signer, signing and verifying `RoundTripper`, profile, typed calls).

**The Go code has never been compiled or run.** The user's rule is that builds and tests run in CI only; local use was limited to `gofmt`. A cheap script screened for unused and missing imports and found none, but type errors, failing tests and logic slips are still likely. The first `go vet ./... && go test -race ./...` is the most valuable next step.

Part of the Go code was written by `rush` sub-agents in isolated git worktrees (scaffold, core primitives, stores, client) and every diff was reviewed and corrected by hand. The verifier, policy, middleware, native tools and fuzz tests were written directly, because rush's smart role has no write tools when a worker is configured and its first runs repeatedly ended without creating files.

Nothing is pushed: there is no remote, and the user has not approved a push. All work is on `main` as small commits.

## Active goal

none

## TaskList

No open tasks. All 13 tasks of the session are completed: preflight, spec policy, spec user management, fixtures, Go scaffold, server stores, core primitives, server verifier, native tools, client SDK, fuzz/conformance tests, CI workflow, final review.

## Decisions

- Transport wrapper around unmodified MCP (not a new tool model); stdio and WebSocket are out of scope for v0.1.
- Per-request Ed25519 signatures with a nonce cache and no session; a small custom signing format over raw bytes instead of RFC 9421 (revisit as Q7).
- Authorization is a flat-scope, first-match, deny-by-default policy owned by the server; the `jack.` tool prefix is reserved and never reaches the policy.
- Any party may generate a key; enrollment is signed by the new key and uses a single-use invite; no privilege escalation, the last administrator is protected, agent keys can never hold `admin`.
- Strict Ed25519: canonical prime-order-subgroup keys only and S < L; the Go code uses `math/big` for the curve checks (standard library only).

## Open questions

- Streaming responses (event streams) cannot be signed in v0.1 and are refused (spec README Q1); per-chunk signatures or a hash chain are undecided.
- Delegation (short-lived certificates from a human key to an agent key), server key pinning and rotation, registry/policy distribution and nonce cache for multiple instances are open (spec README Q2-Q6).
- Licence is undecided.
- Whether to allow local `go build/vet/test` for this project, and whether to push (no remote configured).
- Rust and JavaScript SDKs are not started; they should be checked against the same fixtures.

## Repo state

```
(clean working tree)
```

```
a57876b README: describe the Go layout and the verification status
e9770b6 Add fuzz targets for the header parser, pattern matcher and body classifier
a86a07c Add protocol-native tools and bootstrap
934015a Add server verifier, policy engine and HTTP middleware
85b3492 Add Go client SDK
```
