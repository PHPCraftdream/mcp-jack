# Release plan: v0.1.0

Status: plan, 2026-11-09. Nothing in this document is implemented yet. Versions, tags, pushes and registry publication each need explicit approval from the maintainer.

## 1. Where the project stands

Done and verified in GitHub CI (main at `e681f07`):

- Specification v0.1 after the 2026-11-08 scope reduction: per-request Ed25519 signatures on requests and responses, nonce cache and time window, strict Ed25519 and canonical base64url, signed rejections, protocol-native `jack.*` tools (whoami, user key rotation, invite enrollment, admin user/invite management), single `admin` flag, verified caller identity `{kid, name, admin}` handed to the wrapped MCP handler, audit, out-of-band first administrator.
- SDKs for Go, Rust and TypeScript (server and client), normative generated fixtures, reference verifier, 3 × 3 cross-language interop and credential-transfer matrices, coverage, bounded Go fuzzing, licence and packaged-consumer checks.
- Repository published under MIT OR Apache-2.0; no open issues or pull requests; no tags; nothing published to npm, crates.io or the Go proxy.

Gaps that block a first release:

| # | Gap | Why it matters |
|---|---|---|
| G1 | The server key cannot be rotated. `docs/design/server-key-rotation.md` (sr1) is a heavy design proposal, not implemented. | A frozen server key means every client must be re-pinned by hand on any key change or suspected leak. The maintainer decided on 2026-11-08 that rotation is part of the protocol. |
| G2 | The nonce cache is in memory only and the spec says nothing about restarts. | After a restart, a request captured within the last `window` seconds (30 s by default) can be replayed once. |
| G3 | There are no executables: no gateway, no stdio bridge, no CLI for key generation and bootstrap. D1 and the README promise all three roles. | Existing MCP clients (desktop apps, coding agents) speak stdio or plain HTTP; without a bridge they cannot use mcp-jack at all, and operators have no tool to create the first administrator. |
| G4 | Compatibility with real MCP clients and servers is untested. | Open points: `GET` streams (MCP clients expect `405` when no stream is offered; we answer `501` when the upstream streams), `Accept` negotiation so upstreams answer JSON, pass-through of `MCP-Protocol-Version` and session headers. |
| G5 | Stale texts. | `spec/README.md` status line says fixtures and SDK migration are pending; Q3 lost its "decided: part of the protocol" wording; `README.md` and `docs/readiness.md` call rotation "design pending"; `SECURITY.md` lists "policy checks"; the Rust crate description mentions authorization and "server SDK" only. |
| G6 | No release engineering. | TypeScript is `0.0.0` and `private`, Rust is `0.1.0` with `publish = false`, no changelog, no release workflow, no signed artifacts, no versioning policy. |
| G7 | No user documentation beyond SDK READMEs. | No quickstart, operator guide or threat model; no examples with the official MCP SDKs. |
| G8 | Security assurance is thin. | Only Go has fuzz targets; no differential fuzzing across SDKs; no independent review of the reduced contract; no vulnerability scanning in CI. |

## 2. Release scope

**v0.1.0 contains:** wire format `mcp-jack/v1` frozen for the 0.x series; the three SDKs; minimal server-key rotation; restart replay guard; a Go command-line tool with gateway, stdio bridge, key generation, bootstrap and admin commands; examples with the official MCP SDKs; user and operator documentation; signed release artifacts.

**Not in v0.1.0 (deferred or rejected):**

- Authenticated encrypted session channel and streaming (Q1, v0.2).
- Multi-instance servers, shared nonce store, cluster management (Q5). v0.1 supports one server instance per state store.
- The heavy parts of sr1: generation chains, fork detection and quarantine, `server_id`, 24-hour stabilization, crash-durability contract. They stay a reference for v0.2 hardening.
- Per-user server keys after the first handshake: rejected. All keys would live on the same server, so a server compromise leaks them together; responses are already bound to each request; rotation would multiply. Per-session keys belong to the v0.2 channel (ephemeral key exchange, forward secrecy).
- Server-side hardware signers and OS key-store integrations beyond the existing `Signer` interface.
- Delegation, approval flows, MCP access rules: not protocol features.
- External paid audit: the release is labelled "pre-1.0, not independently audited"; an audit is planned after feedback.

## 3. Decisions needed before work starts

| # | Question | Recommendation |
|---|---|---|
| D-1 | Ship executables (gateway, bridge, CLI) in v0.1.0, or SDKs only? | Ship them, in Go only (single static binary per platform). Without the bridge the protocol has no users. |
| D-2 | Restart replay guard: reject `ts` earlier than server start, or persist nonces? | Reject `ts < server_start` (no extra storage). Cost: a request signed just before a restart fails once and is retried with a fresh `ts`. |
| D-3 | Rotation delivery: native tool, response header, or both? | Native read-only tool `jack.server.key` for any authenticated user; the client SDK calls it on connect and periodically. One path, easy to test. |
| D-4 | Versions and names: `0.1.0` everywhere; npm `mcp-jack`, crate `mcp-jack`, Go tag `v0.1.0`. | Yes; re-check name availability just before publishing. |
| D-5 | Does a release candidate go to the registries (`0.1.0-rc.1`)? | Yes for npm and crates.io pre-release versions; Go uses the `v0.1.0-rc.1` tag. |

## 4. Plan: super-tasks and tasks

Each super-task is one branch, one worktree under `worktrees/` and one pull request; CI is the gate. Task ids are stable references for issues and commits.

### S1. Close the specification and freeze the wire format

Depends on: D-2, D-3.

| Task | Content | Acceptance |
|---|---|---|
| S1.1 | Minimal server-key rotation section in the spec. Announcement record (exact bytes, own domain string): `aud`, old `kid`, new `kid`, new public key, `switch_at`; signed by the current key and by the new key (proof of possession). Tool `jack.server.key` returns the current key and the pending announcement. Server signs with the old key before `switch_at` and with the new key from `switch_at`. A client that verified the announcement against its pin accepts both keys in `[switch_at - window, switch_at + window]`, then drops the old key. One pending rotation at a time, no cancel; a client that missed the switch is re-pinned by hand; no TOFU. Error codes. | Spec text reviewed; sr1 marked "superseded for v0.1, reference for v0.2". |
| S1.2 | Restart replay guard in 01-authentication (per D-2). | Normative rule plus its error code and order in the verification steps. |
| S1.3 | Generator and reference verifier: rotation vectors (valid, wrong signer, bad proof, wrong `aud`, reused key, window edges) and restart-guard vectors; `CASES.md`. | `gen-fixtures.mjs --check` passes in CI. |
| S1.4 | Fix stale texts (G5) and restore the Q3 decision wording in `spec/README.md`, the scope review, `README.md`, `docs/readiness.md`, `SECURITY.md`, the Rust crate description. | No document contradicts the current contract. |
| S1.5 | Versioning and compatibility policy: wire version `v1` frozen for 0.x; SDK semver pre-1.0; what a breaking change is. | `docs/versioning.md`; spec status says "wire format frozen". |

### S2. Rotation and restart guard in the SDKs

Depends on: S1.

| Task | Content | Acceptance |
|---|---|---|
| S2.1 | Go: server key set (current, next, announcement), `jack.server.key`, switch at `switch_at`, restart guard; client fetch/verify/accept window and a pin-update callback (the application persists the new pin; the SDK writes no files). | Go conformance tests on the new fixtures pass in CI. |
| S2.2 | Rust: same as S2.1. | Rust conformance tests pass in CI on stable and MSRV 1.85. |
| S2.3 | TypeScript: same as S2.1. | TS tests pass in CI on Node 20 and 22. |
| S2.4 | Interop scenarios 3 × 3: announce and switch, forged announcement rejected, straggler after the window fails closed, restart guard. | Interop job green with the new scenarios. |

S2.1-S2.3 can run in parallel; S2.4 follows them.

### S3. Executables (Go)

Depends on: D-1. S3.1-S3.3 can start in parallel with S2; S3.4 needs S2.1.

| Task | Content | Acceptance |
|---|---|---|
| S3.1 | `mcp-jack` CLI skeleton: `keygen` (server and user keys, file permissions 0600), `bootstrap` (local first-admin invite), `enroll`, config file format without private keys inline. | Unit tests; documented commands. |
| S3.2 | `mcp-jack gateway`: reverse proxy in front of an unmodified MCP HTTP server, using the Go server SDK; forwards verified identity as configured headers to the upstream only on the trusted hop. | Integration test with a stub upstream. |
| S3.3 | `mcp-jack bridge`: MCP stdio on one side, signed HTTP on the other, using the Go client SDK; key from a file or an external signer. | Integration test: stdio JSON-RPC in, signed request out, verified response back. |
| S3.4 | Admin and rotation commands: `user list/create/revoke/set-admin`, `invite create/list/revoke`, `server-key announce/status`. | Commands covered by tests against a real gateway. |
| S3.5 | Cross-platform builds (Linux, Windows, macOS; amd64 and arm64) in CI. | Artifacts built on every PR, not published. |

### S4. MCP ecosystem compatibility and examples

Depends on: S3.2, S3.3 (for S4.2).

| Task | Content | Acceptance |
|---|---|---|
| S4.1 | Examples per language with the official MCP SDKs: a protected server (Go SDK, Rust `rmcp`, TS `@modelcontextprotocol/sdk`) and a client. | Examples build in CI. |
| S4.2 | End-to-end test in CI: official MCP client → `mcp-jack bridge` → `mcp-jack gateway` → official MCP server; checks `initialize`, `tools/list`, `tools/call`, `GET` stream behaviour, `Accept`, `MCP-Protocol-Version`, session headers. | E2E job green. |
| S4.3 | Fix every incompatibility S4.2 finds (likely: `405` instead of `501` for an unsupported `GET` stream, `Accept` rewriting at the gateway). Spec change if the wire is affected, before the freeze in S1.5 is final. | E2E green with no known workarounds. |

### S5. Security assurance

Depends on: S2, S3.

| Task | Content | Acceptance |
|---|---|---|
| S5.1 | Threat model: assets, attackers, what is and is not protected (no confidentiality without TLS, single instance, unaudited, missed rotation, server compromise). | `docs/threat-model.md`, linked from README and SECURITY.md. |
| S5.2 | Fuzzing beyond Go: Rust `cargo-fuzz` targets for header, body classification, JSON parsing, envelopes; TS property tests; bounded CI runs. | New targets run in CI. |
| S5.3 | Differential fuzzing across the three SDKs for parsers whose disagreement is a vulnerability (header, base64url, JSON duplicates, body classification, rotation record). | Corpus and harness in CI; no disagreements. |
| S5.4 | Independent zero-trust review of spec and SDK changes since PR #14; fix confirmed findings. | Review report and fixes merged. |
| S5.5 | Supply chain in CI: `govulncheck`, `cargo audit`/`cargo deny` advisories, `npm audit`. | Jobs green or findings triaged. |

### S6. Documentation

Depends on: S2, S3 (texts describe the shipped behaviour).

| Task | Content | Acceptance |
|---|---|---|
| S6.1 | README rewritten for users: what it is, status, five-minute quickstart (gateway + bridge), limitations. | Reviewed. |
| S6.2 | Operator guide: key generation and storage, bootstrap, invites and enrollment, user key rotation, server key rotation, audit log, state file backup, clock sync, single instance. | `docs/operator-guide.md`. |
| S6.3 | API docs: Go doc comments for pkg.go.dev, rustdoc for docs.rs, TS API section; per-language quickstarts. | Docs build without warnings. |
| S6.4 | Clean `docs/`: shorten `readiness.md` to current evidence, add a design-docs index, mark historical records as such. | No stale status statements. |

### S7. Release engineering

Can run in parallel with S4-S6. Version changes need explicit approval.

| Task | Content | Acceptance |
|---|---|---|
| S7.1 | Package metadata: description, keywords, README per package, docs.rs metadata; versions set to the release version and `private`/`publish = false` removed only in the release PR. | Consumer checks pass on the release PR. |
| S7.2 | `CHANGELOG.md` and release-notes template. | Present. |
| S7.3 | Release workflow on tag: full CI, `npm publish` with provenance (trusted publishing), `cargo publish`, Go tag, GitHub Release with binaries, checksums and build attestations. | Dry run (`npm publish --dry-run`, `cargo publish --dry-run`) green. |
| S7.4 | Repository settings (maintainer): branch protection with required checks, private vulnerability reporting enabled, npm trusted publisher and crates.io token configured. | Checklist ticked by the maintainer. |
| S7.5 | Re-check the `mcp-jack` name on npm, crates.io and GitHub. | Recorded with date. |

### S8. Release candidate and release

Depends on: S1-S7.

| Task | Content | Acceptance |
|---|---|---|
| S8.1 | `v0.1.0-rc.1`: tag, publish pre-release versions, install from the registries in clean environments, run the E2E job against published artifacts. | Consumer installs and E2E green. |
| S8.2 | Fix RC findings; repeat RC if the wire or public API changed. | No open release blockers. |
| S8.3 | `v0.1.0`: tag, publish, GitHub Release, announcement. | Packages installable; release notes published. |

## 5. Order and critical path

```
D-1..D-5 ─► S1 ─► S2 ─┬─► S5 ─┐
            S3.1-3.3 ─┼─► S3.4, S3.5 ─► S4 ─┼─► S8
                      └─► S6 ───────────────┤
            S7 (parallel, after D-4) ───────┘
```

Critical path: S1 → S2 → S4 → S8. S3 and S7 start early in parallel; S5 and S6 start once S2 and S3 settle.

## 6. Working rules

- One worktree and pull request per super-task; sub-agents only with the maintainer's approval; every sub-agent is told that builds and tests run in GitHub CI only (locally only `cargo check`, `cargo clippy`, `cargo fmt`).
- Fixtures stay generated; every wire change lands in spec, generator, reference verifier and all three SDKs in the same super-task.
- No version change, tag, push or publication without explicit approval.
