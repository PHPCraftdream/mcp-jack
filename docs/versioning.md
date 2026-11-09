# Versioning and release policy

Status: policy, 2026-11-09. This records supplied current owner answers, not approvals inferred from [`release-plan.md`](release-plan.md):

| Decision | Recorded owner answer | Date |
|---|---|---|
| D-1 | Candidate release scope includes the Go CLI, gateway, and stdio bridge. | 2026-11-09 |
| D-4 | No version changes yet; proposed versions and names remain proposals, not approvals. | 2026-11-09 |
| D-5 | An RC is artifact-only, with no registry publication. | 2026-11-09 |

The supplied D-1, D-4, and D-5 answers supersede conflicting recommendations in the release plan; those recommendations are not owner approval.

No D-2 or D-3 answer is recorded here; this document makes no claim about their broader status. These decisions and policies certify no implementation, release, or freeze.

## Version domains

Keep these identifiers distinct; none implies another:

- **Wire signing domains:** current draft identifiers are `mcp-jack/v1/request`, `mcp-jack/v1/response`, and user-key rotation `mcp-jack/v1/rotate` ([`spec/01-authentication.md`](../spec/01-authentication.md), [`spec/03-user-management.md`](../spec/03-user-management.md)). They do not establish a frozen or released protocol.
- **Protocol document version:** the specification identifies itself as draft `v0.1` ([`spec/README.md`](../spec/README.md)); this is not an SDK version or compatibility guarantee.
- **SDK/package versions:** Go, Rust, and TypeScript version independently. For future explicitly authorized SDK releases only, apply pre-1.0 SemVer: breaking public SDK changes increment the minor version; compatible additions increment minor, and compatible fixes increment patch. This is policy, not permission to bump versions now. SDK versions do not identify or change wire format.
- **Prerelease labels and candidate identity:** `-rc.N` is descriptive prerelease metadata, not publication approval or source identity. Identify every candidate by the full source commit SHA.

## Current manifest snapshot

Values below are the checked-in snapshot at worktree base `777771fed0a53011898e55d959b6f8576675fd89`, dated 2026-11-09; they are not release approvals:

| Component | Snapshot | Evidence |
|---|---|---|
| Go module | `github.com/PHPCraftdream/mcp-jack`; `go.mod` has no version field or publication flag. A public source path does not authorize creating a new tag. | [`go.mod`](../go.mod) |
| Rust crate | `mcp-jack` `0.1.0`; `publish = false`. | [`rust/Cargo.toml`](../rust/Cargo.toml) |
| TypeScript package | `mcp-jack` `0.0.0`; `private: true`. | [`ts/package.json`](../ts/package.json) |

Do not change these values or remove publication restrictions for an RC. They do not mean a component is released or approved for publication. Keep the Go 1.22, Rust 1.85, and Node 20/22 baselines and TypeScript's zero-runtime-dependency property unless separately reviewed and approved ([`go.mod`](../go.mod), [`rust/Cargo.toml`](../rust/Cargo.toml), [`.github/workflows/ci.yml`](../.github/workflows/ci.yml), [`ts/package.json`](../ts/package.json), [`ts/README.md`](../ts/README.md)).

## Compatibility, transition, and freeze gates

Compatibility includes wire semantics, SDK/API surfaces, persisted state, static profiles and credentials, and operator workflows. Wire compatibility covers signing byte layout, signing domain, and canonicalization; parse and validation rules, including observable error precedence; identity and admin semantics; and rotation, restart, and replay behavior. Any break in any of these areas requires explicit review and an approved migration or rejection plan. A profile change is not automatically a signing-domain or wire change. A genuinely breaking `mcp-jack/v1` wire change requires a new wire identifier and explicit migration; never silently reinterpret existing `v1` signatures or bytes.

The proposed changed contract remains a candidate until all evidence below is reviewed and accepted for the **same exact full SHA**:

- Reviewed normative spec; generated-fixture freshness and agreement with the reference implementation.
- Matching accept/reject, status, error-order, and nonce-state results in **all Go, Rust, and TypeScript runners**; cross-SDK request and credential matrices.
- MCP end-to-end results through the Go CLI, gateway, and stdio bridge; recorded security-blocker disposition.
- Negative and boundary cases that distinguish old from proposed behavior: tampered signed bytes; ambiguous parsing and error ordering; identity/admin failures; rotation and restart edges when approved; and migration or rejection of old profiles and credentials.

Evidence must describe observed results, not just test names or green-status claims. After protocol, MCP, and security gates are accepted, record explicit freeze approval and the exact contract-baseline SHA. Until then there is no freeze decision and no blanket compatibility guarantee across all 0.x versions.

## RC artifacts and release authorization

An RC, if authorized, is artifact-only: no tag, registry publication, GitHub Release, or public release announcement. Do not bump versions or remove `private: true` / `publish = false` for it. Green CI, this policy, and missing receipts authorize nothing.

Future RC receipts must identify the full source SHA; workflow run and attempt; artifact IDs; platforms and toolchains; actual artifact filenames and inventory; SHA-256 checksums; and attestation subject plus source verification. Package, binary, and consumer checks must consume those exact produced artifacts—not a substitute checkout build or registry package. No missing receipt is approval.

The current [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) shows consumer-package lane wiring only: TypeScript `mcp-jack-0.0.0.tgz`, Rust `mcp-jack-0.1.0.crate`, and Go `go-module-snapshot.tgz`, with inventories. This is not evidence of future RC binaries, checksums, attestations, or release readiness; none is claimed here.

A later stable release requires a separate, explicitly approved release-version PR and a separate publication decision. Record publication-account ownership and trusted-publisher, repository-configuration, and token requirements explicitly before any publish, tag, GitHub Release, or announcement. Keep these decisions separate from candidate/freeze acceptance.
