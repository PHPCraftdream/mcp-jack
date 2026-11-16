# Versioning and release policy

**Status: versioning and release policy for v0.1.0 (unreleased).** The durable-nonce + server-key-rotation profile is implemented; it becomes normative and wire-frozen for the 0.1.x line only when the freeze is accepted on an exact commit, and is candidate text until then (see [`docs/protocol-transition.md`](protocol-transition.md)). Nothing is published; no release is authorized. This policy does not claim tests ran here.

| Decision | Recorded decision | Status |
|---|---|---|
| D-1 | Candidate release scope includes the Go CLI, gateway and stdio bridge. | Go CLI/gateway/bridge source is merged; inclusion in a release remains gated. |
| D-2 | Durable authenticated nonce reservation before native authorization/state mutation or handler dispatch; fail closed on unknown outcome and never automatically retry. No timestamp-startup floor. | Implemented: durable bbolt-backed nonce profile with Linux-only private-file stores plus the Go CLI profile commands; Go is the reference implementation. |
| D-3 | Arbitrarily many pending server-key announcements are allowed, without one-pending or cooldown; OLD remains in use until NEW takes over 48 hours after its announcement. The owner example: K1 announced Monday 10, K2 Monday 11, K1 remains usable until Wednesday 11. | Implemented: rotation delivered across the Go, Rust and TypeScript SDKs and the Go CLI, with Go as the reference implementation. |
| D-4 | No version changes yet; proposed versions and names remain proposals, not approvals. | Current versions/publication restrictions remain unchanged. |
| D-5 | Any separately authorized RC is artifact-only, with no registry publication. | No RC is authorized by this policy. |

The table lists the recorded decisions independently; D-1, D-4 and D-5 concern release scope, versions and RC policy, while D-2 and D-3 are protocol-direction decisions. Candidate technical defaults below do not add owner approvals. D-1 selects Go CLI/gateway/stdio-bridge release scope; D-4 records no version changes yet; D-5 makes any separately authorized RC artifact-only with no registry publication. D-2 selects durable authenticated nonce reservation before native authorization/state mutation/handler dispatch, with unknown outcomes failing closed and no automatic retry; startup timestamp floors are not selected. D-3 selects arbitrary multiple pending server-key announcements without a one-pending rule or cooldown, with OLD remaining in use until NEW takes over 48 hours after announcement. None of these decisions alone authorizes release or freeze; they supersede conflicting historical recommendations in [`release-plan.md`](release-plan.md), including `ts < server_start` and one-pending/automatic-refresh recommendations.

## Version domains

Keep these identifiers distinct; none implies another:

- **Wire signing domains:** current draft identifiers are `mcp-jack/v1/request`, `mcp-jack/v1/response`, and user-key rotation `mcp-jack/v1/rotate` ([`spec/01-authentication.md`](../spec/01-authentication.md), [`spec/03-user-management.md`](../spec/03-user-management.md)). They do not establish a frozen or released protocol. Candidate server-key rotation uses a separate proposed domain; it is not part of current `v1` behavior.
- **Protocol document version:** the specification identifies itself as draft `v0.1` ([`spec/README.md`](../spec/README.md)); this is not an SDK version or compatibility guarantee.
- **SDK/package versions:** Go, Rust and TypeScript version independently. For future explicitly authorized SDK releases only, apply pre-1.0 SemVer: breaking public SDK changes increment the minor version; compatible additions increment minor, and compatible fixes increment patch. This is policy, not permission to bump versions now. SDK versions do not identify or change wire format.
- **Prerelease labels and candidate identity:** `-rc.N` is descriptive prerelease metadata, not publication approval or source identity. Identify every candidate by the full source commit SHA.

## Current manifest snapshot and compatibility decisions

Observed source in this worktree:

| Component | Current checked-in value | Evidence |
|---|---|---|
| Go module | `github.com/PHPCraftdream/mcp-jack`; `go.mod` says `go 1.25.0`. | [`go.mod`](../go.mod) |
| Rust crate | `mcp-jack` `0.1.0`, `rust-version = "1.88"`, `publish = false`. | [`rust/Cargo.toml`](../rust/Cargo.toml) |
| TypeScript package | `mcp-jack` `0.0.0`, `private: true`, Node `>=20`. | [`ts/package.json`](../ts/package.json) |

`go.mod` declares `go 1.25.0`; the CI consumer and interop lanes use it, while the vulnerability-scan and CLI-binary qualification jobs use Go 1.26.11. A minimum language floor is not a security-toolchain endorsement. Deployment builds should use a supported patched toolchain ([`docs/security-dependencies.md`](security-dependencies.md)).

Rust's checked-in manifest already declares 1.88. The earlier approved security migration from Rust 1.85 to 1.88 is reflected in current source and workflow configuration; this statement does not claim a new build or CI run in this task. TypeScript remains Node 20/22 in the existing CI matrix and `private: true`. Keep all component versions and publication restrictions unchanged absent separate explicit approval; no new dependency, Rust MSRV change, or Node baseline change is authorized here.

## Compatibility, transition and freeze gates

Compatibility includes wire semantics, SDK/API surfaces, persisted state, static profiles and credentials, and operator workflows. Wire compatibility covers signing bytes and domains, canonicalization, parsing/validation and error precedence, identity/admin semantics, and restart/replay/rotation behavior. A break in any area requires explicit review and an approved migration or rejection plan. A profile change is not automatically a signing-domain or wire change. Never silently reinterpret existing `mcp-jack/v1` signatures or bytes. Static pins, credentials, profiles and user-key rotation remain unchanged unless an explicitly approved transition says otherwise.

The durable nonce and server-key rotation profile is implemented; its normative, wire-frozen status within the 0.1.x line is declared at the freeze decision, not before. In particular:

- D2 is implemented: durable authenticated nonce reservation before dispatch with bbolt v1.5.0 as the backend, fail-closed unknown outcomes and no automatic retry. Residual limits: one nonce owner per deployment; the private-file stores are Linux-only (Windows CLI stores fail closed); recovery after an abnormal stop is a manual operator procedure; no timestamp-startup floor exists (that remedy was rejected).
- D3 is implemented: fixed publication time P, activation A = P + 172800 seconds (48 hours), both keys valid during the overlap and a strict cutoff at the successor activation; explicit single-page client refresh with no automatic connect-time/periodic refresh, no hidden retry or reset; the durable client ClockGuard fences trust. Residual limit: the suppressed-successor (suppressed-suffix) behavior remains a documented limitation; static pins, credentials, profiles and user-key rotation are unchanged for static clients. See [`spec/candidate/server-key-rotation.md`](../spec/candidate/server-key-rotation.md), [`docs/design/restart-replay.md`](design/restart-replay.md), [`docs/design/minimal-server-rotation.md`](design/minimal-server-rotation.md), and [`docs/design/durable-nonce-backend.md`](design/durable-nonce-backend.md).

Acceptance and freeze require review of evidence for the **same exact full SHA**, including:

- Reviewed normative spec, generated candidate-fixture freshness and agreement with the reference model.
- Matching accept/reject, status, error-order, nonce-state and rotation-boundary results in all Go, Rust and TypeScript runners.
- Separate existing Jack 3×3 request/response interop and 3×3 credential-transfer matrices, plus future candidate-specific coverage. These are distinct from official MCP client/stdio/HTTP-server compatibility and its proposed end-to-end fixture coverage.
- Applicable Go CLI gateway/bridge end-to-end and consumer checks; actual artifact/consumer receipts; and security-blocker disposition.
- Negative/boundary cases for strict Ed25519, restart replay, durable-store failures, key rotation and cutoffs, unknown keys, credential/profile migration or rejection, and any documented MCP compatibility profile.

Evidence must report observed results, not just test names, workflow wiring or green-status claims. The 0.1.x wire profile is not frozen until the freeze is accepted as described above; SDK versions, publication, tags and release actions remain unauthorized and require separate explicit approval. There is no blanket compatibility guarantee across 0.x lines.

## RC artifacts and release authorization

An RC, if separately authorized, is artifact-only: no tag, registry publication, GitHub Release or public release announcement. Do not bump versions or remove `private: true` / `publish = false` for it. Green CI, this policy, a merge receipt or missing receipts authorize nothing. Historical development-receipt history is recorded in [`CHANGELOG.md`](../CHANGELOG.md).

Future RC receipts must identify full source SHA, workflow run and attempt, artifact IDs, platforms and toolchains, actual filenames/inventory, SHA-256 checksums, and attestation subject plus source verification. Package, binary and consumer checks must consume those exact produced artifacts—not a substitute checkout build or registry package. Current consumer-package workflow wiring is not evidence of future RC binaries, checksums, attestations or release readiness; none is claimed here.

A later stable release requires a separate explicitly approved release-version PR and publication decision. Record publication-account ownership and trusted-publisher, repository-configuration and token requirements before any publish, tag, GitHub Release or announcement. Keep those decisions separate from candidate/freeze acceptance.
