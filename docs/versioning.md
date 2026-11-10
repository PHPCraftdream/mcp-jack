# Versioning and release policy

**Status: policy, 2026-11-10.** This records owner decisions and parent-verified release receipts, not approval inferred from the historical plan. This policy does not make a release/freeze decision or claim tests ran here.

| Decision | Recorded decision | Status |
|---|---|---|
| D-1 | Candidate release scope includes the Go CLI, gateway and stdio bridge. | Go source for these roles exists in this worktree; inclusion in a release remains gated. |
| D-2 | Durable authenticated nonce reservation before native authorization/state mutation or handler dispatch; fail closed on unknown outcome and never automatically retry. No timestamp-startup floor. | Design direction selected; backend/SDK contract and implementation acceptance remain future work. |
| D-3 | Arbitrarily many pending server-key announcements are allowed, without one-pending or cooldown; OLD remains in use until NEW takes over 48 hours after its announcement. The owner example: K1 announced Monday 10, K2 Monday 11, K1 remains usable until Wednesday 11. | Direction selected; candidate formal time/event representation, ordering, contract and implementation remain future work. |
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
| Go module | `github.com/PHPCraftdream/mcp-jack`; `go.mod` says `go 1.22`. | [`go.mod`](../go.mod) |
| Rust crate | `mcp-jack` `0.1.0`, `rust-version = "1.88"`, `publish = false`. | [`rust/Cargo.toml`](../rust/Cargo.toml) |
| TypeScript package | `mcp-jack` `0.0.0`, `private: true`, Node `>=20`. | [`ts/package.json`](../ts/package.json) |

The owner approved Go 1.25 after source review as the **whole Go SDK/CLI compatibility floor**, including consumer CI and migration. This approval is future implementation work: this worktree's `go.mod` still says Go 1.22, so do not claim the migration is complete. Deployment builds must use patched Go 1.26.10; a minimum language floor is not a security-toolchain endorsement. The approved floor removes the former Go 1.22 blocker in the conditional bbolt v1.5.0 research, but bbolt is not an added dependency or qualified durable backend ([`docs/design/durable-nonce-backend.md`](design/durable-nonce-backend.md)). Actual adapter, dependency review, filesystem/crash evidence and acceptance are still required.

Rust's checked-in manifest already declares 1.88. The earlier approved security migration from Rust 1.85 to 1.88 is reflected in current source and workflow configuration; this statement does not claim a new build or CI run in this task. TypeScript remains Node 20/22 in the existing CI matrix and `private: true`. Keep all component versions and publication restrictions unchanged absent separate explicit approval; no new dependency, Rust MSRV change, or Node baseline change is authorized here.

## Compatibility, transition and freeze gates

Compatibility includes wire semantics, SDK/API surfaces, persisted state, static profiles and credentials, and operator workflows. Wire compatibility covers signing bytes and domains, canonicalization, parsing/validation and error precedence, identity/admin semantics, and restart/replay/rotation behavior. A break in any area requires explicit review and an approved migration or rejection plan. A profile change is not automatically a signing-domain or wire change. Never silently reinterpret existing `mcp-jack/v1` signatures or bytes. Static pins, credentials, profiles and user-key rotation remain unchanged unless an explicitly approved transition says otherwise.

The durable nonce and server-key rotation directions are selected, but candidate requirements are not yet normative. In particular:

- D2 requires durable authenticated nonce reservation before dispatch, with fail-closed unknown outcomes and no automatic retry. The current SDK nonce stores and Go CLI gateway still use in-memory nonce storage; the proposed transaction backend and SDK seams are not implemented.
- D3 direction is selected. The owner's concrete example—K1 announced Monday 10, K2 announced Monday 11—fixes the English next-announcement retirement rule: K1 remains usable until Wednesday 11 as K2 takes over. The formal candidate time/event representation, ordinal tie behavior (including empty intermediate intervals), strict client cutoff and suppressed-suffix behavior are technical defaults, not separate owner decisions. These details remain non-normative alongside codec, API, bounds, statuses and storage rules. No automatic connect-time/periodic refresh is selected; unknown outer signing key fails closed without fallback or TOFU. See [`spec/candidate/`](../spec/candidate/), [`docs/design/restart-replay.md`](design/restart-replay.md), [`docs/design/minimal-server-rotation.md`](design/minimal-server-rotation.md), and [`docs/design/durable-nonce-backend.md`](design/durable-nonce-backend.md).

Acceptance and freeze require review of evidence for the **same exact full SHA**, including:

- Reviewed normative spec, generated candidate-fixture freshness and agreement with the reference model.
- Matching accept/reject, status, error-order, nonce-state and rotation-boundary results in all Go, Rust and TypeScript runners.
- Separate existing Jack 3×3 request/response interop and 3×3 credential-transfer matrices, plus future candidate-specific coverage. These are distinct from official MCP client/stdio/HTTP-server compatibility and its proposed end-to-end fixture coverage.
- Applicable Go CLI gateway/bridge end-to-end and consumer checks; actual artifact/consumer receipts; and security-blocker disposition.
- Negative/boundary cases for strict Ed25519, restart replay, durable-store failures, key rotation and cutoffs, unknown keys, credential/profile migration or rejection, and any documented MCP compatibility profile.

Evidence must report observed results, not just test names, workflow wiring or green-status claims. After contract, integration and security gates are reviewed and explicitly accepted, record freeze approval and exact baseline SHA. Until then there is no freeze decision or blanket compatibility guarantee across 0.x.

## Parent-verified PR22 receipt and remaining status

PR #22 merged as `c098cf5678716b36d1bff5012f864e2e0d105286` after all 32 checks succeeded on reviewed head `f00fc2e42e935f6632e48d224be3c76581aa6ec5`. All six post-merge workflows succeeded; main ancestry and source-preserving worktree cleanup were verified. These receipts establish design delivery only, not D2/D3 implementation or final acceptance.

## RC artifacts and release authorization

An RC, if separately authorized, is artifact-only: no tag, registry publication, GitHub Release or public release announcement. Do not bump versions or remove `private: true` / `publish = false` for it. Green CI, this policy, a merge receipt or missing receipts authorize nothing.

Future RC receipts must identify full source SHA, workflow run and attempt, artifact IDs, platforms and toolchains, actual filenames/inventory, SHA-256 checksums, and attestation subject plus source verification. Package, binary and consumer checks must consume those exact produced artifacts—not a substitute checkout build or registry package. Current consumer-package workflow wiring is not evidence of future RC binaries, checksums, attestations or release readiness; none is claimed here.

A later stable release requires a separate explicitly approved release-version PR and publication decision. Record publication-account ownership and trusted-publisher, repository-configuration and token requirements before any publish, tag, GitHub Release or announcement. Keep those decisions separate from candidate/freeze acceptance.
