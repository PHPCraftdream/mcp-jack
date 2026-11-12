# Changelog

This changelog records repository history and planned work without implying release authorization. Unreleased entries are not releases. No product version is assigned here; product versions, tags, publication, GitHub Releases, and announcements remain unauthorized.

## Unreleased

### Current foundation baseline

- **PR #16 merged** as `c98f7eb0dac9ad22f11f712a80a3fe9c537426ee`. The foundation policy and approved Go security-scanning change are delivered in merged source. The policy delivery is recorded; Task **#54** is complete after verified post-merge CI and cleanup. Repository-settings verification remains UNVERIFIED.
- **Exact-head CI evidence boundary:** parent-verified PR checks and the six workflow runs below succeeded on tested PR head `8ee8858ec5d9802d02da1d9086e00be61e3e1d9b`, not on the merge SHA by implication. All 32 PR checks succeeded, including both 3×3 matrices, all six vulnerability scans, Rust 1.88 MSRV, and the fresh Rust consumer. Workflow run IDs: main CI `42709461708`; vulnerabilities `42709461656`; licenses `42709462005`; coverage `42709461764`; Go fuzz `42709461672`; fixtures `42709452435`. Attempts were not supplied. These receipts do not establish post-merge success, acceptance of packaging-metadata changes, artifact extraction/inspection, or release readiness.
- The merged Rust security migration uses exact `hickory-resolver`, `hickory-net`, and `hickory-proto` **0.26.1**, and development `time` **0.3.47** / `time-core` **0.1.8**; the product MSRV is **1.88**. CI source now names `rust 1.88 check` and `consumer rust 1.88`. Product versions, edition, and publication flags remain unchanged. `rust/Cargo.lock` is tracked. This records the source baseline and the parent-reported PR-head receipts, not post-merge validation.
- Rust security updates after that baseline, each owner-approved and limited to the exact manifest pin plus the matching lock entries: `hickory-proto` **0.26.2** (RUSTSEC-2026-0487 through 0491) and `hickory-net` / `hickory-resolver` **0.26.2** (RUSTSEC-2026-0509). See `docs/security-dependencies.md`; no other dependency, MSRV, product version or publication flag changed.
- **PR #17 remains open**, candidate head `8c769b36bdb862dca9136b73ad331915d395f73b`; runtime CI is pending. Its CLI work is not merged delivery or acceptance. CLI scope is approved, but implementation/acceptance remains pending.
- Packaging inventory, release-notes, and settings material is descriptive documentation. Its source-defined inventory is not an actual archive-member extraction receipt, and changes in this documentation/metadata candidate have not been validated by the cited foundation CI.

### Implemented contract and SDK history

- **PR #14, merged 2026-11-09 (`cc7318677c2e27f733320987971cc6c10c9525d7`):** Go, Rust, and TypeScript SDKs adopted the admin-only wrapper and verified caller identity contract. Application policy, scopes, and user kinds were removed; ordinary authenticated MCP traffic is forwarded for application authorization, while the protocol `admin` flag gates reserved `jack.admin.*` operations. Legacy state using removed `kind` or `scopes` fields is rejected strictly rather than silently migrated.
- User-key rotation is implemented. It is distinct from server response-signing-key rotation and changing a client's server pin.
- **PR #15, merged 2026-11-09 (`e681f07d20e1ac452a60b54ab656101592d9d8f3`):** documentation-only sr1 server-key-rotation proposal. It is non-normative design material, not implementation or approved rotation policy.

### Planned, not implemented or accepted

- **Task #96** covers artifact-only RC production, verification, and final disposition. Its candidate receipt remains unfilled. No candidate artifact, checksum, attestation, exact-artifact consumer receipt, or RC acceptance is claimed. Foundation policy acceptance does **not** depend on future Task #96 receipts or settings evidence; there is no circular dependency.
- Artifact-only RC scope means no registry publication. Registry-publisher/trusted-publisher ownership is deferred and is not an artifact-only RC prerequisite. No tag, version change, publication, GitHub Release, or announcement is authorized.
- Restart replay protection and server-key rotation remain release gaps. D-2 restart semantics and D-3 server-key rotation delivery/semantics are unresolved; sr1 closes neither. User-key rotation does not resolve D-3.
- Approved Go CLI, gateway, and stdio bridge scope is not a claim of delivery. PR #17 is an open CLI candidate, with runtime CI pending. No delivered CLI acceptance, wire freeze, full release acceptance, or release is claimed.
- Repository settings remain unverified. No settings/account query or change, publication permission, or release action is claimed. Go 1.22 compatibility is not a security endorsement; deployment Go builds require a supported patched toolchain as described in [`docs/security-dependencies.md`](docs/security-dependencies.md).

## Historical context

- The original foundation PR-head CI had Go 1.22.12 vulnerability findings and infrastructure errors in advisory jobs, as recorded in [`docs/security-dependencies.md`](docs/security-dependencies.md) and [`docs/checkpoints/release-foundations-1109.md`](docs/checkpoints/release-foundations-1109.md). These dated historical results are distinct from the later PR-head receipts above.
- Older Rust 1.85 check/context names described a pre-migration snapshot only. The current merged source uses Rust 1.88; do not treat historical 1.85 descriptions as current.

There are no versioned release entries in this file. A future release entry must be based on accepted evidence for the exact source SHA and explicitly authorized release actions.

## Parent integration receipt — 2026-11-09

After the worker handoff, parent verified all six post-merge workflows SUCCESS on exact merge SHA `c98f7eb0dac9ad22f11f712a80a3fe9c537426ee`: CI `42710339786`, vulnerabilities `42710340244`, licenses `42710339825`, coverage `42710340223`, Go fuzz `42710339895`, and fixtures `42710339912`. Primary main was fast-forwarded and ancestry verified. Six completed foundation worktrees and their local branches, plus the remote foundation branch, were removed after byte-verified preservation of source deltas. Task #54 is complete. These are foundation receipts, not evidence for this packaging candidate or any RC/settings acceptance.

PR #17 remains an unmerged CLI candidate. Its initial head `8c769b36bdb862dca9136b73ad331915d395f73b` failed the Linux raw-close test oracle; correction head `9b6778acaa474a162426cc918b9c1708d61acacc` is undergoing full CI. No CLI delivery acceptance is claimed. Repository settings remain UNVERIFIED and future RC receipt fields remain unfilled. These dated facts supersede earlier handoff timing only; recheck the exact future candidate before reliance.
