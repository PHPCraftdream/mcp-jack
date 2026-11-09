# Artifact-only release-candidate receipt (Task #96 template)

**Template status: UNFILLED.** This template supports future artifact-only RC production receipts and their verification/final disposition within consolidated Task **#96**. It is not a release record, approval, or evidence that a candidate exists. Complete it only for an explicitly authorized artifact-only candidate. No version, tag, publication, GitHub Release, announcement, or release authorization is implied.

Foundation PR #16 merged at `c98f7eb0dac9ad22f11f712a80a3fe9c537426ee`. Foundation policy is delivered; Task #54 post-merge verification and cleanup are complete. Future Task #96 RC receipts and settings evidence are not prerequisites for foundation policy acceptance. No circular dependency is intended. **Do not copy the historical foundation PR-head receipts below into the future candidate receipt.**

## Historical foundation CI record (not an RC receipt)

Parent-verified: all 32 PR checks succeeded on tested PR head `8ee8858ec5d9802d02da1d9086e00be61e3e1d9b`, including both 3×3 matrices, all six vulnerability scans, Rust 1.88 MSRV, and fresh consumer. The PR merged as `c98f7eb0dac9ad22f11f712a80a3fe9c537426ee`; these PR-head receipts are not merge-SHA receipts. Post-merge success is recorded in the parent integration receipt below. They do not prove post-merge success, validate packaging-metadata changes, or supply future Task #96 artifact/attestation/consumer receipts. Attempts were not supplied.

| Workflow | Run ID | Parent-reported result | Exact tested SHA |
|---|---:|---|---|
| Main CI | `42709461708` | SUCCESS | `8ee8858ec5d9802d02da1d9086e00be61e3e1d9b` |
| Vulnerabilities | `42709461656` | SUCCESS; all six scans | `8ee8858ec5d9802d02da1d9086e00be61e3e1d9b` |
| Licenses | `42709462005` | SUCCESS | `8ee8858ec5d9802d02da1d9086e00be61e3e1d9b` |
| Coverage | `42709461764` | SUCCESS | `8ee8858ec5d9802d02da1d9086e00be61e3e1d9b` |
| Go fuzz | `42709461672` | SUCCESS | `8ee8858ec5d9802d02da1d9086e00be61e3e1d9b` |
| Fixtures | `42709452435` | SUCCESS | `8ee8858ec5d9802d02da1d9086e00be61e3e1d9b` |

## Production receipt

### Candidate identity and workflow receipt

- Candidate label (descriptive only): `____________________________`
- Exact source commit SHA (full 40-character SHA): `____________________________`
- Repository: `____________________________`
- Event and PR context: `____________________________`
- PR number, if applicable: `________`
- PR head SHA: `____________________________`
- Merge/test SHA, if applicable: `____________________________`
- Specify exact SHA tested by each run: `____________________________`
- Workflow path/name, run ID, URL, and attempt: `____________________________`
- Run conclusion and observed time (UTC): `____________________________`
- Receipt reviewer/date (UTC): `____________________________`

Take the full SHA and event context from actual run receipts. A PR head and synthetic merge SHA are not interchangeable. Record each workflow's tested SHA; historical green results, a different attempt, skipped/cancelled jobs, setup failures, scanner failures/findings, and infrastructure errors do not establish this candidate's acceptance. Record run attempts as observed; do not infer missing values.

### Current source-defined workflow/job inventory

These names and matrix dimensions are from current workflow source, not proof of a future run, a required branch-protection check, or a release job. Confirm actual expanded contexts and emitting GitHub App from receipts before relying on settings. Fill the receipt columns only from the exact candidate run.

| Workflow path | Source-defined job names / dimensions | Candidate run ID/attempt | Exact tested SHA | Observed result/evidence |
|---|---|---|---|---|
| `.github/workflows/ci.yml` | `go (ubuntu-latest)`, `go (windows-latest)`, `go race`, `fixtures are up to date`, `rust (ubuntu-latest)`, `rust (windows-latest)`, `rust 1.88 check`, `ts (ubuntu-latest, node 20)`, `ts (ubuntu-latest, node 22)`, `ts (windows-latest, node 20)`, `ts (windows-latest, node 22)`, `interop matrix (3x3)`, `credential transfer matrix (3x3)`, `consumer ts (node 20)`, `consumer ts (node 22)`, `consumer rust 1.88`, `consumer go 1.22` |  |  |  |
| `.github/workflows/coverage.yml` | `go coverage`, `rust coverage`, `ts coverage` |  |  |  |
| `.github/workflows/fuzz.yml` | `go fuzz (bounded campaign)` |  |  |  |
| `.github/workflows/license.yml` | `go licences`, `rust licences`, `ts licences`, `dual-licence manifests` |  |  |  |
| `.github/workflows/vulnerabilities.yml` | `Go govulncheck (module)`, `Go govulncheck (package)`, `Go govulncheck (symbol)`, `Rust advisories`, `npm audit (ts)`, `npm audit (tools/license/tooling)` |  |  |  |
| `.github/workflows/spec-fixtures.yml` | `generate and upload fixtures` (only if this workflow ran) |  |  |  |

Distinguish success from skipped, cancelled, setup-failed, scanner-failed, advisory finding, and infrastructure failure. Consumer-package lanes exercise their defined packages; they are not release-binary builds. Current workflow source has no RC binary, per-file RC checksum, or attestation job. `spec-fixtures.yml` is not a PR-triggered workflow; the PR-triggered fixture-freshness candidate is `fixtures are up to date` in `ci.yml`.

### Produced artifact inventory and provenance

List only artifacts actually downloaded from this candidate's recorded run. Do not substitute a local build, rebuilt equivalent, registry package, or artifact from another SHA/run.

| Artifact ID | Workflow/run/attempt | GitHub artifact name | Exact filename/path | Platform/architecture | Toolchain(s) | Size | Upload digest (algorithm/value) | Independent per-file SHA-256 | Inventory/extraction evidence |
|---|---|---|---|---|---|---:|---|---|---|
|  |  |  |  |  |  |  |  |  |  |

Record actual artifact ID, name, run and attempt, filenames, platform/toolchain, and inventory. Recompute SHA-256 for each exact file delivered for review. Upload archive/digest metadata is not a per-file checksum. A checksum establishes byte identity only, not source provenance, build correctness, or signer identity.

### Attestation verification

- Attestation exists for each required artifact: `____________________________`
- Exact subject name and digest: `____________________________`
- Digest matched against exact artifact file: `____________________________`
- Signer identity and issuer: `____________________________`
- Repository, workflow identity/path, ref, source SHA asserted: `____________________________`
- Verification method/tool/version, result, evidence: `____________________________`
- Reviewer/date/limitations: `____________________________`

Verify subject/digest against the exact artifact and repository/workflow/ref/source claims against the authorized repository and exact run. Upload digest, checksum, and attestation are distinct evidence. An attestation does not prove a consumer used that artifact. Current workflows use read-only repository permissions and define no RC attestation generation or verification job. If required evidence is unavailable, mark **MISSING** in verification; absence is not a pass.

## Verification and final disposition

### Exact-artifact consumer evidence

For each required target, identify the artifact ID and SHA-256 above that the consumer actually installed or executed. Record consumer workflow/job, run/attempt, exact source SHA, setup/toolchain, job evidence, and result. Confirm the consumed bytes were the recorded artifact—not a checkout rebuild, substitute artifact, or registry package. Missing exact-artifact consumer evidence remains missing; do not infer it from a similar source build.

| Platform/consumer | Exact artifact ID + filename | SHA-256 | Workflow/job + run/attempt | Toolchain/runtime | Observed result/evidence |
|---|---|---|---|---|---|
|  |  |  |  |  |  |

The source-defined package wiring is described in [`package-inventory.md`](package-inventory.md), not an executed receipt. It names TypeScript `mcp-jack-0.0.0.tgz`, Rust `mcp-jack-0.1.0.crate`, and Go `go-module-snapshot.tgz`, with inventories. Go verification consumes its staged module **directory**, not the uploaded tarball; Rust verification extracts the crate; TypeScript verification installs the staged tarball. These are SDK consumer packages, not RC executables. Current workflow source does not produce RC binaries, per-file RC checksums, or build attestations.

### Compatibility, security, and limitations review

Re-evaluate against the exact candidate; these are baseline limitations, not candidate-specific acceptance evidence:

- Non-loopback connections require TLS. Response signatures provide integrity/authenticity under configured key trust, not confidentiality.
- Embedded endpoint, audience, and server-key pin values are not independent trust anchors; record independent sources and compatibility.
- Ordinary application authorization is separate from reserved protocol admin operations.
- Nonces are in memory and lost on restart; no restart guard is implemented. D-2 semantics are unresolved.
- Server response-signing-key rotation is not implemented. D-3 delivery/semantics are unresolved and distinct from implemented user-key rotation.
- Go CLI, gateway, and stdio-bridge scope is approved but not accepted delivery. PR #17 is an open candidate with runtime CI pending.
- A single active owner per state store is assumed; there is no cross-process lock.
- Rust migration is merged: Hickory resolver/net/proto 0.26.1, development `time` 0.3.47 / `time-core` 0.1.8, product MSRV 1.88; the current CI names are `rust 1.88 check` and `consumer rust 1.88`. Go is 1.22 compatibility; Node is 20/22. Record actual candidate toolchains.
- Go 1.22 compatibility is not a deployment security endorsement. Record the actual build toolchain; do not infer deployment security from the separate Go 1.26.10 scan lane.
- No audit, security guarantee, wire freeze, or release readiness is established by this template. Record findings, infrastructure failures, missing/skipped work, and explicit non-guarantees separately.

Candidate-specific evidence/limitations: `________________________________________________________________`

| Surface | Prior contract/API/state/profile/credential behavior | Candidate behavior | Compatibility/migration/rejection decision | Evidence/receipt |
|---|---|---|---|---|
| Wire/signing contract |  |  |  |  |
| Public Go/Rust/TypeScript SDK API |  |  |  |  |
| Persisted state and backup/restore |  |  |  |  |
| Static profile and credential format |  |  |  |  |
| User-key rotation |  |  |  |  |
| Restart replay behavior / D-2 |  |  |  |  |
| Server-key rotation / D-3 |  |  |  |  |
| CLI, gateway, stdio bridge |  |  |  |  |
| TLS, pin trust, application authorization |  |  |  |  |
| Toolchains and compatibility |  |  |  |  |
| Security findings and infrastructure failures |  |  |  |  |

Legacy records with `kind` or `scopes` members, rejection behavior and no-silent-rewrite evidence: `____________________________`
Independent endpoint/audience/server-key pin sources and compatibility evidence: `____________________________`
Operator action, approval, rollback, recovery, backup/restore, and retry receipts: `____________________________`

No automatic retry, migration success, or rollback is promised by this form. Record exact behavior and evidence. User-key rotation is not server-key rotation. D-2/D-3 remain unresolved unless separately decided and evidenced.

### Verification decision

- Receipts match the same exact full SHA and run attempts: `[ ]`
- Required workflow/job outcomes reviewed, including scan findings and infrastructure failures: `[ ]`
- Artifact IDs, inventories/extracted members, filenames, platforms/toolchains, and independent per-file SHA-256 recorded: `[ ]`
- Required attestation subject/digest and source/workflow claims verified: `[ ]`
- Required attestations MISSING (list artifacts/gap; not a pass): `____________________________`
- Required consumers verified against exact produced artifacts: `[ ]`
- Compatibility, migration, security findings, and known gaps reviewed: `[ ]`
- Repository settings independently evidenced (see [`release-settings.md`](release-settings.md)): `[ ]`
- Task #96 decision: `[ ] NOT ACCEPTED  [ ] ACCEPTED FOR THIS EXACT SHA ONLY`
- Decision owner/date/evidence: `____________________________`
- Remaining blockers/follow-up: `____________________________`

Acceptance requires an explicit maintainer decision supported by complete, matching receipts for Task #96; missing required attestation or exact-artifact evidence is not acceptance. This checklist cannot authorize publication, tags, a GitHub Release, or an announcement. Artifact-only RC scope means no registry publication; registry publisher/trusted-publisher ownership is deferred and is not an RC prerequisite. Foundation policy acceptance under Task #54 is not conditional on Task #96 or repository-settings receipts.

## Parent integration receipt — 2026-11-09

After the worker handoff, parent verified all six post-merge workflows SUCCESS on exact merge SHA `c98f7eb0dac9ad22f11f712a80a3fe9c537426ee`: CI `42710339786`, vulnerabilities `42710340244`, licenses `42710339825`, coverage `42710340223`, Go fuzz `42710339895`, and fixtures `42710339912`. Primary main was fast-forwarded and ancestry verified. Six completed foundation worktrees and their local branches, plus the remote foundation branch, were removed after byte-verified preservation of source deltas. Task #54 is complete. These are foundation receipts, not evidence for this packaging candidate or any RC/settings acceptance.

PR #17 remains an unmerged CLI candidate. Its initial head `8c769b36bdb862dca9136b73ad331915d395f73b` failed the Linux raw-close test oracle; correction head `9b6778acaa474a162426cc918b9c1708d61acacc` is undergoing full CI. No CLI delivery acceptance is claimed. Repository settings remain UNVERIFIED and future RC receipt fields remain unfilled. These dated facts supersede earlier handoff timing only; recheck the exact future candidate before reliance.
