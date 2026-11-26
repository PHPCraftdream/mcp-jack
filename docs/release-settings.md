# Release repository-settings checklist

**Status: UNVERIFIED.** This is a maintainer checklist, not evidence of repository settings or an instruction to change them. No read-only settings receipt is recorded here. Do not infer that a control is enabled. Verification requires a maintainer to record the actual value and approved read-only evidence. This document does not configure settings, access accounts, handle credentials, enable publication, or authorize release actions.

**Baseline:** the foundation policy (PR #16) and the code delivered since then are merged: the Go SDK with durable nonces, server-key rotation in all three SDKs, the Go CLI (gateway, bridge, admin and rotation commands), the 3x3 interop matrices including rotation, and the official MCP end-to-end job. This checklist covers the repository settings the owner still has to record. Settings are UNVERIFIED until a maintainer records the actual values below.

## Branch protection for `main` — proposed policy

Review effective branch protection/rulesets, overlapping rulesets, and bypass actors. Recommendations are proposed safeguards, not current settings.

- [ ] Require a pull request and at least one independent approving review (or maintainer-approved higher threshold).
- [ ] Dismiss stale approvals when the reviewed code changes.
- [ ] Require approval of the most recent reviewable push by someone other than its pusher; no author self-approval.
- [ ] Require conversation resolution before merge.
- [ ] Require the agreed CI checks with strict/up-to-date behavior. Confirm actual check context and reporting GitHub App from a real run receipt before configuration; do not guess from workflow source.
- [ ] Restrict bypass actors and record exceptions/rationale; prefer no routine bypass.
- [ ] Disallow force pushes and branch deletion for protected `main`, except a specifically reviewed recovery process.
- [ ] Review merge method, linear-history and signed-commit requirements as explicit policy; record actual values and rationale.
- [ ] Review tag rules separately. No tag/release creation is authorized here.

### Source-defined check inventory

These workflow source names and matrix dimensions describe the repository at the time of the v0.1.0 release-candidate preparation (2026-11-15). They are not verified GitHub contexts, required checks or settings. Confirm exact expanded contexts and the emitting App from actual run receipts, and re-enumerate against the exact candidate SHA before relying on them.

| Workflow | Source-defined jobs / dimensions | Proposed use (not configured/verified) |
|---|---|---|
| `.github/workflows/ci.yml` | `go (ubuntu-latest)`, `go (windows-latest)`, `go race`, `fixtures are up to date`, `layout lint`, `rust (ubuntu-latest)`, `rust (windows-latest)`, `rust 1.88 check`, `ts (ubuntu-latest, node 20)`, `ts (ubuntu-latest, node 22)`, `ts (windows-latest, node 20)`, `ts (windows-latest, node 22)`, `interop matrix (3x3)`, `credential transfer matrix (3x3)`, `rotation interop matrix (3x3)`, `mcp compat e2e (official clients x official servers)`, `Go CLI binary process qualification`, `Go CLI native Darwin process qualification`, `Go CLI portable artifact qualification`, `consumer ts (node 20)`, `consumer ts (node 22)`, `consumer rust 1.88`, `consumer go 1.25` | Require every applicable job and matrix leg; verify exact contexts and identity. |
| `.github/workflows/coverage.yml` | `go coverage`, `rust coverage`, `ts coverage` | Require all three jobs to complete; source sets no coverage thresholds. |
| `.github/workflows/fuzz.yml` | `go fuzz (bounded campaign)` | Require bounded campaign completion; this is not proof of no defects. |
| `.github/workflows/license.yml` | `go licences`, `rust licences`, `ts licences`, `dual-licence manifests` | Require all four checks. |
| `.github/workflows/vulnerabilities.yml` | `Go govulncheck (module)`, `Go govulncheck (package)`, `Go govulncheck (symbol)`, `Rust advisories`, `npm audit (ts)`, `npm audit (tools/license/tooling)` | Require all six scans; no skips; clean completion. Distinguish findings from setup/database/infrastructure failures. |
| `.github/workflows/spec-fixtures.yml` | `generate and upload fixtures`, `generate and upload candidate fixtures` | Triggered by `push` and `workflow_dispatch`, not by `pull_request`; its PR-head result comes from the branch push. Do not treat it as a reliable required PR check; `fixtures are up to date` in `ci.yml` is the PR-triggered freshness check. |

Workflow run results are historical receipts for the commit they ran on, not evidence that a check is required in branch protection and not evidence about repository settings. As proposed policy, require every standing PR-triggered job listed above, including all matrix legs, completion of coverage jobs (without thresholds), bounded fuzz completion, and all six vulnerability scans with no skips and clean completion. This remains an explicit maintainer policy decision and is unverified against actual repository settings.

### Merge queue and strict status behavior

Current `ci.yml`, `coverage.yml`, `fuzz.yml`, `license.yml`, and `vulnerabilities.yml` declare `push` to `main` and `pull_request`; no `merge_group` trigger is present. `spec-fixtures.yml` declares `push` and `workflow_dispatch`. If a merge queue is proposed, determine which workflows must run on queue candidates and separately review trigger wiring. Do not require a status the merge-queue event cannot produce or weaken strict up-to-date checks to work around missing wiring. This checklist authorizes no workflow change.

## Private vulnerability reporting

`SECURITY.md` directs reporters to GitHub's Security tab and “Report a vulnerability.” That text is policy/documentation, **not evidence** that private vulnerability reporting (PVR) is enabled.

- [ ] Maintainer verifies PVR in the public repository Security UI or with a maintainer-supplied read-only receipt; record enabled, disabled, or unavailable.
- [ ] If enabling is separately authorized, record the effective setting and read-only evidence; do not infer enablement from policy text.
- [ ] Verify maintainer-owned handling process and contacts through approved private procedures. Do not put private reports, personal data, secrets, tokens, or sensitive machine paths here or in public issues.
- [ ] If the setting cannot be independently viewed, record `UNVERIFIED` and the evidence gap. Do not test with a vulnerability report or probe accounts/settings.

## Artifact attestations — release-candidate workflow

The owner approved (2026-11-15) an artifact-only release-candidate workflow, `.github/workflows/release-candidate.yml`, started manually for one exact commit. It is the only workflow that may hold `id-token: write` and `attestations: write`, and only on its attestation job; it uses the single approved third-party action `actions/attest-build-provenance`, pinned by commit. Every other workflow keeps repository `contents: read`. Until that workflow is merged and a run has been observed, generation and verification of attestations stay unobserved, and none of this establishes settings or artifact trust.

Attestations are generated only for the exact final candidate artifacts. Verification subject and digest must match the exact consumed bytes and the repository, workflow, ref and full-SHA claims; a per-file SHA-256 is distinct from an upload digest and from an attestation. Record artifact IDs, inventories, platforms, toolchains, verification evidence and exact-artifact consumer results as in [`release-notes-template.md`](release-notes-template.md). The release candidate publishes nothing.

## Publication and registry ownership — deferred

Registry publisher ownership and trusted-publisher decisions are **DEFERRED**. They are not an artifact-only RC prerequisite and are not authorized here. The owner-ordered Rust and TypeScript package versions are 0.1.0; publication flags remain. RC scope is artifact-only, with no registry publication. No publication, registry, token, account, trusted-publisher, or configuration steps are authorized. Do not create/configure credentials or publishers, make further version changes, publish, tag, create a GitHub Release, or announce a release. Future publication needs separate explicit owner authorization and review.

### Trusted Publishing and the 0.1.0 release

This is an owner checklist of values to enter, not verified settings. The document's top-level **UNVERIFIED** disclaimer applies: record actual values and approved read-only evidence; do not infer that any control is enabled.

- [ ] Configure Registry Trusted Publishing for **both** npmjs.com and crates.io with repository `PHPCraftdream/mcp-jack`, workflow file `publish.yml`, and environment `release`.
- [ ] npm: create the package first with the placeholder bootstrap `mcp-jack@0.0.0`. Confirm the packed `package.json` `repository.url` exactly matches the GitHub repository: `git+https://github.com/PHPCraftdream/mcp-jack.git` (package directory `ts`).
- [ ] crates.io: create the crate first with the same placeholder bootstrap. The publishing job's `environment:` must match the environment configured on crates.io.
- [ ] GitHub: under repo Settings → Environments, create `release` and require the owner as reviewer. The `publish-npm` and `publish-crates` jobs in `publish.yml` then wait for manual approval.
- [ ] Dispatch inputs for `publish.yml`: `sha` is the full 40-character SHA and an ancestor of `main`; `rc_run_id` is the run ID of the successful `release-candidate` run for that SHA; `version` must equal the version in `ts/package.json`, `rust/Cargo.toml`, and the artifact names; `registries` is `npm`, `crates`, or `both`.
- [ ] Order: run `release-candidate` on the final release SHA first and let it fully succeed; then dispatch `publish.yml` from `main`.
- [ ] Partial failure: before re-dispatching, check on each registry which version is actually visible — a publish step can succeed while its later visibility check fails. A re-dispatch for a registry that already has the version fails closed; re-dispatch only the registry that lacks the version, with `registries` scoped to it, and never `both` unless neither registry succeeded.

Machine facts from the workflow and registry protocols (not evidence that settings are configured):

- npm requires npm >= 11.5.1 / Node >= 22.14. The workflow uses Node 24 and refuses older npm; use GitHub-hosted runners, `id-token: write` on publish jobs, and no `NODE_AUTH_TOKEN`/`NPM_TOKEN`.
- crates.io RFC 3691: `id-token: write`; `rust-lang/crates-io-auth-action` exchanges the OIDC token for a 30-minute token. The workflow pins `v1.0.6` by full commit SHA because upstream has no `v1` tag.

Unverified assumptions to resolve from the first real run:

- [ ] `npm publish <tarball> --provenance` works on a pre-packed tarball. If not, fallback is publishing from a checked-out SHA after proving pack equality.
- [ ] Provenance is automatic for a public package from a public repository; `--provenance` is passed explicitly for determinism.
- [ ] Exact npm version shipped with Node 24 on runners; the workflow checks it at run time.
- [ ] crates.io sparse-index propagation delay; the visibility check retries.
- [ ] `cargo package` byte-identity across runs; the workflow compares member lists and member bytes of the attested RC crate and of the crate `cargo package` produces from the checked-out SHA instead. It does not compare archive framing or the separate repackage that `cargo publish` uploads.
- [ ] crates.io Trusted Publishing requires the crate to already exist; the bootstrap above is intended to satisfy this.

## Maintainer evidence record

Use approved read-only evidence only. If an item cannot be verified, leave it unchecked and mark `UNVERIFIED`; do not infer values from workflow source or successful CI.

| Control | Proposed state / verified actual value | Evidence URL or approved receipt | Reviewer/owner | Review date (UTC) | Policy decision/open gap |
|---|---|---|---|---|---|
| `main` PR reviews and independent approvals |  |  |  |  |  |
| Stale review dismissal |  |  |  |  |  |
| Most recent push approval / author separation |  |  |  |  |  |
| Required status contexts and emitting App identities |  |  |  |  |  |
| Strict up-to-date requirement |  |  |  |  |  |
| Merge queue compatibility, if applicable |  |  |  |  |  |
| Bypass/admin policy |  |  |  |  |  |
| Force-push and branch-deletion policy |  |  |  |  |  |
| Private vulnerability reporting |  |  |  |  |  |
| Artifact attestation generation/verification |  |  |  |  |  |
| Registry publisher/trusted-publisher ownership | `DEFERRED — not an RC prerequisite` |  |  |  |  |

No repository setting is asserted as verified here. No settings query/change, account access, test, or release action is performed or claimed.

## Historical receipt — foundation, 2026-11-09

All six post-merge workflows succeeded on the foundation merge SHA `c98f7eb0dac9ad22f11f712a80a3fe9c537426ee` (CI `42710339786`, vulnerabilities `42710340244`, licenses `42710339825`, coverage `42710340223`, Go fuzz `42710339895`, fixtures `42710339912`). These are foundation receipts only: they are not evidence about the v0.1.0 candidate, repository settings or any release-candidate acceptance. Recheck the exact future candidate before reliance.
