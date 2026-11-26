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

### Placeholder bootstrap (one-time, token-based)

The `mcp-jack` 0.0.0 placeholder packages create the two registry entries, a prerequisite for configuring Trusted Publishing.

1. Create short-expiry, minimal-scope tokens with 2FA enabled on both accounts: an npm granular token limited to publishing the `mcp-jack` package (or the account's packages, as npm allows) and a crates.io token with the publish-new scope. Never commit them.
2. Create a GitHub environment `registry-bootstrap` on the repository, add required reviewers, and add the secrets `NPM_BOOTSTRAP_TOKEN` and `CARGO_BOOTSTRAP_TOKEN`.
3. Dispatch `.github/workflows/publish-placeholder.yml` from `main` with `confirm` = `publish-placeholder-0.0.0` — once with registry `npm`, once with registry `crates` (or `both` once).
4. Revoke both tokens and delete both secrets from the environment.
5. Configure Trusted Publishing on both registries for the real tokenless releases: repository `PHPCraftdream/mcp-jack`, workflow file `publish.yml`, environment `release` (both npm and crates.io).

**Established:** a published version number can never be reused or replaced. npm unpublish is time-limited; crates.io only supports yanking. npm Trusted Publishing requires npm >= 11.5.1, Node >= 22.14, and `id-token: write` in the publishing workflow. crates.io Trusted Publishing can only be created after the crate exists (a first manual publish).

**UNVERIFIED — owner to confirm:** exact token scopes currently offered by npm and any additional registry or account requirements.

After the Trusted Publishing hand-over succeeds, `tools/release/placeholder/**`, `publish-placeholder.yml`, and the `placeholder-dry-run` job in `ci.yml` are obsolete and may be removed in a later cleanup PR.

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
