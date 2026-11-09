# Release repository-settings checklist

**Status: UNVERIFIED.** This is a maintainer checklist, not evidence of repository settings or an instruction to change them. No read-only settings receipt is recorded here. Do not infer that a control is enabled. Verification requires a maintainer to record the actual value and approved read-only evidence. This document does not configure settings, access accounts, handle credentials, enable publication, or authorize release actions.

**Foundation boundary:** PR #16 merged as `c98f7eb0dac9ad22f11f712a80a3fe9c537426ee`; foundation policy is delivered. Task **#54** post-merge verification and cleanup are complete. Repository-settings evidence and future Task **#96** RC production/verification are not prerequisites for foundation policy acceptance. No circular dependency is intended.

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

### Merged-foundation source-defined check inventory

These workflow source names and matrix dimensions describe the merged foundation baseline, not verified GitHub contexts, required checks, or settings. Confirm exact expanded contexts and emitting App from actual receipts. Parent-reported PR checks succeeded on tested PR head `8ee8858ec5d9802d02da1d9086e00be61e3e1d9b`; PR #16 merged at `c98f7eb0dac9ad22f11f712a80a3fe9c537426ee`. **Historical evidence recorded 2026-11-09.** The successful PR-head checks do not prove post-merge success or settings configuration. Attempts were not supplied.

| Workflow | Merged-foundation source-defined jobs/dimensions | Parent-reported PR-head evidence | Proposed use (not configured/verified) |
|---|---|---|---|
| `.github/workflows/ci.yml` | `go (ubuntu-latest)`, `go (windows-latest)`, `go race`, `fixtures are up to date`, `rust (ubuntu-latest)`, `rust (windows-latest)`, `rust 1.88 check`, `ts (ubuntu-latest, node 20)`, `ts (ubuntu-latest, node 22)`, `ts (windows-latest, node 20)`, `ts (windows-latest, node 22)`, `interop matrix (3x3)`, `credential transfer matrix (3x3)`, `consumer ts (node 20)`, `consumer ts (node 22)`, `consumer rust 1.88`, `consumer go 1.22` | Main CI run `42709461708` SUCCESS; included both 3×3 matrices, Rust 1.88 MSRV, fresh consumer | Require every applicable job and matrix leg; verify exact contexts and identity. |
| `.github/workflows/coverage.yml` | `go coverage`, `rust coverage`, `ts coverage` | Run `42709461764` SUCCESS | Require all three jobs to complete; source sets no coverage thresholds. |
| `.github/workflows/fuzz.yml` | `go fuzz (bounded campaign)` | Run `42709461672` SUCCESS | Require bounded campaign completion; this is not proof of no defects. |
| `.github/workflows/license.yml` | `go licences`, `rust licences`, `ts licences`, `dual-licence manifests` | Run `42709462005` SUCCESS | Require all four checks. |
| `.github/workflows/vulnerabilities.yml` | `Go govulncheck (module)`, `Go govulncheck (package)`, `Go govulncheck (symbol)`, `Rust advisories`, `npm audit (ts)`, `npm audit (tools/license/tooling)` | Run `42709461656` SUCCESS; all six scans | Require all six scans; no skips; clean completion. Distinguish findings from setup/database/infrastructure failures. |
| `.github/workflows/spec-fixtures.yml` | `generate and upload fixtures` | Run `42709452435` SUCCESS | Not a PR-triggered workflow (`push` and `workflow_dispatch`); do not treat as a reliable required PR check. Foundation CI's `fixtures are up to date` was the PR-triggered freshness candidate. |

All 32 PR checks succeeded on the same tested PR head `8ee8858ec5d9802d02da1d9086e00be61e3e1d9b`. Workflow run IDs above are historical exact-head receipts, not evidence that checks are required in branch protection, and not post-merge receipts. The foundation source-defined inventory and parent-reported success do not establish reporting App identity. Do not add guessed contexts. Successful PR-head evidence is separate from the `c98f7...` merge SHA; post-merge success is recorded in the parent integration receipt below.

Before using this merged-foundation inventory for required-check or RC reliance at a future Task #96 SHA, re-enumerate actual workflow contexts, matrix legs, and toolchains against that exact candidate SHA after any changes; do not assume these baseline labels or dimensions still apply. As proposed policy, require every standing PR-triggered job listed above, including all matrix legs, completion of coverage jobs (without thresholds), bounded fuzz completion (which does not guarantee no defects), and all six vulnerability scans with no skips and clean completion. This remains an explicit maintainer policy decision and is unverified against actual repository settings.

### Merge queue and strict status behavior

Current `ci.yml`, `coverage.yml`, `fuzz.yml`, `license.yml`, and `vulnerabilities.yml` declare `push` to `main` and `pull_request`; no `merge_group` trigger is present. `spec-fixtures.yml` declares `push` and `workflow_dispatch`. If a merge queue is proposed, determine which workflows must run on queue candidates and separately review trigger wiring. Do not require a status the merge-queue event cannot produce or weaken strict up-to-date checks to work around missing wiring. This checklist authorizes no workflow change.

## Private vulnerability reporting

`SECURITY.md` directs reporters to GitHub's Security tab and “Report a vulnerability.” That text is policy/documentation, **not evidence** that private vulnerability reporting (PVR) is enabled.

- [ ] Maintainer verifies PVR in the public repository Security UI or with a maintainer-supplied read-only receipt; record enabled, disabled, or unavailable.
- [ ] If enabling is separately authorized, record the effective setting and read-only evidence; do not infer enablement from policy text.
- [ ] Verify maintainer-owned handling process and contacts through approved private procedures. Do not put private reports, personal data, secrets, tokens, or sensitive machine paths here or in public issues.
- [ ] If the setting cannot be independently viewed, record `UNVERIFIED` and the evidence gap. Do not test with a vulnerability report or probe accounts/settings.

## Artifact attestations — future workflow work, not current capability

Current workflows declare repository `contents: read`. Consumer-package lanes upload SDK packages and inventories; other workflows may produce diagnostic, coverage, fuzz, or fixture artifacts. No current workflow defines release-candidate binary, per-file RC checksum, or attestation generation/verification jobs. These facts establish neither settings nor artifact trust.

Future separately approved work should generate attestations only for exact final candidate artifacts, with narrowly scoped minimum permissions; document OIDC issuer/audience/subject claims if used; verify subject and digest against exact consumed bytes and repository/workflow/ref/full-SHA claims; distinguish per-file SHA-256 from upload digest and attestation; and record artifact IDs, inventories, platforms, toolchains, verification evidence, and exact-artifact consumer results as in [`release-notes-template.md`](release-notes-template.md). Keep generation/verification proposed until implemented and observed.

## Publication and registry ownership — deferred

Registry publisher ownership and trusted-publisher decisions are **DEFERRED**. They are not an artifact-only RC prerequisite and are not authorized here. RC scope is artifact-only, with no registry publication. No publication, registry, token, account, trusted-publisher, or configuration steps are authorized. Do not create/configure credentials or publishers, change package flags/versions, publish, tag, create a GitHub Release, or announce a release. Future publication needs separate explicit owner authorization and review.

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

## Parent integration receipt — 2026-11-09

After the worker handoff, parent verified all six post-merge workflows SUCCESS on exact merge SHA `c98f7eb0dac9ad22f11f712a80a3fe9c537426ee`: CI `42710339786`, vulnerabilities `42710340244`, licenses `42710339825`, coverage `42710340223`, Go fuzz `42710339895`, and fixtures `42710339912`. Primary main was fast-forwarded and ancestry verified. Six completed foundation worktrees and their local branches, plus the remote foundation branch, were removed after byte-verified preservation of source deltas. Task #54 is complete. These are foundation receipts, not evidence for this packaging candidate or any RC/settings acceptance.

PR #17 remains an unmerged CLI candidate. Its initial head `8c769b36bdb862dca9136b73ad331915d395f73b` failed the Linux raw-close test oracle; correction head `9b6778acaa474a162426cc918b9c1708d61acacc` is undergoing full CI. No CLI delivery acceptance is claimed. Repository settings remain UNVERIFIED and future RC receipt fields remain unfilled. These dated facts supersede earlier handoff timing only; recheck the exact future candidate before reliance.
