# Checkpoint — 2026-11-09 release foundations

## Session summary

Scope reduction was merged in PR #14 and the design-only server-key rotation proposal in PR #15. The baseline main commit is `e681f07d20e1ac452a60b54ab656101592d9d8f3`; the supplied release-plan commit is `777771fed0a53011898e55d959b6f8576675fd89`. The owner authorized implementation using isolated parallel worktrees, parent review, GitHub CI, green merges, and cleanup. Release tasks #51–#87 are registered as leaves with dependencies. The foundations integration branch is `release-foundations-1109`. Versioning policy and threat model were reviewed and copied into integration. The vulnerability workflow and its documentation were also reviewed and copied; executable acceptance remains pending. MCP research now distinguishes stdio E2E from direct official HTTP-client transport coverage; the parent reviewed the final correction and independently checked the tagged client-source branches. No foundation commit, push, PR, or CI result is claimed by this checkpoint. The owner requested tracking checkpoints and including them in commits; the integration change removes their ignore rule. Committed checkpoints must contain neither secrets nor machine-private paths.

## Active goal

No /goal condition is set. The TaskList governs implementation.

## Decisions

- Include the Go CLI, gateway, and stdio bridge.
- Do not change product/dependency versions or MSRV; preserve npm `private: true` and Rust `publish = false`.
- RC verification uses CI artifacts only. No tags, registry publication, GitHub Release, or announcement are authorized.
- Final wire freeze follows MCP E2E and independent security review, not initial specification drafting.
- Local builds, tests, installs, and vulnerability scans remain prohibited for this foundation work; acceptance runs in GitHub CI.

## In-progress work

- #54: versioning policy; reviewed documentation, pending integration and cleanup.
- #55: MCP transport investigation; same-session review follow-up `release-mcp-1109`, background executor `bfj2ahy88` completed. Parent reviewed the full document and report, verified tagged Go/TypeScript/Rust HTTP-client behavior, and copied the document into integration. No Rush executor remains live; its liveness watchdog was removed.
- #56: threat model; reviewed documentation with updated owner decisions, pending integration and cleanup.
- #74: vulnerability CI; six scans defined (three Go levels, Rust advisories, two npm roots), no execution receipt yet. The review FAIL denotes missing executable acceptance, not a verified static workflow defect.
- #88: remove checkpoint ignore rule and include checkpoints in commits; integration change prepared, not yet delivered.

## Open decisions and blockers

- D-2 restart replay protection is unresolved. Rejecting only `ts < server_start`, or only equality as well, misses previously accepted future-dated requests. Do not implement that comparison as proven restart protection.
- D-3 minimal server rotation and delivery/refresh/persistence semantics remain unresolved. The sr1 document is not implementation or normative approval.
- MCP bounded profile and isolated official-SDK fixture toolchains remain recommendations, not accepted compatibility guarantees.
- Final publication task #87 requires new explicit owner permission.

## Continuation

All four foundation workers have finished and their deliverables were reviewed and copied into integration. Review all additions and the staged diff before committing. Push the authorized foundation PR and immediately start a background `gh pr checks --watch -i 60` watcher. Investigate and fix actual failures without masking status or weakening scan scope. Merge only the verified green head, verify post-merge CI and main ancestry, then remove only integrated task-owned branches and worktrees. Do not mark foundation tasks completed before their delivery and cleanup criteria are met.
