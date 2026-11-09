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

## Later CI evidence and approved correction

Foundation commit `efc07106783d07d7c01fceacfcb8f1193d5d2b8f` was pushed in PR #16. The original CI watcher completed with failures. Go module scanning reported 66 standard-library advisories on Go 1.22.12; symbol scanning found reachable HTTP/X.509 paths, including GO-2026-6809 (fixed in Go 1.26.10). These are actual findings, not clean results. GitHub also returned internal server errors that prevented several jobs from being scheduled. Infrastructure retries for fixtures, fuzz, licenses, main CI and coverage all completed successfully on that original head. The vulnerability workflow still requires a new-head run with every scan executed.

The owner explicitly approved a separate patched Go security-CI toolchain and deployment guidance, preserving go.mod 1.22, compatibility checks, all SDK/dependency versions and publication restrictions. Parent verified Go 1.26.10 release provenance at go.dev. Go 1.22 compatibility is not a security endorsement, and scanning a newer toolchain does not fix deployments built using the old one. No advisory ignore, threshold reduction or blanket risk acceptance is authorized.

Vulnerability session `release-vuln-1109` was resumed for this two-file correction; background executor `b0c3pvbx7` then completed. Parent reviewed its report and actual two-file changes and copied them into integration. The security lane now selects Go 1.26.10 and govulncheck v1.3.0, with explicit Go version output; scanner coverage and direct failure propagation remain unchanged. Parent independently verified the tagged scanner manifest (Go 1.25 minimum, x/tools v0.44.0). Post-change executable acceptance is still pending, which is the reason for the worker review's FAIL verdict. No Rush executor remains live, and its watchdog was removed. Parent separately reconciled versioning policy and this checkpoint.

## Later parallel-package review and owner decisions

- Packaging Task #79 source and follow-up completed. Parent reviewed all six files, corrected RC task references to consolidated #96, and copied the bundle into `release-packaging-integration-1109` without staging or committing. Future RC receipts do not gate foundation policy acceptance.
- CLI Task #89 initial executor `bc1hy3hze` and oracle-fix follow-up `bblbqf40s` completed. Parent read all 22 added files, verified cancellation-vs-timeout diagnostics and causal RawConn would-block/close controls, then copied the bundle into `release-cli-integration-1109`. Go formatting succeeded; no build/test executed, and no CLI commit or runtime acceptance is claimed.
- The owner explicitly accepted the healthy, local, bounded-latency filesystem deployment assumption for CLI/gateway. There is no enforced hard disk/kernel-stall deadline. Preserve state ownership until mutation completes, report unknown enrollment effects honestly and never automatically retry. This is a supported-deployment limitation, not implementation of interruptible persistence or stronger durability.
- Design Task #52 initial run `bu1k1u3rt` completed; parent read both candidate documents. Same-session follow-up `bm59jn145` addresses two verified configuration-lifecycle gaps: raising a live request freshness window can revive a purged nonce, and recalculating rotation overlap with a larger window can revive retired trust. D2/D3 mechanisms remain unapproved.
- Rust security migration remains executor `bpezzdjde`, session `release-rust-security-1109`, under Task #54. Do not infer completion without notification or supported terminal evidence.

## TaskList consolidation requested by the owner

The owner explicitly requested merging related TaskList entries, not only assigning multiple leaves to an executor. The current list contains 17 unfinished work packages plus completed decision #51. Historical IDs in earlier worker prompts and reports are not new tasks to recreate.

| Current task | Previous task IDs | Package |
|---|---|---|
| #52 | #52, #53 | Candidate restart/rotation design; session release-security-design-1109, executor bu1k1u3rt |
| #54 | #54, #55, #56, #74, #88 | Foundations, advisory CI, security remediation and tracked checkpoints; PR #16; Rust fix session release-rust-security-1109, executor bpezzdjde |
| #57 | #57, #58 | Candidate spec, independent fixtures and transition/stale-doc reconciliation |
| #59 | #59 | Go SDK implementation and regressions |
| #60 | #60, #70 | Rust SDK implementation and bounded fuzzing |
| #61 | #61, #71 | TypeScript SDK implementation and property/mutation tests |
| #62 | #62, #72 | 3×3 interop and differential fuzzing |
| #79 | #79, #80, #82 | Package metadata, changelog, notes and settings checklist; session release-packaging-1109; follow-up bgeft82ko completed, pending parent review |
| #89 | #63, #64, #65 | Go CLI, gateway and stdio bridge; session release-cli-1109, executor bc1hy3hze |
| #90 | #66, #67 | Admin/rotation commands and multiplatform binaries |
| #91 | #68, #69 | Official MCP examples, E2E and compatibility fixes |
| #92 | #73 | Independent security review and fixes |
| #93 | #84 | Final protocol freeze |
| #94 | #75, #76, #77, #78 | README, operator/API guides, docs readiness |
| #95 | #81, #83 | Artifact-only release workflow and read-only registry-name checks |
| #96 | #85, #86 | Artifact-only RC production, verification and fixes |
| #97 | #87 | Separate final publication permission and release |

Related acceptance criteria and executor references were preserved in the retained/replacement task descriptions. Dependencies were rebuilt without references to deleted entries; deletion does not imply completion. No executor was relaunched or cancelled for this consolidation. The owner separately approved affected Rust security dependency upgrades and necessary MSRV up to 1.88; that is not permission to change product versions or publish.

## Continuation

After reviewing the security correction, include this updated checkpoint in the next commit and push PR #16. Immediately start a background `gh pr checks --watch -i 60` watcher. Require all six advisory scans and all other workflows to execute successfully on the new exact head; partial runs, infrastructure errors and old-head retries are not sufficient. Investigate and fix actual failures without masking status or weakening scan scope. Merge only the verified green head, verify post-merge CI and main ancestry, then remove only integrated task-owned branches and worktrees. Do not mark foundation tasks completed before their delivery and cleanup criteria are met.

## Rust security integration follow-up

Rust executor `bpezzdjde` and same-session correction `bg3ycodt6` are terminal (`end_turn`, supported `why`: done, no batch roots). Parent reviewed the package and corrected the material typed-error regression: simultaneous cleanup failure preserves Streaming/Unauthenticated/Protocol variants and payloads; string-bearing errors retain combined diagnostics. Typed variants cannot carry a secondary cleanup diagnostic without an API change; this limitation is explicit. Resolver mapper coverage is simulated unit coverage, not genuine builder-failure injection. Full test execution remains a CI gate.

Parent copied nine reviewed files into this integration worktree, corrected the worker's inaccurate claim that Cargo.lock was ignored (it is tracked), and successfully ran Rust 1.88.0 Cargo metadata resolution without builds/tests. Cargo resolved Hickory resolver/net/proto 0.26.1, time 0.3.47 and time-core 0.1.8, preserving unrelated package versions. Necessary new transitive and platform dependencies were reviewed in the lock/metadata diff; no fabricated checksums or advisory exceptions. Cargo formatting and whitespace check passed. Rust liveness watchdog was removed after completion. Design executor `bm59jn145` remains last-confirmed live; no D2/D3 approval is implied. New-head CI and merge remain outstanding.

### CI on 0081128 and immediate lint correction

All six security scans passed in workflow 42708406201 on exact head 00811283b91ea82d2eed6fe88fd6f362ba823b64. License 42708406500, coverage 42708406287, bounded Go fuzz 42708406710 and fixture workflow 42708396069 also passed. Main CI 42708406176 failed on both Linux and Windows at strict clippy: `chunks_exact_to_as_chunks` in the existing interop hex decoder, newly applicable with MSRV 1.88. Rust MSRV and fresh packaged consumer passed, but interop/credential matrices were skipped because their prerequisite jobs failed; these are not passing matrices.

Parent corrected only the decoder's chunk iteration to `as_chunks::<2>().0.iter()`. The existing exact-64-byte guard guarantees an empty remainder and the same 32 pairs/error order; `as_chunks` is available at the approved Rust 1.88 floor. No lint suppression or check-scope reduction. A new exact-head full CI run is required before merge.
