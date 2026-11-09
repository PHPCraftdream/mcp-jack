# Checkpoint — Go CLI integration, 2026-11-09

## Session summary

Task #89 implements the approved Go keygen/bootstrap/enroll CLI, bounded loopback gateway with private Unix-socket upstream, and legacy MCP stdio bridge. Source executor and same-session regression-oracle correction are terminal. Parent reviewed all 22 files, including cancellation versus timeout diagnostics, actual would-block/close controls and positive readiness controls. The integration copy was formatted with gofmt; no local builds or tests ran. Foundation PR #16 is merged at c98f7eb0dac9ad22f11f712a80a3fe9c537426ee after 32 successful PR checks. This branch fast-forwarded to that baseline without losing its CLI additions. Foundation post-merge CI remains under a separate watcher. CLI runtime acceptance is pending GitHub CI.

## Scope and decisions

- Product versions and publication flags remain unchanged. No publication, tag or release is authorized.
- Operator explicitly accepted healthy local bounded-latency filesystem deployment; disk/kernel stalls have no enforced hard deadline. Mutation ownership remains held until completion, uncertain effects are not treated as rollback, and automatic retries are forbidden.
- Unix private-file and Unix-socket profile only; unsupported private operations fail closed on other platforms. Process bridge IO requires interruptible owned Unix pipes. No Windows functional-security or universal MCP conformance claim.
- Bridge targets protocol version 2025-11-25, terminal JSON, no sessions/SSE/automatic reinitialization or replay. GET refusal and upstream SSE refusal remain distinct.
- Admin/rotation commands, multiplatform artifact acceptance, official-SDK compatibility and restart/rotation implementation remain separate tasks.

## Acceptance and continuation

Run full exact-head GitHub CI, including added package and process tests, race checks, security scans, licenses and existing interoperability matrices. Fix actual failures in the same cycle without weakening tests. Merge only the verified green head, verify post-merge results and main ancestry, then remove only byte-verified integrated task-owned worktrees and branches. The reviewed source worktree differs from the integration copy by parent formatting and documented owner-decision text; do not infer byte equality without checking. Task #89 remains in progress until delivery and cleanup.

## First CLI CI and close-oracle correction

On head 8c769b36bdb862dca9136b73ad331915d395f73b, normal/race/coverage Linux runs failed both raw-close cases because their oracle required os.ErrClosed. The logs did not print the actual raw error value. All six advisory scans and license checks passed; interop matrices were skipped, not accepted. Same-session executor bebu75594 completed, supported why confirms done/end_turn/no roots. Parent reviewed its report and actual test/document edits. No production changes were needed.

RawConn returns internal poll errors directly, unlike public File.Read/Write's wrapErr conversion. Parent independently fetched the Go 1.22.12 tagged rawconn/file/poll source. The revised oracle derives an opaque close reference from a separate prepared pipe through public APIs, rejects syscall/deadline/EOF/invalid classes and callback execution on that closed reference, and compares the active error via errors.Is after actual EAGAIN. Positive peer controls remain; separate post-close public File IO must match os.ErrClosed with zero bytes. No parked-goroutine or in-flight public FileIO claim. Parent formatting and whitespace check passed; no local build/test ran. Full new-head CI remains required.

Foundation Task #54 is now complete: PR16 merge c98f7eb, all six post-merge workflows successful, primary main ancestry verified, completed foundation worktrees/local branches and remote foundation branch removed after byte-verified source preservation. CLI delivery and cleanup remain pending.

## Post-merge backpressure correction — 2026-11-10

PR17 head9b6778a passed all32 checks and merged as40e9076. Post-merge race CI then failed the owned-output fixture before its write-attempt observation; the same failure repeated after packaging d3401c3 and design07aec81 merges, including both blocked and broken subcases. Other five workflows on each merge succeeded. These are real failed acceptance receipts, not clean post-merge results. No diagnostic established the prior Run error, so expensive pre-output processing exhausting the 2000ms budget remains a hypothesis rather than proven runtime cause.

Same-session executor bjfc7wf1b completed; supported why confirms done/end_turn/no batch roots. Parent read the complete revised fixture and documentation diff, then copied only the reviewed test/document changes into release-cli-backpressure-1110 based on current main07aec81, preserving parent Go1.22 source links. The test uses a small signed response, actual pipe saturation to one-byte EAGAIN, exact-response syscall observations, separate EPIPE/closed verdicts, positive peer-drain/EOF/no-extra-output control, exact lifecycle counts, and immutable Run diagnostics published after join. Production and call budget remain unchanged. Parent gofmt and whitespace checks passed; no local builds/tests ran.

Parent added five focused race repetitions in the existing GitHub CI race job, in addition to the complete race suite, to obtain repeated runtime evidence without local execution. New exact-head full CI and post-merge CI remain required. CLI watchdog removed after terminal; no Rush worker is live. Tasks52/79/89 remain open:52 independently needs genuine D2/D3 owner decisions; all three source/integration cleanups await corrected main acceptance. Existing primary historical checkpoints became visible as untracked after foundation removed their ignore rule; they were preserved, not deleted or silently staged.

## Admission-race correction — 2026-11-10

PR20 passed all32 checks including five focused race repetitions and merged as df23521. Post-merge main CI and race repetitions passed, but coverage42717913146 failed broken-output before initialized HTTP with exact diagnostics: code1/protocol stderr, calls[1,0,0], no terminal write and joined cleanup. Other five workflows passed. This new evidence supersedes large-response workload as an explanation for that occurrence; the log does not identify which branch ran.

Source inspection verified two premature protocol-rejection branches when initialized occupies pending while initialize Write/completion remains outstanding and tools/list is consumed. Same-session executor bqtaie8xg completed; parent read the full changed production loop, all added tests, report and docs diff. New admission disables ordinary receive while pending is full, handles completion only in its own select arm, and routes EOF/framing/read errors/malformed/cancellation to a separate unbuffered terminal channel. One inflight/one pending/one bounded reader-held frame and existing timer/cancellation/join ownership remain. A control behind a reader-held ordinary frame cannot bypass it; that limit is explicit.

Parent copied reviewed production/test/docs changes into release-cli-admission-1110 on df23521, preserved parent Go1.22 references, and ran only gofmt/whitespace checks, not local tests/builds. Regressions hold initialize Write after peer observation; an internal invocation-local observer asserts the actual select candidate is nil with busy/pending state, while a separate default Run case checks exact ordered signed HTTP bodies/output and cleanup. Pending EOF/error/cancellation controls remain. Parent extended five focused race repetitions to admission cases and added five coverage-instrumented repetitions alongside complete suites. No passing runtime result is yet claimed for this fix.

All Rush workers are terminal; admission watchdog removed. New exact-head/full/post-merge CI remains required before cleanup. D2/D3 are still unapproved, Task52 remains open independently of delivery of candidate documents. Source archives made before the latest worker edits are historical snapshots; preserve a new byte-verified CLI source snapshot before deletion.
