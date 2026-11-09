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
