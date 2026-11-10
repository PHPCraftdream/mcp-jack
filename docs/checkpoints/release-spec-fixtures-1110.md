# Candidate specification and fixtures — parent takeover

## Scope and status

Task #57 prepares candidate durable-nonce and overlapping server-key rotation contracts, independent fixture sources, and an explicit transition boundary. Current v1 signing bytes, current conformance vectors, SDKs, manifests and publication settings remain unchanged. Final protocol freeze and runtime/backend acceptance remain later gates.

## Executor disposition

The owner explicitly requested stopping the delegated executor and completing the work directly. The parent stopped executor bx3ppm1r7, cancelled the session's remaining wake schedule, confirmed no jobs remain, and removed its liveness watchdog. The interrupted output envelope is empty, not a successful completion report. No replacement agent was launched. The parent continues in the same isolated worktree.

## Parent corrections before initial CI

- Removed repeated/corrupted persistence prose and stale PR #22 pending-workflow statements.
- Fixed the fixture test's doubled spec directory, missing new-public-key argument, missing sequence tombstone expectations, missing tie-selection event, and noncanonical-base64 mutation.
- Replaced a test-only duplicate JSON parser oracle with the actual candidate response parser.
- Preserved UTF-8 bytes until ASCII record validation; rejected fractional/exponent head ordinals before numeric coercion.
- Included retained keys in extension reuse checks.
- Wired ClockGuard into refresh authentication/payload, pre-CAS and final gates; uncertain clock writes fence before trust CAS.
- Replaced a constant-only commit-count assertion with an assertion against executed results.
- Counted targeted expiry deletion within the 128-row transaction budget and distinguished uncertain rollback-latch writes from confirmed clock fences, with direct regressions.

Initial source-only commit: 16e0c7b; draft PR #23. The first CI watcher is bv82v2j2k. These are in-flight identifiers, not passing receipts.
- Preserved unused duplicate modules outside the integrated source set rather than silently discarding them.

## Verification and continuation

No local build, test, generator, scanner, Node or installation command was run. Initial candidate generation, deterministic checking, independent verification and tests must execute in GitHub CI. The first source-only CI run is not final acceptance. Download its exact generated artifacts into a new isolated directory, inspect them, integrate generated fixture bytes and the generated case index, then enforce a standing check of committed bytes before regeneration. Preserve all existing current-v1 gates.

Review all remaining changes and actual CI failures before merge. Merge only an exact green head, verify post-merge workflows and main ancestry, preserve source data, then remove only completed task-owned worktree and branches. Task #57 remains in progress until those gates pass.

The pre-existing untracked nested directory in the primary checkout has unknown provenance and is not included or deleted. The original release-plan worktree and historical untracked checkpoints remain untouched. The local checkpoint commit ba3082e was included by a fast-forward of this feature worktree to main, preserving main's future fast-forward path without rewriting history.
