# Checkpoint — Restart and minimal rotation candidates, 2026-11-09

## Session summary

Task #52 covers two non-normative, unapproved design candidates, not SDK implementation. Initial executor bu1k1u3rt and configuration-lifecycle correction bm59jn145 are terminal. Parent read both full final documents and reports. The restart candidate now fixes Wcurrent for the nonce-cache/boot-lease lifetime; changes require close/drain and a newly proven floor/lease/map. The rotation candidate persists immutable response_window_seconds in client/server binding snapshots and fails closed on missing/mismatched values, including restore and ACK reconciliation. Concrete replay and retired-trust revival counterexamples and distinguishing vectors are documented. Reviewer found a duplicated clock-latch sentence; parent removed it while retaining the original latch rule. Two documents were copied into a separate integration worktree based on delivered foundation c98f7eb, with factual foundation-status corrections. No local tests/builds or normative/runtime changes.

## Open owner decisions

- D2: conditional timestamp floor with strong all-lifetime clock/history and owner/drain premises, versus a separately specified durable-nonce/epoch alternative. NTP or a fresh clock reading does not prove the timestamp-floor premise; unknown history must fail closed.
- D3/R1: canonical min1 record, schedule, immutable per-binding window, bounded retained history and trusted-clock limits.
- D3/R2: authenticated read-only tool and explicit caller refresh recommendation versus separately opted-in connect/periodic refresh. No automatic ambiguous-effect retry.
- R3: application/server CAS/ACK/unknown fencing, chosen durability, restore/rollback and OOB compromise/missed-announcement recovery limits.
- Compatibility/error-order and exact-byte fixture/SDK/interop gates remain future acceptance work.

## Continuation

Deliver these documents only as candidate design. Exact-head CI and green merge do not approve the mechanisms. Task #52 remains in progress until genuine owner decisions; Task #57 normative candidate/fixtures and SDK tasks remain blocked. Preserve product versions/publication flags. Parent must verify post-merge ancestry/CI and preserve source differences before deleting task-owned worktrees. A shared Rush watchdog was removed once all executions became terminal; babysit remains separate.
