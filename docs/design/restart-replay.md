# Design candidate: durable restart replay protection

**Status:** Task 52 design-only reconciliation. The supplied owner direction accepts **durable authenticated nonce reservation before dispatch** for D2 and approves the Go operator gateway's backend direction: investigate/select a vetted transaction library, not a custom journal. No particular library/version, dependency, API, error contract, migration procedure, platform guarantee, or operational policy is approved. See [durable nonce backend feasibility](durable-nonce-backend.md). This is not normative, implemented, or evidence of a durable guarantee.

**Baseline and provenance:** checked worktree HEAD is `3398e7bde8aef1ae4d76ac55e482a06265fb5922`. The user supplies parent-verified full-PR and green post-merge CI provenance for this baseline; it was not independently fetched here and is not evidence for these candidate changes. Earlier external design/release records are historical and do not override the supplied D2 choice.

**Scope:** design only. No source, normative specification, SDK/API, test, fixture, version, dependency, package metadata, publication setting, artifact, or tag changes. Preserve the owner-approved Go 1.25 target (manifest migration pending), Rust MSRV 1.88, TypeScript `private: true`, Rust `publish = false`, and artifact-only RC/no publication. D3 is separate: for successor records `R_i` and keys `K_i`, fixed publication time `P_i` determines `A_i=P_i+172800` seconds. The server uses `K_0` before the first activation, then the key `K_i` with the greatest activation `A_i <= now`, breaking equal-activation ties by greatest ordinal; `K_i`'s cutoff is `A_{i+1}`. Multiple future statements may be pending at their fixed times; multiple pending announcements are owner-directed. No rescheduling is implied. Codec/API and technical admission details remain candidate.

## 1. Source evidence: current behavior, not a remedy

| Source | Observed behavior and limit |
|---|---|
| [`spec/01-authentication.md`](../../spec/01-authentication.md) §§4, lines 66–90 | Inclusive freshness `abs(now-ts) <= window` (default 30 seconds), then signature, then atomic `(kid, nonce)` check/record, then dispatch. A validly signed refusal consumes the nonce. The spec does not provide persistence or restart recovery. |
| [`server/verify.go`](../../server/verify.go) lines 197–249; [`server/nonce.go`](../../server/nonce.go) lines 5–47 | Go samples time at `Verify` entry, checks the key/freshness/signature, then calls the bool-returning in-memory nonce store before authorization. The bool cannot report durable-write outcomes. |
| [`rust/src/server/verify.rs`](../../rust/src/server/verify.rs) lines 169–275; [`rust/src/server/nonce.rs`](../../rust/src/server/nonce.rs) lines 36–72 | Rust likewise samples time at verify entry, records after signature and before authorization, and uses an in-memory mutex/map with inclusive retention. |
| [`ts/src/server/verify.ts`](../../ts/src/server/verify.ts) lines 594–643; [`ts/src/server/nonce.ts`](../../ts/src/server/nonce.ts) lines 7–49 | TypeScript likewise verifies before recording and authorizes afterward; its synchronous in-memory map is not cross-process exclusion or persistence. |
| [`server/statefile.go`](../../server/statefile.go) lines 30–38, 264–325 | `FileState` uses a per-object mutex and temp/sync/rename writes for registry/invite edits. This is not nonce history, cross-process reservation, or proof of directory-metadata/power-loss durability. |
| [`internal/cli/gateway.go`](../../internal/cli/gateway.go) lines 105–175; [`internal/cli/storage_unix.go`](../../internal/cli/storage_unix.go) lines 1–41; [`internal/cli/storage_other.go`](../../internal/cli/storage_other.go) lines 1–8 | CLI has an `O_EXCL` state-owner marker, fresh in-memory nonces, and admission/count limits. These do not establish durable nonce or clock guarantees. Private-file support is not a Linux/macOS/Windows durable-backend proof; other targets fail closed. |

## 2. Accepted D2 mechanism and contract boundaries

### Admission and reservation

Preserve the current eligible-key/enrollment rules, checked inclusive freshness, and signature verification. Invalid signatures and other pre-authentication failures write no nonce state. Pending enrollment keeps its existing signature and submitted-key-hash binding; do not change enrollment parsing or state policy.

After cryptographic verification, the final authoritative **freshness/admission linearization** is the durable reservation transaction, not the stale verify-entry time sample. It takes a fresh raw clock sample and revalidates, in that transaction, the accepting owner and store generation, immutable `W`, `rawNow >= persisted H`, freshness using that same `rawNow` and `W`, and the captured public-key/registered-active/enrollment state. A changed snapshot fails closed without retry. Keep the lifetime exclusive-owner handle held while serving, but do not hold a per-request admission/store mutex through cryptography or handler execution; the final admission transaction serializes admission.

There is one accepting deployment owner with enforced exclusion and one shared gate/backend for its requests. If two processes attempt to open it, the second is refused; multi-owner cluster operation is not supported. A per-object mutex or deployment assumption is insufficient. A confirmed durable commit for the exact authenticated `(kid, nonce, request identity)` is the only dispatch authorization. A later authorization refusal, crash, or handler failure does not undo it; this is not exactly-once application execution. The fence blocks later admissions, not operations already authorized. Before replacing/recovering a store, close and drain old authorized work.

Conceptual write outcomes:

- **Committed:** proceed only with a durable receipt for the exact reservation.
- **Definitely not committed:** do not dispatch; this operation did not consume the nonce.
- **Unknown:** do not dispatch or issue an automatic replacement write/retry. Fence the owner/store, reconcile authoritative state by exact operation identity, and never automatically re-dispatch the original operation whether the reservation is found or absent. Persist an unsafe fence across restart in durable fence/recovery metadata. If storage cannot confirm that fence, an externally enforced startup reconciliation gate must prevent any owner from reopening admission. Exact error and reopening policy remain undecided.

A crash before confirmed commit has no dispatch permission; after confirmed commit the nonce remains consumed even if dispatch did not begin. A lost response is not a safe retry signal.

Implementation direction only: SDKs need an application-owned durable-backend seam with a common semantic, portable boundary; a callback alone is insufficient. The Go operator gateway/CLI must use an actual durable adapter, exclusive open/startup recovery, and resource-admission/purge integration; the existing gateway's fresh in-memory map does not implement this feature. Owner direction approves vetting/selecting a transaction library for the Go gateway rather than a custom journal; no dependency/version has been selected or added, and Go 1.25 is now the explicitly approved target; the source manifest and compatibility lanes still require migration. See [durable nonce backend feasibility](durable-nonce-backend.md) for the conditional bbolt candidate and blocker. No Rust/TypeScript dependency or API is proposed.

### Durable state, time, expiry, and ownership

Persist versioned, strictly decoded, bounded metadata binding deployment/store identity, immutable `W`, `H`, live `(kid, nonce)` entries, checked expiry, and exact request/operation identity needed for unknown-outcome reconciliation. Reject unknown versions, malformed/duplicate/inconsistent entries, impossible timestamps, trailing data, and oversized data. Missing, corrupt, unreadable, or detected-rollback state is not an empty cache.

Keep `retainUntil = checkedAdd(ts, W)`: an entry is live at equality (`now <= retainUntil`), and may be expired only when `now > retainUntil`. Replay does not extend retention; never evict a live entry. Persist `H`, the irreversible lower bound on admissible raw time. Reject and latch any raw sample below persisted `H`; do not clamp it, clear the latch at catch-up, or infer safe time. The unsafe-clock latch must survive restart as durable fence/recovery metadata, or be enforced by an external startup reconciliation gate as in unknown-outcome recovery; a volatile flag alone is insufficient. Do not require a persisted `H` advance for invalid or unauthenticated requests. Advance `H` durably before **every expiry-based use** that treats a nonce as absent—not merely on purge—and serialize its advance with purge/expiry and reservation atomically or by an ordered crash-safe backend transaction. `H` need not advance on every observed clock sample. A raw sample below `H` cannot reserve. If advancing `H` or establishing the fence fails or has unknown outcome, fail closed. Thus purge at `now=216` followed by restart at `now=215` cannot make a purged nonce appear absent.

This is not a timestamp startup floor: no `ts > server_start`, `ts > S+W`, boot lease, or request timestamp fence is selected. Validate clock/stored expiry domains and checked `ts+W`; overflow or invalid data fails closed. Refuse any live `W` change, increase or decrease; normal recovery requires the exact stored value. A separately authorized migration must preserve all possibly-live history or meet the trusted history/time-barrier condition below; no migration API is approved.

A missing store may be initialized only by explicit out-of-band initialization of a proven never-used deployment with proof there were no prior accepted requests, and only after metadata is durably initialized before admission. `FileState` interpreting a missing file as empty is not that proof. Existing volatile nonce history cannot be migrated by starting an empty durable store after restart. Clean initialization requires either (a) stop/drain every owner and atomically hand off all possibly-live tuples with safe `W/H`, or (b) a trusted all-lifetime upper bound `U` on accepted timestamps and trusted raw clock **strictly beyond checked `U+W`**. For any separately authorized future `W` migration, the barrier must use the proposed new `W` with checked arithmetic and prove all historical windows are `<=` that proposed `W`; the trusted all-lifetime `U` and history bounds must be established for that proposed `W`. Preserve complete possibly-live history otherwise; unknown historical windows or missing bounds fail closed. The current immutable `W` does not cover unknown historical windows. Fixed-`W` sleep or NTP correction is not proof. This is a recovery/migration gate, not a per-request floor, wire epoch, or approved API.

### Backend feasibility and bounds

The approved Go operator-gateway direction is to vet/select a transaction library, not build a custom journal. [durable-nonce-backend.md](durable-nonce-backend.md) records a conditional bbolt design and the historical version-floor comparison, now resolved by explicit Go 1.25 approval: bbolt is a plausible candidate, but no version/dependency is selected; the Go 1.25 target is approved but not implemented here; and maintenance/security support for the only reviewed Go-1.22-compatible bbolt version is unverified. No certified backend or platform durability is claimed.

The backend must strictly bind version, deployment, `W/H`, entries, expiry, and request/operation identity, with exclusive ownership, commit acknowledgment, startup recovery, and unknown-outcome fencing. It must obtain backend-specific atomicity, owner exclusion/fencing, recovery, platform flush/fsync, locking, and crash-loss evidence before any platform claim; `FileState` is not this proof. A self-consistent older backup cannot be detected by local `H` alone; require external monotonic evidence or explicit operator recovery, never automatic reset. The conditional Go design proposes separate namespaces for nonce and (if separately approved) public server-rotation state; it does not claim transactions include registry files or signer custody.

Bound bytes, live entries, in-flight reservations, queues, admission rate, per-write work, and purge batches/work. The backend note gives proposed starting values, which remain unapproved engineering proposals; at capacity refuse without dispatch or live-entry eviction. Physical database size and platform support require version/filesystem-specific enforcement and review. Healthy-filesystem/CLI acceptance is not proof of nonce durability or clock rollback resistance.

## 3. Rejected timestamp-floor comparison only

The selected mechanism is durable nonce state. A timestamp-floor comparison is neither a recommendation nor fallback. Any proposed strict floor `ts > F` would require proven limits for the **entire prior history**: every old raw sample `<= S+B`, every old window `<= Wmax`, and full all-lifetime proof, giving `F=S+B+Wmax`. Restart/NTP observations alone do not prove these limits. With `W=30`, `S=101`, an honest `ts=132` remains eligible above `F=131` when `B=0`; that does not make the floor the selected mechanism. If using a full quarantine comparison, equality `now=F+W` still leaves old `ts=F` fresh at the inclusive edge; equality is not enough.

| Comparison / distinction | Counterexample |
|---|---|
| `ts < server_start` | With `W=30`, old owner accepts signed `(K,N,ts=100)` at `now=100`; restart at `100` and exact replay pass inclusive freshness and this comparison. |
| `ts <= server_start` | Old owner accepts `ts=130` at `now=100`; restart at `101`, where exact replay remains fresh (`29` seconds) and `130 <= 101` is false. |
| `S+W` floor | With `W=30`, old `ts=130` accepted at `now=100`; restart at `S=101`, replay is fresh but fails strict `ts>S+W`. A floor therefore changes acceptance and is not D2. |

## 4. Discriminating design vectors (not tests)

No tests, fixtures, builds, runtime probes, or CI were run for this documentation change.

| Case | Required design outcome |
|---|---|
| Same-second/future replay | `W=30`; reserve `(K,N,ts=100)` at `now=100`, restart/replay at `100`; also reserve `ts=130` at `100`, restart/replay at `101`. Durable live history refuses both; no timestamp-floor decision. |
| Concurrent reservation | Concurrent valid duplicates through the single shared gate yield at most one durable commit/dispatch; second process opening the owner is refused. Cluster/multi-owner operation is unsupported. |
| Commit/refusal/crash | Confirmed reservation followed by authorization refusal or crash remains consumed while live; after safe expiry under the `H` rule, the pair may be reused with a new timestamp. Crash before confirmed commit never dispatches; after commit it remains consumed even if dispatch did not start. |
| Definite/unknown outcome | Definite noncommit does not dispatch or consume. Unknown fences, does not dispatch/retry, and exact-identity reconciliation never redispatches the original operation whether present or absent. |
| Delayed crypto / final freshness | Valid `ts=100`, `W=30`, precheck at `now=100`, final sample at `now=131`: final timestamp is out of window; no reservation or dispatch. |
| Expiry equality and +1 | For `ts=100,W=30`, `retainUntil=130`: at `130` replay; only at `131`, after safe durable `H` advance, may it expire and be reused. |
| Owner generation change | Owner/store generation changes or closes during cryptography: fail closed, with no reservation, retry, or use of the old generation. |
| Forward purge / rollback | Purge an entry with expiry `215` at `now=216` after persisting `H=216`; restart sample `215` fails closed before treating it absent. |
| Safe expiry reuse | Under `W=30`, after `(K,N,ts=100)` expires and only after safe `H=131`, the same pair with new `ts=131` may be ordinarily signature/freshness checked and newly reserved; the captured `ts=100` is not fresh. |
| Changed window | Under `W=15`, `ts=200` has expiry `215`; after purge at `216`, proposed `W=30` and replay at `216` are refused: changed `W` is rejected and no live-window recovery is claimed. |
| Volatile-history migration | Old volatile owner accepted `ts=130` at `now=101` under `W=30`; restart at `101` with an empty durable store has no history proof and must fail closed, not admit replay. Require complete atomic handoff or trusted all-lifetime `U` plus raw clock `>U+W`. |
| Invalid signature / enrollment | Invalid signature performs zero nonce writes. Valid pending enrollment retains existing signature/hash behavior and reserves before enrollment/state mutation. |
| Bounds / damaged state | Full capacity refuses without evicting a live record. Missing, corrupt, or detectably rolled-back state fails closed; local `H` alone does not prove detection of a self-consistent old backup. |

## 5. Decisions and release boundary

Backend direction is owner-approved, but exact backend feasibility/version selection, platform/recovery guarantees, SDK application-owned backend seam, storage/unknown-outcome errors, compatibility, and CLI operator workflow still require review before implementation or normative/API change. The backend note's proposed bounds are engineering starting limits for qualification and implementation review, not additional product decisions. Later executable acceptance belongs only to parent GitHub CI; Task 57 and any later normative fixtures are future acceptance work, not performed here. Healthy-filesystem prior acceptance is not nonce-persistence, clock, or rotation-durability proof. No local acceptance was run.

D3 remains separate: for successor records `R_i` and keys `K_i`, fixed `P_i` determines `A_i=P_i+172800` seconds; the server uses `K_0` before the first activation, then the `K_i` whose activation is the greatest `A_i <= now`, breaking ties by greatest ordinal, with cutoff `A_{i+1}`. Multiple future statements may be pending at their fixed times. This does not persist/fence nonces or establish a safe nonce clock. No normative spec, public API, implementation, tests, fixtures, or release action is authorized here; no tag, registry publication, GitHub Release, or announcement is proposed.
