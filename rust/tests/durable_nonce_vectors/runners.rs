use super::*;

// ---------------------------------------------------------------------------
// Exclusions and deviations: data, not comments. Reasons are copied verbatim
// from the Go runner durable/nonce_vectors_linux_test.go.
// ---------------------------------------------------------------------------

struct VectorExclusion {
    reason: &'static str,
    spec: &'static str,
}

fn exclusions() -> HashMap<&'static str, VectorExclusion> {
    HashMap::from([
        (
            "generation-change-zero-commit",
            VectorExclusion {
                reason: "Not expressible against the Go seam: server.NonceAdmission carries no \
                     captured owner/store generation, so a per-request generation mismatch \
                     cannot be injected. Go revalidates the captured store state structurally \
                     under the admission mutex (transaction.go decodes and compares the full \
                     metadata), and a second owner is refused at Open (lifetime-exclusive \
                     ownership), which is the structural counterpart of this vector. The Rust \
                     seam has the same shape: DurableAdmission carries no captured \
                     owner/store generation and the store revalidates its full metadata under \
                     the admission mutex.",
                spec: "spec/candidate/durable-nonces.md L42: \"capture immutable \
                     active-key/registered-caller/enrollment snapshot, positive immutable W, \
                     accepting owner and store generation\"; L44: \"Store admission uses a \
                     lifetime-exclusive owner; a second process opening it is refused.\"",
            },
        ),
        (
            "definite-abort-confirmed-cleanup",
            VectorExclusion {
                reason: "The Go implementation reports a confirmed-cleanup abort with its \
                     step's status (401 timestamp_out_of_window), not the JS model's 503 \
                     classification; the drivable instance is identical to \
                     delayed-final-after-confirmed-intent, which is driven and asserts the \
                     confirmed cleanup (2 writes, 0 live, 0 intents, 0 dispatch). The Rust \
                     implementation reports the same step status for the same drivable \
                     instance.",
                spec: "spec/candidate/durable-nonces.md L48: \"Any failure needing intent \
                     cleanup is reported with its step's status only after cleanup is \
                     confirmed; uncertain cleanup/fence becomes unknown 503 \
                     durability_unavailable.\"",
            },
        ),
    ])
}

fn deviations() -> HashMap<&'static str, Vec<&'static str>> {
    HashMap::from([
        (
            "crash-after-commit-no-dispatch",
            vec![
                "expect.status 503/durability_unavailable and expect.effects zeros are the JS \
                 model's lost-response placeholder; the Rust store returns the committed \
                 response in-process and there is no in-process crash. This driver asserts the \
                 durable claims instead: commit succeeded (live=1, 2 writes), no native/dispatch \
                 side effect, clean Close, reopen succeeds unfenced, and the same pair replays \
                 401 replayed_nonce with zero further writes and no re-dispatch.",
                "Spec quote, spec/candidate/durable-nonces.md L74: \"crash after confirmed \
                 reservation but before dispatch leaves the pair consumed and never \
                 auto-redelivers.\"",
            ],
        ),
        (
            "key-snapshot-change-zero-commit",
            vec![
                "Same state_changed fencing divergence as window-decrease-refused, on the \
                 store-direct drive.",
            ],
        ),
        (
            "enrollment-snapshot-change-zero-commit",
            vec!["Same state_changed fencing divergence as key-snapshot-change-zero-commit."],
        ),
        (
            "capacity-live-plus-intent",
            vec![
                "Vector state (highWater=0 with ts=100 rows) is loader-rejectable per spec L58 \
                 and record.go validateRecord; seeded with metadata.HighWater=100 (the derivable \
                 floor). expect.highWater=0 is therefore not assertable; the driver asserts \
                 highWater=100 and everything else exactly (503 capacity_exhausted, 4096 live \
                 rows preserved row-for-row, unfenced, effects 0).",
                "expect.callbacks=0/expect.writes=0 count committed mutations in the JS model; \
                 the Rust store performs the atomic capacity check inside the intent \
                 transaction (spec L48 step 5), so one aborted transaction is observed. \
                 Transaction counting itself is not observable through the public Rust API, \
                 so the driver asserts the unchanged metadata and row counts instead.",
            ],
        ),
        (
            "capacity-tombstones",
            vec![
                "Same high-water floor and aborted-transaction counting deviations as \
                 capacity-live-plus-intent.",
            ],
        ),
        (
            "unknown-final-present",
            vec![
                "The reservationFound distinction is unobservable in single-snapshot \
                 transaction semantics: an injected fault after apply leaves the final state \
                 uncommitted on disk with the prepared intent row. The driver asserts the \
                 identical terminal state for both variants: fenced, 503 durability_unavailable, \
                 exactly one unresolved row in InspectRecovery, ReconcileUnknown producing \
                 exactly one terminal tombstone (tombstoneCount=1), and Open refused after \
                 reconciliation. expect.tombstoneOutcome unknown_found/unknown_absent is not \
                 separately assertable.",
            ],
        ),
        (
            "unknown-final-absent",
            vec!["Same rollback-resting-state deviation as unknown-final-present."],
        ),
        (
            "unknown-intent-absent",
            vec![
                "Partially driven. Unassertable expect fields: highWater=100 and writes=1 \
                 (committed) because the H advance and the intent commit are one atomic \
                 transaction per spec L62 (\"durably advance H to the raw sample in an atomic \
                 ordered transaction\"); a failed intent transaction leaves H=0 with zero \
                 committed writes and one aborted transaction call. Asserted instead: 503 \
                 durability_unavailable, fenced, no rows, the Dirty recovery gate, \
                 ReconcileUnknown refusal on empty history (manual fence), and a refused \
                 reopen.",
            ],
        ),
        (
            "all-cases",
            vec![
                "expect.callbacks/expect.writes count store transactions, which are not \
                 observable through the public Rust integration API; guarded assertions cover \
                 status, code, nonce_recorded, high-water, row counts, fence state, and \
                 effect counters instead.",
            ],
        ),
    ])
}

// ---------------------------------------------------------------------------
// Deterministic synthetic identities (identical to the Go runner).
// ---------------------------------------------------------------------------

fn run_single(case: &VectorCase, plan: Plan) {
    let Plan::Single {
        recorded,
        assert_unsafe,
        fenced,
    } = plan
    else {
        unreachable!()
    };
    let harness = new_harness(case, &plan);
    let event = case.event.as_ref().expect("single event");
    let result = drive_event(&harness, event, "/mcp");
    if let Some(status) = case.expect.status {
        assert_status(&case.id, &result, status, &case.expect.code);
    }
    if let Some(recorded) = recorded {
        assert_recorded(&case.id, &result, recorded);
    }
    if assert_unsafe {
        let info = nonce_store_info(&harness.store);
        assert!(
            info.unsafe_latched,
            "case {}: unsafe latch not durably set",
            case.id
        );
    }
    assert_end(&harness, case, &case.expect, false);
    // The fence expectation may be overridden by the plan (see deviations).
    let mut expect = case.expect.clone();
    if let Some(fenced) = fenced {
        expect.fenced = fenced;
    }
    // A committed request still holds its serving lease; close drains leases.
    std::mem::drop(result);
    assert_close_fencing(harness, case, &expect);
}

fn run_sequence(case: &VectorCase, plan: Plan) {
    let harness = new_harness(case, &plan);
    let statuses = case.expect.statuses.as_ref().expect("expect.statuses");
    let dispatches = count_list(&case.expect.dispatches);
    let mut recorded = 0;
    let mut accepted_total = 0;
    for (index, event) in case.sequence.iter().enumerate() {
        let target = if index > 0 && event.request_identity != case.sequence[0].request_identity {
            // A different signed request identity: different exact signing bytes.
            "/alternate"
        } else {
            "/mcp"
        };
        let result = drive_event(&harness, event, target);
        let (status, code) = &statuses[index];
        assert_status(&case.id, &result, *status, code);
        if result.nonce_recorded {
            recorded += 1;
        }
        accepted_total += harness.counters.lock().unwrap().accepted;
        if let Some(want) = dispatches.get(index) {
            let accepted = harness.counters.lock().unwrap().accepted as i64;
            assert_eq!(accepted, *want, "case {}: dispatches[{index}]", case.id);
        }
    }
    assert_eq!(
        recorded,
        case.expect.confirmed_commits.unwrap_or_default(),
        "case {}: confirmedCommits",
        case.id
    );
    // Sequence effects accumulate across events; assert them here and skip
    // the per-event assertion inside assert_end (accepted resets per event,
    // so the running total is the authorization/handler effect count).
    assert_eq!(
        (accepted_total as i64, accepted_total as i64, 0,),
        (
            case.expect.effects.authorization,
            case.expect.effects.handler,
            case.expect.effects.state_mutation
        ),
        "case {}: effects",
        case.id
    );
    assert_end(&harness, case, &case.expect, true);
    assert_close_fencing(harness, case, &case.expect);
}

// Snapshot revalidation for the store-direct vectors: accepts the entry
// sample and rejects every later sample, the Rust expression of a snapshot
// that changed after cryptography (the verifier builds this from registry
// state and cannot be forced to flip mid-request from outside).
thread_local! {
    static VALIDATE_CALLS: Cell<u32> = const { Cell::new(0) };
}

fn flaky_snapshot_valid(_now: i64) -> bool {
    VALIDATE_CALLS.with(|calls| {
        let next = calls.get() + 1;
        calls.set(next);
        next == 1
    })
}

fn run_store_direct(case: &VectorCase, plan: Plan) {
    let harness = new_harness(case, &plan);
    let event = case.event.as_ref().expect("store-direct event");
    harness.clock.start_store_drive(event);
    VALIDATE_CALLS.with(|calls| calls.set(0));
    let kid_value = kid(&event.kid);
    let nonce_value = nonce(&event.nonce);
    let signing =
        request_signing_string("GET", "/mcp", AUD, &kid_value, event.ts, &nonce_value, &[]);
    let admission = DurableAdmission {
        kid: &kid_value,
        nonce: &nonce_value,
        signature: &signature(&format!("{}:{}", event.kid, event.nonce)),
        signing_bytes: signing.as_bytes(),
        timestamp: event.ts,
        window: event.window,
        snapshot_valid: flaky_snapshot_valid,
    };
    let reserve = harness.store.reserve(&admission);
    match reserve {
        Err(error) => {
            assert_eq!(error.status, 503, "case {}: status", case.id);
            assert_eq!(error.code, "state_changed", "case {}: code", case.id);
        }
        Ok(_) => panic!("case {}: reserve accepted with a changed snapshot", case.id),
    }
    let validate_calls = VALIDATE_CALLS.with(|calls| calls.get());
    assert_eq!(validate_calls, 2, "case {}: validateCalls", case.id);
    assert_end(&harness, case, &case.expect, false);
    // state_changed is a definite refusal: the store stays unfenced and the
    // cleaned-up intent leaves nothing for recovery.
    assert!(
        harness.store.close().is_ok(),
        "case {}: state_changed refusal must not fence the store",
        case.id
    );
    drop(harness);
}

/// Fails the persist of the final transaction: the fault fires when the final
/// clock sample is taken (sample ordinal 2 of the event), so the intent
/// transaction is committed and the final transaction never reaches the disk
/// — the filesystem equivalent of a crash between the two transactions.
fn fault_final_persist(dir: &Path) -> Box<dyn FnMut() + Send> {
    let dir = dir.to_path_buf();
    Box::new(move || fs::set_permissions(&dir, read_only_dir()).expect("fault: read-only dir"))
}

/// Fails the persist of the intent transaction (sample ordinal 1).
fn fault_intent_persist(dir: &Path) -> Box<dyn FnMut() + Send> {
    let dir = dir.to_path_buf();
    Box::new(move || fs::set_permissions(&dir, read_only_dir()).expect("fault: read-only dir"))
}

/// Shared terminal flow of the unknown-outcome vectors: fenced refusal,
/// exactly one unresolved row, terminal no-redelivery tombstone, and a
/// refused reopen (Go: runUnknownFinalVector, with the documented deviation).
fn run_unknown_final(case: &VectorCase, plan: Plan) {
    let harness = new_harness(case, &plan);
    let event = case.event.as_ref().expect("unknown-final event");
    harness.clock.start_event(event);
    harness
        .clock
        .arm_fault(3, fault_final_persist(&harness.sandbox.0));
    let result = drive_event(&harness, event, "/mcp");
    // The fault left the directory read-only; restore it so close and recovery can run.
    fs::set_permissions(&harness.sandbox.0, read_write_dir())
        .expect("restore directory permissions");
    assert_status(&case.id, &result, 503, "durability_unavailable");
    assert!(
        !result.accepted,
        "case {}: unknown outcome dispatched",
        case.id
    );
    assert!(
        !result.nonce_recorded,
        "case {}: unknown outcome recorded",
        case.id
    );
    let (auth, handler, mutation) = effect_counters(&harness);
    assert_eq!(
        (auth, handler, mutation),
        (0, 0, 0),
        "case {}: effects",
        case.id
    );
    // The intent transaction durably advanced H; the rolled-back final
    // transaction leaves that advance intact, so expect.highWater holds.
    let info = nonce_store_info(&harness.store);
    assert_eq!(
        info.high_water, case.expect.high_water,
        "case {}: highWater",
        case.id
    );
    // Fenced close leaves the persisted dirty epoch; recovery follows.
    assert!(
        harness.store.close().is_err(),
        "case {}: fenced close",
        case.id
    );
    let report = inspect_recovery(&harness.path, &harness.options).expect("inspect recovery");
    assert!(
        report.dirty,
        "case {}: recovery report lost the dirty gate",
        case.id
    );
    let unresolved = report.live.len() + report.intents.len() + report.tombstones.len();
    assert_eq!(unresolved, 1, "case {}: unresolved rows", case.id);
    let claim = if report.live.len() == 1 {
        report.live[0].clone()
    } else {
        report.intents[0].clone()
    };
    reconcile_unknown(&harness.path, &harness.options, &report.hash, &claim)
        .expect("reconcile unknown");
    let after = inspect_recovery(&harness.path, &harness.options).expect("post-reconcile inspect");
    assert_eq!(
        after.tombstones.len(),
        case.expect.tombstone_count as usize,
        "case {}: tombstones",
        case.id
    );
    assert_eq!(
        after.live.len(),
        case.expect.live_count as usize,
        "case {}: live",
        case.id
    );
    assert_eq!(
        after.intents.len(),
        case.expect.intent_count as usize,
        "case {}: intents",
        case.id
    );
    expects_reopen_refused(&harness, &case.id);
    drop(harness);
}

/// Drives unknown-intent-absent as far as the Rust seam allows (Go:
/// runUnknownIntentVector; see the deviation entry).
fn run_unknown_intent(case: &VectorCase, plan: Plan) {
    let harness = new_harness(case, &plan);
    let event = case.event.as_ref().expect("unknown-intent event");
    harness.clock.start_event(event);
    harness
        .clock
        .arm_fault(2, fault_intent_persist(&harness.sandbox.0));
    let result = drive_event(&harness, event, "/mcp");
    // The fault left the directory read-only; restore it so close and recovery can run.
    fs::set_permissions(&harness.sandbox.0, read_write_dir())
        .expect("restore directory permissions");
    assert_status(&case.id, &result, 503, "durability_unavailable");
    assert!(
        !result.accepted,
        "case {}: unknown intent admitted",
        case.id
    );
    assert!(
        !result.nonce_recorded,
        "case {}: unknown intent recorded",
        case.id
    );
    assert!(
        harness.store.close().is_err(),
        "case {}: fenced close",
        case.id
    );
    // Failed intent transaction persisted no H advance (deviation).
    let report = inspect_recovery(&harness.path, &harness.options).expect("inspect recovery");
    assert!(
        report.dirty,
        "case {}: absent unknown operation lost the dirty gate",
        case.id
    );
    let unresolved = report.live.len() + report.intents.len() + report.tombstones.len();
    assert_eq!(unresolved, 0, "case {}: rows after failed intent", case.id);
    assert_eq!(
        report.high_water, 0,
        "case {}: failed intent persisted an H advance",
        case.id
    );
    let claim = mcp_jack::server::durable_format::DurableReceipt {
        version: 1,
        deployment: report.deployment_id.clone(),
        store_generation: report.store_generation,
        owner_generation: report.owner_generation,
        intent_id: "candidate-vector-claim".to_owned(),
        operation_id: [7; 16],
        kid: kid(&event.kid),
        nonce: nonce(&event.nonce),
        signature: signature(&format!("{}:{}", event.kid, event.nonce)),
        request_hash: encode_b64url(&[9; 32]),
        timestamp: event.ts,
        retain_until: event.ts + event.window,
        high_water: 0,
    };
    use mcp_jack::server::durable_format::DurableStoreError;
    let reconciled = reconcile_unknown(&harness.path, &harness.options, &report.hash, &claim);
    assert!(
        matches!(reconciled, Err(DurableStoreError::RecoveryRequired)),
        "case {}: empty unknown history treated as abort: {:?}",
        case.id,
        reconciled
    );
    expects_reopen_refused(&harness, &case.id);
    drop(harness);
}

/// Crash-after-commit-no-dispatch with the documented deviation: the Rust
/// store returns the committed response in-process, so the driver asserts
/// the durable claims plus clean reopen and replay (Go: runCrashVector).
fn run_crash(case: &VectorCase, plan: Plan) {
    let harness = new_harness(case, &plan);
    let event = case.event.as_ref().expect("crash event");
    let result = drive_event(&harness, event, "/mcp");
    assert!(
        result.accepted && result.nonce_recorded,
        "case {}: committed reservation did not survive to the response",
        case.id
    );
    assert_eq!(
        harness.counters.lock().unwrap().native_calls,
        0,
        "case {}: nativeCalls",
        case.id
    );
    let info = nonce_store_info(&harness.store);
    assert_eq!(info.live, 1, "case {}: liveRows", case.id);
    assert_eq!(
        info.high_water, case.expect.high_water,
        "case {}: highWater",
        case.id
    );
    // The committed request holds its serving lease until the response is finished.
    std::mem::drop(result);
    assert!(
        harness.store.close().is_ok(),
        "case {}: clean close after commit",
        case.id
    );
    // Reopen after the simulated crash succeeds unfenced; the reopened store
    // keeps a constant clock at the committed high water.
    let reopen_clock = ScriptedClock::new(&[case.expect.high_water]);
    let reopened = Arc::new(
        DurableNonceStore::open(&harness.path, &harness.options, reopen_clock.boxed())
            .expect("reopen after committed reservation"),
    );
    let harness = Harness {
        store: reopened,
        ..harness
    };
    // The same pair replays without any further write and never re-dispatches.
    let replay = drive_event(&harness, event, "/mcp");
    assert!(
        !replay.accepted && !replay.nonce_recorded && replay.code == "replayed_nonce",
        "case {}: committed pair re-dispatched after crash: {}/{}",
        case.id,
        replay.http_status,
        replay.code
    );
    assert!(
        harness.store.close().is_ok(),
        "case {}: reopen close",
        case.id
    );
    drop(harness);
}

/// Capacity refusal with the documented high-water floor deviation
/// (Go: runCapacityVector).
fn run_capacity(case: &VectorCase, plan: Plan) {
    let harness = new_harness(case, &plan);
    let event = case.event.as_ref().expect("capacity event");
    let result = drive_event(&harness, event, "/mcp");
    if let Some(status) = case.expect.status {
        assert_status(&case.id, &result, status, &case.expect.code);
    }
    assert!(
        !result.nonce_recorded,
        "case {}: capacity refusal recorded a nonce",
        case.id
    );
    assert!(
        !nonce_store_info(&harness.store).unsafe_latched,
        "case {}: fenced",
        case.id
    );
    let (auth, handler, mutation) = effect_counters(&harness);
    assert_eq!(
        (auth, handler, mutation),
        (0, 0, 0),
        "case {}: effects",
        case.id
    );
    let info = nonce_store_info(&harness.store);
    // Deviation: high-water floor (100) instead of the vector's 0.
    assert_eq!(info.high_water, 100, "case {}: high-water floor", case.id);
    if case.expect.preserve_live {
        assert_eq!(
            info.live, case.expect.live_count as usize,
            "case {}: preservedLive",
            case.id
        );
    }
    if case.expect.preserve_tombstones {
        assert_eq!(
            info.tombstones, case.expect.tombstone_count as usize,
            "case {}: preservedTombstones",
            case.id
        );
    }
    // capacity_exhausted is definite and does not fence: the close fails only
    // when the seeded state holds an unresolved intent or the tombstone cap.
    let needs_recovery = info.intents != 0 || info.tombstones >= 64;
    assert_eq!(
        harness.store.close().is_err(),
        needs_recovery,
        "case {}: close outcome",
        case.id
    );
    drop(harness);
}

// ---------------------------------------------------------------------------
// Test.
// ---------------------------------------------------------------------------

#[test]
fn candidate_nonce_vectors() {
    let fixture = load_fixture();
    let exclusions = exclusions();
    let deviations = deviations();
    // Every fixture case is driven or explicitly excluded...
    for case in &fixture.cases {
        assert!(
            plan_of(&case.id).is_some() || exclusions.contains_key(case.id.as_str()),
            "case {} is neither driven nor explicitly excluded",
            case.id
        );
    }
    // ...and every plan, exclusion, and deviation id exists in the fixture,
    // so renamed or dropped fixtures cannot leave silent stale entries.
    let ids: Vec<&str> = fixture.cases.iter().map(|c| c.id.as_str()).collect();
    for id in plan_ids() {
        assert!(ids.contains(&id), "plan {id} does not exist in the fixture");
    }
    for id in exclusions.keys() {
        assert!(
            ids.contains(id),
            "exclusion {id} does not exist in the fixture"
        );
    }
    for id in deviations.keys() {
        assert!(
            ids.contains(id) || *id == "all-cases",
            "deviation {id} does not exist in the fixture"
        );
    }
    assert_eq!(fixture.cases.len(), 24, "exactly 24 candidate vectors");

    let mut summary_pass = 0usize;
    let mut summary_excluded = 0usize;
    let mut summary_deviation = 0usize;
    for case in &fixture.cases {
        if let Some(exclusion) = exclusions.get(case.id.as_str()) {
            println!(
                "excluded {}: {}; spec: {}",
                case.id, exclusion.reason, exclusion.spec
            );
            summary_excluded += 1;
            continue;
        }
        let plan = plan_of(&case.id).expect("planned case");
        match plan {
            Plan::Single { .. } => run_single(case, plan),
            Plan::Sequence => run_sequence(case, plan),
            Plan::StoreDirect => run_store_direct(case, plan),
            Plan::Crash => run_crash(case, plan),
            Plan::UnknownFinal => run_unknown_final(case, plan),
            Plan::UnknownIntent => run_unknown_intent(case, plan),
            Plan::Capacity => run_capacity(case, plan),
        }
        if deviations.contains_key(case.id.as_str()) {
            summary_deviation += 1;
        } else {
            summary_pass += 1;
        }
    }
    println!("VECTOR-SUMMARY corpus=nonce sdk=rust pass={summary_pass} excluded={summary_excluded} deviation={summary_deviation}");
}

fn plan_ids() -> Vec<&'static str> {
    vec![
        "same-second-restart-replay",
        "future-ts-restart-replay",
        "concurrent-same-pair",
        "concurrent-different-request-identity",
        "expiry-equality",
        "expiry-plus-one-fresh-timestamp",
        "delayed-crypto-final-freshness",
        "delayed-final-after-confirmed-intent",
        "definite-abort-confirmed-cleanup",
        "purge-highwater-rollback",
        "window-decrease-refused",
        "window-increase-refused",
        "key-snapshot-change-zero-commit",
        "enrollment-snapshot-change-zero-commit",
        "bad-signature-zero-writes",
        "commit-then-authorization-refusal",
        "crash-after-commit-no-dispatch",
        "unknown-final-present",
        "unknown-final-absent",
        "unknown-intent-absent",
        "capacity-live-plus-intent",
        "capacity-tombstones",
        "no-effects-without-final-commit",
    ]
}
