use super::*;

#[test]
fn guard_fixture_shape_and_error_table() {
    let vectors = load_vectors();
    assert_eq!(vectors.format, FIXTURE_FORMAT, "format string");
    assert_eq!(
        vectors.client_cases.len(),
        CLIENT_CASE_COUNT,
        "client cases"
    );
    assert_eq!(vectors.event_cases.len(), EVENT_CASE_COUNT, "event cases");
    let mut ids: Vec<&str> = vectors
        .client_cases
        .iter()
        .map(|case| case.id.as_str())
        .collect();
    ids.extend(vectors.event_cases.iter().map(|case| case.id.as_str()));
    ids.sort_unstable();
    assert_eq!(
        ids.len(),
        CLIENT_CASE_COUNT + EVENT_CASE_COUNT,
        "fixture ids must be unique: {ids:?}"
    );
    let mut local_errors = vectors.client_local_errors.clone();
    local_errors.sort();
    let mut expected = EXPECTED_CLIENT_LOCAL_ERRORS.to_vec();
    expected.sort_unstable();
    assert_eq!(local_errors, expected, "client_local_errors table");
    let mut stale_cases = 0;
    let mut busy_cases = 0;
    for case in &vectors.client_cases {
        // The stale vector deliberately ships a response ts (173800) newer than
        // the client now (173769) — that divergence IS the vector's point.
        if case.id != "new-key-lower-bound-minus-one-is-stale" {
            assert_eq!(
                Some(case.input.response.now),
                u64::try_from(case.input.response.ts).ok(),
                "{}: response now/ts agree",
                case.id
            );
        }
        assert!(
            !case.input.response.request_sig.is_empty()
                && !case.input.response.signature.is_empty(),
            "{}: carrier signature material present",
            case.id
        );
        assert!(!case.input.snapshot.fence, "{}: unfenced anchor", case.id);
        assert_eq!(
            case.input.snapshot.revision, 1,
            "{}: anchor revision",
            case.id
        );
        assert!(
            case.input.snapshot.records.len() <= 1,
            "{}: anchor carries at most the ordinal-1 seed record",
            case.id
        );
        if case.input.snapshot.records.len() == 1 {
            assert_eq!(
                case.input.cursor.ordinal, 1,
                "{}: seeded record implies cursor ordinal 1",
                case.id
            );
        }
        assert_eq!(
            case.input.final_clock_generation, 1,
            "{}: single clock generation (Rust has no generation concept)",
            case.id
        );
        // committed=true implies exactly one trust-CAS callback in the model.
        if case.expect.committed == Some(true) {
            assert_eq!(case.expect.callbacks, 1, "{}: commit callback", case.id);
        }
        if case.input.callback_outcome != "ack" {
            // Only the unknown-outcome and (excluded) conflict callbacks differ.
            assert!(
                case.expect.error.is_some(),
                "{}: non-ack callback must error",
                case.id
            );
        }
        if case.input.stale_snapshot {
            stale_cases += 1;
        }
        if case.input.writer_busy {
            busy_cases += 1;
        }
    }
    assert_eq!(stale_cases, 1, "exactly one stale-snapshot vector");
    assert_eq!(busy_cases, 1, "exactly one busy-writer vector");
}

#[test]
fn guard_every_vector_is_classified() {
    let vectors = load_vectors();
    let mut all: Vec<&str> = vectors
        .client_cases
        .iter()
        .map(|case| case.id.as_str())
        .collect();
    all.extend(vectors.event_cases.iter().map(|case| case.id.as_str()));
    for id in &all {
        let driven = DRIVEN_FULL.contains(id) || DRIVEN_WITH_DEVIATION.contains(id);
        let excluded = EXCLUDED.iter().any(|(excluded_id, _)| excluded_id == id);
        assert!(driven || excluded, "unclassified vector {id}");
        if DRIVEN_WITH_DEVIATION.contains(id) {
            assert!(
                DEVIATIONS
                    .iter()
                    .any(|(deviation_id, _)| deviation_id == id),
                "deviation-driven vector {id} missing from DEVIATIONS"
            );
        }
    }
    for (deviation_id, _) in DEVIATIONS {
        assert!(
            all.contains(&deviation_id),
            "DEVIATIONS names unknown vector {deviation_id}"
        );
    }
    for (excluded_id, _) in EXCLUDED {
        assert!(
            all.contains(&excluded_id),
            "EXCLUDED names unknown vector {excluded_id}"
        );
    }
    // pass counts the vectors driven without a recorded deviation.
    eprintln!(
        "VECTOR-SUMMARY corpus=rotation-state sdk=rust pass={} excluded={} deviation={}",
        DRIVEN_FULL.len(),
        EXCLUDED.len(),
        DRIVEN_WITH_DEVIATION.len()
    );
}

// ---------------------------------------------------------------------------
// Driven client_cases (refresh semantics against the real controller/store).
// ---------------------------------------------------------------------------

#[test]
fn vector_first_bridge_before_cutoff() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "first-bridge-before-cutoff");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    initialize_trust(&sandbox.file(), &options, 173_799);
    let clock = SharedClock::at(173_799);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let result = drive_refresh(&mut store, case).expect("commits before activation");
    expect_ok(case, result.clone());
    assert_eq!(result.revision, 2);
    assert_eq!(result.head.ordinal, 1);
    assert!(result.complete);
    assert_eq!(result.terminal.ordinal, 1);
    let (snapshot, _) = store.snapshot().expect("snapshot");
    // carrierTrusted: the carrier key stays eligible at the final sample.
    assert_eq!(snapshot.keys[0].known_cutoff, Some(173_800));
    assert!(173_799 < snapshot.keys[0].known_cutoff.expect("cutoff"));
    eprintln!(
        "verdict {} = driven-full (Ok, committed true, revision 2, head 1, carrier trusted)",
        case.id
    );
}

#[test]
fn vector_first_bridge_at_cutoff() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "first-bridge-at-cutoff");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    initialize_trust(&sandbox.file(), &options, 173_800);
    let clock = SharedClock::at(173_800);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let error = drive_refresh(&mut store, case).expect_err("bridge expires at A");
    expect_err(case, &error);
    // committed:false, callbacks:0 => the anchor snapshot is untouched.
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision, 1);
    assert_eq!(snapshot.head.ordinal, 0);
    eprintln!(
        "verdict {} = driven-full (rotation_bridge_expired, committed false, zero adoption)",
        case.id
    );
}

#[test]
fn vector_unknown_outer_before_invalid_payload() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "unknown-outer-before-invalid-payload");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    initialize_trust(&sandbox.file(), &options, 1_000);
    let clock = SharedClock::at(1_000);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let error = drive_refresh(&mut store, case).expect_err("unknown key refused");
    expect_err(case, &error);
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision, 1);
    eprintln!(
        "verdict {} = driven-full (unknown_server_key; key set checked before the body)",
        case.id
    );
}

#[test]
fn vector_exact_duplicate_at_new_key_lower_bound() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "exact-duplicate-at-new-key-lower-bound");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    seed_ord1(&sandbox.file(), &options, &vectors, 173_769);
    let clock = SharedClock::at(173_800);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let result = drive_refresh(&mut store, case).expect("duplicate is a no-op success");
    expect_ok(case, result);
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision, 2, "no trust revision increment");
    assert_eq!(snapshot.head.ordinal, 1, "head unchanged");
    // carrierTrusted: the new key is within its interval at now=173800.
    assert_eq!(snapshot.keys[1].not_before, 173_800);
    assert_eq!(snapshot.keys[1].known_cutoff, None);
    eprintln!(
        "verdict {} = driven-full (Ok duplicate no-op, callbacks 0, revision stays 2)",
        case.id
    );
}

#[test]
fn vector_new_key_lower_bound_minus_one_is_stale() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "new-key-lower-bound-minus-one-is-stale");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    seed_ord1(&sandbox.file(), &options, &vectors, 173_769);
    let clock = SharedClock::at(173_769);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let error = drive_refresh(&mut store, case).expect_err("outside the window");
    expect_err(case, &error);
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision, 2, "no adoption");
    eprintln!(
        "verdict {} = driven-full (timestamp_out_of_window, committed false)",
        case.id
    );
}

#[test]
fn vector_duplicate_prefix_then_extension() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "duplicate-prefix-then-extension");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    seed_ord1(&sandbox.file(), &options, &vectors, 173_769);
    let clock = SharedClock::at(173_800);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let result = drive_refresh(&mut store, case).expect("extension commits");
    expect_ok(case, result.clone());
    assert!(result.committed);
    assert_eq!(result.revision, 3, "one trust revision increment");
    assert_eq!(result.head.ordinal, 2, "head ordinal 2");
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.keys.len(), 3);
    assert_eq!(snapshot.records.len(), 2);
    eprintln!(
        "verdict {} = driven-full (committed true, head ordinal 2, revision 3, carrier trusted)",
        case.id
    );
}

#[test]
fn vector_late_callback_ack_retains_snapshot_but_rejects_carrier() {
    let vectors = load_vectors();
    let case = find_client(
        &vectors,
        "late-callback-ack-retains-snapshot-but-rejects-carrier",
    );
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    // The model samples preCallbackNow (173799) until the callback and finalNow
    // (173800) at the final gate. The controller samples 5 times before the
    // final gate (store open advance, controller construction, raw outer
    // clock, outer ClockGuard, pre-callback ClockGuard), then once there.
    initialize_trust(&sandbox.file(), &options, 173_799);
    let clock = SharedClock::at(173_800);
    clock.enqueue(&[173_799; 5]);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let error = drive_refresh(&mut store, case).expect_err("carrier fails the final gate");
    expect_err(case, &error);
    assert_eq!(clock.samples(), 6, "five pre-callback samples, one final");
    store.close().expect("close after late-carrier failure");
    // committed stays true: reopen proves the ACK was retained.
    let reopen = SharedClock::at(173_800);
    let mut store = open_trust(&sandbox.file(), &options, &reopen);
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision, 2, "ACK retained");
    assert_eq!(snapshot.head.ordinal, 1);
    assert_eq!(snapshot.keys.len(), 2);
    // carrierTrusted:false: at equality the old key is strictly retired.
    assert_eq!(snapshot.keys[0].known_cutoff, Some(173_800));
    eprintln!(
        "verdict {} = driven-full (rotation_key_interval; commit retained, carrier untrusted)",
        case.id
    );
}

#[test]
fn vector_conflicting_duplicate_prefix_is_not_adopted() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "conflicting-duplicate-prefix-is-not-adopted");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    seed_ord1(&sandbox.file(), &options, &vectors, 173_769);
    let clock = SharedClock::at(173_800);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let error = drive_refresh(&mut store, case).expect_err("conflicting duplicate");
    expect_err(case, &error);
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision, 2, "conflicting record not adopted");
    assert_eq!(snapshot.records.len(), 1);
    eprintln!(
        "verdict {} = driven-full (rotation_conflict, zero adoption)",
        case.id
    );
}

#[test]
fn vector_gapped_prefix_cannot_be_claimed_by_head() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "gapped-prefix-cannot-be-claimed-by-head");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    seed_ord1(&sandbox.file(), &options, &vectors, 173_799);
    let clock = SharedClock::at(173_799);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let error = drive_refresh(&mut store, case).expect_err("gap refused");
    expect_err(case, &error);
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision, 2, "no adoption");
    assert_eq!(snapshot.records.len(), 1);
    eprintln!(
        "verdict {} = driven-full (rotation_gap, committed false)",
        case.id
    );
}

#[test]
fn vector_whole_response_body_cap_plus_one() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "whole-response-body-cap-plus-one");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    initialize_trust(&sandbox.file(), &options, 1_000);
    let clock = SharedClock::at(1_000);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let response = response_of(case);
    assert_eq!(
        response.body.len(),
        MAX_RESULT_BODY_BYTES + 1,
        "fixture body is exactly cap+1"
    );
    let error = drive_refresh(&mut store, case).expect_err("over the body cap");
    expect_err(case, &error);
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision, 1);
    eprintln!(
        "verdict {} = driven-full (rotation_result_invalid at 262145 bytes, committed false)",
        case.id
    );
}

// --- deviation-driven client_cases ---------------------------------------

#[test]
fn vector_trust_callback_unknown_fences() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "trust-callback-unknown-fences");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    seed_ord1(&sandbox.file(), &options, &vectors, 173_769);
    let clock = SharedClock::at(173_800);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    fs::set_permissions(&sandbox.0, fs::Permissions::from_mode(0o500))
        .expect("chmod sandbox read-only");
    // The unknown CAS outcome can surface from the CAS itself (accept_refresh)
    // or from the fenced advance inside RotationController::new; both are the
    // same rotation_state_unknown the fixture expects.
    let error = match RotationController::new(&mut store) {
        Ok(mut controller) => controller
            .accept_refresh(
                response_of(case),
                case.input.expected_id.to_string().as_bytes(),
                &cursor_of(&case.input.cursor),
            )
            .expect_err("unknown CAS outcome"),
        Err(error) => error,
    };
    assert_eq!(error.code, "rotation_state_unknown");
    assert_eq!(
        case.expect.error.as_deref(),
        Some("rotation_state_unknown"),
        "{}: fixture expects the unknown outcome",
        case.id
    );
    // Restore the sandbox before any close/reopen attempt.
    fs::set_permissions(&sandbox.0, fs::Permissions::from_mode(0o700))
        .expect("restore sandbox permissions");
    assert_eq!(case.expect.fenced, Some(true), "{}: model fences", case.id);
    drop(store);
    // fenced:true => a reopen is refused (the bundle stays dirty on disk).
    let reopen = SharedClock::at(173_800);
    let reopen_error =
        match RotationTrustStore::open(&sandbox.file(), options.clone(), reopen.closure()) {
            Err(error) => error.code,
            Ok(_) => panic!("fenced store refuses reopen"),
        };
    assert_eq!(reopen_error, "rotation_state_unavailable");
    let (high_water, revision, unsafe_clock) = clock_doc(&sandbox.file());
    assert_eq!(
        high_water, case.input.final_now,
        "clock high-water unchanged"
    );
    assert_eq!(revision, 2, "clock revision unchanged by the failed CAS");
    assert!(!unsafe_clock);
    eprintln!(
        "verdict {} = driven-with-deviation (rotation_state_unknown; fenced reopen; \
         CAS counters unobservable)",
        case.id
    );
}

#[test]
fn vector_busy_writer_stops_before_trust_callback() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "busy-writer-stops-before-trust-callback");
    assert!(case.input.writer_busy, "fixture marks the writer busy");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    seed_ord1(&sandbox.file(), &options, &vectors, 173_769);
    let clock = SharedClock::at(173_800);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    // Structural counterpart: the Rust store is a single-writer exclusive
    // FileOwner, so a second concurrent writer is refused before any callback.
    let second_clock = SharedClock::at(173_800);
    let second_error =
        match RotationTrustStore::open(&sandbox.file(), options.clone(), second_clock.closure()) {
            Err(error) => error.code,
            Ok(_) => panic!("second writer refused"),
        };
    assert_eq!(second_error, "rotation_state_unavailable");
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(
        snapshot.revision, 2,
        "zero adoption while a writer is active"
    );
    eprintln!(
        "verdict {} = driven-with-deviation (model rotation_state_changed maps to \
         rotation_state_unavailable: the exclusive single-writer file owner refuses \
         the second writer before any callback)",
        case.id
    );
}

#[test]
fn vector_stale_whole_snapshot_stops_before_callback() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "stale-whole-snapshot-stops-before-callback");
    assert!(
        case.input.stale_snapshot,
        "fixture marks the snapshot stale"
    );
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    seed_ord1(&sandbox.file(), &options, &vectors, 173_769);
    let clock = SharedClock::at(173_800);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    // Capture the pre-callback snapshot, advance the durable state, then drive
    // the production exact whole-snapshot compare with the stale value.
    let (stale, _) = store.snapshot().expect("pre-callback snapshot");
    let extension = find_client(&vectors, "duplicate-prefix-then-extension");
    let committed = drive_refresh(&mut store, extension).expect("extension commits");
    assert!(committed.committed);
    let error = store
        .check_snapshot_clock(&stale)
        .expect_err("stale snapshot refused");
    assert_eq!(error.code, "rotation_state_changed");
    // Zero adoption from the refused compare: durable state keeps the extension.
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision, 3, "no rollback and no double adoption");
    assert_eq!(snapshot.head.ordinal, 2);
    eprintln!(
        "verdict {} = driven-with-deviation (rotation_state_changed from the production \
         exact whole-snapshot compare with zero adoption; not a mid-refresh interleaving: \
         the controller owns the store via &mut)",
        case.id
    );
}

// ---------------------------------------------------------------------------
// Driven event_cases: selection.
// ---------------------------------------------------------------------------

#[test]
fn vector_same_second_greatest_ordinal_wins() {
    let vectors = load_vectors();
    let case = find_event(&vectors, "same-second-greatest-ordinal-wins");
    let EventInput::Selection {
        after,
        at,
        before,
        records,
    } = &case.input
    else {
        panic!("selection input");
    };
    let snapshot = &find_client(&vectors, "first-bridge-before-cutoff")
        .input
        .snapshot;
    let binding = Binding {
        endpoint: &snapshot.endpoint,
        aud: &snapshot.aud,
    };
    let anchor: [u8; 32] = decode_b64url(&snapshot.anchor.public_key)
        .expect("anchor key")
        .try_into()
        .expect("32 bytes");
    let mut authorizers: BTreeMap<String, [u8; 32]> = BTreeMap::new();
    authorizers.insert(snapshot.anchor.kid.clone(), anchor);
    let mut parsed = Vec::new();
    for wire in records {
        let record = parse_record(wire.as_bytes(), binding, &authorizers).expect("record");
        authorizers.insert(record.new_kid.clone(), record.public_key);
        parsed.push(record);
    }
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].ordinal, 1);
    assert_eq!(parsed[1].ordinal, 2);
    assert_eq!(selected_ordinal(&parsed, *before).expect("selection"), 0);
    assert_eq!(selected_ordinal(&parsed, *at).expect("selection"), 2);
    assert_eq!(selected_ordinal(&parsed, *after).expect("selection"), 2);
    eprintln!(
        "verdict {} = driven-full (selected ordinals 0/2/2 at 173799/173800/173801)",
        case.id
    );
}

// ---------------------------------------------------------------------------
// Driven event_cases: ClockGuard.
// ---------------------------------------------------------------------------

/// Builds the fixture guard state by driving the real store: init at H-3,
/// open at H-2, advance to H-1, advance to H => clock revision 4 at H.
fn open_guard_store(
    path: &Path,
    guard: &ClockGuard,
    clock: &SharedClock,
) -> RotationTrustStore<BoxClock> {
    assert_eq!(guard.revision, 4, "guard revision the fixture ships");
    assert_eq!(guard.window, 30);
    let vectors = load_vectors();
    let snapshot = &find_client(&vectors, "first-bridge-before-cutoff")
        .input
        .snapshot;
    assert_eq!(
        guard.binding, snapshot.endpoint,
        "guard binding is the endpoint of the seeded snapshot"
    );
    let options = trust_options(snapshot);
    assert!(guard.high_water >= 3);
    clock.set(guard.high_water - 2);
    initialize_trust(path, &options, guard.high_water - 3);
    let mut store = open_trust(path, &options, clock);
    clock.set(guard.high_water - 1);
    store.advance_and_check().expect("advance to H-1");
    clock.set(guard.high_water);
    store.advance_and_check().expect("advance to H");
    let (high_water, revision, unsafe_clock) = clock_doc(path);
    assert_eq!(
        (high_water, revision, unsafe_clock),
        (guard.high_water, 4, false)
    );
    store
}

#[test]
fn vector_clock_rollback_latches() {
    let vectors = load_vectors();
    let case = find_event(&vectors, "clock-rollback-latches");
    let EventInput::Clock {
        guard,
        raw_now,
        latch,
    } = &case.input
    else {
        panic!("clock input");
    };
    assert_eq!(latch.as_deref(), None, "plain rollback latch");
    let sandbox = Sandbox::new();
    let clock = SharedClock::at(0);
    let mut store = open_guard_store(&sandbox.file(), guard, &clock);
    let baseline = clock.samples();
    clock.set(*raw_now);
    let error = store
        .advance_and_check()
        .expect_err("rollback refuses")
        .code;
    assert_eq!(error, "rotation_clock_unsafe");
    assert_eq!(clock.samples() - baseline, 1, "exactly one clock callback");
    // The latch write is durable: exactly one write (revision 4 -> 5, unsafe).
    let (high_water, revision, unsafe_clock) = clock_doc(&sandbox.file());
    assert_eq!(
        (high_water, revision, unsafe_clock),
        (guard.high_water, 5, true)
    );
    // The latch persists: the next check refuses without even sampling.
    let second = store.advance_and_check().expect_err("latched").code;
    assert_eq!(second, "rotation_clock_unsafe");
    assert_eq!(
        clock.samples() - baseline,
        1,
        "no further sample once latched"
    );
    eprintln!(
        "verdict {} = driven-full (rotation_clock_unsafe, callbacks 1, durable latch rev 5 unsafe)",
        case.id
    );
}

#[test]
fn vector_clock_equal_is_noop() {
    let vectors = load_vectors();
    let case = find_event(&vectors, "clock-equal-is-noop");
    let EventInput::Clock {
        guard,
        raw_now,
        latch,
    } = &case.input
    else {
        panic!("clock input");
    };
    assert_eq!(latch.as_deref(), None);
    let sandbox = Sandbox::new();
    let clock = SharedClock::at(0);
    let mut store = open_guard_store(&sandbox.file(), guard, &clock);
    let baseline = clock.samples();
    clock.set(*raw_now);
    let result = store.advance_and_check().expect("equal sample is a noop");
    assert_eq!(result.high_water, guard.high_water);
    assert_eq!(result.revision, guard.revision);
    assert!(!result.unsafe_clock);
    assert_eq!(clock.samples() - baseline, 1, "one sample");
    let (high_water, revision, unsafe_clock) = clock_doc(&sandbox.file());
    assert_eq!(
        (high_water, revision, unsafe_clock),
        (guard.high_water, 4, false)
    );
    eprintln!(
        "verdict {} = driven-with-deviation (error null, H/revision/unsafe exact, writes 0 via \
         durable clock doc; the model's callbacks:0 counts durable callbacks while the Rust \
         ClockGuard necessarily samples once)",
        case.id
    );
}

#[test]
fn vector_clock_rollback_latch_unknown_is_unavailable() {
    let vectors = load_vectors();
    let case = find_event(&vectors, "clock-rollback-latch-unknown-is-unavailable");
    let EventInput::Clock {
        guard,
        raw_now,
        latch,
    } = &case.input
    else {
        panic!("clock input");
    };
    assert_eq!(latch.as_deref(), Some("unknown"));
    let sandbox = Sandbox::new();
    let clock = SharedClock::at(0);
    let mut store = open_guard_store(&sandbox.file(), guard, &clock);
    let baseline = clock.samples();
    clock.set(*raw_now);
    clock.fail();
    let error = store
        .advance_and_check()
        .expect_err("failing sample refuses")
        .code;
    assert_eq!(error, "rotation_clock_unavailable");
    assert_eq!(clock.samples() - baseline, 1, "exactly one clock callback");
    // H/revision/unsafe unchanged: the model's failed sample performs no write.
    let (high_water, revision, unsafe_clock) = clock_doc(&sandbox.file());
    assert_eq!(
        (high_water, revision, unsafe_clock),
        (guard.high_water, 4, false)
    );
    eprintln!(
        "verdict {} = driven-with-deviation (rotation_clock_unavailable with H/revision/unsafe \
         exact; deviation: the model writes a latch on the failed sample while Rust fences \
         without writing the latch)",
        case.id
    );
}

#[test]
fn vector_clock_advance_persists_revision() {
    let vectors = load_vectors();
    let case = find_event(&vectors, "clock-advance-persists-revision");
    let EventInput::Clock {
        guard,
        raw_now,
        latch,
    } = &case.input
    else {
        panic!("clock input");
    };
    assert_eq!(latch.as_deref(), None);
    let sandbox = Sandbox::new();
    let clock = SharedClock::at(0);
    let mut store = open_guard_store(&sandbox.file(), guard, &clock);
    let baseline = clock.samples();
    clock.set(*raw_now);
    let result = store.advance_and_check().expect("advance persists");
    assert_eq!(result.high_water, *raw_now);
    assert_eq!(result.revision, guard.revision + 1);
    assert!(!result.unsafe_clock);
    assert_eq!(clock.samples() - baseline, 1);
    let (high_water, revision, unsafe_clock) = clock_doc(&sandbox.file());
    assert_eq!((high_water, revision, unsafe_clock), (*raw_now, 5, false));
    eprintln!(
        "verdict {} = driven-full (H 173801, revision 5, one durable write)",
        case.id
    );
}
