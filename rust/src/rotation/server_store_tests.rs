use super::store_tests::{next, options, Sandbox};
use super::*;
use std::cell::Cell;
use std::fs;
use std::path::Path;
use std::rc::Rc;

const ANCHOR: &str = "opaque-provider/anchor";

// Именованная мутация: метка, in-place изменение desired snapshot и ожидаемый код отказа.
type Refusal = (&'static str, fn(&mut ServerSnapshot), &'static str);

fn server_options() -> RotationServerStoreOptions {
    let base = options();
    RotationServerStoreOptions {
        binding: base.binding,
        window: base.window,
        checkpoint: base.checkpoint,
        anchor_reference: ANCHOR.into(),
    }
}

fn payload(path: &Path) -> serde_json::Value {
    let outer: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    serde_json::from_str(outer["payload"].as_str().unwrap()).unwrap()
}

fn marker_path(path: &Path) -> std::path::PathBuf {
    path.with_file_name("trust.owner")
}

fn initialize(path: &Path) {
    RotationServerStore::initialize_unused(path, server_options(), || Ok(100)).unwrap();
}

/// Следующая fixed-P публикация поверх текущего ring: P = 100 = clock.high_water.
fn published(previous: &ServerSnapshot, clock: &ClockTuple) -> ServerSnapshot {
    let public = next(&previous.public, clock);
    let key = public.keys.last().expect("new key");
    let mut signer_references = previous.signer_references.clone();
    signer_references.push(SignerReference {
        kid: key.kid.clone(),
        reference: format!("opaque-provider/{}", key.kid),
    });
    ServerSnapshot {
        format_version: 1,
        public,
        signer_references,
    }
}

#[test]
fn lifecycle_exclusive_owner_one_fixed_p_publication_and_clean_reopen() {
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    let marker = marker_path(&path);
    let calls = Cell::new(0);
    assert!(
        RotationServerStore::open(&path, server_options(), || {
            calls.set(calls.get() + 1);
            Ok(100)
        })
        .is_err()
    );
    assert_eq!(calls.get(), 0);
    RotationServerStore::initialize_unused(&path, server_options(), || {
        assert_eq!(payload(&path)["dirty"], true);
        assert!(marker.exists(), "marker must precede every clock sample");
        Ok(100)
    })
    .unwrap();
    assert_eq!(
        payload(&path)["domain"],
        "mcp-jack/server-ring/private-file/v1"
    );
    let original = fs::read(&path).unwrap();
    assert!(
        RotationServerStore::initialize_unused(&path, server_options(), || panic!(
            "must not sample"
        ))
        .is_err()
    );
    assert_eq!(original, fs::read(&path).unwrap());
    let mut wrong = server_options();
    wrong.anchor_reference = "opaque-provider/other".into();
    assert!(RotationServerStore::open(&path, wrong, || panic!("wrong profile")).is_err());
    let mut store = RotationServerStore::open(&path, server_options(), || Ok(100)).unwrap();
    assert!(
        RotationServerStore::open(&path, server_options(), || panic!("second owner")).is_err()
    );
    let (previous, captured) = store.snapshot().unwrap();
    assert_eq!(previous.signer_references.len(), 1);
    let desired = published(&previous, &captured);
    let guard_before = payload(&path)["clock"].clone();
    store
        .compare_and_swap(&previous, &desired, &captured)
        .unwrap();
    assert_eq!(
        payload(&path)["clock"],
        guard_before,
        "publication must not rewrite the logical ClockGuard"
    );
    let error = store
        .compare_and_swap(&previous, &desired, &captured)
        .unwrap_err();
    assert_eq!(error.code, "rotation_state_changed");
    let error = store.check_snapshot_clock(&previous).unwrap_err();
    assert_eq!(error.code, "rotation_state_changed");
    let (committed, _) = store.snapshot().unwrap();
    assert_eq!(committed.public.records.len(), 1);
    assert_eq!(committed.signer_references.len(), 2);
    store.close().unwrap();
    store.close().unwrap();
    assert!(!marker.exists());
    assert!(store.snapshot().is_err());
    let mut reopened = RotationServerStore::open(&path, server_options(), || Ok(100)).unwrap();
    assert_eq!(reopened.snapshot().unwrap().0.public.head.ordinal, 1);
    assert_eq!(payload(&path)["owner"], 3);
    reopened.close().unwrap();
}

#[test]
fn publication_refusals_leave_the_ring_and_guard_untouched() {
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    initialize(&path);
    let mut store = RotationServerStore::open(&path, server_options(), || Ok(100)).unwrap();
    let (previous, clock) = store.snapshot().unwrap();
    let good = published(&previous, &clock);
    let before = fs::read(&path).unwrap();
    let refusals: &[Refusal] = &[
        ("replaced reference", |value| value.signer_references[0].reference = "replacement".to_owned(), "rotation_state_unavailable"),
        ("fenced target", |value| value.public.fenced = true, "rotation_state_unavailable"),
        ("moved P", |value| value.public.clock.high_water += 1, "rotation_state_changed"),
        ("clock tuple of another revision", |value| value.public.clock.revision += 1, "rotation_state_changed"),
    ];
    for (label, mutate, code) in refusals {
        let mut desired = good.clone();
        mutate(&mut desired);
        let error = store
            .compare_and_swap(&previous, &desired, &clock)
            .unwrap_err();
        assert_eq!(error.code, *code, "{label}");
        assert_eq!(fs::read(&path).unwrap(), before, "{label}");
    }
    let mut foreign = clock.clone();
    foreign.revision += 1;
    let error = store
        .compare_and_swap(&previous, &good, &foreign)
        .unwrap_err();
    assert_eq!(error.code, "rotation_state_changed");
    let error = store.compare_and_swap(&good, &good, &clock).unwrap_err();
    assert_eq!(error.code, "rotation_state_unavailable");
    assert_eq!(fs::read(&path).unwrap(), before);
    store.compare_and_swap(&previous, &good, &clock).unwrap();
    store.close().unwrap();
}

#[test]
fn rollback_or_invalid_time_latches_unsafe_and_blocks_clean_close() {
    for invalid_time in [99, MAX_TIMESTAMP + 1] {
        let sandbox = Sandbox::new();
        let path = sandbox.file();
        initialize(&path);
        let time = Rc::new(Cell::new(100));
        let callback = time.clone();
        let mut store =
            RotationServerStore::open(&path, server_options(), move || Ok(callback.get()))
                .unwrap();
        time.set(invalid_time);
        let error = store.advance_and_check().unwrap_err();
        assert_eq!(error.code, "rotation_clock_unsafe");
        let guard: serde_json::Value =
            serde_json::from_str(payload(&path)["clock"].as_str().unwrap()).unwrap();
        assert_eq!(guard["high_water"], 100);
        assert_eq!(guard["unsafe"], true);
        let latched = fs::read(&path).unwrap();
        time.set(200);
        let error = store.advance_and_check().unwrap_err();
        assert_eq!(error.code, "rotation_clock_unsafe");
        assert_eq!(fs::read(&path).unwrap(), latched, "catch-up must not clear");
        assert!(store.close().is_err());
        assert!(marker_path(&path).exists());
        assert!(RotationServerStore::open(&path, server_options(), || Ok(100)).is_err());
    }
}

#[test]
fn serving_leases_hold_the_dirty_epoch_and_drain_before_a_clean_close() {
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    initialize(&path);
    let mut store = RotationServerStore::open(&path, server_options(), || Ok(100)).unwrap();
    let one = store.acquire_serving_lease().unwrap();
    let two = store.acquire_serving_lease().unwrap();
    assert!(store.close().is_err());
    assert_eq!(payload(&path)["dirty"], true, "a lease keeps the dirty epoch");
    assert!(store.snapshot().is_err(), "closing refuses new final gates");
    assert!(store.acquire_serving_lease().is_err());
    drop(one);
    assert!(store.close().is_err(), "the second lease is still held");
    drop(two);
    store.close().unwrap();
    assert_eq!(payload(&path)["dirty"], false);
    assert!(store.acquire_serving_lease().is_err());
}

#[test]
fn client_and_server_files_anchors_and_profiles_are_not_interchangeable() {
    let sandbox = Sandbox::new();
    let server_path = sandbox.file();
    let client_path = server_path.with_file_name("client");
    RotationServerStore::initialize_unused(&server_path, server_options(), || Ok(100)).unwrap();
    RotationTrustStore::initialize_unused(&client_path, options(), || Ok(100)).unwrap();
    let server_bytes = fs::read(&server_path).unwrap();
    let client_bytes = fs::read(&client_path).unwrap();
    assert!(RotationTrustStore::open(&server_path, options(), || panic!("domain")).is_err());
    assert!(
        RotationServerStore::open(&client_path, server_options(), || panic!("domain")).is_err()
    );
    for anchor_reference in [String::new(), "x".repeat(MAX_SIGNER_REFERENCE_BYTES + 1)] {
        let mut bad = server_options();
        bad.anchor_reference = anchor_reference;
        let bad_path = server_path.with_file_name("bad");
        assert!(RotationServerStore::initialize_unused(&bad_path, bad, || panic!("bad")).is_err());
        assert!(!bad_path.exists());
    }
    assert_eq!(fs::read(&server_path).unwrap(), server_bytes);
    assert_eq!(fs::read(&client_path).unwrap(), client_bytes);
    assert!(!marker_path(&server_path).exists());
    assert!(!client_path.with_file_name("client.owner").exists());
    RotationServerStore::open(&server_path, server_options(), || Ok(100))
        .unwrap()
        .close()
        .unwrap();
}
