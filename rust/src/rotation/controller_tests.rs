use super::store_tests::{initialize, next, options, Sandbox};
use super::*;
use crate::auth_header::{format_response_auth, ResponseAuth};
use crate::client::{InMemorySigner, Signer};
use crate::encoding::encode_b64url;
use crate::signing::{request_signing_string, response_signing_string};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

fn response(seed: u8, timestamp: i64, body: &[u8]) -> RotationResponse {
    let server = InMemorySigner::from_seed(&[seed; 32]).unwrap();
    let client = InMemorySigner::from_seed(&[33; 32]).unwrap();
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).unwrap();
    let request = request_signing_string(
        "POST", "/mcp?exact=query", "store-test", client.kid(), timestamp,
        &encode_b64url(&nonce), b"exact request body",
    );
    let request_signature = encode_b64url(&client.sign(request.as_bytes()).unwrap());
    let signed = response_signing_string(200, &request_signature, server.kid(), timestamp, body);
    RotationResponse {
        status: 200,
        headers: vec![format_response_auth(&ResponseAuth {
            kid: server.kid().into(), ts: timestamp,
            sig: encode_b64url(&server.sign(signed.as_bytes()).unwrap()),
        })],
        request_signature,
        body: body.to_vec(),
    }
}

#[test]
fn ordinary_exact_opaque_body_inclusive_window_and_no_trust_mutation() {
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    initialize(&path);
    let now = Rc::new(Cell::new(100));
    let calls = Rc::new(Cell::new(0));
    let clock_time = now.clone();
    let clock_calls = calls.clone();
    let mut store = RotationTrustStore::open(&path, options(), move || {
        clock_calls.set(clock_calls.get() + 1);
        Ok(clock_time.get())
    }).unwrap();
    {
        let mut controller = RotationController::new(&mut store).unwrap();
        calls.set(0);
        now.set(130);
        let body = [0xff, 0, 10, 13];
        assert_eq!(controller.verify_response(response(31, 100, &body)).unwrap(), body);
        assert_eq!(calls.get(), 3);
    }
    let (snapshot, clock) = store.snapshot().unwrap();
    assert_eq!(snapshot.revision, 1);
    assert_eq!(snapshot.clock.high_water, 100);
    assert_eq!(clock.high_water, 130);
    store.close().unwrap();
}

#[test]
fn unknown_key_and_body_cap_precede_clock_bad_crypto_never_advances_guard() {
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    initialize(&path);
    let now = Rc::new(Cell::new(100));
    let calls = Rc::new(Cell::new(0));
    let clock_time = now.clone();
    let clock_calls = calls.clone();
    let mut store = RotationTrustStore::open(&path, options(), move || {
        clock_calls.set(clock_calls.get() + 1);
        Ok(clock_time.get())
    }).unwrap();
    {
        let mut controller = RotationController::new(&mut store).unwrap();
        calls.set(0);
        let mut unknown = response(99, 100, b"opaque");
        unknown.body = vec![0; 1024 * 1024 + 1];
        let error = controller.verify_response(unknown).unwrap_err();
        assert_eq!(error.code, "unknown_server_key");
        assert_eq!(error.http_status, 0);
        assert_eq!(calls.get(), 0);
        let mut large = response(31, 100, b"opaque");
        large.body = vec![0; 1024 * 1024 + 1];
        assert_eq!(controller.verify_response(large).unwrap_err().code, "rotation_result_invalid");
        assert_eq!(calls.get(), 0);
        now.set(101);
        for mutation in ["body", "status", "request", "signature"] {
            let mut changed = response(31, 100, b"opaque");
            match mutation {
                "body" => changed.body.push(0),
                "status" => changed.status = 201,
                "request" => changed.request_signature = encode_b64url(&[7; 64]),
                "signature" => {
                    let mut auth = crate::auth_header::parse_response_auth(&[&changed.headers[0]]).unwrap();
                    let mut signature = crate::encoding::decode_b64url_fixed(&auth.sig, 64).unwrap();
                    signature[0] ^= 1;
                    auth.sig = encode_b64url(&signature);
                    changed.headers[0] = format_response_auth(&auth);
                }
                _ => unreachable!(),
            }
            let error = controller.verify_response(changed).unwrap_err();
            assert_eq!(error.code, "bad_signature");
            assert_eq!(error.http_status, 0);
            assert_eq!(error.message, "rotation response refused");
        }
        assert_eq!(calls.get(), 4);
    }
    assert_eq!(store.snapshot().unwrap().1.high_water, 100);
    store.close().unwrap();
}

#[test]
fn final_freshness_and_rollback_refuse_body_without_undoing_clock_state() {
    for final_time in [131, 99] {
        let sandbox = Sandbox::new();
        let path = sandbox.file();
        initialize(&path);
        let queue = Rc::new(RefCell::new(VecDeque::new()));
        let callback = queue.clone();
        let mut store = RotationTrustStore::open(&path, options(), move || {
            Ok(callback.borrow_mut().pop_front().unwrap_or(100))
        }).unwrap();
        {
            let mut controller = RotationController::new(&mut store).unwrap();
            queue.borrow_mut().extend([100, 100, final_time]);
            let error = controller.verify_response(response(31, 100, b"never return")).unwrap_err();
            assert_eq!(error.code, if final_time == 99 { "rotation_clock_unsafe" } else { "timestamp_out_of_window" });
            assert!(queue.borrow().is_empty());
        }
        if final_time == 99 {
            assert_eq!(store.advance_and_check().unwrap_err().code, "rotation_clock_unsafe");
            assert!(store.close().is_err());
        } else {
            let (snapshot, clock) = store.snapshot().unwrap();
            assert_eq!(snapshot.revision, 1);
            assert_eq!(clock.high_water, 131);
            store.close().unwrap();
        }
    }
}

#[test]
fn acknowledged_successor_and_strict_final_cutoff_leave_static_pin_unchanged() {
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    initialize(&path);
    let base = Rc::new(Cell::new(100));
    let queue = Rc::new(RefCell::new(VecDeque::new()));
    let clock_base = base.clone();
    let callback = queue.clone();
    let mut store = RotationTrustStore::open(&path, options(), move || {
        Ok(callback.borrow_mut().pop_front().unwrap_or(clock_base.get()))
    }).unwrap();
    let (previous, clock) = store.snapshot().unwrap();
    let desired = next(&previous, &clock);
    let cutoff = desired.keys[1].not_before;
    store.compare_and_swap(&previous, &desired, &clock).unwrap();
    base.set(cutoff - 1);
    {
        let mut controller = RotationController::new(&mut store).unwrap();
        queue.borrow_mut().extend([cutoff - 1, cutoff - 1, cutoff]);
        assert_eq!(controller.verify_response(response(31, i64::try_from(cutoff - 1).unwrap(), b"old")).unwrap_err().code, "rotation_key_interval");
        base.set(cutoff);
        let next_response = response(32, i64::try_from(cutoff).unwrap(), b"next");
        let old = InMemorySigner::from_seed(&[31; 32]).unwrap();
        let references: Vec<&str> = next_response.headers.iter().map(String::as_str).collect();
        assert_eq!(crate::signing::verify_response(
            &old.public_key(), next_response.status, &references,
            &next_response.request_signature, &next_response.body,
            i64::try_from(cutoff).unwrap(), 30,
        ).unwrap_err().code, "unknown_server_key");
        assert_eq!(controller.verify_response(next_response).unwrap(), b"next");
    }
    let (snapshot, clock) = store.snapshot().unwrap();
    assert_eq!(snapshot.revision, 2);
    assert_eq!(clock.high_water, cutoff);
    store.close().unwrap();
}
