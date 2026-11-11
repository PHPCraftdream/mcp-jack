use super::store_tests::{initialize, options, Sandbox};
use super::*;
use crate::auth_header::{format_response_auth, ResponseAuth};
use crate::client::{InMemorySigner, Signer};
use crate::encoding::{body_hash, decode_b64url_fixed, encode_b64url};
use crate::signing::{request_signing_string, response_signing_string};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

fn chain() -> Vec<Record> {
    let options = options();
    let old = InMemorySigner::from_seed(&[31; 32]).unwrap();
    let next = InMemorySigner::from_seed(&[32; 32]).unwrap();
    let last = InMemorySigner::from_seed(&[33; 32]).unwrap();
    let binding = Binding { endpoint: &options.binding.endpoint, aud: &options.binding.aud };
    let first = create_record(binding, &options.checkpoint, &old, &next, 100).unwrap();
    let cursor = Checkpoint {
        ordinal: first.ordinal, hash: first.hash.clone(), kid: first.new_kid.clone(),
        public_key: first.public_key, published_at: first.published_at,
    };
    let second = create_record(binding, &cursor, &next, &last, 100).unwrap();
    vec![first, second]
}

fn payload(records: &[Record], head: ResultCursor, complete: bool) -> serde_json::Value {
    let options = options();
    serde_json::json!({
        "current": {"kid": options.checkpoint.kid, "public_key": encode_b64url(&options.checkpoint.public_key)},
        "records": records.iter().map(|record| record.wire.clone()).collect::<Vec<_>>(),
        "head": {"ordinal": head.ordinal, "hash": head.hash}, "complete": complete,
    })
}

fn signed_page(seed: u8, timestamp: u64, status: i64, payload: serde_json::Value, cursor: &ResultCursor) -> RotationResponse {
    let body = serde_json::json!({"jsonrpc":"2.0","id":7,"result":{
        "content":[{"type":"text","text":payload.to_string()}],
        "structuredContent":payload,"isError":false,
    }}).to_string().into_bytes();
    let server = InMemorySigner::from_seed(&[seed; 32]).unwrap();
    let client = InMemorySigner::from_seed(&[34; 32]).unwrap();
    let request_body = serde_json::json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{
        "name":"jack.server.key","arguments":{"after_ordinal":cursor.ordinal,"after_hash":cursor.hash},
    }}).to_string();
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).unwrap();
    let timestamp = i64::try_from(timestamp).unwrap();
    let request = request_signing_string("POST", "/mcp", "store-test", client.kid(), timestamp, &encode_b64url(&nonce), request_body.as_bytes());
    let request_signature = encode_b64url(&client.sign(request.as_bytes()).unwrap());
    let signing = response_signing_string(status, &request_signature, server.kid(), timestamp, &body);
    RotationResponse {
        status, request_signature, body,
        headers: vec![format_response_auth(&ResponseAuth {
            kid: server.kid().into(), ts: timestamp,
            sig: encode_b64url(&server.sign(signing.as_bytes()).unwrap()),
        })],
    }
}

fn cursor(record: &Record) -> ResultCursor {
    ResultCursor { ordinal: record.ordinal, hash: record.hash.clone() }
}
fn anchor() -> ResultCursor { ResultCursor { ordinal: 0, hash: "-".into() } }

#[test]
fn explicit_pages_overlap_declared_head_duplicate_noop_and_clean_reopen() {
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    initialize(&path);
    let mut store = RotationTrustStore::open(&path, options(), || Ok(100)).unwrap();
    let records = chain();
    {
        let mut controller = RotationController::new(&mut store).unwrap();
        let empty = controller.accept_refresh(signed_page(31, 100, 200, payload(&[], anchor(), true), &anchor()), b"7", &anchor()).unwrap();
        assert!(!empty.committed); assert_eq!(empty.revision, 1);
        let first = controller.accept_refresh(signed_page(31, 100, 200, payload(&records[..1], cursor(&records[1]), false), &anchor()), b"7", &anchor()).unwrap();
        assert!(first.committed); assert_eq!(first.revision, 2);
        assert_eq!(first.head, cursor(&records[1]));
        assert_eq!(first.terminal, cursor(&records[0]));
        assert!(!first.complete);
        let second = controller.accept_refresh(signed_page(31, 100, 200, payload(&records, cursor(&records[1]), true), &first.terminal), b"7", &first.terminal).unwrap();
        assert!(second.committed); assert_eq!(second.revision, 3);
        let duplicate = controller.accept_refresh(signed_page(31, 100, 200, payload(&records, cursor(&records[1]), true), &second.terminal), b"7", &second.terminal).unwrap();
        assert!(!duplicate.committed); assert_eq!(duplicate.revision, 3);
    }
    store.close().unwrap();
    let mut reopened = RotationTrustStore::open(&path, options(), || Ok(100)).unwrap();
    let (snapshot, _) = reopened.snapshot().unwrap();
    assert_eq!(snapshot.revision, 3);
    assert_eq!(snapshot.head, cursor(&records[1]));
    assert_eq!(snapshot.records.len(), 2);
    assert_eq!(selected_ordinal(&records, records[0].activates_at).unwrap(), 2);
    reopened.close().unwrap();
}

#[test]
fn refresh_refuses_current_id_status_cursor_future_publication_and_tampered_proofs() {
    let sandbox = Sandbox::new(); let path = sandbox.file(); initialize(&path);
    let calls = Rc::new(Cell::new(0)); let callback = calls.clone();
    let mut store = RotationTrustStore::open(&path, options(), move || { callback.set(callback.get()+1); Ok(100) }).unwrap();
    let records = chain(); let head = cursor(&records[0]);
    {
        let mut controller = RotationController::new(&mut store).unwrap();
        calls.set(0);
        assert_eq!(controller.accept_refresh(signed_page(99, 100, 200, payload(&records[..1], head.clone(), true), &anchor()), b"7", &anchor()).unwrap_err().code, "unknown_server_key");
        assert_eq!(calls.get(), 0);
        for case in ["current", "id", "status", "cursor", "future", "reuse", "next-proof", "old-proof"] {
            let mut changed = records[..1].to_vec();
            if case == "future" {
                let options = options();
                let old = InMemorySigner::from_seed(&[31; 32]).unwrap(); let next = InMemorySigner::from_seed(&[32; 32]).unwrap();
                changed[0] = create_record(Binding { endpoint: &options.binding.endpoint, aud: &options.binding.aud }, &options.checkpoint, &old, &next, 101).unwrap();
            }
            if case == "reuse" {
                let options = options();
                let old = InMemorySigner::from_seed(&[32; 32]).unwrap();
                let reused = InMemorySigner::from_seed(&[31; 32]).unwrap();
                let previous = Checkpoint {
                    ordinal: changed[0].ordinal, hash: changed[0].hash.clone(),
                    kid: changed[0].new_kid.clone(), public_key: changed[0].public_key,
                    published_at: 100,
                };
                changed.push(create_record(Binding { endpoint: &options.binding.endpoint, aud: &options.binding.aud }, &previous, &old, &reused, 100).unwrap());
            }
            if case == "next-proof" || case == "old-proof" {
                let mut lines: Vec<String> = changed[0].wire.split('\n').map(str::to_owned).collect();
                let index = if case == "next-proof" { 10 } else { 11 };
                let mut signature = decode_b64url_fixed(&lines[index], 64).unwrap(); signature[0] ^= 1;
                lines[index] = encode_b64url(&signature);
                changed[0].wire = lines.join("\n");
                changed[0].hash = body_hash(changed[0].wire.as_bytes());
            }
            let mut page = payload(&changed, cursor(changed.last().unwrap()), true);
            if case == "current" {
                let wrong = InMemorySigner::from_seed(&[32; 32]).unwrap();
                page["current"] = serde_json::json!({"kid":wrong.kid(),"public_key":encode_b64url(&wrong.public_key())});
            }
            let requested = if case == "cursor" { head.clone() } else { anchor() };
            let status = if case == "status" { 201 } else { 200 };
            let expected_id = if case == "id" { b"8" } else { b"7" };
            let error = controller.accept_refresh(signed_page(31, 100, status, page, &requested), expected_id, &requested).unwrap_err();
            assert_eq!(error.code, if case == "cursor" { "rotation_gap" } else if case == "future" || case == "reuse" || case.ends_with("proof") { "rotation_record_invalid" } else { "rotation_result_invalid" }, "{case}");
            assert_eq!(error.http_status, 0);
        }
    }
    assert_eq!(store.snapshot().unwrap().0.revision, 1);
    store.close().unwrap();
}

#[test]
fn first_bridge_equality_and_late_final_failure_preserve_exact_commit_outcome() {
    let records = chain(); let activation = records[0].activates_at;
    for late_commit in [false, true] {
        let sandbox = Sandbox::new(); let path = sandbox.file(); initialize(&path);
        let queue = Rc::new(RefCell::new(VecDeque::new())); let callback = queue.clone();
        let mut store = RotationTrustStore::open(&path, options(), move || Ok(callback.borrow_mut().pop_front().unwrap_or(100))).unwrap();
        {
            let mut controller = RotationController::new(&mut store).unwrap();
            if late_commit { queue.borrow_mut().extend([activation-1, activation-1, activation-1, activation]); }
            else { queue.borrow_mut().extend([activation-1, activation-1, activation]); }
            let error = controller.accept_refresh(signed_page(31, activation-1, 200, payload(&records[..1], cursor(&records[0]), true), &anchor()), b"7", &anchor()).unwrap_err();
            assert_eq!(error.code, if late_commit { "rotation_key_interval" } else { "rotation_bridge_expired" });
            assert!(queue.borrow().is_empty());
        }
        let (snapshot, clock) = store.snapshot().unwrap();
        assert_eq!(snapshot.revision, if late_commit { 2 } else { 1 });
        assert_eq!(snapshot.head.ordinal, u64::from(late_commit));
        assert_eq!(clock.high_water, activation);
        store.close().unwrap();
    }
}

pub(super) fn crash_refresh<C: FnMut() -> Result<u64, RotationError>>(store: &mut RotationTrustStore<C>) {
    let records = chain();
    let mut controller = RotationController::new(store).unwrap();
    controller.accept_refresh(signed_page(31, 100, 200, payload(&records[..1], cursor(&records[0]), true), &anchor()), b"7", &anchor()).unwrap();
}
