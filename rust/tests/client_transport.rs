//! Port of Go client/transport_test.go (six tests): SigningTransport signs
//! every request against the fake TestServer and verifies every response;
//! error mapping, streaming guard, tamper detection and window checks follow
//! the Go assertions exactly.

mod common;

use std::sync::{Arc, Mutex};

use common::harness::*;

use mcp_jack::client::signer::Signer;
use mcp_jack::client::transport::{
    HttpRequest, HttpResponse, SigningTransport, Transport, TransportError,
};
use mcp_jack::error::codes;
use serde_json::json;

/// Builds a SigningTransport over the fake server: alice signs, the test
/// server key is pinned, fixed clock, window 30 (Go: newTransport).
fn new_transport(srv: &Arc<TestServer>) -> SigningTransport<Arc<TestServer>> {
    SigningTransport {
        transport: Arc::clone(srv),
        aud: FIXTURE_AUD.to_string(),
        signer: Arc::new(signer_by_name("alice")),
        server_key: srv.pub_key,
        now: fixed_clock(FIXTURE_NOW),
        nonce: Arc::new(|| Ok(vec![7u8; 16])),
        window_seconds: 30,
    }
}

/// A signed POST to the /mcp target with a JSON body (Go: postMCP).
fn post_mcp(body: &[u8]) -> HttpRequest {
    HttpRequest {
        method: "POST".to_string(),
        url: TEST_URL.to_string(),
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: body.to_vec(),
    }
}

/// Go: TestTransportRoundTripHappyPath.
#[test]
fn transport_round_trip_happy_path() {
    let srv = TestServer::new();
    let want_body = rpc_result_body(&json!({"ok": true}));
    let captured: Arc<Mutex<Option<(String, i64)>>> = Arc::new(Mutex::new(None));
    let captured_clone = Arc::clone(&captured);
    srv.set_handler(Box::new(move |srv, _method, _target, auth, _body| {
        *captured_clone.lock().expect("mutex") = Some((auth.kid.clone(), auth.ts));
        srv.write_signed_json(auth, 200, &want_body)
    }));

    let tr = new_transport(&srv);
    let resp = tr
        .round_trip(post_mcp(br#"{"ping":1}"#))
        .expect("signed round trip must verify");
    assert_eq!(200, resp.status);
    assert_eq!(rpc_result_body(&json!({"ok": true})), resp.body);

    let got = captured.lock().expect("mutex").clone().expect("captured");
    assert_eq!(got.0, signer_by_name("alice").kid(), "server saw kid");
    assert_eq!(got.1, FIXTURE_NOW, "server saw ts");
}

/// Go: TestTransportUnsigned401SurfacesError. Only the status is trusted:
/// the unsigned body is never parsed (spec 01 section 5; Go divergence: Go
/// surfaces the untrusted body code/message).
#[test]
fn transport_unsigned_401_surfaces_error() {
    let srv = TestServer::new();
    srv.set_handler(Box::new(|srv, _method, _target, _auth, _body| {
        srv.write_unsigned_json(401, br#"{"error":{"code":"unknown_key","message":"nope"}}"#)
    }));
    let tr = new_transport(&srv);
    let err = tr
        .round_trip(post_mcp(br#"{"ping":1}"#))
        .expect_err("401 without auth");
    match err {
        TransportError::Unauthenticated(u) => {
            assert_eq!(u.status, 401);
        }
        other => panic!("expected Unauthenticated, got {other:?}"),
    }
}

/// Go: TestTransportSigned401PassesThrough.
#[test]
fn transport_signed_401_passes_through() {
    let srv = TestServer::new();
    let want_body = br#"{"error":{"code":"unknown_key","message":"expired"}}"#.to_vec();
    srv.set_handler(Box::new(move |srv, _method, _target, auth, _body| {
        srv.write_signed_json(auth, 401, &want_body)
    }));
    let tr = new_transport(&srv);
    let resp = tr
        .round_trip(post_mcp(br#"{"ping":1}"#))
        .expect("a signed 401 verifies and passes through");
    assert_eq!(401, resp.status);
    assert_eq!(
        br#"{"error":{"code":"unknown_key","message":"expired"}}"#.to_vec(),
        resp.body
    );
}

/// Go: TestTransportRefusesStreamingResponse.
#[test]
fn transport_refuses_streaming_response() {
    let srv = TestServer::new();
    srv.set_handler(Box::new(|_srv, _method, _target, _auth, _body| {
        // Streams cannot be body-hashed so they are refused per spec 01
        // section 5 (open question Q1) — signed or not; an unsigned stream
        // suffices here because the streaming guard fires before verification.
        HttpResponse {
            status: 200,
            headers: vec![("Content-Type".to_string(), "text/event-stream".to_string())],
            body: b"data: x\n\n".to_vec(),
        }
    }));
    let tr = new_transport(&srv);
    let err = tr
        .round_trip(post_mcp(br#"{"ping":1}"#))
        .expect_err("streaming must be refused");
    assert_eq!(TransportError::Streaming, err);
}

/// Go: TestTransportDetectsTamperedBody.
#[test]
fn transport_detects_tampered_body() {
    let srv = TestServer::new();
    srv.set_handler(Box::new(|srv, _method, _target, auth, _body| {
        // The response signature is computed over body_a, but body_b (same
        // length, one flipped byte) is sent — exactly the Go test.
        let body_a = rpc_result_body(&json!({"ok": true}));
        let mut body_b = body_a.clone();
        let last = body_b.len() - 2;
        body_b[last] = b'X';
        let header = srv.sign_response(&auth.sig, 200, &body_a);
        HttpResponse {
            status: 200,
            headers: vec![
                ("Jack-Auth".to_string(), header),
                ("Content-Type".to_string(), "application/json".to_string()),
            ],
            body: body_b,
        }
    }));
    let tr = new_transport(&srv);
    let err = tr
        .round_trip(post_mcp(br#"{"ping":1}"#))
        .expect_err("tampered body must fail verification");
    match err {
        TransportError::Protocol(j) => assert_eq!(j.code, codes::BAD_SIGNATURE),
        other => panic!("expected Protocol(bad_signature), got {other:?}"),
    }
}

/// Go: TestTransportRejectsUnpinnedServerKey.
#[test]
fn transport_rejects_unpinned_server_key() {
    let srv = TestServer::new();
    let mut tr = new_transport(&srv);
    tr.server_key = fresh_key();
    srv.set_handler(Box::new(|srv, _method, _target, auth, _body| {
        srv.write_signed_json(auth, 200, &rpc_result_body(&json!({"ok": true})))
    }));
    let err = tr
        .round_trip(post_mcp(br#"{"ping":1}"#))
        .expect_err("a response from an unpinned key must be rejected");
    match err {
        TransportError::Protocol(j) => assert_eq!(j.code, codes::UNKNOWN_SERVER_KEY),
        other => panic!("expected Protocol(unknown_server_key), got {other:?}"),
    }
}

/// Go: TestTransportRejectsStaleTimestamp.
#[test]
fn transport_rejects_stale_timestamp() {
    let srv = TestServer::new();
    let mut tr = new_transport(&srv);
    // The response ts stays at the fixture clock, so the shifted request
    // clock puts it outside the window.
    tr.now = fixed_clock(FIXTURE_NOW + 3600);
    srv.set_handler(Box::new(|srv, _method, _target, auth, _body| {
        srv.write_signed_json(auth, 200, &rpc_result_body(&json!({"ok": true})))
    }));
    let err = tr
        .round_trip(post_mcp(br#"{"ping":1}"#))
        .expect_err("an out-of-window response ts must be rejected");
    match err {
        TransportError::Protocol(j) => assert_eq!(j.code, codes::TIMESTAMP_OUT_OF_WINDOW),
        other => panic!("expected Protocol(timestamp_out_of_window), got {other:?}"),
    }
}
