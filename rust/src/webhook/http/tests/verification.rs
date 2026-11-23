//! Fake-resolver and fake-transport tests of the verification senders
//! (spec 06 R5.9, R5.12, R6.10, R5.4).
//!
//! The well-known document fetch and the challenge `POST` run over the same
//! [`Sender`] and the same fakes as the delivery tests: [`FakeResolver`]
//! scripts the answers, [`FakeTransport`] records every request and answers
//! with a scripted status and body, and [`FakeClock`] records every
//! `sleep_until`. Nothing below touches a socket, a DNS server or Tokio.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use crate::webhook::delivery::MAX_BODY_BYTES;
use crate::webhook::http::transport::{Sender, SenderConfig, MAX_DOCUMENT_BYTES};

use super::rebinding::{
    message, FakeClock, FakeResolver, FakeTransport, LOOPBACK, NAME_URL, PUBLIC, T0,
};

/// The well-known url of [`NAME_URL`] (spec 06 R5.9).
const DOCUMENT_URL: &str = "https://example.com/.well-known/mcp-webhook-receiver.json";

/// A nonce of the R5.3 shape: 22 base64url characters.
const NONCE: &str = "abcdefghijklmnopqrstuv";

/// A second nonce of the same shape, never the issued one (spec 06 R5.4).
const OTHER_NONCE: &str = "ABCDEFGHIJKLMNOPQRSTUV";

/// One sender wired to its fakes, so a test can read back what they saw.
struct Rig {
    sender: Sender,
    transport: Arc<FakeTransport>,
    resolver: Arc<FakeResolver>,
    clock: Arc<FakeClock>,
}

/// Builds the real sender over the scripted resolver and transport, the
/// recording clock and one response body for every scripted status.
fn rig(answers: Vec<Vec<IpAddr>>, responses: Vec<(u16, Option<i64>)>, body: Vec<u8>) -> Rig {
    let transport = Arc::new(FakeTransport::new(responses).with_body(body));
    let resolver = Arc::new(FakeResolver::new(answers));
    let clock = Arc::new(FakeClock::new(T0));
    let sender = Sender::new(
        transport.clone(),
        resolver.clone(),
        clock.clone(),
        SenderConfig {
            allowed_ranges: Vec::new(),
            max_body_bytes: MAX_BODY_BYTES,
        },
    );
    Rig {
        sender,
        transport,
        resolver,
        clock,
    }
}

/// Returns one address as the resolver answer type.
fn ip(address: Ipv4Addr) -> IpAddr {
    IpAddr::V4(address)
}

/// Reports whether one sent request carries the named header.
fn has_header(request: &crate::webhook::http::transport::TransportRequest, name: &str) -> bool {
    request
        .headers
        .iter()
        .any(|(header, _)| header.eq_ignore_ascii_case(name))
}

#[test]
fn r5_12_a_blocked_document_answer_never_reaches_the_transport() {
    let rig = rig(vec![vec![ip(LOOPBACK)]], vec![(200, None)], Vec::new());
    let error = rig
        .sender
        .fetch_receiver_document(NAME_URL)
        .expect_err("a blocked answer is refused");
    assert_eq!(error.http_status, 400);
    assert_eq!(error.code, "blocked_address");
    assert_eq!(error.reason(), Some("loopback"));
    assert_eq!(rig.transport.calls(), 0);
    let queries = rig.resolver.queries();
    assert_eq!(queries.len(), 2, "validation plus the R6.9 recheck");
    assert_eq!(queries[0], ("example.com".to_owned(), 443));
}

#[test]
fn r5_9_a_200_document_with_receivers_parses() {
    let rig = rig(
        vec![vec![ip(PUBLIC)]],
        vec![(200, None)],
        br#"{"receivers":["/hooks/"]}"#.to_vec(),
    );
    let document = rig
        .sender
        .fetch_receiver_document(NAME_URL)
        .expect("a valid document parses");
    assert_eq!(document.receivers, vec!["/hooks/".to_owned()]);
    assert_eq!(rig.transport.calls(), 1);
    let requests = rig.transport.requests();
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].url, DOCUMENT_URL);
    assert_eq!(requests[0].connect.address, PUBLIC.to_string());
    assert!(has_header(&requests[0], "Accept"));
    assert!(requests[0]
        .headers
        .iter()
        .any(|(name, value)| name == "Accept" && value == "application/json"));
}

#[test]
fn r5_9_a_404_is_document_fetch_failed() {
    let rig = rig(vec![vec![ip(PUBLIC)]], vec![(404, None)], Vec::new());
    let error = rig
        .sender
        .fetch_receiver_document(NAME_URL)
        .expect_err("a 404 sets no route 4");
    assert_eq!(error.code, "document_fetch_failed");
    assert_eq!(error.reason(), Some("status_404"));
    assert_eq!(rig.transport.calls(), 1);
    assert!(rig.clock.sleeps().is_empty());
}

#[test]
fn r5_9_an_oversized_document_is_too_large() {
    let rig = rig(
        vec![vec![ip(PUBLIC)]],
        vec![(200, None)],
        vec![b'x'; MAX_DOCUMENT_BYTES + 1],
    );
    let error = rig
        .sender
        .fetch_receiver_document(NAME_URL)
        .expect_err("one byte over the cap is refused");
    assert_eq!(error.code, "document_fetch_failed");
    assert_eq!(error.reason(), Some("too_large"));
    assert_eq!(rig.transport.calls(), 1);
}

#[test]
fn r6_10_a_document_redirect_is_refused_and_not_followed() {
    let rig = rig(vec![vec![ip(PUBLIC)]], vec![(302, None)], Vec::new());
    let error = rig
        .sender
        .fetch_receiver_document(NAME_URL)
        .expect_err("a 3xx is never followed");
    assert_eq!(error.code, "redirect_refused");
    assert_eq!(error.reason(), Some("redirect"));
    assert_eq!(rig.transport.calls(), 1);
}

#[test]
fn r5_4_an_echoed_challenge_is_ok() {
    let rig = rig(
        vec![vec![ip(PUBLIC)]],
        vec![(200, None)],
        format!(r#"{{"challenge":"{NONCE}"}}"#).into_bytes(),
    );
    let verdict = rig.sender.send_challenge(&message(NAME_URL), NONCE);
    assert!(verdict.ok);
    assert_eq!(verdict.code, None);
    assert_eq!(verdict.reason, None);
    assert_eq!(rig.transport.calls(), 1);
    let requests = rig.transport.requests();
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].url, NAME_URL);
    assert_eq!(requests[0].connect.address, PUBLIC.to_string());
    assert!(has_header(&requests[0], "webhook-id"));
    assert!(has_header(&requests[0], "webhook-timestamp"));
    assert!(has_header(&requests[0], "webhook-signature"));
    assert!(has_header(&requests[0], "X-MCP-Subscription-Id"));
    let body: serde_json::Value =
        serde_json::from_slice(&requests[0].body).expect("the challenge body is JSON");
    assert_eq!(body["type"], "verification");
    assert_eq!(body["challenge"], NONCE);
}

#[test]
fn r5_4_a_wrong_nonce_is_challenge_failed() {
    let rig = rig(
        vec![vec![ip(PUBLIC)]],
        vec![(200, None)],
        format!(r#"{{"challenge":"{OTHER_NONCE}"}}"#).into_bytes(),
    );
    let verdict = rig.sender.send_challenge(&message(NAME_URL), NONCE);
    assert!(!verdict.ok);
    assert_eq!(verdict.code, Some("challenge_failed"));
    assert_eq!(verdict.reason.as_deref(), Some("mismatch"));
}

#[test]
fn r5_4_a_challenge_is_never_retried() {
    let rig = rig(vec![vec![ip(PUBLIC)]], vec![(503, None)], Vec::new());
    let verdict = rig.sender.send_challenge(&message(NAME_URL), NONCE);
    assert!(!verdict.ok);
    assert_eq!(verdict.code, Some("challenge_failed"));
    assert_eq!(verdict.reason.as_deref(), Some("status"));
    assert_eq!(rig.transport.calls(), 1);
    assert!(rig.clock.sleeps().is_empty());
}
