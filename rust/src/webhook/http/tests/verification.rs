//! Fake-resolver and fake-transport tests of the verification senders
//! (spec 06 R5.9, R5.12, R6.10, R5.4, R5.5).
//!
//! The well-known document fetch and the challenge `POST` run over the same
//! hardened path and the same fakes as the delivery tests: [`FakeResolver`]
//! scripts the answers, [`FakeTransport`] records every request and answers
//! with a scripted status and body, and [`FakeClock`] records every
//! `sleep_until_ms`. Nothing below touches a socket, a DNS server or Tokio.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use crate::webhook::delivery::LastError;
use crate::webhook::http::document::WebhookDocumentFetcher;
use crate::webhook::http::sender::{Clock, SendAction, Sender, SenderConfig};
use crate::webhook::http::transport::{
    TransportFailure, TransportRequest, TransportResponse, WebhookTransport, MAX_DOCUMENT_BYTES,
};
use crate::webhook::verification::document::DocumentFetcher;
use crate::webhook::verification::gate::{EndpointGate, EndpointPair};
use crate::webhook::verification::nonce::{MAX_ECHO_BYTES, NONCE_TTL_MS};

use super::rebinding::{
    has_header, message, FakeClock, FakeResolver, FakeTransport, GateMode, Rig, ScriptedGate,
    LOOPBACK, NAME_URL, NONCE, PRINCIPAL, PUBLIC, T0_MS,
};

/// The well-known url of [`NAME_URL`] (spec 06 R5.9).
const DOCUMENT_URL: &str = "https://example.com/.well-known/mcp-webhook-receiver.json";

/// The R8.2 canonical url of [`DEFAULT_PORT_URL`] (spec 06 R8.2).
const CANONICAL_URL: &str = "https://example.com/hook";

/// The same callback written with its default port, so its R8.2 canonical
/// form differs from the subscribed spelling (spec 06 R8.2).
const DEFAULT_PORT_URL: &str = "https://example.com:443/hook";

/// A second nonce of the R5.3 shape, never the issued one (spec 06 R5.4).
const OTHER_NONCE: &str = "ABCDEFGHIJKLMNOPQRSTUV";

/// A valid receiver document body (spec 06 R5.9).
const DOCUMENT_BODY: &str = r#"{"receivers":["/hooks/"]}"#;

/// The body limit of one delivery request (spec 06 R1.2).
const BODY_LIMIT: usize = crate::webhook::delivery::MAX_BODY_BYTES;

/// One document fetcher wired to its fakes, so a test can read back what
/// they saw.
struct DocumentRig {
    fetcher: WebhookDocumentFetcher,
    transport: Arc<FakeTransport>,
    resolver: Arc<FakeResolver>,
}

/// Builds the real fetcher over one scripted transport and resolver.
fn document_rig(transport: FakeTransport, answers: Vec<Vec<IpAddr>>) -> DocumentRig {
    let transport = Arc::new(transport);
    let resolver = Arc::new(FakeResolver::new(answers));
    let fetcher = WebhookDocumentFetcher::new(transport.clone(), resolver.clone(), Vec::new());
    DocumentRig {
        fetcher,
        transport,
        resolver,
    }
}

/// Returns one address as the resolver answer type.
fn ip(address: Ipv4Addr) -> IpAddr {
    IpAddr::V4(address)
}

/// Builds a sender whose gate runs the challenge and whose transport answers
/// every request with `status` and `body` (spec 06 R5.4, R5.5).
fn challenge_rig(status: u16, body: Vec<u8>) -> Rig {
    challenge_rig_with(FakeTransport::new(vec![(status, None)]).with_body(body))
}

/// Builds a sender whose gate runs the challenge over the given transport
/// (spec 06 R5.4, R5.5).
fn challenge_rig_with(transport: FakeTransport) -> Rig {
    let transport = Arc::new(transport);
    let resolver = Arc::new(FakeResolver::new(vec![vec![ip(PUBLIC)]]));
    let clock = Arc::new(FakeClock::new(T0_MS));
    let gate = Arc::new(ScriptedGate::new(GateMode::Challenge));
    let sender = Sender::new(
        transport.clone(),
        resolver.clone(),
        clock.clone(),
        SenderConfig {
            allowed_ranges: Vec::new(),
            max_body_bytes: BODY_LIMIT,
            verification_ttl_ms: None,
        },
        gate.clone(),
    );
    Rig {
        sender,
        transport,
        resolver,
        clock,
        gate,
    }
}

#[test]
fn r5_12_a_blocked_document_answer_never_reaches_the_transport() {
    let rig = document_rig(
        FakeTransport::new(vec![(200, None)]),
        vec![vec![ip(LOOPBACK)]],
    );
    let error = rig
        .fetcher
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
    let rig = document_rig(
        FakeTransport::new(vec![(200, None)]).with_body(DOCUMENT_BODY.as_bytes().to_vec()),
        vec![vec![ip(PUBLIC)]],
    );
    let document = rig
        .fetcher
        .fetch(NAME_URL)
        .expect("a valid document parses");
    assert_eq!(document.receivers, vec!["/hooks/".to_owned()]);
    assert_eq!(rig.transport.calls(), 1);
    let requests = rig.transport.requests();
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].url, DOCUMENT_URL);
    assert_eq!(requests[0].connect.address, PUBLIC.to_string());
    assert!(requests[0]
        .headers
        .iter()
        .any(|(name, value)| name == "Accept" && value == "application/json"));
}

#[test]
fn r5_9_a_404_is_document_fetch_failed() {
    let rig = document_rig(
        FakeTransport::new(vec![(404, None)]),
        vec![vec![ip(PUBLIC)]],
    );
    let error = rig
        .fetcher
        .fetch_receiver_document(NAME_URL)
        .expect_err("a 404 sets no route 4");
    assert_eq!(error.code, "document_fetch_failed");
    assert_eq!(error.reason(), Some("status_404"));
    assert_eq!(rig.transport.calls(), 1);
}

#[test]
fn r5_9_an_oversized_document_is_too_large() {
    let rig = document_rig(
        FakeTransport::new(vec![(200, None)]).with_body(vec![b'x'; MAX_DOCUMENT_BYTES + 1]),
        vec![vec![ip(PUBLIC)]],
    );
    let error = rig
        .fetcher
        .fetch_receiver_document(NAME_URL)
        .expect_err("one byte over the cap is refused");
    assert_eq!(error.code, "document_fetch_failed");
    assert_eq!(error.reason(), Some("too_large"));
    assert_eq!(rig.transport.calls(), 1);
}

#[test]
fn r5_9_an_overflow_with_a_valid_json_prefix_is_too_large() {
    // The stored prefix alone would parse, so only the R1.2/R5.9 overflow
    // flag can refuse it.
    let rig = document_rig(
        FakeTransport::new(vec![(200, None)])
            .with_body(DOCUMENT_BODY.as_bytes().to_vec())
            .with_overflow(),
        vec![vec![ip(PUBLIC)]],
    );
    let error = rig
        .fetcher
        .fetch_receiver_document(NAME_URL)
        .expect_err("an overflow is refused before parsing");
    assert_eq!(error.code, "document_fetch_failed");
    assert_eq!(error.reason(), Some("too_large"));
}

#[test]
fn r5_9_a_declared_length_above_the_cap_is_too_large() {
    let rig = document_rig(
        FakeTransport::new(vec![(200, None)])
            .with_body(DOCUMENT_BODY.as_bytes().to_vec())
            .with_declared(MAX_DOCUMENT_BYTES as u64 + 1),
        vec![vec![ip(PUBLIC)]],
    );
    let error = rig
        .fetcher
        .fetch_receiver_document(NAME_URL)
        .expect_err("a declared length above the cap is refused");
    assert_eq!(error.code, "document_fetch_failed");
    assert_eq!(error.reason(), Some("too_large"));
}

#[test]
fn r6_10_a_document_redirect_is_refused_and_not_followed() {
    let rig = document_rig(
        FakeTransport::new(vec![(302, None)]),
        vec![vec![ip(PUBLIC)]],
    );
    let error = rig
        .fetcher
        .fetch_receiver_document(NAME_URL)
        .expect_err("a 3xx is never followed");
    assert_eq!(error.code, "redirect_refused");
    assert_eq!(error.reason(), Some("redirect"));
    assert_eq!(rig.transport.calls(), 1);
}

#[test]
fn r5_4_an_echoed_challenge_is_ok() {
    let body = format!(r#"{{"challenge":"{NONCE}"}}"#).into_bytes();
    let rig = challenge_rig(200, body);
    let outcome = rig.sender.deliver(&message(NAME_URL));
    assert_eq!(outcome.action, SendAction::Accepted);
    let verdicts = rig.gate.verdicts();
    assert_eq!(verdicts.len(), 1);
    assert!(verdicts[0].ok);
    assert_eq!(verdicts[0].code, None);
    assert_eq!(verdicts[0].reason, None);
    assert_eq!(rig.gate.verifies(), vec![T0_MS]);
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
    // The delivery follows the same gate and is sent after the challenge.
    assert_eq!(rig.transport.calls(), 2);
    assert!(rig.clock.sleeps().is_empty());
}

#[test]
fn r5_5_the_challenge_destination_is_the_canonical_url() {
    let body = format!(r#"{{"challenge":"{NONCE}"}}"#).into_bytes();
    let rig = challenge_rig(200, body);
    let outcome = rig.sender.deliver(&message(DEFAULT_PORT_URL));
    assert_eq!(outcome.action, SendAction::Accepted);
    let requests = rig.transport.requests();
    assert_eq!(requests[0].url, CANONICAL_URL);
    assert_ne!(requests[0].url, DEFAULT_PORT_URL);
    assert_eq!(requests[0].connect.address, PUBLIC.to_string());
    let body: serde_json::Value =
        serde_json::from_slice(&requests[0].body).expect("the challenge body is JSON");
    assert_eq!(body["challenge"], NONCE);
    assert_eq!(body["type"], "verification");
}

#[test]
fn r5_4_a_wrong_nonce_is_challenge_failed() {
    let body = format!(r#"{{"challenge":"{OTHER_NONCE}"}}"#).into_bytes();
    let rig = challenge_rig(200, body);
    let outcome = rig.sender.deliver(&message(NAME_URL));
    assert_eq!(
        outcome.action,
        SendAction::Final {
            last_error: LastError::ChallengeFailed
        }
    );
    assert_eq!(rig.transport.calls(), 1);
    let verdicts = rig.gate.verdicts();
    assert_eq!(verdicts[0].code, Some("challenge_failed"));
    assert_eq!(verdicts[0].reason.as_deref(), Some("mismatch"));
    assert!(rig.clock.sleeps().is_empty());
}

#[test]
fn r5_4_a_challenge_is_never_retried() {
    let rig = challenge_rig(503, Vec::new());
    let outcome = rig.sender.deliver(&message(NAME_URL));
    assert_eq!(
        outcome.action,
        SendAction::Final {
            last_error: LastError::ChallengeFailed
        }
    );
    assert_eq!(rig.transport.calls(), 1);
    let verdicts = rig.gate.verdicts();
    assert_eq!(verdicts[0].code, Some("challenge_failed"));
    assert_eq!(verdicts[0].reason.as_deref(), Some("status"));
    assert!(rig.clock.sleeps().is_empty());
}

/// Returns a valid echo of [`NONCE`] as the bytes the transport answers with
/// (spec 06 R5.4).
fn echo_body() -> Vec<u8> {
    format!(r#"{{"challenge":"{NONCE}"}}"#).into_bytes()
}

/// Asserts that `rig` ended the message as `challenge_failed` with the fixed
/// reason `too_large`, after the one challenge `POST` and no retry
/// (spec 06 R5.4, R5.5).
fn assert_too_large(rig: &Rig) {
    let outcome = rig.sender.deliver(&message(NAME_URL));
    assert_eq!(
        outcome.action,
        SendAction::Final {
            last_error: LastError::ChallengeFailed
        }
    );
    assert_eq!(rig.transport.calls(), 1, "the challenge is never retried");
    let verdicts = rig.gate.verdicts();
    assert_eq!(verdicts.len(), 1);
    assert_eq!(verdicts[0].code, Some("challenge_failed"));
    assert_eq!(verdicts[0].reason.as_deref(), Some("too_large"));
    assert!(rig.clock.sleeps().is_empty());
}

#[test]
fn r5_4_an_echo_above_4096_bytes_is_too_large() {
    // A valid JSON echo padded with trailing spaces: only the size cap can
    // refuse it (spec 06 R5.4).
    let mut body = echo_body();
    body.resize(MAX_ECHO_BYTES + 1, b' ');
    assert_eq!(body.len(), MAX_ECHO_BYTES + 1);
    let rig = challenge_rig(200, body);
    assert_too_large(&rig);
}

#[test]
fn r5_4_a_declared_length_above_4096_is_too_large() {
    let rig = challenge_rig_with(
        FakeTransport::new(vec![(200, None)])
            .with_body(echo_body())
            .with_declared(MAX_ECHO_BYTES as u64 + 1),
    );
    assert_too_large(&rig);
}

#[test]
fn r5_4_an_overflowing_echo_with_a_valid_json_prefix_is_too_large() {
    // The stored prefix alone is a valid echo, so only the R1.2/R5.4 overflow
    // flag can refuse it (spec 06 R5.4).
    let rig = challenge_rig_with(
        FakeTransport::new(vec![(200, None)])
            .with_body(echo_body())
            .with_overflow(),
    );
    assert_too_large(&rig);
}

/// Returns the echo an endpoint answers with: an object carrying the
/// `challenge` member of the request body (spec 06 R5.4).
fn echo_of(request: &TransportRequest) -> Vec<u8> {
    let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&request.body) else {
        return Vec::new();
    };
    serde_json::to_vec(&serde_json::json!({"challenge": parsed["challenge"].clone()}))
        .unwrap_or_default()
}

/// A transport that echoes the request's `challenge` and moves the test clock
/// forward after every send, so the sample the sender takes after the
/// challenge response is far later than the instant the nonce was issued
/// (spec 06 R5.3, R5.4).
struct SlowTransport {
    inner: Arc<FakeTransport>,
    clock: Arc<FakeClock>,
    step_ms: i64,
}

impl WebhookTransport for SlowTransport {
    fn send(&self, request: &TransportRequest) -> Result<TransportResponse, TransportFailure> {
        let mut response = self.inner.send(request)?;
        response.body = echo_of(request);
        self.clock.advance(self.step_ms);
        Ok(response)
    }
}

#[test]
fn r5_3_a_response_that_outlived_the_nonce_is_expired() {
    // The echo itself is correct, but it is judged 600_001 ms after the issue
    // instant, so the nonce is spent and no delivery follows
    // (spec 06 R5.3, R5.4).
    let transport = Arc::new(FakeTransport::new(vec![(200, None)]));
    let resolver = Arc::new(FakeResolver::new(vec![vec![ip(PUBLIC)]]));
    let clock = Arc::new(FakeClock::new(T0_MS));
    let slow = Arc::new(SlowTransport {
        inner: transport.clone(),
        clock: clock.clone(),
        step_ms: NONCE_TTL_MS + 1,
    });
    let gate = Arc::new(EndpointGate::new(Vec::new(), None));
    let sender = Sender::new(
        slow,
        resolver,
        clock.clone(),
        SenderConfig {
            allowed_ranges: Vec::new(),
            max_body_bytes: BODY_LIMIT,
            verification_ttl_ms: None,
        },
        gate.clone(),
    );

    let outcome = sender.deliver(&message(NAME_URL));
    assert_eq!(
        outcome.action,
        SendAction::Final {
            last_error: LastError::ChallengeFailed
        }
    );
    assert_eq!(outcome.attempts, 0);
    assert_eq!(transport.calls(), 1, "only the challenge POST was sent");
    assert!(clock.sleeps().is_empty());
    let pair = EndpointPair::new(PRINCIPAL, NAME_URL).expect("the test url is a valid pair");
    assert!(!gate.cached(&pair, clock.now_ms()));
}
