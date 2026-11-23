//! Fake-resolver and fake-transport tests of the hardened delivery path
//! (spec 06 R6.8-R6.10, R1.7, R1.9).
//!
//! Nothing below touches a socket, a DNS server or Tokio. [`FakeResolver`]
//! returns a scripted answer list per call, [`FakeTransport`] records every
//! [`TransportRequest`] and returns a scripted response, and [`FakeClock`]
//! records every `sleep_until`. The real [`prepare`] and [`Sender`] run over
//! those fakes, so the R6.8 connect target, the R6.9 recheck, the R6.10
//! redirect refusal and the R1.8 schedule are checked without I/O.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;

use crate::webhook::delivery::{LastError, MAX_BODY_BYTES};
use crate::webhook::encoding::WebhookSecret;
use crate::webhook::http::transport::{
    prepare, Clock, HostResolver, OutgoingMessage, PreparedRequest, SendAction, Sender,
    SenderConfig, TransportFailure, TransportRequest, TransportResponse, WebhookTransport,
};
use crate::webhook::{MessageKind, WebhookError};

/// The schedule origin every sender test uses, in unix seconds.
pub(super) const T0: i64 = 1_767_225_600;

/// A globally routed address (spec 06 R6.5 `Allow`).
pub(super) const PUBLIC: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);

/// A second globally routed address, different from [`PUBLIC`].
pub(super) const OTHER_PUBLIC: Ipv4Addr = Ipv4Addr::new(8, 8, 4, 4);

/// The loopback address of the R6.5 `Reject` table.
pub(super) const LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

/// A host name url on the default `https` port.
pub(super) const NAME_URL: &str = "https://example.com/hook";

/// The same host name on a non-default port.
pub(super) const PORT_URL: &str = "https://example.com:8443/hook";

/// A global IPv6 literal url.
pub(super) const IPV6_URL: &str = "https://[2606:4700::1111]/hook";

/// A valid `whsec_` secret (spec 06 R2.1), taken from the signature vectors.
pub(super) const SECRET: &str = "whsec_Ha+2nPDW61Z9H5/Uc/1B8csaLDZJ6SeG9jHX+FmQbZk=";

/// The seed of the fixed signed-emission key.
pub(super) const KEY_SEED: [u8; 32] = [7u8; 32];

/// A resolver that returns one scripted answer list per call and records
/// every `(host, port)` it was asked for (spec 06 R6.8, R6.9).
pub(super) struct FakeResolver {
    script: Vec<Vec<IpAddr>>,
    calls: Mutex<Vec<(String, u16)>>,
}

impl FakeResolver {
    /// Builds a resolver over the given script; the last entry repeats when
    /// the sender asks more often than the script has entries.
    pub(super) fn new(script: Vec<Vec<IpAddr>>) -> Self {
        Self {
            script,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Returns every `(host, port)` query in call order.
    pub(super) fn queries(&self) -> Vec<(String, u16)> {
        self.calls.lock().expect("resolver calls").clone()
    }
}

impl HostResolver for FakeResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, WebhookError> {
        let mut calls = self.calls.lock().expect("resolver calls");
        let index = calls.len().min(self.script.len().saturating_sub(1));
        calls.push((host.to_owned(), port));
        Ok(self.script[index].clone())
    }
}

/// A transport that records every request and returns one scripted
/// `(status, retry_after)` per call (spec 06 R1.7).
pub(super) struct FakeTransport {
    script: Vec<(u16, Option<i64>)>,
    body: Vec<u8>,
    requests: Mutex<Vec<TransportRequest>>,
}

impl FakeTransport {
    /// Builds a transport over the given script; the last entry repeats when
    /// there are more attempts than scripted responses. Every response
    /// carries an empty body until [`FakeTransport::with_body`] sets one.
    pub(super) fn new(script: Vec<(u16, Option<i64>)>) -> Self {
        Self {
            script,
            body: Vec::new(),
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Returns the transport answering every scripted response with `body`.
    pub(super) fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Returns the number of requests the sender sent.
    pub(super) fn calls(&self) -> usize {
        self.requests.lock().expect("transport requests").len()
    }

    /// Returns every request the sender sent, in order.
    pub(super) fn requests(&self) -> Vec<TransportRequest> {
        self.requests.lock().expect("transport requests").clone()
    }
}

impl WebhookTransport for FakeTransport {
    fn send(&self, request: &TransportRequest) -> Result<TransportResponse, TransportFailure> {
        let mut requests = self.requests.lock().expect("transport requests");
        let index = requests.len().min(self.script.len().saturating_sub(1));
        let (status, retry_after) = self.script[index];
        let body = self.body.clone();
        requests.push(request.clone());
        Ok(TransportResponse {
            status,
            retry_after,
            body,
            declared_length: None,
        })
    }
}

/// A clock that starts at a fixed instant and records every `sleep_until`
/// (spec 06 R1.8).
pub(super) struct FakeClock {
    now: Mutex<i64>,
    sleeps: Mutex<Vec<i64>>,
}

impl FakeClock {
    /// Builds a clock reading `now` until the first sleep.
    pub(super) fn new(now: i64) -> Self {
        Self {
            now: Mutex::new(now),
            sleeps: Mutex::new(Vec::new()),
        }
    }

    /// Returns every `sleep_until` target, in call order.
    pub(super) fn sleeps(&self) -> Vec<i64> {
        self.sleeps.lock().expect("clock sleeps").clone()
    }
}

impl Clock for FakeClock {
    fn now(&self) -> i64 {
        *self.now.lock().expect("clock")
    }

    fn sleep_until(&self, at: i64) {
        self.sleeps.lock().expect("clock sleeps").push(at);
        *self.now.lock().expect("clock") = at;
    }
}

/// One sender wired to its fakes, so a test can read back what they saw.
struct Rig {
    sender: Sender,
    transport: Arc<FakeTransport>,
    resolver: Arc<FakeResolver>,
    clock: Arc<FakeClock>,
}

/// Builds the real sender over the scripted resolver and transport and the
/// recording clock.
fn rig(answers: Vec<Vec<IpAddr>>, responses: Vec<(u16, Option<i64>)>) -> Rig {
    let transport = Arc::new(FakeTransport::new(responses));
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

/// Returns one address as the `prepare` answer type.
fn ip(address: Ipv4Addr) -> IpAddr {
    IpAddr::V4(address)
}

/// Runs `prepare` with no override ranges, a `POST` and an empty header set.
fn prepared(
    url: &str,
    answers: &[IpAddr],
    recheck: &[IpAddr],
) -> Result<PreparedRequest, WebhookError> {
    prepare(
        url,
        answers,
        recheck,
        &[],
        "POST",
        Vec::new(),
        b"{}".to_vec(),
        MAX_BODY_BYTES,
    )
}

/// Unwraps the refusal of `prepare`, panicking on an allow.
fn expect_refusal(result: Result<PreparedRequest, WebhookError>) -> WebhookError {
    match result {
        Ok(prepared) => panic!(
            "the request was prepared for {:?}",
            prepared.request.connect
        ),
        Err(error) => error,
    }
}

/// Builds one verification message carrying a real secret and signing key.
pub(super) fn message(url: &str) -> OutgoingMessage {
    OutgoingMessage {
        url: url.to_owned(),
        subscription_id: "sub_0123456789abcdef".to_owned(),
        kind: MessageKind::Verification,
        body: br#"{"type":"verification"}"#.to_vec(),
        secrets: vec![WebhookSecret::parse(SECRET).expect("the test secret is valid")],
        signing_keys: vec![("kid-1".to_owned(), SigningKey::from_bytes(&KEY_SEED))],
        aud: None,
        jack_signing: None,
    }
}

#[test]
fn r6_9_a_changed_recheck_is_dns_rebinding() {
    let answers = [ip(PUBLIC)];
    let recheck = [ip(OTHER_PUBLIC)];
    let error = expect_refusal(prepared(NAME_URL, &answers, &recheck));
    assert_eq!(error.http_status, 400);
    assert_eq!(error.code, "dns_rebinding");
    assert_eq!(error.reason(), Some("address_changed"));

    // The same answer on the recheck is the normal case and is allowed.
    let prepared = prepared(NAME_URL, &answers, &answers).expect("the same answer is allowed");
    assert_eq!(prepared.request.connect.address, PUBLIC.to_string());
}

#[test]
fn r6_8_a_blocked_answer_is_refused_with_its_reason() {
    let answers = [ip(LOOPBACK)];
    let error = expect_refusal(prepared(NAME_URL, &answers, &answers));
    assert_eq!(error.http_status, 400);
    assert_eq!(error.code, "blocked_address");
    assert_eq!(error.reason(), Some("loopback"));
}

#[test]
fn r6_8_no_answer_is_refused_before_any_request() {
    let error = expect_refusal(prepared(NAME_URL, &[], &[]));
    assert_eq!(error.http_status, 400);
    assert_eq!(error.code, "no_answer");
    assert_eq!(error.reason(), Some("no_records"));

    // The sender's own path for an empty answer set is the R1.9
    // `connection_refused` category, and no request is built (R1.9).
    let rig = rig(vec![Vec::new()], vec![(200, None)]);
    let outcome = rig.sender.deliver(&message(NAME_URL));
    assert_eq!(
        outcome.action,
        SendAction::Abandoned {
            last_error: LastError::ConnectionRefused
        }
    );
    assert_eq!(outcome.attempts, 4);
    assert_eq!(rig.transport.calls(), 0);
}

#[test]
fn r6_8_the_connect_target_carries_the_validated_address() {
    let connect = prepared(NAME_URL, &[ip(PUBLIC)], &[])
        .expect("a global answer is allowed")
        .request
        .connect;
    let address: IpAddr = connect
        .address
        .parse()
        .expect("connect.address is an IpAddr");
    assert_eq!(address, ip(PUBLIC));
    assert_ne!(connect.address, "example.com");
    assert_eq!(connect.host_header, "example.com");
    assert_eq!(connect.sni.as_deref(), Some("example.com"));

    // A non-default port is part of the Host header (spec 06 R6.8).
    let connect = prepared(PORT_URL, &[ip(PUBLIC)], &[])
        .expect("a global answer is allowed")
        .request
        .connect;
    assert_eq!(connect.host_header, "example.com:8443");
    assert_eq!(connect.sni.as_deref(), Some("example.com"));

    // An IPv6 literal is its own answer and is sent with no SNI.
    let connect = prepared(IPV6_URL, &[], &[])
        .expect("a global IPv6 literal is allowed")
        .request
        .connect;
    let address: IpAddr = connect
        .address
        .parse()
        .expect("connect.address is an IpAddr");
    assert_eq!(
        address,
        "2606:4700::1111".parse::<IpAddr>().expect("valid IPv6")
    );
    assert_eq!(connect.host_header, "[2606:4700::1111]");
    assert_eq!(connect.sni, None);
}

#[test]
fn r6_10_a_redirect_is_final_and_never_followed() {
    let rig = rig(vec![vec![ip(PUBLIC)]], vec![(302, None)]);
    let outcome = rig.sender.deliver(&message(NAME_URL));
    assert_eq!(
        outcome.action,
        SendAction::Final {
            last_error: LastError::Http4xx
        }
    );
    assert_eq!(outcome.attempts, 1);
    assert_eq!(outcome.last_status, Some(302));
    assert_eq!(rig.transport.calls(), 1);
    assert!(rig.clock.sleeps().is_empty());
    let requests = rig.transport.requests();
    assert_eq!(requests[0].url, NAME_URL);
    assert_eq!(requests[0].connect.address, PUBLIC.to_string());
}

#[test]
fn r1_8_a_503_retries_on_the_pinned_slots_and_stops_after_four() {
    let rig = rig(vec![vec![ip(PUBLIC)]], vec![(503, None)]);
    let outcome = rig.sender.deliver(&message(NAME_URL));
    assert_eq!(
        outcome.action,
        SendAction::Abandoned {
            last_error: LastError::Http5xx
        }
    );
    assert_eq!(outcome.attempts, 4);
    assert_eq!(outcome.last_status, Some(503));
    assert_eq!(rig.transport.calls(), 4);
    assert_eq!(rig.clock.sleeps(), vec![T0 + 30, T0 + 270, T0 + 870]);
}

#[test]
fn r1_7_a_200_accepts_and_a_410_is_final_after_one_attempt() {
    let accepted = rig(vec![vec![ip(PUBLIC)]], vec![(200, None)]);
    let outcome = accepted.sender.deliver(&message(NAME_URL));
    assert_eq!(outcome.action, SendAction::Accepted);
    assert_eq!(outcome.attempts, 1);
    assert_eq!(outcome.last_status, Some(200));
    assert_eq!(accepted.transport.calls(), 1);
    assert!(accepted.clock.sleeps().is_empty());

    let gone = rig(vec![vec![ip(PUBLIC)]], vec![(410, None)]);
    let outcome = gone.sender.deliver(&message(NAME_URL));
    assert_eq!(
        outcome.action,
        SendAction::Final {
            last_error: LastError::Http4xx
        }
    );
    assert_eq!(outcome.attempts, 1);
    assert_eq!(outcome.last_status, Some(410));
    assert_eq!(gone.transport.calls(), 1);
    assert!(gone.clock.sleeps().is_empty());
}

#[test]
fn r6_8_a_blocked_answer_never_reaches_the_transport() {
    let rig = rig(vec![vec![ip(LOOPBACK)]], vec![(200, None)]);
    let outcome = rig.sender.deliver(&message(NAME_URL));
    assert_eq!(
        outcome.action,
        SendAction::Final {
            last_error: LastError::ConnectionRefused
        }
    );
    assert_eq!(outcome.attempts, 1);
    assert_eq!(outcome.last_status, None);
    assert_eq!(rig.transport.calls(), 0);
    assert!(rig.clock.sleeps().is_empty());
    let queries = rig.resolver.queries();
    assert_eq!(queries.len(), 2, "validation plus the R6.9 recheck");
    assert_eq!(queries[0], ("example.com".to_owned(), 443));
}
