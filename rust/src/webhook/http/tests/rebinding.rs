//! Fake-resolver, fake-transport and scripted-gate tests of the hardened
//! delivery path (spec 06 R6.8-R6.10, R1.7, R1.9, R5.1, R5.2).
//!
//! Nothing below touches a socket, a DNS server or Tokio. [`FakeResolver`]
//! returns a scripted answer list per call, [`FakeTransport`] records every
//! [`TransportRequest`] and returns a scripted response, [`FakeClock`]
//! records every `sleep_until_ms`, and [`ScriptedGate`] scripts the pair's
//! verification status. The real [`prepare`] and [`Sender`] run over those
//! fakes, so the R6.8 connect target, the R6.9 recheck, the R6.10 redirect
//! refusal, the R1.8 schedule and the R5.1 gate are checked without I/O.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;

use crate::webhook::delivery::{LastError, MAX_BODY_BYTES};
use crate::webhook::encoding::WebhookSecret;
use crate::webhook::http::sender::{Clock, OutgoingMessage, SendAction, Sender, SenderConfig};
use crate::webhook::http::transport::{
    prepare, FailureKind, HostResolver, PreparedRequest, TransportFailure, TransportRequest,
    TransportResponse, WebhookTransport, MAX_DOCUMENT_BYTES,
};
use crate::webhook::verification::gate::{
    ChallengeSender, EndpointGate, EndpointPair, EndpointVerifier, VerificationRequest,
};
use crate::webhook::verification::nonce::EchoVerdict;
use crate::webhook::verification::route::VerificationRoute;
use crate::webhook::{codes, MessageKind, WebhookError};

/// The schedule origin every sender test uses, in unix seconds.
pub(super) const T0: i64 = 1_767_225_600;

/// [`T0`] in Unix milliseconds, the unit of the sender's clock
/// (spec 06 R1.5, R1.8).
pub(super) const T0_MS: i64 = T0 * 1000;

/// Returns one whole-second instant as Unix milliseconds, the unit of every
/// `Clock` and gate instant (spec 06 R1.5, R5.2).
pub(super) fn millis(seconds: i64) -> i64 {
    seconds * 1000
}

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

/// The verified principal of every test pair (spec 06 R5.2).
pub(super) const PRINCIPAL: &str = "principal.example";

/// A valid `whsec_` secret (spec 06 R2.1), taken from the signature vectors.
pub(super) const SECRET: &str = "whsec_Ha+2nPDW61Z9H5/Uc/1B8csaLDZJ6SeG9jHX+FmQbZk=";

/// The seed of the fixed signed-emission key.
pub(super) const KEY_SEED: [u8; 32] = [7u8; 32];

/// A nonce of the R5.3 shape: 22 base64url characters.
pub(super) const NONCE: &str = "abcdefghijklmnopqrstuv";

/// How far ahead of its entry a test stamps the R1.6 whole-attempt deadline:
/// the 20 s cap of one attempt (spec 06 R1.6).
pub(super) const ATTEMPT: Duration = Duration::from_secs(20);

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

/// How a [`FakeTransport`] answers (spec 06 R1.7, R6.9, R1.2).
pub(super) struct FakeTransport {
    script: Vec<(u16, Option<i64>)>,
    body: Vec<u8>,
    declared: Option<u64>,
    overflow: bool,
    mismatch: bool,
    cache_control: Option<String>,
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
            declared: None,
            overflow: false,
            mismatch: false,
            cache_control: None,
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Returns the transport answering every scripted response with `body`.
    pub(super) fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Returns the transport declaring `length` on every response
    /// (spec 06 R5.9).
    pub(super) fn with_declared(mut self, length: u64) -> Self {
        self.declared = Some(length);
        self
    }

    /// Returns the transport reporting every response as overflowing the
    /// body cap (spec 06 R1.2, R5.9).
    pub(super) fn with_overflow(mut self) -> Self {
        self.overflow = true;
        self
    }

    /// Returns the transport refusing every send with the R6.9 peer
    /// mismatch, after recording the request (spec 06 R6.9).
    pub(super) fn with_peer_mismatch(mut self) -> Self {
        self.mismatch = true;
        self
    }

    /// Returns the transport reporting `cache_control` as the raw
    /// `Cache-Control` header of every response (spec 06 R7.2).
    pub(super) fn with_cache_control(mut self, cache_control: &str) -> Self {
        self.cache_control = Some(cache_control.to_owned());
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
        requests.push(request.clone());
        if self.mismatch {
            return Err(TransportFailure::peer_mismatch());
        }
        let mut body = self.body.clone();
        let mut overflow = self.overflow;
        if body.len() > request.max_body_bytes {
            body.truncate(request.max_body_bytes);
            overflow = true;
        }
        Ok(TransportResponse {
            status,
            retry_after,
            body,
            declared_length: self.declared,
            overflow,
            cache_control: self.cache_control.clone(),
        })
    }
}

/// A clock that starts at a fixed instant and records every `sleep_until_ms`
/// (spec 06 R1.8).
///
/// Its readings are Unix milliseconds. `sleep_until_ms` moves the reading to
/// the target, so a retry sleep really passes the time, and [`FakeClock::advance`]
/// moves it without a sleep.
pub(super) struct FakeClock {
    now: Mutex<i64>,
    sleeps: Mutex<Vec<i64>>,
}

impl FakeClock {
    /// Builds a clock reading `now_ms` until the first sleep.
    pub(super) fn new(now_ms: i64) -> Self {
        Self {
            now: Mutex::new(now_ms),
            sleeps: Mutex::new(Vec::new()),
        }
    }

    /// Returns every `sleep_until_ms` target, in call order.
    pub(super) fn sleeps(&self) -> Vec<i64> {
        self.sleeps.lock().expect("clock sleeps").clone()
    }

    /// Moves the reading forward by `by_ms` milliseconds without a sleep.
    pub(super) fn advance(&self, by_ms: i64) {
        let mut now = self.now.lock().expect("clock");
        *now = now.saturating_add(by_ms);
    }
}

impl Clock for FakeClock {
    fn now_ms(&self) -> i64 {
        *self.now.lock().expect("clock")
    }

    fn sleep_until_ms(&self, at_ms: i64) {
        self.sleeps.lock().expect("clock sleeps").push(at_ms);
        *self.now.lock().expect("clock") = at_ms;
    }
}

/// How a [`ScriptedGate`] answers the R5.1/R5.2 calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GateMode {
    /// Every pair is already verified; `verify` is never called.
    Verified,
    /// No pair is verified and every `verify` is refused.
    Refusing,
    /// The pair is verified only until this Unix-millisecond instant; later
    /// `verify` is refused, so a grant that expires during a retry sleep stops
    /// it.
    VerifiedUntil(i64),
    /// No pair is verified until `verify` runs the challenge; the echo
    /// verdict decides and a success grants the pair.
    Challenge,
}

/// A gate that scripts [`EndpointVerifier`] and records what it was asked
/// (spec 06 R5.1, R5.2).
///
/// `verify` records the `now_ms` instant and the grant expiry it was handed,
/// so a test can prove the sender bounded the gate by the grant (R5.2).
pub(super) struct ScriptedGate {
    mode: GateMode,
    granted: Mutex<bool>,
    verifies: Mutex<Vec<i64>>,
    grants: Mutex<Vec<Option<i64>>>,
    verdicts: Mutex<Vec<EchoVerdict>>,
}

impl ScriptedGate {
    /// Builds a gate in the given mode.
    pub(super) fn new(mode: GateMode) -> Self {
        Self {
            mode,
            granted: Mutex::new(false),
            verifies: Mutex::new(Vec::new()),
            grants: Mutex::new(Vec::new()),
            verdicts: Mutex::new(Vec::new()),
        }
    }

    /// Returns the `now_ms` of every `verify` call, in call order.
    pub(super) fn verifies(&self) -> Vec<i64> {
        self.verifies.lock().expect("gate verifies").clone()
    }

    /// Returns the grant expiry of every `verify` call, in call order.
    pub(super) fn grants(&self) -> Vec<Option<i64>> {
        self.grants.lock().expect("gate grants").clone()
    }

    /// Returns every challenge echo verdict the gate judged.
    pub(super) fn verdicts(&self) -> Vec<EchoVerdict> {
        self.verdicts.lock().expect("gate verdicts").clone()
    }
}

impl EndpointVerifier for ScriptedGate {
    fn is_verified(&self, _pair: &EndpointPair, now_ms: i64) -> bool {
        match self.mode {
            GateMode::Verified => true,
            GateMode::Refusing => false,
            GateMode::VerifiedUntil(limit) => now_ms <= limit,
            GateMode::Challenge => *self.granted.lock().expect("gate grant"),
        }
    }

    fn verify(
        &self,
        pair: &EndpointPair,
        subscription_id: &str,
        now_ms: i64,
        expires_at_ms: Option<i64>,
        challenge: &dyn ChallengeSender,
    ) -> Result<VerificationRoute, WebhookError> {
        self.verifies.lock().expect("gate verifies").push(now_ms);
        self.grants.lock().expect("gate grants").push(expires_at_ms);
        match self.mode {
            GateMode::Verified => Ok(VerificationRoute::Cache),
            GateMode::Refusing | GateMode::VerifiedUntil(_) => Err(challenge_refusal()),
            GateMode::Challenge => {
                let request = VerificationRequest {
                    pair,
                    subscription_id,
                    nonce: NONCE,
                    now: now_ms,
                };
                let verdict = challenge.send_challenge(&request).verdict;
                let accepted = verdict.ok;
                self.verdicts.lock().expect("gate verdicts").push(verdict);
                if accepted {
                    *self.granted.lock().expect("gate grant") = true;
                    Ok(VerificationRoute::Challenge)
                } else {
                    Err(challenge_refusal())
                }
            }
        }
    }
}

/// Builds the `challenge_failed` error a refusing gate returns
/// (spec 06 R5.1, R5.4).
fn challenge_refusal() -> WebhookError {
    WebhookError::with_reason(
        0,
        codes::CHALLENGE_FAILED,
        "no_route",
        "the pair is not verified",
    )
}

/// One sender wired to its fakes, so a test can read back what they saw.
pub(super) struct Rig {
    pub(super) sender: Sender,
    pub(super) transport: Arc<FakeTransport>,
    pub(super) resolver: Arc<FakeResolver>,
    pub(super) clock: Arc<FakeClock>,
    pub(super) gate: Arc<ScriptedGate>,
}

/// Builds the real sender over a verified pair, the scripted resolver and
/// transport, and the recording clock.
pub(super) fn rig(answers: Vec<Vec<IpAddr>>, responses: Vec<(u16, Option<i64>)>) -> Rig {
    rig_with_gate(GateMode::Verified, answers, responses)
}

/// Builds the real sender over the given gate mode.
pub(super) fn rig_with_gate(
    mode: GateMode,
    answers: Vec<Vec<IpAddr>>,
    responses: Vec<(u16, Option<i64>)>,
) -> Rig {
    let transport = Arc::new(FakeTransport::new(responses));
    let resolver = Arc::new(FakeResolver::new(answers));
    let clock = Arc::new(FakeClock::new(T0_MS));
    let gate = Arc::new(ScriptedGate::new(mode));
    let sender = Sender::new(
        transport.clone(),
        resolver.clone(),
        clock.clone(),
        SenderConfig {
            allowed_ranges: Vec::new(),
            max_body_bytes: MAX_BODY_BYTES,
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

/// Returns one address as the `prepare` answer type.
pub(super) fn ip(address: Ipv4Addr) -> IpAddr {
    IpAddr::V4(address)
}

/// Runs `prepare` with no override ranges, a `POST`, an empty header set and
/// a deadline stamped `ATTEMPT` from now.
fn prepared(
    url: &str,
    answers: &[IpAddr],
    recheck: &[IpAddr],
) -> Result<PreparedRequest, WebhookError> {
    prepared_at(url, answers, recheck, Instant::now() + ATTEMPT)
}

/// Runs `prepare` with no override ranges, a `POST`, an empty header set and
/// the given absolute R1.6 deadline (spec 06 R1.6).
fn prepared_at(
    url: &str,
    answers: &[IpAddr],
    recheck: &[IpAddr],
    deadline: Instant,
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
        deadline,
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
        principal: PRINCIPAL.to_owned(),
        url: url.to_owned(),
        subscription_id: "sub_0123456789abcdef".to_owned(),
        kind: MessageKind::Verification,
        body: br#"{"type":"verification"}"#.to_vec(),
        secrets: vec![WebhookSecret::parse(SECRET).expect("the test secret is valid")],
        signing_keys: vec![("kid-1".to_owned(), SigningKey::from_bytes(&KEY_SEED))],
        aud: None,
        jack_signing: None,
        expires_at_ms: None,
    }
}

/// Reports whether one sent request carries the named header.
pub(super) fn has_header(request: &TransportRequest, name: &str) -> bool {
    request
        .headers
        .iter()
        .any(|(header, _)| header.eq_ignore_ascii_case(name))
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
fn r1_6_the_request_carries_the_absolute_deadline_it_was_given() {
    // `prepare` stores exactly the deadline it was handed, so the transport
    // charges the lookups and the request build to the same budget.
    let deadline = Instant::now() + Duration::from_millis(250);
    let prepared =
        prepared_at(NAME_URL, &[ip(PUBLIC)], &[], deadline).expect("a global answer is allowed");
    assert_eq!(prepared.request.deadline, deadline);

    // The per-phase caps stay the R1.6 constants, below the whole-attempt cap.
    assert!(prepared.request.connect_timeout <= ATTEMPT);
    assert!(prepared.request.response_timeout <= ATTEMPT);
}

#[test]
fn r1_2_the_body_cap_is_checked_before_the_decision() {
    let error = expect_refusal(prepare(
        NAME_URL,
        &[ip(PUBLIC)],
        &[ip(PUBLIC)],
        &[],
        "POST",
        Vec::new(),
        vec![b'x'; MAX_BODY_BYTES + 1],
        MAX_BODY_BYTES,
        Instant::now() + ATTEMPT,
    ));
    assert_eq!(error.http_status, 413);
    assert_eq!(error.code, "body_too_large");
}

#[test]
fn r1_2_an_overflowing_response_keeps_the_prefix() {
    // The transport reads one byte past the cap, so the body it stores is the
    // prefix and the overflow flag is set (spec 06 R1.2, R5.9).
    let mut bytes = Vec::new();
    let prefix = vec![b'{'; MAX_DOCUMENT_BYTES];
    assert!(!crate::webhook::http::transport::capture_body(
        &mut bytes,
        &prefix,
        MAX_DOCUMENT_BYTES
    ));
    assert!(crate::webhook::http::transport::capture_body(
        &mut bytes,
        b"x",
        MAX_DOCUMENT_BYTES
    ));
    assert_eq!(bytes.len(), MAX_DOCUMENT_BYTES);
    assert_eq!(bytes, prefix);
}

#[test]
fn r5_1_an_unverified_pair_is_final_with_challenge_failed() {
    let rig = rig_with_gate(
        GateMode::Refusing,
        vec![vec![ip(PUBLIC)]],
        vec![(200, None)],
    );
    let outcome = rig.sender.deliver(&message(NAME_URL));
    assert_eq!(
        outcome.action,
        SendAction::Final {
            last_error: LastError::ChallengeFailed
        }
    );
    assert_eq!(outcome.attempts, 0);
    assert_eq!(outcome.last_status, None);
    assert_eq!(rig.transport.calls(), 0);
    assert_eq!(rig.gate.verifies(), vec![T0_MS]);
    // With no grant expiry and no configured TTL the sender bounds nothing.
    assert_eq!(rig.gate.grants(), vec![None]);
    assert!(rig.clock.sleeps().is_empty());
}

#[test]
fn r5_1_verification_runs_before_every_retry() {
    // The grant covers two seconds only, so the 503 retry at T0 + 30 must
    // re-verify and must not receive the event (spec 06 R5.1, R5.2).
    let rig = rig_with_gate(
        GateMode::VerifiedUntil(millis(T0 + 2)),
        vec![vec![ip(PUBLIC)]],
        vec![(503, None)],
    );
    let outcome = rig.sender.deliver(&message(NAME_URL));
    assert_eq!(
        outcome.action,
        SendAction::Final {
            last_error: LastError::ChallengeFailed
        }
    );
    assert_eq!(outcome.attempts, 1);
    assert_eq!(rig.transport.calls(), 1);
    assert_eq!(rig.clock.sleeps(), vec![millis(T0 + 30)]);
    assert_eq!(rig.gate.verifies(), vec![millis(T0 + 30)]);
}

#[test]
fn r6_9_a_peer_mismatch_is_final_after_one_attempt() {
    let rig = rig(vec![vec![ip(PUBLIC)]], vec![(200, None)]);
    // The fake transport reports the R6.9 mismatch instead of a response.
    let transport = Arc::new(FakeTransport::new(vec![(200, None)]).with_peer_mismatch());
    let sender = Sender::new(
        transport.clone(),
        rig.resolver.clone(),
        rig.clock.clone(),
        SenderConfig {
            allowed_ranges: Vec::new(),
            max_body_bytes: MAX_BODY_BYTES,
            verification_ttl_ms: None,
        },
        rig.gate.clone(),
    );
    let outcome = sender.deliver(&message(NAME_URL));
    assert_eq!(
        outcome.action,
        SendAction::Final {
            last_error: LastError::ConnectionRefused
        }
    );
    assert_eq!(outcome.attempts, 1);
    assert_eq!(transport.calls(), 1);
    assert!(rig.clock.sleeps().is_empty());
    assert_eq!(
        FailureKind::PeerMismatch,
        TransportFailure::peer_mismatch().kind
    );
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
    assert_eq!(
        rig.clock.sleeps(),
        vec![millis(T0 + 30), millis(T0 + 270), millis(T0 + 870)]
    );
    assert!(rig.gate.verifies().is_empty());
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

#[test]
fn r7_2_the_response_carries_the_raw_cache_control_value() {
    // The transport reports the header it read, so the card cache derives the
    // R7.2 lifetime from the receiver's own value instead of a fixed cap
    // (spec 06 R7.2).
    let transport = FakeTransport::new(vec![(200, None)]).with_cache_control("max-age=60");
    let request = prepared(NAME_URL, &[ip(PUBLIC)], &[])
        .expect("a global answer is allowed")
        .request;
    let response = transport
        .send(&request)
        .expect("the fake transport answers the request");
    assert_eq!(response.cache_control.as_deref(), Some("max-age=60"));
}

/// An allowlist entry that covers [`NAME_URL`] (spec 06 R5.7).
const NAME_ALLOWLIST: &str = "https://example.com/hook";

/// The configured verification TTL of the grant tests, in milliseconds
/// (spec 06 R5.2).
const GRANT_TTL_MS: i64 = 60_000;

/// An [`EndpointVerifier`] that delegates to a real [`EndpointGate`] and
/// records every `verify` call with the instant and the grant expiry it was
/// handed (spec 06 R5.1, R5.2).
struct CountingVerifier {
    gate: EndpointGate,
    verifies: Mutex<Vec<(i64, Option<i64>)>>,
}

impl CountingVerifier {
    /// Wraps the real gate (spec 06 R5.2).
    fn new(gate: EndpointGate) -> Self {
        Self {
            gate,
            verifies: Mutex::new(Vec::new()),
        }
    }

    /// Returns the `(now_ms, expires_at_ms)` of every `verify` call, in call
    /// order (spec 06 R5.2).
    fn verifies(&self) -> Vec<(i64, Option<i64>)> {
        self.verifies.lock().expect("gate verifies").clone()
    }
}

impl EndpointVerifier for CountingVerifier {
    fn is_verified(&self, pair: &EndpointPair, now_ms: i64) -> bool {
        self.gate.is_verified(pair, now_ms)
    }

    fn verify(
        &self,
        pair: &EndpointPair,
        subscription_id: &str,
        now_ms: i64,
        expires_at_ms: Option<i64>,
        challenge: &dyn ChallengeSender,
    ) -> Result<VerificationRoute, WebhookError> {
        self.verifies
            .lock()
            .expect("gate verifies")
            .push((now_ms, expires_at_ms));
        self.gate
            .verify(pair, subscription_id, now_ms, expires_at_ms, challenge)
    }
}

/// A sender over a real [`EndpointGate`] on an allowlist route, so the gate
/// verifies without a challenge and only the grant expiry can stop it
/// (spec 06 R5.2, R5.7).
struct GrantRig {
    sender: Sender,
    transport: Arc<FakeTransport>,
    clock: Arc<FakeClock>,
    gate: Arc<CountingVerifier>,
    pair: EndpointPair,
}

/// Builds the allowlist rig of [`GrantRig`] over `responses`.
fn grant_rig(responses: Vec<(u16, Option<i64>)>) -> GrantRig {
    let transport = Arc::new(FakeTransport::new(responses));
    let resolver = Arc::new(FakeResolver::new(vec![vec![ip(PUBLIC)]]));
    let clock = Arc::new(FakeClock::new(T0_MS));
    let gate = Arc::new(CountingVerifier::new(EndpointGate::new(
        vec![NAME_ALLOWLIST.to_owned()],
        Some(GRANT_TTL_MS),
    )));
    let sender = Sender::new(
        transport.clone(),
        resolver,
        clock.clone(),
        SenderConfig {
            allowed_ranges: Vec::new(),
            max_body_bytes: MAX_BODY_BYTES,
            verification_ttl_ms: Some(GRANT_TTL_MS),
        },
        gate.clone(),
    );
    let pair = EndpointPair::new(PRINCIPAL, NAME_URL).expect("the test url is a valid pair");
    GrantRig {
        sender,
        transport,
        clock,
        gate,
        pair,
    }
}

#[test]
fn r5_2_a_grant_that_ended_during_the_retry_sleep_stops_the_second_attempt() {
    // The grant ends exactly at the R1.8 retry slot, so the second attempt
    // finds the pair unverified and must not carry the event
    // (spec 06 R5.1, R5.2).
    let rig = grant_rig(vec![(503, None)]);
    let mut message = message(NAME_URL);
    message.expires_at_ms = Some(T0_MS + 30_000);

    let outcome = rig.sender.deliver(&message);
    assert_eq!(
        outcome.action,
        SendAction::Final {
            last_error: LastError::ChallengeFailed
        }
    );
    assert_eq!(outcome.attempts, 1);
    assert_eq!(outcome.last_status, Some(503));
    assert_eq!(rig.transport.calls(), 1);
    assert_eq!(rig.clock.sleeps(), vec![millis(T0 + 30)]);
    // The gate ran again before the second attempt, and both calls were handed
    // the grant's expiry rather than the configured TTL alone (R5.2).
    assert_eq!(
        rig.gate.verifies(),
        vec![
            (T0_MS, Some(T0_MS + 30_000)),
            (millis(T0 + 30), Some(T0_MS + 30_000)),
        ]
    );
    assert!(!rig.gate.gate.cached(&rig.pair, millis(T0 + 30)));
}

#[test]
fn r5_2_a_verification_past_its_grant_never_carries_the_first_attempt() {
    let rig = grant_rig(vec![(200, None)]);
    let mut message = message(NAME_URL);
    message.expires_at_ms = Some(T0_MS - 1);

    let outcome = rig.sender.deliver(&message);
    assert_eq!(
        outcome.action,
        SendAction::Final {
            last_error: LastError::ChallengeFailed
        }
    );
    assert_eq!(outcome.attempts, 0);
    assert_eq!(outcome.last_status, None);
    assert_eq!(rig.transport.calls(), 0);
    assert!(rig.clock.sleeps().is_empty());
    assert_eq!(rig.gate.verifies(), vec![(T0_MS, Some(T0_MS - 1))]);
    assert!(!rig.gate.gate.cached(&rig.pair, T0_MS));
}
