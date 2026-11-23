//! Gate order, the challenge route and the fail-closed cache of spec 06
//! R5.2-R5.5.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::webhook::verification::document::{DocumentFetcher, ReceiverDocument};
use crate::webhook::verification::gate::{
    ChallengeResult, ChallengeSender, EndpointGate, EndpointPair, EndpointVerifier,
    VerificationRequest,
};
use crate::webhook::verification::nonce::{
    accept_echo, pair_key, EchoAttempt, EchoVerdict, NONCE_TTL_MS,
};
use crate::webhook::verification::route::VerificationRoute;
use crate::webhook::{codes, WebhookError};

use serde_json::Value;

/// The callback url every test pair is built from (spec 06 R5.2).
const URL: &str = "https://hooks.example.test/hooks/x";

/// An allowlist entry that covers [`URL`] (spec 06 R5.7).
const ALLOWLIST: &str = "https://hooks.example.test/hooks";

/// A receiver document that covers [`URL`]'s path (spec 06 R5.9).
const DOCUMENT: &str = r#"{"receivers":["/hooks/"]}"#;

/// Builds the pair of [`URL`] for one principal (spec 06 R5.2).
fn pair(principal: &str) -> EndpointPair {
    EndpointPair::new(principal, URL).expect("the test url is a valid callback url")
}

/// A challenge sender that counts its calls and returns a fixed verdict
/// (spec 06 R5.4).
///
/// `checked_at` is the fresh sample the gate must judge at: `None` reports the
/// issue instant, and a set value makes the check land there, so a test can
/// push it past the nonce life (spec 06 R5.3).
struct CountingSender {
    calls: AtomicUsize,
    verdict: EchoVerdict,
    checked_at: Option<i64>,
    destination: std::sync::Mutex<Option<String>>,
    nonce: std::sync::Mutex<Option<String>>,
}

impl CountingSender {
    /// Builds a sender answering `verdict` at the issue instant
    /// (spec 06 R5.4).
    fn new(verdict: EchoVerdict) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            verdict,
            checked_at: None,
            destination: std::sync::Mutex::new(None),
            nonce: std::sync::Mutex::new(None),
        }
    }

    /// Returns the sender reporting its verdict at `checked_at_ms`, the
    /// instant sampled after the response (spec 06 R5.3).
    fn with_checked_at(mut self, checked_at_ms: i64) -> Self {
        self.checked_at = Some(checked_at_ms);
        self
    }

    /// Returns how often the gate called the sender (spec 06 R5.2).
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Returns the destination the last request carried (spec 06 R5.5).
    fn destination(&self) -> Option<String> {
        self.destination.lock().expect("lock").clone()
    }

    /// Returns the nonce the last request carried (spec 06 R5.3).
    fn nonce(&self) -> Option<String> {
        self.nonce.lock().expect("lock").clone()
    }
}

impl ChallengeSender for CountingSender {
    fn send_challenge(&self, request: &VerificationRequest<'_>) -> ChallengeResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.destination.lock().expect("lock") = Some(request.pair.canonical_url().to_string());
        *self.nonce.lock().expect("lock") = Some(request.nonce.to_string());
        ChallengeResult::at(self.verdict.clone(), self.checked_at.unwrap_or(request.now))
    }
}

/// A challenge sender whose endpoint always echoes the FIRST nonce it ever
/// saw, the way a stale or replayed challenge answer behaves
/// (spec 06 R5.3, R5.4).
///
/// The first send is accepted (`accepted()`, judged at the issue instant);
/// every later send is answered with the latched first nonce, which is a
/// `mismatch` against the fresh nonce the gate issued.
struct FirstNonceSender {
    /// Every nonce the gate handed to this sender, in send order
    /// (spec 06 R5.3).
    nonces: std::sync::Mutex<Vec<String>>,
}

impl FirstNonceSender {
    /// Builds a sender that has seen no nonce yet (spec 06 R5.3).
    fn new() -> Self {
        Self {
            nonces: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Returns every nonce the gate handed to this sender (spec 06 R5.3).
    fn nonces(&self) -> Vec<String> {
        self.nonces.lock().expect("lock").clone()
    }
}

impl ChallengeSender for FirstNonceSender {
    fn send_challenge(&self, request: &VerificationRequest<'_>) -> ChallengeResult {
        let mut nonces = self.nonces.lock().expect("lock");
        nonces.push(request.nonce.to_string());
        let echoes_the_first = nonces.len() == 1;
        drop(nonces);
        let verdict = if echoes_the_first {
            accepted()
        } else {
            rejected("mismatch")
        };
        ChallengeResult::at(verdict, request.now)
    }
}

/// A document fetcher that counts its calls and answers a fixed body
/// (spec 06 R5.9).
struct CountingFetcher {
    calls: AtomicUsize,
    body: &'static str,
}

impl CountingFetcher {
    /// Builds a fetcher answering `body` (spec 06 R5.9).
    fn new(body: &'static str) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            body,
        }
    }

    /// Returns how often the gate called the fetcher (spec 06 R5.9).
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl DocumentFetcher for CountingFetcher {
    fn fetch(&self, _canonical_url: &str) -> Result<ReceiverDocument, WebhookError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        crate::webhook::verification::document::check_document_fetch(200, self.body)
    }
}

/// Returns the success verdict of an accepted echo (spec 06 R5.4).
fn accepted() -> EchoVerdict {
    EchoVerdict {
        ok: true,
        code: None,
        reason: None,
    }
}

/// Returns the `challenge_failed` verdict with `reason` (spec 06 R5.4).
fn rejected(reason: &str) -> EchoVerdict {
    EchoVerdict {
        ok: false,
        code: Some(codes::CHALLENGE_FAILED),
        reason: Some(reason.to_string()),
    }
}

#[test]
fn cache_beats_every_later_route() {
    let hook_calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hook_calls);
    let fetcher = Arc::new(CountingFetcher::new(DOCUMENT));
    let gate = EndpointGate::new(vec![ALLOWLIST.to_string()], None)
        .with_hook(Box::new(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            true
        }))
        .with_document(fetcher.clone());
    let sender = CountingSender::new(accepted());
    let pair = pair("alice");

    gate.record_success(&pair, 0, None);
    let route = gate
        .verify(&pair, "sub_0123456789abcdef", 0, None, &sender)
        .expect("a cached pair verifies");

    assert_eq!(route, VerificationRoute::Cache);
    assert_eq!(hook_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fetcher.calls(), 0);
    assert_eq!(sender.calls(), 0);
}

#[test]
fn allowlist_beats_the_hook() {
    let hook_calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hook_calls);
    let gate =
        EndpointGate::new(vec![ALLOWLIST.to_string()], None).with_hook(Box::new(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            true
        }));
    let sender = CountingSender::new(accepted());
    let pair = pair("alice");

    let route = gate
        .verify(&pair, "sub_0123456789abcdef", 0, None, &sender)
        .expect("an allowlisted pair verifies");

    assert_eq!(route, VerificationRoute::Allowlist);
    assert_eq!(hook_calls.load(Ordering::SeqCst), 0);
    assert_eq!(sender.calls(), 0);
    assert!(gate.cached(&pair, 0));
}

#[test]
fn hook_beats_the_document() {
    let fetcher = Arc::new(CountingFetcher::new(DOCUMENT));
    let gate = EndpointGate::new(Vec::new(), None)
        .with_hook(Box::new(|_| true))
        .with_document(fetcher.clone());
    let sender = CountingSender::new(accepted());
    let pair = pair("alice");

    let route = gate
        .verify(&pair, "sub_0123456789abcdef", 0, None, &sender)
        .expect("the hook verifies the pair");

    assert_eq!(route, VerificationRoute::OutOfBand);
    assert_eq!(fetcher.calls(), 0);
    assert_eq!(sender.calls(), 0);
}

#[test]
fn document_beats_the_challenge() {
    let fetcher = Arc::new(CountingFetcher::new(DOCUMENT));
    let gate = EndpointGate::new(Vec::new(), None).with_document(fetcher.clone());
    let sender = CountingSender::new(accepted());
    let pair = pair("alice");

    let route = gate
        .verify(&pair, "sub_0123456789abcdef", 0, None, &sender)
        .expect("a covering document verifies the pair");

    assert_eq!(route, VerificationRoute::WellKnown);
    assert_eq!(fetcher.calls(), 1);
    assert_eq!(sender.calls(), 0);
    assert!(gate.cached(&pair, 0));
}

#[test]
fn a_document_that_does_not_cover_the_path_falls_through_to_the_challenge() {
    let fetcher = Arc::new(CountingFetcher::new(r#"{"receivers":["/other/"]}"#));
    let gate = EndpointGate::new(Vec::new(), None).with_document(fetcher);
    let sender = CountingSender::new(accepted());
    let pair = pair("alice");

    let route = gate
        .verify(&pair, "sub_0123456789abcdef", 0, None, &sender)
        .expect("the challenge verifies the pair");

    assert_eq!(route, VerificationRoute::Challenge);
    assert_eq!(sender.calls(), 1);
}

#[test]
fn a_failed_challenge_is_challenge_failed() {
    let gate = EndpointGate::new(Vec::new(), None);
    let sender = CountingSender::new(rejected("mismatch"));
    let pair = pair("alice");

    let error = gate
        .verify(&pair, "sub_0123456789abcdef", 0, None, &sender)
        .expect_err("a mismatched echo fails the handshake");

    assert_eq!(error.code, codes::CHALLENGE_FAILED);
    assert_eq!(error.reason.as_deref(), Some("mismatch"));
}

#[test]
fn a_total_failure_reports_no_route() {
    let gate = EndpointGate::new(Vec::new(), None);
    let sender = CountingSender::new(EchoVerdict {
        ok: false,
        code: Some(codes::CHALLENGE_FAILED),
        reason: None,
    });
    let pair = pair("alice");

    let error = gate
        .verify(&pair, "sub_0123456789abcdef", 0, None, &sender)
        .expect_err("no route verifies the pair");

    assert_eq!(error.code, codes::CHALLENGE_FAILED);
    assert_eq!(error.reason.as_deref(), Some("no_route"));
}

#[test]
fn a_failed_challenge_writes_no_cache_entry() {
    let gate = EndpointGate::new(Vec::new(), None);
    let sender = CountingSender::new(rejected("mismatch"));
    let pair = pair("alice");

    assert!(gate
        .verify(&pair, "sub_0123456789abcdef", 0, None, &sender)
        .is_err());
    assert!(!gate.cached(&pair, 0));
    assert!(!gate.is_verified(&pair, 0));
}

#[test]
fn a_second_echo_of_the_same_nonce_is_reused() {
    // An accepted challenge makes the GATE consume the nonce, so the flag this
    // oracle replays with is the one the gate recorded, never one the test
    // wrote (spec 06 R5.3).
    let gate = EndpointGate::new(Vec::new(), None);
    let sender = CountingSender::new(accepted());
    let pair = pair("alice");

    let route = gate
        .verify(&pair, "sub_0123456789abcdef", 10, None, &sender)
        .expect("the accepted echo verifies the pair");

    assert_eq!(route, VerificationRoute::Challenge);
    let nonce = sender.nonce().expect("the sender saw a nonce");
    assert_eq!(gate.pending_consumed(&nonce), Some(true));

    // The real replay: the nonce the gate issued, the instant it issued it and
    // the flag the gate itself reports (spec 06 R5.3).
    let consumed = gate
        .pending_consumed(&nonce)
        .expect("the gate issued the nonce");
    let pair_value = serde_json::json!([pair.principal(), pair.canonical_url()]);
    let replay = accept_echo(&EchoAttempt {
        nonce: Some(&nonce),
        expected: Some(&nonce),
        issued_at: 10,
        now: 10 + NONCE_TTL_MS,
        ttl: NONCE_TTL_MS,
        consumed,
        pair: Some(&pair_value),
        expected_pair: Some(&pair_value),
    });
    assert!(!replay.ok);
    assert_eq!(replay.reason.as_deref(), Some("reused"));

    // The same attempt with the flag cleared is inside its life and correctly
    // paired, so the `reused` verdict above comes from the single-use rule
    // alone (spec 06 R5.3).
    let unconsumed = accept_echo(&EchoAttempt {
        nonce: Some(&nonce),
        expected: Some(&nonce),
        issued_at: 10,
        now: 10 + NONCE_TTL_MS,
        ttl: NONCE_TTL_MS,
        consumed: false,
        pair: Some(&pair_value),
        expected_pair: Some(&pair_value),
    });
    assert!(unconsumed.ok);
    assert_eq!(unconsumed.reason, None);
}

#[test]
fn a_spent_nonce_answered_after_the_cache_ttl_is_a_mismatch() {
    // A cleared cache re-runs the handshake with a fresh nonce, and an endpoint
    // that answers with the nonce it already spent fails it (spec 06 R5.2,
    // R5.3, R5.4).
    let gate = EndpointGate::new(Vec::new(), Some(1_000));
    let sender = FirstNonceSender::new();
    let pair = pair("alice");

    let route = gate
        .verify(&pair, "sub_0123456789abcdef", 0, None, &sender)
        .expect("the endpoint echoes the nonce it was sent");

    assert_eq!(route, VerificationRoute::Challenge);
    let issued = sender.nonces();
    assert_eq!(issued.len(), 1);
    let spent = issued[0].clone();
    assert_eq!(gate.pending_consumed(&spent), Some(true));

    // Past the cache TTL of R5.2 the pair is verified again; the gate issues a
    // fresh nonce and the endpoint answers with the spent one, which is a
    // `mismatch` and caches nothing (spec 06 R5.3, R5.4).
    let later = 1_001;
    assert!(!gate.cached(&pair, later));
    let error = gate
        .verify(&pair, "sub_0123456789abcdef", later, None, &sender)
        .expect_err("the spent nonce never verifies a second handshake");

    assert_eq!(error.code, codes::CHALLENGE_FAILED);
    assert_eq!(error.reason.as_deref(), Some("mismatch"));
    let issued = sender.nonces();
    assert_eq!(issued.len(), 2);
    assert_ne!(issued[1], spent, "the gate issued a fresh nonce");
    assert_eq!(gate.pending_consumed(&issued[1]), Some(false));
    assert!(!gate.cached(&pair, later));
    assert!(!gate.is_verified(&pair, later));
}

#[test]
fn a_pair_with_an_empty_member_is_never_a_match() {
    assert!(EndpointPair::new("", URL).is_err());
    assert!(EndpointPair::new("alice", "").is_err());
    let empty_principal = Value::Array(vec![
        Value::String(String::new()),
        Value::String(URL.to_string()),
    ]);
    assert!(pair_key(Some(&empty_principal)).is_none());
}

#[test]
fn a_successful_challenge_caches_the_pair() {
    let gate = EndpointGate::new(Vec::new(), Some(1_000));
    let sender = CountingSender::new(accepted());
    let pair = pair("alice");

    let route = gate
        .verify(&pair, "sub_0123456789abcdef", 100, None, &sender)
        .expect("the echo verifies the pair");

    assert_eq!(route, VerificationRoute::Challenge);
    let nonce = sender.nonce().expect("the sender saw a nonce");
    assert_eq!(nonce.len(), 22);
    assert!(gate.cached(&pair, 100));
    assert!(gate.cached(&pair, 1_099));
    assert!(!gate.cached(&pair, 1_100));
}

#[test]
fn the_challenge_goes_to_the_pairs_canonical_url() {
    let gate = EndpointGate::new(Vec::new(), None);
    let sender = CountingSender::new(accepted());
    let pair = EndpointPair::new("alice", "https://hooks.example.test:443/hooks/x")
        .expect("the default port is canonicalized away");

    gate.verify(&pair, "sub_0123456789abcdef", 0, None, &sender)
        .expect("the echo verifies the pair");

    assert_eq!(pair.canonical_url(), "https://hooks.example.test/hooks/x");
    assert_ne!(
        pair.canonical_url(),
        "https://hooks.example.test:443/hooks/x"
    );
    assert_eq!(
        sender.destination().as_deref(),
        Some("https://hooks.example.test/hooks/x")
    );
}

#[test]
fn cache_ttl_is_the_minimum_of_the_configured_ttl_and_the_grant() {
    // 60 s configured, a grant 30 s away, so the cache may hold for 30 s
    // (spec 06 R5.2).
    let gate = EndpointGate::new(Vec::new(), Some(60_000));
    assert_eq!(gate.cache_ttl(1_000, Some(31_000)), Some(30_000));
    // A subscription with no expiry is bounded by the configured TTL only.
    assert_eq!(gate.cache_ttl(1_000, None), Some(60_000));
    // No configured TTL leaves the grant alone as the only bound.
    assert_eq!(gate.cache_ttl(1_000, Some(5_000)), Some(4_000));
    // Neither bound means the verification never expires.
    let unbounded = EndpointGate::new(Vec::new(), None);
    assert_eq!(unbounded.cache_ttl(1_000, None), None);
}

#[test]
fn a_grant_already_past_is_never_cached() {
    let gate = EndpointGate::new(Vec::new(), Some(60_000));
    let pair = pair("alice");
    let ttl = gate
        .cache_ttl(1_000, Some(400))
        .expect("the configured TTL keeps a bound");
    assert!(ttl <= 0, "a past grant leaves no cache life, got {ttl}");

    gate.record_success(&pair, 1_000, Some(400));
    assert!(!gate.cached(&pair, 1_000));
    assert!(!gate.is_verified(&pair, 1_000));
}

#[test]
fn a_challenge_judged_after_the_nonce_life_is_expired() {
    // The echo is correct at the issue instant, but the gate must judge it at
    // the sample taken after the response, which is past the 600 s life
    // (spec 06 R5.3, R5.4).
    let gate = EndpointGate::new(Vec::new(), None);
    let sender = CountingSender::new(accepted()).with_checked_at(NONCE_TTL_MS + 1);
    let pair = pair("alice");

    let error = gate
        .verify(&pair, "sub_0123456789abcdef", 0, None, &sender)
        .expect_err("a nonce past its life is spent");

    assert_eq!(error.code, codes::CHALLENGE_FAILED);
    assert_eq!(error.reason.as_deref(), Some("expired"));
    assert!(!gate.cached(&pair, 0));
    assert!(!gate.cached(&pair, NONCE_TTL_MS + 1));
}

#[test]
fn a_challenge_judged_exactly_at_the_nonce_life_is_accepted() {
    // The rule is `age > ttl`, so the 600 s boundary itself is still inside
    // the nonce life (spec 06 R5.3).
    let gate = EndpointGate::new(Vec::new(), None);
    let sender = CountingSender::new(accepted()).with_checked_at(NONCE_TTL_MS);
    let pair = pair("alice");

    let route = gate
        .verify(&pair, "sub_0123456789abcdef", 0, None, &sender)
        .expect("the boundary echo is still fresh");

    assert_eq!(route, VerificationRoute::Challenge);
    assert!(gate.cached(&pair, NONCE_TTL_MS));
}
