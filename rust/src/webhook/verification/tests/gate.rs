//! Gate order, the challenge route and the fail-closed cache of spec 06
//! R5.2-R5.5.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::webhook::verification::document::{DocumentFetcher, ReceiverDocument};
use crate::webhook::verification::gate::{
    ChallengeSender, EndpointGate, EndpointPair, EndpointVerifier, VerificationRequest,
};
use crate::webhook::verification::nonce::{
    accept_echo, pair_key, EchoAttempt, EchoVerdict, PendingNonce, NONCE_TTL_SECONDS,
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
struct CountingSender {
    calls: AtomicUsize,
    verdict: EchoVerdict,
    destination: std::sync::Mutex<Option<String>>,
    nonce: std::sync::Mutex<Option<String>>,
}

impl CountingSender {
    /// Builds a sender answering `verdict` (spec 06 R5.4).
    fn new(verdict: EchoVerdict) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            verdict,
            destination: std::sync::Mutex::new(None),
            nonce: std::sync::Mutex::new(None),
        }
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
    fn send_challenge(&self, request: &VerificationRequest<'_>) -> EchoVerdict {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.destination.lock().expect("lock") = Some(request.pair.canonical_url().to_string());
        *self.nonce.lock().expect("lock") = Some(request.nonce.to_string());
        self.verdict.clone()
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

    gate.record_success(&pair, 0);
    let route = gate
        .verify(&pair, "sub_0123456789abcdef", 0, &sender)
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
        .verify(&pair, "sub_0123456789abcdef", 0, &sender)
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
        .verify(&pair, "sub_0123456789abcdef", 0, &sender)
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
        .verify(&pair, "sub_0123456789abcdef", 0, &sender)
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
        .verify(&pair, "sub_0123456789abcdef", 0, &sender)
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
        .verify(&pair, "sub_0123456789abcdef", 0, &sender)
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
        .verify(&pair, "sub_0123456789abcdef", 0, &sender)
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
        .verify(&pair, "sub_0123456789abcdef", 0, &sender)
        .is_err());
    assert!(!gate.cached(&pair, 0));
    assert!(!gate.is_verified(&pair, 0));
}

#[test]
fn a_second_echo_of_the_same_nonce_is_reused() {
    let spent = PendingNonce {
        issued_at: 10,
        pair: ("alice".to_string(), URL.to_string()),
        consumed: true,
    };
    let pair_value = serde_json::json!([spent.pair.0, spent.pair.1]);
    let verdict = accept_echo(&EchoAttempt {
        nonce: Some("AAAAAAAAAAAAAAAAAAAAAA"),
        expected: Some("AAAAAAAAAAAAAAAAAAAAAA"),
        issued_at: spent.issued_at,
        now: 10 + NONCE_TTL_SECONDS,
        ttl: NONCE_TTL_SECONDS,
        consumed: spent.consumed,
        pair: Some(&pair_value),
        expected_pair: Some(&pair_value),
    });

    assert!(!verdict.ok);
    assert_eq!(verdict.reason.as_deref(), Some("reused"));
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
        .verify(&pair, "sub_0123456789abcdef", 100, &sender)
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

    gate.verify(&pair, "sub_0123456789abcdef", 0, &sender)
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
