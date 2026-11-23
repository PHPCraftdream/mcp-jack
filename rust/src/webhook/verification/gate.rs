//! The fail-closed per-pair verification gate of spec 06 section 5
//! (R5.2, R5.3, R5.5): one `(principal, canonical_url)` pair, the fixed route
//! order, the single-use challenge nonce and the success cache.
//!
//! Everything here is pure: `now` is an argument, the challenge and the
//! well-known document arrive through injected traits, and the gate owns the
//! only state it reads — its cache and its pending nonces. A caller's pair is
//! copied at entry, so later caller mutations cannot change a verdict, and
//! the one `Mutex` is never held while a challenge or a fetch runs
//! (spec 06 R5.2, R5.3, R5.5).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::webhook::ssrf::url::check_url;
use crate::webhook::verification::allowlist::allowlist_matches;
use crate::webhook::verification::cache::VerificationCache;
use crate::webhook::verification::document::{document_covers, DocumentFetcher};
use crate::webhook::verification::nonce::{
    self, EchoAttempt, EchoVerdict, PendingNonce, NONCE_TTL_SECONDS,
};
use crate::webhook::verification::route::VerificationRoute;
use crate::webhook::{codes, WebhookError};

/// The status of a verification-side refusal: the challenge answers the
/// subscribe call, not a receiver request, so no wire status is reported
/// (spec 06 R5.5).
const NO_HTTP_STATUS: u16 = 0;

/// The R6.2 code reused for a pair member that is not usable
/// (spec 06 R5.3).
const INVALID_CALLBACK_URL: &str = "invalid_callback_url";

/// The fixed reason of a pair with a zero-length `principal`
/// (spec 06 R5.3).
const REASON_PRINCIPAL: &str = "principal";

/// The fixed reason of a challenge that produced no reason of its own
/// (spec 06 R5.2).
const REASON_NO_ROUTE: &str = "no_route";

/// The application's out-of-band confirmation hook (spec 06 R5.8).
///
/// The alias keeps the gate's field readable; the public
/// [`EndpointGate::with_hook`] still takes the boxed closure itself.
type Hook = Box<dyn Fn(&EndpointPair) -> bool + Send + Sync>;

/// One `(principal, canonical_url)` pair a sender may verify and deliver to
/// (spec 06 R5.1, R5.2).
///
/// The pair owns its strings and its canonical url is rendered by
/// [`check_url`], so two pairs built from different renderings of the same
/// endpoint compare equal and a pair with an empty member cannot be built
/// (spec 06 R5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointPair {
    /// The verified Jack identity name of R8.1 (spec 06 R5.2, R8.1).
    principal: String,
    /// The R8.2 canonical form of the callback url (spec 06 R5.2, R8.2).
    canonical_url: String,
    /// The path of the canonical url, compared exactly as sent
    /// (spec 06 R5.10).
    path: String,
}

impl EndpointPair {
    /// Builds a pair from a principal and a callback url (spec 06 R5.2,
    /// R5.3).
    ///
    /// The url is validated and rendered in its R8.2 canonical form by
    /// [`check_url`], so a `dot_segment` url keeps its `invalid_callback_url`
    /// code and reason (R5.11). An empty principal is refused as
    /// `invalid_callback_url` with reason `principal`, because a pair with a
    /// zero-length member is not a usable pair (R5.3).
    pub fn new(principal: &str, url: &str) -> Result<Self, WebhookError> {
        if principal.is_empty() {
            return Err(WebhookError::with_reason(
                NO_HTTP_STATUS,
                INVALID_CALLBACK_URL,
                REASON_PRINCIPAL,
                "the pair principal is empty",
            ));
        }
        let checked = check_url(url)?;
        Ok(Self {
            principal: principal.to_owned(),
            canonical_url: checked.canonical,
            path: checked.path,
        })
    }

    /// Returns the pair's principal (spec 06 R5.2, R8.1).
    pub fn principal(&self) -> &str {
        &self.principal
    }

    /// Returns the pair's R8.2 canonical url (spec 06 R5.2, R8.2).
    pub fn canonical_url(&self) -> &str {
        &self.canonical_url
    }

    /// Returns the path of the canonical url (spec 06 R5.10).
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// One challenge attempt: the pair, the subscription being created and the
/// nonce to send (spec 06 R5.3, R5.5).
#[derive(Debug, Clone, Copy)]
pub struct VerificationRequest<'a> {
    /// The pair the attempt is bound to (spec 06 R5.3).
    pub pair: &'a EndpointPair,
    /// The subscription id the challenge carries in `X-MCP-Subscription-Id`
    /// (spec 06 R5.5).
    pub subscription_id: &'a str,
    /// The single-use nonce to send (spec 06 R5.3, R5.4).
    pub nonce: &'a str,
    /// The unix time of the attempt, in the unit of the other `now`
    /// arguments (spec 06 R5.3).
    pub now: i64,
}

/// Posts one challenge and judges the echo (spec 06 R5.4, R5.5).
///
/// The implementation performs the only I/O of the verification path; the
/// gate never calls it while holding its lock.
pub trait ChallengeSender {
    /// Posts the signed `verification` envelope carrying `request.nonce` to
    /// `request.pair.canonical_url()` and judges the echo by R5.4.
    fn send_challenge(&self, request: &VerificationRequest<'_>) -> EchoVerdict;
}

/// Looks a pair's verification status up and runs the fixed route order
/// (spec 06 R5.2).
pub trait EndpointVerifier: Send + Sync {
    /// True when the pair already has a live verification (R5.2 route 1).
    fn is_verified(&self, pair: &EndpointPair, now: i64) -> bool;

    /// Runs the fixed R5.2 order (cache, allowlist, out-of-band hook,
    /// well-known document, challenge) and caches a success.
    fn verify(
        &self,
        pair: &EndpointPair,
        subscription_id: &str,
        now: i64,
        challenge: &dyn ChallengeSender,
    ) -> Result<VerificationRoute, WebhookError>;
}

/// The gate state: the success cache and the pending nonces
/// (spec 06 R5.2, R5.3).
///
/// One `Mutex` owns both maps, so no lock ordering between them exists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct GateState {
    /// Every pair that completed a route successfully (spec 06 R5.2).
    cache: VerificationCache,
    /// Every nonce issued and not yet forgotten, with its attempt pair
    /// (spec 06 R5.3).
    pending: HashMap<String, PendingNonce>,
}

/// The fail-closed per-pair verification gate (spec 06 R5.2).
///
/// A pair is verified by the first route of R5.2 that succeeds, and a panic
/// or a refusal anywhere leaves it unverified (R5.1). The gate holds the
/// allowlist, the optional out-of-band hook, the optional document fetcher,
/// the success cache and the pending nonces; the challenge itself is a
/// caller-supplied [`ChallengeSender`] (R5.8, R5.9).
pub struct EndpointGate {
    /// The operator allowlist entries of R5.7, in configuration order.
    allowlist: Vec<String>,
    /// The grant TTL a success is cached for; `None` never expires
    /// (spec 06 R5.2).
    verification_ttl_ms: Option<i64>,
    /// The application's out-of-band confirmation hook (spec 06 R5.8).
    hook: Option<Hook>,
    /// The well-known document fetcher (spec 06 R5.9, R5.12).
    document: Option<Arc<dyn DocumentFetcher>>,
    /// The cache and the pending nonces, under one lock (spec 06 R5.2,
    /// R5.3).
    state: Mutex<GateState>,
}

impl EndpointGate {
    /// Builds a gate with an allowlist and a success TTL (spec 06 R5.2,
    /// R5.7).
    ///
    /// `verification_ttl_ms` is the subscription grant in the unit of the
    /// `now` arguments; `None` caches a success for the life of the process
    /// (R5.2).
    pub fn new(allowlist: Vec<String>, verification_ttl_ms: Option<i64>) -> Self {
        Self {
            allowlist,
            verification_ttl_ms,
            hook: None,
            document: None,
            state: Mutex::new(GateState::default()),
        }
    }

    /// Installs the application's out-of-band confirmation hook
    /// (spec 06 R5.8).
    ///
    /// The hook is called at most once per verification attempt and only
    /// after the cache and the allowlist missed (R5.2, R5.8).
    pub fn with_hook(mut self, hook: Box<dyn Fn(&EndpointPair) -> bool + Send + Sync>) -> Self {
        self.hook = Some(hook);
        self
    }

    /// Installs the well-known document fetcher (spec 06 R5.9, R5.12).
    ///
    /// The fetcher runs over the hardened path of section 6 and its verdict
    /// is judged by [`document_covers`]; a failed fetch never contributes
    /// route 4 (R5.9).
    pub fn with_document(mut self, fetcher: Arc<dyn DocumentFetcher>) -> Self {
        self.document = Some(fetcher);
        self
    }

    /// Records a successful verification of the pair for the grant TTL
    /// (spec 06 R5.2).
    pub fn record_success(&self, pair: &EndpointPair, now: i64) {
        self.lock().cache.record(
            &pair.principal,
            &pair.canonical_url,
            now,
            self.verification_ttl_ms,
        );
    }

    /// Returns true when the pair has a live cached verification
    /// (spec 06 R5.2, R5.12).
    ///
    /// Only the TTL expires a cached verification; a delivery failure never
    /// does (R5.12).
    pub fn cached(&self, pair: &EndpointPair, now: i64) -> bool {
        self.lock()
            .cache
            .is_verified(&pair.principal, &pair.canonical_url, now)
    }

    /// Locks the gate state, recovering a poisoned lock instead of panicking
    /// (spec 06 R5.2).
    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl EndpointVerifier for EndpointGate {
    /// True when the pair already has a live verification (spec 06 R5.2
    /// route 1).
    fn is_verified(&self, pair: &EndpointPair, now: i64) -> bool {
        self.cached(pair, now)
    }

    /// Runs the fixed R5.2 order (cache, allowlist, out-of-band hook,
    /// well-known document, challenge) and caches a success
    /// (spec 06 R5.2, R5.3, R5.5).
    ///
    /// The pair is copied at entry and never re-read from the caller. The
    /// challenge is the last route: it issues a fresh nonce bound to the
    /// recorded pair, sends it once, and accepts only through
    /// [`nonce::accept_echo`]; an accepted nonce is marked consumed and the
    /// pair is cached for the grant TTL. A failure returns `challenge_failed`
    /// carrying the echo verdict's fixed-literal reason and writes no cache
    /// entry (R5.3, R5.4). The gate lock is never held across the challenge
    /// send or the document fetch (R5.2).
    fn verify(
        &self,
        pair: &EndpointPair,
        subscription_id: &str,
        now: i64,
        challenge: &dyn ChallengeSender,
    ) -> Result<VerificationRoute, WebhookError> {
        let owned = EndpointPair {
            principal: pair.principal.clone(),
            canonical_url: pair.canonical_url.clone(),
            path: pair.path.clone(),
        };
        if self.cached(&owned, now) {
            return Ok(VerificationRoute::Cache);
        }
        if allowlist_matches(&self.allowlist, &owned.canonical_url).is_some() {
            self.record_success(&owned, now);
            return Ok(VerificationRoute::Allowlist);
        }
        if self.hook.as_ref().is_some_and(|hook| hook(&owned)) {
            self.record_success(&owned, now);
            return Ok(VerificationRoute::OutOfBand);
        }
        if self.document_covers_pair(&owned) {
            self.record_success(&owned, now);
            return Ok(VerificationRoute::WellKnown);
        }
        self.challenge(&owned, subscription_id, now, challenge)
    }
}

impl EndpointGate {
    /// Runs the well-known route: fetch through the injected fetcher and
    /// match the pair's path, with the lock released (spec 06 R5.9, R5.10).
    ///
    /// A failed fetch, or a document that does not cover the path, is simply
    /// not a route; the sender then falls through to the challenge (R5.9).
    fn document_covers_pair(&self, pair: &EndpointPair) -> bool {
        let Some(fetcher) = &self.document else {
            return false;
        };
        match fetcher.fetch(&pair.canonical_url) {
            Ok(document) => document_covers(&document, &pair.path).is_some(),
            Err(_) => false,
        }
    }

    /// Runs the challenge route, the last of R5.2 (spec 06 R5.3, R5.4).
    ///
    /// The nonce is issued and recorded before the send, the lock is
    /// released for the send, and only an echo that passes
    /// [`nonce::accept_echo`] consumes the nonce and caches the pair
    /// (R5.3, R5.4).
    fn challenge(
        &self,
        pair: &EndpointPair,
        subscription_id: &str,
        now: i64,
        challenge: &dyn ChallengeSender,
    ) -> Result<VerificationRoute, WebhookError> {
        let nonce = nonce::random_nonce()?;
        let recorded = PendingNonce {
            issued_at: now,
            pair: (pair.principal.clone(), pair.canonical_url.clone()),
            consumed: false,
        };
        self.lock().pending.insert(nonce.clone(), recorded.clone());
        let request = VerificationRequest {
            pair,
            subscription_id,
            nonce: &nonce,
            now,
        };
        let echo = challenge.send_challenge(&request);
        let consumed = match self.lock().pending.get(&nonce) {
            Some(pending) => pending.consumed,
            None => true,
        };
        let pair_value = serde_json::json!([recorded.pair.0, recorded.pair.1]);
        let accepted = nonce::accept_echo(&EchoAttempt {
            nonce: Some(nonce.as_str()),
            expected: Some(nonce.as_str()),
            issued_at: recorded.issued_at,
            now,
            ttl: NONCE_TTL_SECONDS,
            consumed,
            pair: Some(&pair_value),
            expected_pair: Some(&pair_value),
        });
        if echo.ok && accepted.ok {
            let mut state = self.lock();
            if let Some(pending) = state.pending.get_mut(&nonce) {
                pending.consumed = true;
            }
            state.cache.record(
                &pair.principal,
                &pair.canonical_url,
                now,
                self.verification_ttl_ms,
            );
            return Ok(VerificationRoute::Challenge);
        }
        let reason = if echo.ok {
            accepted.reason
        } else {
            echo.reason
        };
        Err(WebhookError::with_reason(
            NO_HTTP_STATUS,
            codes::CHALLENGE_FAILED,
            reason.unwrap_or_else(|| REASON_NO_ROUTE.to_string()),
            "the challenge handshake did not verify",
        ))
    }
}
