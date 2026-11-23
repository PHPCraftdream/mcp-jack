//! The HTTP-facing sender of spec 06 section 1 and the fail-closed
//! verification of section 5 (R5.1, R5.2, R5.12).
//!
//! The module is pure: [`Sender::deliver`] runs the R1.8 loop over a
//! [`WebhookTransport`], a [`HostResolver`], a [`Clock`] and an
//! [`EndpointVerifier`]. No socket, no wall clock and no entropy source is
//! used directly, so every decision can be reproduced from its inputs.
//!
//! The rules kept here are the sender's:
//!
//! * no message reaches the wire before its `(principal, canonical_url)` pair
//!   is verified by the injected gate, re-checked before every attempt
//!   (R5.1, R5.2, R1.9);
//! * the challenge POST is sent over the same hardened path as a delivery, to
//!   the pair's canonical url only, and is never retried (R5.5, R5.12);
//! * one fresh `webhook-id` per message and a fresh `webhook-timestamp` and
//!   signature per attempt (R1.4, R1.5);
//! * `delivery::sender_decision` after every attempt, so `410` and `413` are
//!   never retried and the fourth attempt is always the last (R1.7, R1.8);
//! * a `3xx` is final for that message and is never followed (R1.7, R6.10);
//! * a refusal before any request is sent is final, with the R1.9 category
//!   of its code (R1.9, R6.8, R6.9);
//! * a body above the configured cap is never built into a request (R1.2);
//! * one attempt is bounded by the R1.6 whole-attempt cap, and a connected
//!   peer that differs from the validated address is final (R1.6, R6.9).

use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;

use crate::webhook::delivery::{
    self, LastError, SenderAction, SenderAttempt, SenderDecision, ATTEMPT_TIMEOUT_SECONDS,
};
use crate::webhook::encoding::WebhookSecret;
use crate::webhook::http::transport::{
    prepare, resolve_answers, FailureKind, HostResolver, TransportResponse, WebhookTransport,
};
use crate::webhook::signatures::{emission_header, EmissionKey, EmissionSecret, SignatureContent};
use crate::webhook::ssrf::url::{check_url, UrlParts};
use crate::webhook::verification::gate::{
    ChallengeSender, EndpointPair, EndpointVerifier, VerificationRequest,
};
use crate::webhook::verification::nonce::{challenge_echo, EchoVerdict};
use crate::webhook::w1::{self, JackSigningParts};
use crate::webhook::{codes, subscription, MessageKind, WebhookError};

/// The default Jack response window of spec 06 R4.4, in seconds: 30 s,
/// never more than 120 s and independent of the 300 s Standard Webhooks
/// window. [`delivery_headers`] uses it to decide whether the `w1` header it
/// is about to build can pass the receiver's window check.
pub const JACK_WINDOW_SECONDS: i64 = 30;

/// One message as the sender needs it to build the R1.1 headers.
///
/// The secrets and signing keys are ordered current first, previous second,
/// so the emission order of R2.8 is preserved; entries past the second are
/// ignored by the emission set. The type deliberately has no `Debug`
/// implementation: it owns delivery secrets and private keys.
pub struct OutgoingMessage {
    /// The verified Jack identity name of the receiving pair (spec 06 R5.2,
    /// R8.1).
    pub principal: String,
    /// The callback url exactly as subscribed (spec 06 R6.1).
    pub url: String,
    /// The subscription id of `X-MCP-Subscription-Id` (spec 06 R1.1).
    pub subscription_id: String,
    /// The kind the `webhook-id` prefix is drawn from (spec 06 R1.4).
    pub kind: MessageKind,
    /// The raw body bytes exactly as signed (spec 06 R2.3).
    pub body: Vec<u8>,
    /// The delivery secrets, current first (spec 06 R2.8).
    pub secrets: Vec<WebhookSecret>,
    /// The `(kid, key)` pairs that sign `v1a` and `v2a`, current first
    /// (spec 06 R2.8).
    pub signing_keys: Vec<(String, SigningKey)>,
    /// The Jack audience of `w1` (spec 06 R4.3).
    pub aud: Option<String>,
    /// The `(kid, key)` pair of `Jack-Webhook-Auth`, when configured
    /// (spec 06 R4.1).
    pub jack_signing: Option<(String, SigningKey)>,
}

/// What happened to one message after the R1.8 loop (spec 06 R1.7, R1.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendAction {
    /// A `2xx` accepted the message; no retry is needed (spec 06 R1.7).
    Accepted,
    /// The message is final for a non-retryable outcome: a `3xx`, `410`,
    /// `413`, another `4xx`, a section 6 refusal before any request was
    /// sent, or an unverified pair (spec 06 R1.7, R1.9, R5.1).
    Final {
        /// The recorded `lastError` category (spec 06 R1.9).
        last_error: LastError,
    },
    /// A retryable outcome ran out of the four attempts or of the
    /// `t0 + 900 s` cap (spec 06 R1.8).
    Abandoned {
        /// The recorded `lastError` category (spec 06 R1.9).
        last_error: LastError,
    },
}

/// The result of one [`Sender::deliver`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendOutcome {
    /// The accept, final or abandoned decision (spec 06 R1.7, R1.8).
    pub action: SendAction,
    /// The number of attempts made, 0 when no request could be built or the
    /// pair was refused before any send (spec 06 R5.1).
    pub attempts: u32,
    /// The last HTTP status read, when any attempt reached a response.
    pub last_status: Option<u16>,
}

/// The sender's fixed configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderConfig {
    /// The operator override ranges of R6.11, checked after the registry
    /// tables.
    pub allowed_ranges: Vec<String>,
    /// The largest raw body a request may carry (spec 06 R1.2).
    pub max_body_bytes: usize,
    /// The grant TTL a verification success is cached for, in the unit of
    /// [`Clock::now`] (spec 06 R5.2). The sender does not own the gate, so
    /// this value is carried here only to build the gate and the sender from
    /// one configuration.
    pub verification_ttl_ms: Option<i64>,
}

/// The sender's clock: the R1.8 schedule origin, the per-attempt timestamp,
/// the verification instant and the waits between attempts.
pub trait Clock {
    /// Returns the current Unix time in whole seconds (spec 06 R1.5).
    fn now(&self) -> i64;

    /// Blocks until `at` Unix seconds have passed (spec 06 R1.8).
    fn sleep_until(&self, at: i64);
}

/// The sender of spec 06 section 1: one message, up to four attempts, each
/// preceded by the pair's verification gate.
pub struct Sender {
    transport: Arc<dyn WebhookTransport>,
    resolver: Arc<dyn HostResolver>,
    clock: Arc<dyn Clock>,
    config: SenderConfig,
    gate: Arc<dyn EndpointVerifier>,
}

impl Sender {
    /// Builds a sender over the given transport, resolver, clock and gate.
    ///
    /// There is no default gate: a sender cannot exist without one, so no
    /// delivery path can skip the R5.1 check (spec 06 R5.1).
    pub fn new(
        transport: Arc<dyn WebhookTransport>,
        resolver: Arc<dyn HostResolver>,
        clock: Arc<dyn Clock>,
        config: SenderConfig,
        gate: Arc<dyn EndpointVerifier>,
    ) -> Self {
        Self {
            transport,
            resolver,
            clock,
            config,
            gate,
        }
    }

    /// Delivers one message and returns its outcome (spec 06 R1.6-R1.10,
    /// R5.1, R5.2).
    ///
    /// The pair is built once from `principal` and `url`, so a refused url is
    /// final with the refusal's R1.9 category, and one `webhook-id` is drawn
    /// per message (R1.4). Every attempt re-reads the clock and re-checks the
    /// pair before anything touches the network; an unverified pair runs the
    /// gate, and a refusal or a still-unverified pair ends the message as
    /// `Final { ChallengeFailed }` without a request (R5.1, R5.2, R1.9).
    ///
    /// The attempt itself regenerates the timestamp and the signatures (R1.5),
    /// resolves the host twice under the R1.6 whole-attempt budget — the
    /// validation answers and the R6.9 recheck — and the two answer sets plus
    /// the override ranges decide the connect target (R6.8-R6.10). A
    /// `PeerMismatch` is final `ConnectionRefused` and is never retried
    /// (R6.9); otherwise `delivery::sender_decision` decides accept, retry at
    /// the scheduled time, or final, so `410`, `413` and `3xx` are never
    /// retried and a redirect is never followed.
    pub fn deliver(&self, message: &OutgoingMessage) -> SendOutcome {
        let pair = match EndpointPair::new(&message.principal, &message.url) {
            Ok(pair) => pair,
            Err(error) => {
                return SendOutcome {
                    action: SendAction::Final {
                        last_error: refusal_of(&error),
                    },
                    attempts: 0,
                    last_status: None,
                }
            }
        };
        let webhook_id = match subscription::random_webhook_id(message.kind) {
            Ok(webhook_id) => webhook_id,
            // The closed R1.9 list has no local-error category; a failed
            // entropy source cannot be retried on the wire either.
            Err(_) => {
                return SendOutcome {
                    action: SendAction::Final {
                        last_error: LastError::ConnectionRefused,
                    },
                    attempts: 0,
                    last_status: None,
                }
            }
        };
        let endpoint = match check_url(&message.url) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                return SendOutcome {
                    action: SendAction::Final {
                        last_error: refusal_of(&error),
                    },
                    attempts: 0,
                    last_status: None,
                }
            }
        };
        let t0 = self.clock.now();
        let mut attempts = 0u32;
        let mut last_status = None;
        loop {
            // R5.1, R5.2: the pair is verified before EVERY attempt, so a
            // grant that expired during a retry sleep cannot carry an event.
            let now = self.clock.now();
            if !self.verified(&pair, message, now) {
                return SendOutcome {
                    action: SendAction::Final {
                        last_error: LastError::ChallengeFailed,
                    },
                    attempts,
                    last_status,
                };
            }
            attempts += 1;
            match self.attempt(message, &webhook_id, &endpoint) {
                Attempt::Refused(last_error) => {
                    return SendOutcome {
                        action: SendAction::Final { last_error },
                        attempts,
                        last_status,
                    }
                }
                Attempt::Response(response) => {
                    last_status = Some(response.status);
                    let retryable = retryable_status(response.status);
                    let decision = delivery::sender_decision(&SenderAttempt {
                        status: Some(response.status),
                        transport: None,
                        retry_after: response.retry_after,
                        attempt: attempts,
                        t0,
                        response_time: self.clock.now(),
                    });
                    if let Some(outcome) = self.settle(decision, retryable, attempts, last_status) {
                        return outcome;
                    }
                }
                Attempt::Failure(last_error) => {
                    let decision = delivery::sender_decision(&SenderAttempt {
                        status: None,
                        transport: Some(last_error),
                        retry_after: None,
                        attempt: attempts,
                        t0,
                        response_time: self.clock.now(),
                    });
                    if let Some(outcome) = self.settle(decision, true, attempts, last_status) {
                        return outcome;
                    }
                }
            }
        }
    }

    /// Returns true when the pair is verified, running the gate when it is
    /// not and re-checking afterwards (spec 06 R5.1, R5.2).
    ///
    /// A gate refusal or a pair the gate did not record is `false`, so the
    /// caller ends the message as `Final { ChallengeFailed }` without any
    /// request (R5.1, R1.9). The challenge adapter is built per delivery and
    /// posts only to the pair's canonical url (R5.5).
    fn verified(&self, pair: &EndpointPair, message: &OutgoingMessage, now: i64) -> bool {
        if self.gate.is_verified(pair, now) {
            return true;
        }
        let challenge = DeliveryChallenge {
            sender: self,
            message,
        };
        if self
            .gate
            .verify(pair, &message.subscription_id, now, &challenge)
            .is_err()
        {
            return false;
        }
        self.gate.is_verified(pair, now)
    }

    /// Runs one attempt up to a response or an R1.9 category.
    ///
    /// The R1.6 whole-attempt budget starts before the first lookup, so DNS,
    /// connect, TLS, the write and the read share one cap; a spent budget is
    /// `timeout` and any other resolution failure is `connection_refused`
    /// (spec 06 R1.6, R1.9).
    fn attempt(&self, message: &OutgoingMessage, webhook_id: &str, endpoint: &UrlParts) -> Attempt {
        let budget = Duration::from_secs(ATTEMPT_TIMEOUT_SECONDS);
        let started = Instant::now();
        let (answers, recheck) = match resolve_answers(&*self.resolver, endpoint, budget) {
            Ok(pair) => pair,
            Err(error) => return Attempt::Failure(resolution_failure(&error)),
        };
        let remaining = budget.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Attempt::Failure(LastError::Timeout);
        }
        let now = self.clock.now();
        let timestamp = now.to_string();
        let headers = delivery_headers(message, webhook_id, &timestamp, now, JACK_WINDOW_SECONDS);
        let prepared = match prepare(
            &message.url,
            &answers,
            &recheck,
            &self.config.allowed_ranges,
            "POST",
            headers,
            message.body.clone(),
            self.config.max_body_bytes,
            remaining,
        ) {
            Ok(prepared) => prepared,
            Err(error) => return Attempt::Refused(refusal_of(&error)),
        };
        match self.transport.send(&prepared.request) {
            Ok(response) => Attempt::Response(response),
            // R6.9: a peer that differs from the validated address is final
            // `connection_refused`, never retried on the new address.
            Err(failure) if failure.kind == FailureKind::PeerMismatch => {
                Attempt::Refused(LastError::ConnectionRefused)
            }
            Err(failure) => Attempt::Failure(failure.error),
        }
    }

    /// Applies one decision, sleeping for a retry; `None` means the loop
    /// continues with the next attempt (spec 06 R1.8).
    fn settle(
        &self,
        decision: SenderDecision,
        retryable_outcome: bool,
        attempts: u32,
        last_status: Option<u16>,
    ) -> Option<SendOutcome> {
        match decision.action {
            SenderAction::Accept => Some(SendOutcome {
                action: SendAction::Accepted,
                attempts,
                last_status,
            }),
            SenderAction::Retry { next_at } => {
                self.clock.sleep_until(next_at);
                None
            }
            SenderAction::Final => {
                let last_error = decision.last_error.unwrap_or(LastError::ConnectionRefused);
                let action = if retryable_outcome {
                    SendAction::Abandoned { last_error }
                } else {
                    SendAction::Final { last_error }
                };
                Some(SendOutcome {
                    action,
                    attempts,
                    last_status,
                })
            }
        }
    }

    /// Posts one verification envelope over the hardened path, once and never
    /// retried, and judges the echo (spec 06 R5.4, R5.5, R5.12).
    ///
    /// The destination is [`VerificationRequest::pair`]'s canonical url, never
    /// the message url: the envelope carries `request.subscription_id` and
    /// `request.nonce`, a fresh timestamp, and the signatures of the
    /// message's secrets and keys, with `w1` when one is configured (R5.5). A
    /// refusal before the send or a transport failure returns `ok = false`
    /// with `challenge_failed` and that R1.9 category as the fixed-literal
    /// reason (R5.5).
    fn post_challenge(
        &self,
        message: &OutgoingMessage,
        request: &VerificationRequest<'_>,
    ) -> EchoVerdict {
        let Ok(body) = serde_json::to_vec(&serde_json::json!({
            "type": "verification",
            "challenge": request.nonce,
        })) else {
            return challenge_rejection(LastError::Http4xx.as_str());
        };
        let envelope = OutgoingMessage {
            principal: request.pair.principal().to_owned(),
            url: request.pair.canonical_url().to_owned(),
            subscription_id: request.subscription_id.to_owned(),
            kind: MessageKind::Verification,
            body,
            secrets: message.secrets.clone(),
            signing_keys: message.signing_keys.clone(),
            aud: message.aud.clone(),
            jack_signing: message.jack_signing.clone(),
        };
        let Ok(webhook_id) = subscription::random_webhook_id(MessageKind::Verification) else {
            // The closed R1.9 list has no local-error category; a failed
            // entropy source cannot be retried on the wire either.
            return challenge_rejection(LastError::ConnectionRefused.as_str());
        };
        let endpoint = match check_url(&envelope.url) {
            Ok(endpoint) => endpoint,
            Err(error) => return challenge_rejection(error.reason().unwrap_or(error.code())),
        };
        let budget = Duration::from_secs(ATTEMPT_TIMEOUT_SECONDS);
        let started = Instant::now();
        let (answers, recheck) = match resolve_answers(&*self.resolver, &endpoint, budget) {
            Ok(pair) => pair,
            Err(error) => return challenge_rejection(resolution_failure(&error).as_str()),
        };
        let remaining = budget.saturating_sub(started.elapsed());
        let now = self.clock.now();
        let timestamp = now.to_string();
        let headers =
            delivery_headers(&envelope, &webhook_id, &timestamp, now, JACK_WINDOW_SECONDS);
        let prepared = match prepare(
            &envelope.url,
            &answers,
            &recheck,
            &self.config.allowed_ranges,
            "POST",
            headers,
            envelope.body.clone(),
            self.config.max_body_bytes,
            remaining,
        ) {
            Ok(prepared) => prepared,
            Err(error) => return challenge_rejection(error.reason().unwrap_or(error.code())),
        };
        match self.transport.send(&prepared.request) {
            Ok(response) => challenge_echo(
                response.status,
                &String::from_utf8_lossy(&response.body),
                request.nonce,
            ),
            Err(failure) => challenge_rejection(failure.error.as_str()),
        }
    }
}

/// The per-delivery [`ChallengeSender`] the gate calls for route 5
/// (spec 06 R5.5, R5.12).
///
/// It carries the sender and the delivery's secrets only; the destination,
/// the subscription id and the nonce come from the [`VerificationRequest`],
/// so the message url can never become the challenge destination.
struct DeliveryChallenge<'a> {
    sender: &'a Sender,
    message: &'a OutgoingMessage,
}

impl ChallengeSender for DeliveryChallenge<'_> {
    /// Posts the envelope to the pair's canonical url and judges the echo
    /// (spec 06 R5.4, R5.5).
    fn send_challenge(&self, request: &VerificationRequest<'_>) -> EchoVerdict {
        self.sender.post_challenge(self.message, request)
    }
}

/// Builds the R1.1 header set of one attempt.
///
/// The headers are `Content-Type: application/json`, the lowercase
/// `webhook-id`, `webhook-timestamp` and `webhook-signature`,
/// `X-MCP-Subscription-Id`, and `Jack-Webhook-Auth` when a `w1` key is
/// configured (spec 06 R1.1). The signature value is the R2.8 emission set
/// of the current and previous secrets and keys, computed over the raw body
/// (R2.2-R2.6).
///
/// `now` and `jack_window` guard the `w1` header: it is emitted only when
/// `timestamp` lies inside the Jack window of R4.4, because a signature the
/// receiver is bound to reject must not be constructed. A caller that passes
/// the current time always satisfies it.
pub fn delivery_headers(
    message: &OutgoingMessage,
    webhook_id: &str,
    timestamp: &str,
    now: i64,
    jack_window: i64,
) -> Vec<(String, String)> {
    let content = SignatureContent {
        webhook_id,
        timestamp,
        body: &message.body,
    };
    let secrets: Vec<EmissionSecret<'_>> = message
        .secrets
        .iter()
        .enumerate()
        .map(|(index, secret)| EmissionSecret {
            secret,
            current: index == 0,
        })
        .collect();
    let keys: Vec<EmissionKey<'_>> = message
        .signing_keys
        .iter()
        .enumerate()
        .map(|(index, (kid, signing_key))| EmissionKey {
            kid,
            signing_key,
            current: index == 0,
        })
        .collect();
    let signature = emission_header(&secrets, &keys, &message.subscription_id, &content);
    let mut headers = vec![
        ("Content-Type".to_owned(), "application/json".to_owned()),
        ("webhook-id".to_owned(), webhook_id.to_owned()),
        ("webhook-timestamp".to_owned(), timestamp.to_owned()),
        ("webhook-signature".to_owned(), signature),
        (
            "X-MCP-Subscription-Id".to_owned(),
            message.subscription_id.clone(),
        ),
    ];
    if let Some((kid, signing_key)) = &message.jack_signing {
        if jack_timestamp_ok(timestamp, now, jack_window) {
            let parts = JackSigningParts {
                aud: message.aud.as_deref().unwrap_or_default(),
                subscription_id: &message.subscription_id,
                webhook_id,
                timestamp,
                callback_url: &message.url,
                body: &message.body,
            };
            headers.push((
                "Jack-Webhook-Auth".to_owned(),
                w1::sign(signing_key, kid, &parts),
            ));
        }
    }
    headers
}

/// Reports whether `timestamp` is inside the R4.4 window around `now`.
fn jack_timestamp_ok(timestamp: &str, now: i64, jack_window: i64) -> bool {
    timestamp
        .parse::<i64>()
        .is_ok_and(|seconds| delivery::freshness(now, seconds, jack_window).is_ok())
}

/// One attempt before the R1.8 decision.
enum Attempt {
    /// A response was read (spec 06 R1.7).
    Response(TransportResponse),
    /// No response was read; the category is retryable (spec 06 R1.9).
    Failure(LastError),
    /// The section 6 or R6.9 decision refused the attempt; the message is
    /// final (spec 06 R1.9, R6.8, R6.9).
    Refused(LastError),
}

/// Reports whether a status is retryable when the schedule is exhausted
/// (spec 06 R1.7).
fn retryable_status(status: u16) -> bool {
    matches!(status, 425 | 429) || (500..=599).contains(&status)
}

/// Maps a section 6 or R5 refusal code to its R1.9 category; a code without
/// an official mapping is a client-side refusal, hence `http_4xx`
/// (spec 06 R1.9).
fn refusal_of(error: &WebhookError) -> LastError {
    delivery::map_internal_outcome(error.code()).unwrap_or(LastError::Http4xx)
}

/// Maps one resolver failure to its R1.9 category: a spent budget is
/// `timeout` and every other resolution failure is `connection_refused`
/// (spec 06 R1.6, R1.9).
fn resolution_failure(error: &WebhookError) -> LastError {
    if error.code() == LastError::Timeout.as_str() {
        LastError::Timeout
    } else {
        LastError::ConnectionRefused
    }
}

/// Builds the `challenge_failed` verdict carrying one fixed-literal reason
/// (spec 06 R5.4, R5.5).
fn challenge_rejection(reason: &str) -> EchoVerdict {
    EchoVerdict {
        ok: false,
        code: Some(codes::CHALLENGE_FAILED),
        reason: Some(reason.to_owned()),
    }
}
