//! The HTTP-facing sender of spec 06 section 1 and the connect decision of
//! section 6, plus the receiver adapters of section 5.
//!
//! The module is pure: [`prepare`] turns a validated URL, the resolver
//! answers and the re-resolution into a [`TransportRequest`] carrying the
//! R6.8 connect target; [`Sender::deliver`] runs the R1.8 loop over a
//! [`WebhookTransport`], a [`HostResolver`] and a [`Clock`]. No socket, no
//! wall clock and no entropy source is used directly, so every decision can
//! be reproduced from its inputs.
//!
//! The rules kept here are the sender's:
//!
//! * one fresh `webhook-id` per message and a fresh `webhook-timestamp` and
//!   signature per attempt (R1.4, R1.5);
//! * `delivery::sender_decision` after every attempt, so `410` and `413` are
//!   never retried and the fourth attempt is always the last (R1.7, R1.8);
//! * a `3xx` is final for that message and is never followed (R1.7, R6.10);
//! * a refusal before any request is sent is final, with the R1.9 category
//!   of its code (R1.9, R6.8, R6.9);
//! * a body above the configured cap is never built into a request (R1.2).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::webhook::delivery::{
    self, LastError, SenderAction, SenderAttempt, SenderDecision, CONNECT_TIMEOUT_SECONDS,
    RESPONSE_TIMEOUT_SECONDS,
};
use crate::webhook::encoding::WebhookSecret;
use crate::webhook::receiver::errors::rejection;
use crate::webhook::receiver::DeliveryOutcome;
use crate::webhook::signatures::{emission_header, EmissionKey, EmissionSecret, SignatureContent};
use crate::webhook::ssrf::delivery::{
    delivery_decision, ConnectTarget, DeliveryDecision, DeliveryInput,
};
use crate::webhook::ssrf::host::HostKind;
use crate::webhook::ssrf::url::{check_url, UrlParts};
use crate::webhook::verification::document::{
    check_document_fetch, well_known_url, ReceiverDocument,
};
use crate::webhook::verification::nonce::{challenge_echo, EchoVerdict};
use crate::webhook::w1::{self, JackSigningParts};
use crate::webhook::{codes, subscription, MessageKind, WebhookError};

/// The default Jack response window of spec 06 R4.4, in seconds: 30 s,
/// never more than 120 s and independent of the 300 s Standard Webhooks
/// window. [`delivery_headers`] uses it to decide whether the `w1` header it
/// is about to build can pass the receiver's window check.
pub const JACK_WINDOW_SECONDS: i64 = 30;

/// The largest receiver document the well-known fetch accepts, in bytes
/// (spec 06 R5.9). A larger body is refused before its text is judged.
pub const MAX_DOCUMENT_BYTES: usize = 8192;

/// The status of a verification-side refusal: the well-known fetch and the
/// challenge POST answer the subscribe call, not a receiver request, so no
/// wire status is reported (spec 06 R5.9, R5.12).
const NO_HTTP_STATUS: u16 = 0;

/// The invalid-input status the profile uses for a rejected client value
/// (spec 06 section 3).
const BAD_REQUEST: u16 = 400;

/// The R6.2 code of a canonical url that does not parse (spec 06 R5.9).
const INVALID_CALLBACK_URL: &str = "invalid_callback_url";

/// The R6.2 reason of a canonical url that does not parse (spec 06 R6.2).
const REASON_URL: &str = "url";

/// The fixed reason of a document response that is a `3xx` (spec 06 R6.10).
const REASON_REDIRECT: &str = "redirect";

/// The fixed `document_fetch_failed` reason of a body above
/// [`MAX_DOCUMENT_BYTES`] (spec 06 R5.9).
const REASON_TOO_LARGE: &str = "too_large";

/// The `Accept` value of the well-known document fetch (spec 06 R5.9).
const ACCEPT_JSON: &str = "application/json";

/// Resolves a host name to its answers at delivery time (spec 06 R6.8).
///
/// A literal host is never passed here: [`prepare`] and [`Sender::deliver`]
/// treat an IP literal as its own name, exactly as R6.8 requires.
pub trait HostResolver {
    /// Returns every answer for `host` in resolver order (spec 06 R6.8).
    ///
    /// The port is supplied for resolvers that need it (for example a
    /// service-lookup resolver); a plain A/AAAA resolver may ignore it. An
    /// error is a DNS failure, which the sender records as
    /// `connection_refused` (spec 06 R1.9).
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, WebhookError>;
}

/// One outbound delivery request after the section 6 decision (spec 06
/// R6.8-R6.10).
#[derive(Debug, Clone)]
pub struct TransportRequest {
    /// The callback url exactly as subscribed, never normalized (R6.1).
    pub url: String,
    /// The HTTP method, `POST` for every delivery (R1.1).
    pub method: &'static str,
    /// The R1.1 headers, without `Host` and without framing headers.
    pub headers: Vec<(String, String)>,
    /// The raw body bytes exactly as they are signed (R2.3).
    pub body: Vec<u8>,
    /// The validated address and the names to present (R6.8).
    pub connect: ConnectTarget,
    /// The connect-phase cap of one attempt: 10 s (R1.6).
    pub connect_timeout: Duration,
    /// The response-phase cap of one attempt: 10 s (R1.6).
    pub response_timeout: Duration,
    /// The largest response body the transport may buffer (R1.2).
    pub max_body_bytes: usize,
}

/// One response the transport read (spec 06 R1.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportResponse {
    /// The HTTP status.
    pub status: u16,
    /// The `Retry-After` delay in seconds, when the header held a number;
    /// an HTTP-date form is not parsed (spec 06 R1.8).
    pub retry_after: Option<i64>,
    /// The response body, at most `max_body_bytes` bytes.
    pub body: Vec<u8>,
    /// The declared `Content-Length`, when the header held one.
    pub declared_length: Option<u64>,
}

/// A transport failure, restricted to the three R1.9 network categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportFailure {
    /// `connection_refused`, `timeout` or `tls_error` (spec 06 R1.9).
    pub error: LastError,
}

/// The blocking transport of one delivery attempt.
pub trait WebhookTransport {
    /// Sends one request and returns its response or an R1.9 network
    /// failure.
    ///
    /// Redirects are never followed: a `3xx` is returned as the response and
    /// the caller classifies it as final `http_4xx` (spec 06 R6.10).
    fn send(&self, request: &TransportRequest) -> Result<TransportResponse, TransportFailure>;
}

/// A request that passed the section 6 decision and may be sent (spec 06
/// R6.8-R6.10).
#[derive(Debug, Clone)]
pub struct PreparedRequest {
    /// The request, including the validated connect target.
    pub request: TransportRequest,
    /// The reason of the first allowed answer, or `allowed_range`
    /// (spec 06 R6.5, R6.11).
    pub reason: String,
}

/// Applies the R6.8/R6.9/R6.10 decision and builds the outbound request.
///
/// `answers` is the resolver answer set at validation time and `recheck` the
/// answer set of the fresh resolution immediately before connect. Every
/// answer is classified in resolver order by
/// [`delivery_decision`]; the first `reject` refuses the attempt with
/// `blocked_address` and its reason, a recheck whose canonical address
/// differs refuses with `dns_rebinding`, and an `allow` carries the first
/// allowed address into [`TransportRequest::connect`] (spec 06 R6.8, R6.9).
///
/// A body above `max_body_bytes` is refused with the receiver's fixed
/// `413 body_too_large` answer before any request is built (spec 06 R1.2).
#[allow(clippy::too_many_arguments)]
pub fn prepare(
    url: &str,
    answers: &[IpAddr],
    recheck: &[IpAddr],
    allowed_ranges: &[String],
    method: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    max_body_bytes: usize,
) -> Result<PreparedRequest, WebhookError> {
    if body.len() > max_body_bytes {
        return Err(rejection(codes::BODY_TOO_LARGE));
    }
    let answer_text: Vec<String> = answers.iter().map(ToString::to_string).collect();
    let recheck_text: Vec<String> = recheck.iter().map(ToString::to_string).collect();
    let decision = delivery_decision(&DeliveryInput {
        url,
        answers: &answer_text,
        recheck: &recheck_text,
        allowed_ranges,
        redirect_status: None,
    });
    match decision {
        DeliveryDecision::Allow { connect, reason } => Ok(PreparedRequest {
            request: TransportRequest {
                url: url.to_owned(),
                method,
                headers,
                body,
                connect,
                connect_timeout: Duration::from_secs(CONNECT_TIMEOUT_SECONDS),
                response_timeout: Duration::from_secs(RESPONSE_TIMEOUT_SECONDS),
                max_body_bytes,
            },
            reason,
        }),
        DeliveryDecision::Reject { code, reason } => Err(WebhookError::with_reason(
            400,
            code,
            reason,
            "the delivery is refused before any request is sent",
        )),
    }
}

/// What happened to one message after the R1.8 loop (spec 06 R1.7, R1.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendAction {
    /// A `2xx` accepted the message; no retry is needed (spec 06 R1.7).
    Accepted,
    /// The message is final for a non-retryable outcome: a `3xx`, `410`,
    /// `413`, another `4xx`, or a section 6 refusal before any request was
    /// sent (spec 06 R1.7, R1.9).
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
    /// The number of attempts made, 0 when no request could be built.
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
}

/// The sender's clock: the R1.8 schedule origin, the per-attempt timestamp
/// and the waits between attempts.
pub trait Clock {
    /// Returns the current Unix time in whole seconds (spec 06 R1.5).
    fn now(&self) -> i64;

    /// Blocks until `at` Unix seconds have passed (spec 06 R1.8).
    fn sleep_until(&self, at: i64);
}

/// The sender of spec 06 section 1: one message, up to four attempts.
pub struct Sender {
    transport: Arc<dyn WebhookTransport>,
    resolver: Arc<dyn HostResolver>,
    clock: Arc<dyn Clock>,
    config: SenderConfig,
}

impl Sender {
    /// Builds a sender over the given transport, resolver and clock.
    pub fn new(
        transport: Arc<dyn WebhookTransport>,
        resolver: Arc<dyn HostResolver>,
        clock: Arc<dyn Clock>,
        config: SenderConfig,
    ) -> Self {
        Self {
            transport,
            resolver,
            clock,
            config,
        }
    }

    /// Delivers one message and returns its outcome (spec 06 R1.6-R1.10).
    ///
    /// A fresh `webhook-id` is drawn once per message (R1.4), and every
    /// attempt regenerates the timestamp and the signatures (R1.5). The host
    /// is resolved twice per attempt — validation and the R6.9 recheck —
    /// and the two answer sets plus the override ranges decide the connect
    /// target (R6.8-R6.10). A refusal before sending is final with its R1.9
    /// category; otherwise `delivery::sender_decision` decides accept, retry
    /// at the scheduled time, or final, so `410`, `413` and `3xx` are never
    /// retried and a redirect is never followed.
    pub fn deliver(&self, message: &OutgoingMessage) -> SendOutcome {
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
        let host = if endpoint.host_kind == HostKind::Name {
            Some(endpoint.host_value)
        } else {
            None
        };
        let t0 = self.clock.now();
        let mut attempts = 0u32;
        let mut last_status = None;
        loop {
            attempts += 1;
            match self.attempt(message, &webhook_id, host.as_deref(), endpoint.port) {
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

    /// Runs one attempt up to a response or an R1.9 category.
    fn attempt(
        &self,
        message: &OutgoingMessage,
        webhook_id: &str,
        host: Option<&str>,
        port: u16,
    ) -> Attempt {
        let (answers, recheck) = match host {
            Some(name) => {
                let answers = match self.resolver.resolve(name, port) {
                    Ok(answers) if !answers.is_empty() => answers,
                    _ => return Attempt::Failure(LastError::ConnectionRefused),
                };
                // R6.9: the address actually connected to must equal the
                // validated one, so the name is resolved again right before
                // the decision.
                let recheck = match self.resolver.resolve(name, port) {
                    Ok(answers) if !answers.is_empty() => answers,
                    _ => return Attempt::Failure(LastError::ConnectionRefused),
                };
                (answers, recheck)
            }
            None => (Vec::new(), Vec::new()),
        };
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
        ) {
            Ok(prepared) => prepared,
            Err(error) => return Attempt::Refused(refusal_of(&error)),
        };
        match self.transport.send(&prepared.request) {
            Ok(response) => Attempt::Response(response),
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
}

/// The verification-side senders of spec 06 section 5 (R5.9, R5.12).
///
/// Both use the same hardened path as [`Sender::deliver`]: the destination is
/// validated by [`check_url`], the host is resolved at fetch time and again
/// before connect, the section 6 decision runs in [`prepare`], and a `3xx` is
/// never followed (spec 06 R5.12, R6.8-R6.10).
impl Sender {
    /// Fetches `/.well-known/mcp-webhook-receiver.json` over the hardened
    /// path (spec 06 R5.9, R5.12).
    ///
    /// The url is [`well_known_url`] of the delivery origin; a canonical url
    /// that does not parse is `invalid_callback_url` (R5.9). The host is
    /// resolved twice — validation and the R6.9 recheck — and the section 6
    /// decision of [`prepare`] surfaces as its own [`WebhookError`], so a
    /// blocked, rebinding or redirect refusal keeps the decision's code
    /// (R6.8-R6.10). The request is a `GET` with `Accept: application/json`,
    /// a `3xx` is `redirect_refused`, a body above [`MAX_DOCUMENT_BYTES`] is
    /// refused, and the body is judged by [`check_document_fetch`] (R5.9).
    pub fn fetch_receiver_document(
        &self,
        canonical_url: &str,
    ) -> Result<ReceiverDocument, WebhookError> {
        let Some(url) = well_known_url(canonical_url) else {
            return Err(invalid_canonical_url());
        };
        let endpoint = match check_url(&url) {
            Ok(endpoint) => endpoint,
            Err(_) => return Err(invalid_canonical_url()),
        };
        let Some((answers, recheck)) = self.resolve_pair(&endpoint) else {
            return Err(network_error(LastError::ConnectionRefused));
        };
        let prepared = prepare(
            &url,
            &answers,
            &recheck,
            &self.config.allowed_ranges,
            "GET",
            vec![("Accept".to_owned(), ACCEPT_JSON.to_owned())],
            Vec::new(),
            MAX_DOCUMENT_BYTES,
        )?;
        let response = match self.transport.send(&prepared.request) {
            Ok(response) => response,
            Err(failure) => return Err(network_error(failure.error)),
        };
        if (300..=399).contains(&response.status) {
            return Err(WebhookError::with_reason(
                NO_HTTP_STATUS,
                codes::REDIRECT_REFUSED,
                REASON_REDIRECT,
                "the document response is a redirect",
            ));
        }
        if response.body.len() > MAX_DOCUMENT_BYTES {
            return Err(WebhookError::with_reason(
                NO_HTTP_STATUS,
                codes::DOCUMENT_FETCH_FAILED,
                REASON_TOO_LARGE,
                "the document body exceeds the size cap",
            ));
        }
        let body_text = String::from_utf8_lossy(&response.body);
        check_document_fetch(response.status, &body_text)
    }

    /// Sends one verification envelope — a `verification` body carrying
    /// `nonce` — as a delivery `POST` over the hardened path and judges the
    /// echo (spec 06 R5.4-R5.6, R5.12).
    ///
    /// One attempt only, never retried: a fresh `webhook-id` is drawn, the
    /// timestamp and signatures come from [`delivery_headers`] over the
    /// envelope body, and the section 6 decision runs before the send, with
    /// the subscription's own headers and id (R5.5). The answer is judged by
    /// [`challenge_echo`] (R5.4); a refusal before the send or a transport
    /// failure with an R1.9 category returns `ok = false` with
    /// `challenge_failed` and that fixed-literal reason (R5.5).
    pub fn send_challenge(&self, message: &OutgoingMessage, nonce: &str) -> EchoVerdict {
        let Ok(body) = serde_json::to_vec(&serde_json::json!({
            "type": "verification",
            "challenge": nonce,
        })) else {
            return challenge_rejection(codes::CHALLENGE_FAILED);
        };
        let challenge = OutgoingMessage {
            url: message.url.clone(),
            subscription_id: message.subscription_id.clone(),
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
        let endpoint = match check_url(&challenge.url) {
            Ok(endpoint) => endpoint,
            Err(error) => return challenge_rejection(error.reason().unwrap_or(error.code())),
        };
        let Some((answers, recheck)) = self.resolve_pair(&endpoint) else {
            return challenge_rejection(LastError::ConnectionRefused.as_str());
        };
        let now = self.clock.now();
        let timestamp = now.to_string();
        let headers = delivery_headers(
            &challenge,
            &webhook_id,
            &timestamp,
            now,
            JACK_WINDOW_SECONDS,
        );
        let prepared = match prepare(
            &challenge.url,
            &answers,
            &recheck,
            &self.config.allowed_ranges,
            "POST",
            headers,
            challenge.body.clone(),
            self.config.max_body_bytes,
        ) {
            Ok(prepared) => prepared,
            Err(error) => return challenge_rejection(error.reason().unwrap_or(error.code())),
        };
        match self.transport.send(&prepared.request) {
            Ok(response) => challenge_echo(
                response.status,
                &String::from_utf8_lossy(&response.body),
                nonce,
            ),
            Err(failure) => challenge_rejection(failure.error.as_str()),
        }
    }

    /// Resolves the endpoint twice — the validation answers and the R6.9
    /// recheck — or returns `None` when a resolution fails or is empty
    /// (spec 06 R6.8, R6.9).
    ///
    /// A literal host is its own answer and is never passed to the resolver
    /// (spec 06 R6.8), so both lists are empty in that case.
    fn resolve_pair(&self, endpoint: &UrlParts) -> Option<(Vec<IpAddr>, Vec<IpAddr>)> {
        if endpoint.host_kind != HostKind::Name {
            return Some((Vec::new(), Vec::new()));
        }
        let answers = self
            .resolver
            .resolve(&endpoint.host_value, endpoint.port)
            .ok()
            .filter(|answers| !answers.is_empty())?;
        let recheck = self
            .resolver
            .resolve(&endpoint.host_value, endpoint.port)
            .ok()
            .filter(|answers| !answers.is_empty())?;
        Some((answers, recheck))
    }
}

/// Builds the `invalid_callback_url` rejection of a canonical url that does
/// not parse (spec 06 R5.9, R6.2).
fn invalid_canonical_url() -> WebhookError {
    WebhookError::with_reason(
        BAD_REQUEST,
        INVALID_CALLBACK_URL,
        REASON_URL,
        "the canonical url is not acceptable",
    )
}

/// Maps one R1.9 transport category to its error code (spec 06 R1.9, R5.12).
fn network_error(last_error: LastError) -> WebhookError {
    WebhookError::with_reason(
        NO_HTTP_STATUS,
        last_error.as_str(),
        last_error.as_str(),
        "the request failed before a response was read",
    )
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

/// One attempt before the R1.8 decision.
enum Attempt {
    /// A response was read (spec 06 R1.7).
    Response(TransportResponse),
    /// No response was read; the category is retryable (spec 06 R1.9).
    Failure(LastError),
    /// The section 6 decision refused the attempt before sending
    /// (spec 06 R1.9, R6.8-R6.10).
    Refused(LastError),
}

/// Reports whether a status is retryable when the schedule is exhausted
/// (spec 06 R1.7).
fn retryable_status(status: u16) -> bool {
    matches!(status, 425 | 429) || (500..=599).contains(&status)
}

/// Maps a section 6 refusal code to its R1.9 category; a code without an
/// official mapping is a client-side refusal, hence `http_4xx`
/// (spec 06 R1.9).
fn refusal_of(error: &WebhookError) -> LastError {
    delivery::map_internal_outcome(error.code()).unwrap_or(LastError::Http4xx)
}

/// One message as the sender needs it to build the R1.1 headers.
///
/// The secrets and signing keys are ordered current first, previous second,
/// so the emission order of R2.8 is preserved; entries past the second are
/// ignored by the emission set. The type deliberately has no `Debug`
/// implementation: it owns delivery secrets and private keys.
pub struct OutgoingMessage {
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

/// Adapts one `http` request to the receiver's header list and declared
/// length (spec 06 R3.1-R3.6).
///
/// Repeated header names are kept, in the order the request stores them, so
/// the receiver's duplicate-header refusal of R3.2 sees every repeat. The
/// declared length is the single `Content-Length` value, raised to the
/// buffered body length so an understated header cannot shrink the R3.6
/// size check; a request without `Content-Length`, or with several, has no
/// declared length. A non-UTF-8 value is decoded lossily so it still fails
/// the grammar of the header it belongs to.
pub fn adapt_request<B>(
    request: &::http::Request<B>,
    body: Vec<u8>,
) -> (Vec<(String, String)>, Option<u64>) {
    let headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .map(|(name, value)| {
            let text = match value.to_str() {
                Ok(text) => text.to_owned(),
                Err(_) => String::from_utf8_lossy(value.as_bytes()).into_owned(),
            };
            (name.as_str().to_owned(), text)
        })
        .collect();
    let declared = declared_length(request.headers());
    let body_length = u64::try_from(body.len()).unwrap_or(u64::MAX);
    let declared = declared.map(|length| length.max(body_length));
    (headers, declared)
}

/// Parses a non-empty run of decimal digits as a `u64`.
fn parse_decimal(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Returns the single `Content-Length` of a header map, when it holds one.
pub(crate) fn declared_length(headers: &::http::HeaderMap) -> Option<u64> {
    let mut values = headers.get_all(::http::header::CONTENT_LENGTH).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok().and_then(parse_decimal),
        _ => None,
    }
}

/// Adapts one receiver answer to an `http` response (spec 06 section 3).
///
/// The status is the outcome's status, the body is the JSON serialization of
/// the outcome's body and the only header is
/// `Content-Type: application/json`. An unrepresentable status falls back to
/// `500`, which no receiver path produces.
pub fn adapt_response(outcome: &DeliveryOutcome) -> ::http::Response<::bytes::Bytes> {
    let body = serde_json::to_vec(&outcome.body).unwrap_or_else(|_| b"{}".to_vec());
    let status = ::http::StatusCode::from_u16(outcome.status)
        .unwrap_or(::http::StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = ::http::Response::new(::bytes::Bytes::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        ::http::header::CONTENT_TYPE,
        ::http::HeaderValue::from_static("application/json"),
    );
    response
}
