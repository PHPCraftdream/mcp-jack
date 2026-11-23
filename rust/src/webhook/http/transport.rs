//! The transport contracts of spec 06 sections 1, 5 and 6, the hardened
//! request decision of section 6 (R6.8-R6.10) and the receiver adapters of
//! section 5.
//!
//! The module is pure: [`prepare`] turns a validated URL, the resolver
//! answers and the re-resolution into a [`TransportRequest`] carrying the
//! R6.8 connect target; the sender loop lives in
//! [`crate::webhook::http::sender`] and drives a [`WebhookTransport`], a
//! [`HostResolver`] and a clock. No socket, no wall clock and no entropy
//! source is used directly, so every decision can be reproduced from its
//! inputs.
//!
//! The deadlines and the document cap are defined once — by `delivery` and by
//! the R5.9 document module — and re-exported here, so the sender, the
//! document fetcher and the transport judge the same numbers (spec 06 R1.6,
//! R5.9).

use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::webhook::receiver::DeliveryOutcome;
use crate::webhook::ssrf::delivery::{
    delivery_decision, ConnectTarget, DeliveryDecision, DeliveryInput,
};
use crate::webhook::ssrf::host::HostKind;
use crate::webhook::ssrf::url::UrlParts;
use crate::webhook::{codes, WebhookError};

/// The connect-phase cap of one attempt: 10 s (spec 06 R1.6).
pub use crate::webhook::delivery::CONNECT_TIMEOUT_SECONDS;

/// The response-phase cap of one attempt: 10 s after the request is written
/// (spec 06 R1.6).
pub use crate::webhook::delivery::RESPONSE_TIMEOUT_SECONDS;

/// The cap on one whole attempt: 20 s, covering DNS, connect, TLS, the
/// request write and the response read (spec 06 R1.6).
pub use crate::webhook::delivery::ATTEMPT_TIMEOUT_SECONDS;

/// The largest receiver document the well-known fetch accepts, in bytes
/// (spec 06 R5.9). A larger body is refused before its text is judged.
///
/// The cap is defined by [`crate::webhook::verification::document`], which
/// owns the R5.9 verdict, and re-exported here so the fetch path and the
/// verdict judge one number (spec 06 R5.9, R5.12).
pub use crate::webhook::verification::document::MAX_DOCUMENT_BYTES;

/// Resolves a host name to its answers at delivery time (spec 06 R6.8).
///
/// A literal host is never passed here: [`prepare`] and the sender treat an
/// IP literal as its own name, exactly as R6.8 requires. The `Send + Sync`
/// supertraits let one resolver be shared by the sender and by the R5.9
/// document fetcher, whose [`crate::webhook::verification::document::DocumentFetcher`]
/// bound already requires them.
pub trait HostResolver: Send + Sync {
    /// Returns every answer for `host` in resolver order (spec 06 R6.8).
    ///
    /// The port is supplied for resolvers that need it (for example a
    /// service-lookup resolver); a plain A/AAAA resolver may ignore it. An
    /// error is a DNS failure, which the sender records as
    /// `connection_refused` (spec 06 R1.9).
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, WebhookError>;

    /// Returns every answer for `host` within the whole-attempt budget
    /// (spec 06 R6.8).
    ///
    /// The default ignores the budget and delegates to [`HostResolver::resolve`],
    /// so a scripted resolver needs only that method; a resolver that can
    /// bound its own lookup overrides this one (spec 06 R1.6, R6.8).
    fn resolve_within(
        &self,
        host: &str,
        port: u16,
        _budget: Duration,
    ) -> Result<Vec<IpAddr>, WebhookError> {
        self.resolve(host, port)
    }
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
    /// The cap on this whole attempt, from DNS to the last response byte
    /// (R1.6); the transport bounds connect, TLS, write and read by it.
    pub attempt_timeout: Duration,
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
    /// True when the response carried more body than `max_body_bytes`, or
    /// declared more than it; `body` is then truncated to the cap
    /// (spec 06 R1.2, R5.9).
    pub overflow: bool,
}

/// Why one attempt failed (spec 06 R1.9, R6.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// A network failure with an R1.9 category; the sender retries it on the
    /// R1.8 schedule (spec 06 R1.8, R1.9).
    Network,
    /// The connected peer differs from the validated address; the attempt is
    /// final and is never retried on the new address (spec 06 R6.9).
    PeerMismatch,
}

/// A transport failure: the R1.9 category and why the attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportFailure {
    /// `connection_refused`, `timeout` or `tls_error` (spec 06 R1.9).
    pub error: crate::webhook::delivery::LastError,
    /// Whether the failure is retryable or a rebinding refusal
    /// (spec 06 R1.8, R6.9).
    pub kind: FailureKind,
}

impl TransportFailure {
    /// Builds a retryable network failure with its R1.9 category
    /// (spec 06 R1.9).
    pub fn network(error: crate::webhook::delivery::LastError) -> Self {
        Self {
            error,
            kind: FailureKind::Network,
        }
    }

    /// Builds the R6.9 rebinding refusal: the peer is not the validated
    /// address, so the attempt is final (spec 06 R6.9).
    pub fn peer_mismatch() -> Self {
        Self {
            error: crate::webhook::delivery::LastError::ConnectionRefused,
            kind: FailureKind::PeerMismatch,
        }
    }
}

/// The blocking transport of one delivery attempt.
///
/// The `Send + Sync` supertraits let one transport be shared by the sender
/// and by the R5.9 document fetcher, whose
/// [`crate::webhook::verification::document::DocumentFetcher`] bound already
/// requires them.
pub trait WebhookTransport: Send + Sync {
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
/// answer is classified in resolver order by [`delivery_decision`]; the first
/// `reject` refuses the attempt with `blocked_address` and its reason, a
/// recheck whose canonical address differs refuses with `dns_rebinding`, and
/// an `allow` carries the first allowed address into
/// [`TransportRequest::connect`] (spec 06 R6.8, R6.9).
///
/// A body above `max_body_bytes` is refused with the receiver's fixed
/// `413 body_too_large` answer before any request is built (spec 06 R1.2).
///
/// `attempt_timeout` is the R1.6 whole-attempt cap — DNS, connect, TLS, the
/// request write and the response read — carried into the request so the
/// transport can bound everything it does (spec 06 R1.6).
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
    attempt_timeout: Duration,
) -> Result<PreparedRequest, WebhookError> {
    if body.len() > max_body_bytes {
        return Err(crate::webhook::receiver::errors::rejection(
            codes::BODY_TOO_LARGE,
        ));
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
                attempt_timeout,
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

/// Resolves the endpoint twice — the validation answers and the R6.9
/// recheck — with both lookups bounded by what is left of `budget`.
///
/// A literal host is its own answer and is never passed to the resolver
/// (spec 06 R6.8), so both lists are empty in that case. An empty answer set
/// is the fixed `connection_refused` failure and a resolver error keeps its
/// own R1.9 category (spec 06 R1.9, R6.8, R6.9).
pub(crate) fn resolve_answers(
    resolver: &dyn HostResolver,
    endpoint: &UrlParts,
    budget: Duration,
) -> Result<(Vec<IpAddr>, Vec<IpAddr>), WebhookError> {
    if endpoint.host_kind != HostKind::Name {
        return Ok((Vec::new(), Vec::new()));
    }
    let started = Instant::now();
    let answers = resolver.resolve_within(
        &endpoint.host_value,
        endpoint.port,
        budget.saturating_sub(started.elapsed()),
    )?;
    if answers.is_empty() {
        return Err(no_answer());
    }
    let recheck = resolver.resolve_within(
        &endpoint.host_value,
        endpoint.port,
        budget.saturating_sub(started.elapsed()),
    )?;
    if recheck.is_empty() {
        return Err(no_answer());
    }
    Ok((answers, recheck))
}

/// Builds the fixed empty-answer failure, whose code is the R1.9 category a
/// DNS failure maps to (spec 06 R1.9).
fn no_answer() -> WebhookError {
    WebhookError::new(
        500,
        "connection_refused",
        "the webhook host has no usable answer",
    )
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

/// Appends one response-body chunk under the R1.2 cap and reports whether the
/// body overflowed (spec 06 R1.2, R5.9).
///
/// At most one byte past the cap is buffered, so the
/// [`TransportResponse::overflow`] flag is decided from the read itself; a
/// body that crosses the cap keeps its prefix and is truncated back to it.
/// The boolean return is true when the reader must stop.
pub(crate) fn capture_body(bytes: &mut Vec<u8>, data: &[u8], max_body_bytes: usize) -> bool {
    let read_cap = max_body_bytes.saturating_add(1);
    let remaining = read_cap.saturating_sub(bytes.len());
    let take = data.len().min(remaining);
    bytes.extend_from_slice(&data[..take]);
    if bytes.len() > max_body_bytes {
        bytes.truncate(max_body_bytes);
        return true;
    }
    false
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
