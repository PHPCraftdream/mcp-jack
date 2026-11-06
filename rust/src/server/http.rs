//! Tower Layer/Service HTTP adapter (Go: server/middleware.go).
//!
//! Buffers the request body up to a limit, verifies it, answers protocol-native
//! jack.* tools itself, forwards everything else to the wrapped service and
//! signs every verified answer. Because responses are buffered before signing,
//! streaming responses are refused with 501 (v0.1, spec README Q1).
//!
//! Both buffers are bounded: requests by [`HandlerConfig::max_body_bytes`]
//! (413 on overflow) and inner responses by
//! [`HandlerConfig::max_response_bytes`] (signed 502 `response_too_large` on
//! overflow). Limits of the response cap: it bounds bytes read, not time, and
//! the body is dropped on overflow. A body that never yields a frame, or yields
//! only empty frames, is not stopped by it (empty frames add no bytes and are
//! not retained, but the loop keeps awaiting). A deadline on the inner service
//! covers only obtaining the response (headers + body handle); body consumption
//! happens in this adapter's future, so a deadline for it must wrap the whole
//! `JackService` produced by `JackLayer` (e.g. tower timeout or
//! `tokio::time::timeout` around the call). That is the caller's
//! responsibility; this crate has no timeout option. The inner service's own
//! allocations before it returns its response are not bounded either.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, Bytes};
use ed25519_dalek::Signer as _;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt, Full};
use serde_json::value::RawValue;
use tower_layer::Layer;
use tower_service::Service;

use crate::auth_header::{format_response_auth, ResponseAuth};
use crate::encoding::{encode_b64url, key_id};
use crate::server::verify::{Verifier, VerifyResult};

/// Alias for boxed errors flowing through body polling; http-body's own alias
/// is not nameable because the `http-body` crate is not a direct dependency.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Default body limit applied when [`HandlerConfig::max_body_bytes`] is zero
/// (Go: defaultMaxBodyBytes).
const DEFAULT_MAX_BODY_BYTES: usize = 1 << 20;

/// Default inner-response limit applied when
/// [`HandlerConfig::max_response_bytes`] is zero; matches the client buffer
/// default.
const DEFAULT_MAX_RESPONSE_BYTES: usize = 1 << 20;

/// Configures [`JackLayer::new`] (Go: HandlerConfig). Infallible in Rust: the
/// Go nil/length checks are unrepresentable (Arc, typed key).
pub struct HandlerConfig {
    /// Authenticates and authorizes every request.
    pub verifier: Arc<Verifier>,
    /// Signs responses (spec 01 section 5); clients pin its public key.
    pub server_key: ed25519_dalek::SigningKey,
    /// Bounds the request body; zero means 1 MiB (Go: limit <= 0). The body
    /// must be read in full to be hashed, so the limit is a DoS guard.
    pub max_body_bytes: usize,
    /// Bounds the buffered inner response, independently of
    /// `max_body_bytes`; zero means 1 MiB. Exactly this many bytes pass; one
    /// more is answered with a signed 502 `response_too_large` and the inner
    /// body is dropped. It bounds bytes read, not time: a body that never
    /// yields a frame (or only empty frames) is not stopped by it. A timeout on
    /// the inner service covers only obtaining the response; a deadline
    /// including body consumption must wrap the whole `JackService` produced by
    /// `JackLayer` (caller's responsibility; no timeout option here). The inner
    /// service's own pre-return allocations are not bounded (see module docs).
    pub max_response_bytes: usize,
}

/// Tower layer wrapping an unmodified MCP server (Go: `handler` + NewHandler).
/// Only authenticated and authorized requests reach the inner service and every
/// verified answer is signed. No `Debug`/`Display`: `SigningKey`'s derived
/// forms would print key material.
///
/// ```ignore
/// use bytes::Bytes;
/// use http_body_util::Full;
/// use tower::Layer as _;
/// use mcp_jack::server::http::{HandlerConfig, JackLayer};
///
/// let layer = JackLayer::new(HandlerConfig {
///     verifier,
///     server_key,
///     max_body_bytes: 0,
///     max_response_bytes: 0,
/// });
/// let service = layer.layer(tower::service_fn(|req: http::Request<Full<Bytes>>| async move {
///     Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(Bytes::new())))
/// }));
/// ```
pub struct JackLayer {
    verifier: Arc<Verifier>,
    server_key: ed25519_dalek::SigningKey,
    kid: String,
    limit: usize,
    response_limit: usize,
}

impl JackLayer {
    /// Wraps an inner service so requests are verified and answers signed
    /// (Go: NewHandler). The Go nil checks are unrepresentable here, so this
    /// is infallible.
    pub fn new(cfg: HandlerConfig) -> Self {
        // Go: limit <= 0 means the default; 0 in usize covers that exactly.
        let limit = if cfg.max_body_bytes == 0 {
            DEFAULT_MAX_BODY_BYTES
        } else {
            cfg.max_body_bytes
        };
        let response_limit = if cfg.max_response_bytes == 0 {
            DEFAULT_MAX_RESPONSE_BYTES
        } else {
            cfg.max_response_bytes
        };
        Self {
            kid: key_id(cfg.server_key.verifying_key().as_bytes()),
            verifier: cfg.verifier,
            server_key: cfg.server_key,
            limit,
            response_limit,
        }
    }
}

impl<S> Layer<S> for JackLayer {
    type Service = JackService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        JackService {
            verifier: Arc::clone(&self.verifier),
            server_key: self.server_key.clone(),
            kid: self.kid.clone(),
            limit: self.limit,
            response_limit: self.response_limit,
            inner,
        }
    }
}

/// The wrapped service produced by [`JackLayer`] (Go: `handler`). Cloning is
/// what tower's readiness protocol requires of the inner service anyway.
#[derive(Clone)]
pub struct JackService<S> {
    verifier: Arc<Verifier>,
    server_key: ed25519_dalek::SigningKey,
    kid: String,
    limit: usize,
    response_limit: usize,
    inner: S,
}

/// Boxed on purpose: the layer fans out over many response shapes, so a
/// per-shape concrete future would duplicate the whole pipeline.
type JackFuture<E> = Pin<Box<dyn Future<Output = Result<http::Response<Full<Bytes>>, E>> + Send>>;

impl<B, S, ResBody> Service<http::Request<B>> for JackService<S>
where
    // BodyExt has a blanket impl over http_body::Body and http_body is not
    // nameable through this crate's deps, so BodyExt is the bound used.
    S: Service<http::Request<Full<Bytes>>, Response = http::Response<ResBody>>
        + Clone
        + Send
        + 'static,
    // Send + 'static only: the future owns a clone of the service (call
    // clones self), so no &self is held across the await and Sync is not
    // needed.
    S::Error: Send + 'static,
    S::Future: Send + 'static,
    ResBody: BodyExt + Send + 'static,
    ResBody::Error: Into<BoxError>,
    B: BodyExt + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = http::Response<Full<Bytes>>;
    // ServeHTTP has no error path in Go; propagating inner errors unchanged is
    // the direct analogue.
    type Error = S::Error;
    type Future = JackFuture<S::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Pure forward: `call` moves THIS (readied) instance into the future,
        // so no clone-and-swap is needed here.
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        // tower contract: the instance readied by poll_ready must serve this
        // request; a clone may have dropped readiness state, so the ready
        // inner is moved into the future and self keeps a fresh clone for the
        // next readiness cycle.
        let clone = self.inner.clone();
        let ready_inner = std::mem::replace(&mut self.inner, clone);
        let mut this = JackService {
            verifier: Arc::clone(&self.verifier),
            server_key: self.server_key.clone(),
            kid: self.kid.clone(),
            limit: self.limit,
            response_limit: self.response_limit,
            inner: ready_inner,
        };
        Box::pin(async move { this.serve(req).await })
    }
}

impl<S, ResBody> JackService<S>
where
    S: Service<http::Request<Full<Bytes>>, Response = http::Response<ResBody>>
        + Clone
        + Send
        + 'static,
    S::Error: Send + 'static,
    S::Future: Send + 'static,
    ResBody: BodyExt + Send + 'static,
    // Needed to poll the inner response body through the shared BoxError alias.
    ResBody::Error: Into<BoxError>,
{
    async fn serve<B>(
        &mut self,
        req: http::Request<B>,
    ) -> Result<http::Response<Full<Bytes>>, S::Error>
    where
        B: BodyExt + Send + 'static,
        B::Data: Send,
        B::Error: Into<BoxError>,
    {
        let (parts, body) = req.into_parts();

        if parts.method != Method::GET && parts.method != Method::POST {
            return Ok(plain_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "only GET and POST are defined",
            ));
        }

        // Mirror http.MaxBytesReader: exactly limit bytes pass, anything over
        // (including a checked_add overflow) is 413.
        // No &self borrow crosses this await: buffer_body is an associated
        // function, so its future does not borrow the service (a stored
        // &JackService<S> would force S: Sync).
        let buffered = match Self::buffer_body(body, self.limit).await {
            Ok(bytes) => bytes,
            Err(BodyReadError::TooLarge) => {
                return Ok(plain_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "invalid_request",
                    "request body is too large",
                ));
            }
            Err(BodyReadError::Read) => {
                return Ok(plain_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "request body could not be read",
                ));
            }
        };

        // Never normalized: the signing string binds the target as received.
        let target = match parts.uri.path_and_query() {
            Some(pq) => pq.as_str().to_owned(),
            // Asterisk/authority forms have no path_and_query.
            None => parts.uri.path().to_owned(),
        };
        let method = parts.method.as_str().to_owned();

        // A non-UTF-8 header value cannot reach the verifier (Request.auth_values
        // holds Strings), so it gets the same rejection a grammar violation gets.
        let mut auth_values = Vec::new();
        for value in parts.headers.get_all("Jack-Auth") {
            match value.to_str() {
                Ok(v) => auth_values.push(v.to_owned()),
                Err(_) => {
                    let mut res = unsigned_rejection(
                        401,
                        "malformed_auth",
                        "Jack-Auth header is not valid UTF-8",
                    );
                    res.headers_mut()
                        .insert("WWW-Authenticate", HeaderValue::from_static("Jack-Auth"));
                    return Ok(res);
                }
            }
        }

        let vreq = crate::server::verify::Request {
            method,
            target,
            auth_values,
            body: buffered.to_vec(),
        };
        let res = self.verifier.verify(&vreq);
        if !res.accepted {
            return Ok(self.reject(&res));
        }
        if res.native {
            return Ok(self.native(&res));
        }
        self.forward(parts, buffered, &res).await
    }

    /// Reads the whole body into memory enforcing `limit` on the fly
    /// (Go: io.ReadAll(http.MaxBytesReader(...))). Trailer frames are ignored;
    /// data frames carry the body bytes. The body is owned, so it is dropped
    /// (and never polled again) as soon as an error is returned.
    async fn buffer_body<B>(body: B, limit: usize) -> Result<Bytes, BodyReadError>
    where
        B: BodyExt,
        B::Error: Into<BoxError>,
    {
        // The bodies arrive as owned values from http::Request, so they are
        // pinned locally instead of requiring callers to keep them Unpin.
        let mut body = std::pin::pin!(body);
        let mut buf = bytes::BytesMut::new();
        let mut total: usize = 0;
        // The limit is checked BEFORE extending the buffer, so an oversized
        // frame never lands in memory.
        while let Some(frame) = body.as_mut().frame().await {
            let frame = frame.map_err(|_| BodyReadError::Read)?;
            let Some(mut data) = frame.into_data().ok() else {
                continue;
            };
            let len = data.remaining();
            let Some(next) = total.checked_add(len) else {
                return Err(BodyReadError::TooLarge);
            };
            if next > limit {
                return Err(BodyReadError::TooLarge);
            }
            total = next;
            buf.put(&mut data);
        }
        Ok(buf.freeze())
    }

    /// Answers a failed request (Go: reject). Once authentication succeeded the
    /// client holds a request signature to bind to, so the answer is signed; an
    /// authentication failure may be unsigned (spec 01 section 5).
    fn reject(&self, res: &VerifyResult) -> http::Response<Full<Bytes>> {
        let body = Bytes::from(error_body(&res.code, &res.message));
        // Go sets WWW-Authenticate on every 401 BEFORE choosing the
        // signed/unsigned branch, so both branches share the header logic.
        let mut headers = http::HeaderMap::new();
        if res.http_status == 401 {
            headers.insert("WWW-Authenticate", HeaderValue::from_static("Jack-Auth"));
        }
        if res.nonce_recorded {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            return self.signed_with_headers(res.http_status, res, headers, body);
        }
        let mut builder = http::Response::builder().status(res.http_status);
        for (name, value) in &headers {
            builder = builder.header(name, value);
        }
        builder
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(body))
            .expect("static status and header values cannot fail")
    }

    /// Answers a protocol-native tool call as a JSON-RPC response whose result
    /// is an MCP CallToolResult carrying the structured payload (Go: native).
    /// serde's default map key order is alphabetical, which would diverge from
    /// Go's field-order marshaling, so structs with declared field order are
    /// used instead of `json!`.
    fn native(&self, res: &VerifyResult) -> http::Response<Full<Bytes>> {
        let Some(structured) = &res.structured else {
            // Unreachable: native results always carry structured content, but
            // the fallback keeps the Go error path for refactors.
            return self.internal(res);
        };
        let text = match serde_json::to_string(structured) {
            Ok(text) => text,
            Err(_) => return self.internal(res),
        };
        let id = match res.rpc_id.as_deref() {
            // None serializes as null, matching Go's nil json.RawMessage.
            None => None,
            Some(raw) => match RawValue::from_string(raw.to_owned()) {
                Ok(id) => Some(id),
                Err(_) => return self.internal(res),
            },
        };
        let payload = RpcResponse {
            jsonrpc: "2.0",
            id,
            result: CallToolResult {
                content: [TextContent {
                    r#type: "text",
                    text: &text,
                }],
                structured_content: structured,
                is_error: false,
            },
        };
        // Unreachable failure: serde cannot fail on String/&str fields.
        let body = serde_json::to_string(&payload).expect("static JSON-RPC shape serializes");
        self.signed(200, res, body.into_bytes().into())
    }

    /// Go's fallback for a marshal failure: a signed 500 (Go: rejectInternal).
    fn internal(&self, res: &VerifyResult) -> http::Response<Full<Bytes>> {
        self.signed(
            500,
            res,
            error_body("internal_error", "internal error").into(),
        )
    }

    /// Hands an authorized request to the wrapped service and signs what it
    /// answers (Go: forward).
    async fn forward(
        &mut self,
        parts: http::request::Parts,
        body: Bytes,
        res: &VerifyResult,
    ) -> Result<http::Response<Full<Bytes>>, S::Error> {
        let inner_req = http::Request::from_parts(parts, Full::new(body));
        // Clone-and-swap so the future owns the inner instance and self stays
        // usable for the next call.
        let inner = {
            let inner_clone = self.inner.clone();
            let mut inner_svc = std::mem::replace(&mut self.inner, inner_clone);
            match inner_svc.call(inner_req).await {
                Ok(inner) => inner,
                // Inner errors propagate unchanged: ServeHTTP has no error path
                // in Go and propagation is the direct analogue.
                Err(err) => return Err(err),
            }
        };

        let (inner_parts, inner_body) = inner.into_parts();
        // Go parses the media type and compares the type before ';'; a missing
        // or non-UTF-8 header means NOT streaming (its error path).
        let streaming = inner_parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/event-stream"));
        if streaming {
            // Refuse BEFORE buffering: dropping the body unread is the point —
            // an endless SSE stream must not be pulled into memory. Fresh
            // headers, discarding all inner ones (Go builds a new header).
            let body = error_body(
                "streaming_unsupported",
                "streaming responses cannot be signed in v0.1",
            );
            return Ok(self.signed(501, res, body.into_bytes().into()));
        }
        // Bounded by response_limit (default 1 MiB): the inner body is moved
        // into buffer_body, which stops polling and drops it on overflow, and
        // never appends an oversized frame. Overflow is a signed 502 with a
        // fresh header set, so no upstream header or partial byte survives.
        // A read error cannot be mapped into S::Error generically, so it is
        // answered as a signed 500 instead of propagating (request binding
        // preserved) — Go cannot hit this path at all.
        let buffered = match Self::buffer_body(inner_body, self.response_limit).await {
            Ok(bytes) => bytes,
            Err(BodyReadError::TooLarge) => {
                let body = error_body(
                    "response_too_large",
                    "upstream response exceeds the configured limit",
                );
                return Ok(self.signed(502, res, body.into_bytes().into()));
            }
            Err(BodyReadError::Read) => return Ok(self.internal(res)),
        };

        // Content-Length: the buffered length decides (Go: header.Del).
        // Transfer-Encoding described the inner transport, not this buffered
        // body. Jack-Auth is REPLACED, not appended (Go: header.Set); the
        // parser rejects a repeated header. Content-Type keeps append
        // semantics: Go header.Clone() keeps the inner values, including
        // multi-value headers.
        let mut headers = inner_parts.headers;
        headers.remove(CONTENT_LENGTH);
        headers.remove(http::header::TRANSFER_ENCODING);
        headers.remove("Jack-Auth");
        let status = inner_parts.status;
        Ok(self.signed_with_headers(status.as_u16(), res, headers, buffered))
    }

    /// Signs a response over a fresh header set holding only its own
    /// `Content-Type`; `Jack-Auth` is then added (Go: writeSigned).
    fn signed(&self, status: u16, res: &VerifyResult, body: Bytes) -> http::Response<Full<Bytes>> {
        let mut headers = http::HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        self.signed_with_headers(status, res, headers, body)
    }

    /// Signs the response over its status, the request signature and the exact
    /// body bytes (spec 01 section 5) and attaches the Jack-Auth header
    /// (Go: writeSigned). The clock always comes from the verifier config.
    fn signed_with_headers(
        &self,
        status: u16,
        res: &VerifyResult,
        headers: http::HeaderMap,
        body: Bytes,
    ) -> http::Response<Full<Bytes>> {
        let now = self.verifier.now();
        let signing = crate::signing::response_signing_string(
            status as i64,
            &res.request_sig,
            &self.kid,
            now,
            &body,
        );
        let sig = self.server_key.sign(signing.as_bytes()).to_bytes();
        let auth = format_response_auth(&ResponseAuth {
            kid: self.kid.clone(),
            ts: now,
            sig: encode_b64url(&sig),
        });
        let mut builder = http::Response::builder()
            .status(status)
            .header("Jack-Auth", auth);
        for (name, value) in &headers {
            // Static status/header values: construction cannot fail.
            builder = builder.header(name, value);
        }
        builder
            .body(Full::new(body))
            .expect("static status and header values cannot fail")
    }
}

/// Why a body could not be buffered (Go: *http.MaxBytesError vs other errors).
enum BodyReadError {
    /// The limit was exceeded (Go: MaxBytesError).
    TooLarge,
    /// Any other read failure.
    Read,
}

/// Unsigned JSON error for requests that never reached authentication
/// (Go: writeError): Content-Type only, no WWW-Authenticate, no signature.
fn plain_error(status: StatusCode, code: &str, message: &str) -> http::Response<Full<Bytes>> {
    unsigned_rejection(status.as_u16(), code, message)
}

/// Builds an unsigned JSON rejection body response (Go: writeRaw path).
fn unsigned_rejection(status: u16, code: &str, message: &str) -> http::Response<Full<Bytes>> {
    // Statuses here are protocol constants: construction cannot fail.
    http::Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(error_body(code, message))))
        .expect("static status and header values cannot fail")
}

/// Renders the rejection body of spec 01 section 4 (Go: errorBody).
fn error_body(code: &str, message: &str) -> String {
    // Unreachable failure: serde cannot fail on String fields.
    serde_json::to_string(&ErrorEnvelope {
        error: ErrorDetail { code, message },
    })
    .expect("error envelope always serializes")
}

#[derive(serde::Serialize)]
struct ErrorDetail<'a> {
    code: &'a str,
    message: &'a str,
}

#[derive(serde::Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorDetail<'a>,
}

/// Field declaration order is load-bearing: it fixes the JSON key order to
/// match Go's struct marshaling byte for byte.
#[derive(serde::Serialize)]
struct TextContent<'a> {
    #[serde(rename = "type")]
    r#type: &'a str,
    text: &'a str,
}

#[derive(serde::Serialize)]
struct CallToolResult<'a> {
    content: [TextContent<'a>; 1],
    #[serde(rename = "structuredContent")]
    structured_content: &'a serde_json::Value,
    #[serde(rename = "isError")]
    is_error: bool,
}

#[derive(serde::Serialize)]
struct RpcResponse<'a> {
    jsonrpc: &'a str,
    /// None serializes as null, matching Go's nil json.RawMessage.
    id: Option<Box<RawValue>>,
    result: CallToolResult<'a>,
}
