//! Tower Layer/Service HTTP adapter (Go: server/middleware.go).
//!
//! Buffers the request body up to a limit, verifies it, answers protocol-native
//! jack.* tools itself, forwards everything else to the wrapped service and
//! signs every verified answer. Because responses are buffered before signing,
//! streaming responses are refused with 501 (v0.1, spec README Q1).
//!
//! Both buffers are bounded: requests by the builder's body limit (413 on
//! overflow) and inner responses by its response limit (signed 502
//! `response_too_large` on overflow). Limits of the response cap: it bounds bytes read, not time, and
//! the body is dropped on overflow. A body that never yields a frame, or yields
//! only empty frames, is not stopped by it (empty frames add no bytes and are
//! not retained, but the loop keeps awaiting). A deadline on the inner service
//! covers only obtaining the response (headers + body handle); body consumption
//! happens in this adapter's future, so a deadline for it must wrap the whole
//! `JackService` produced by `JackLayer` (e.g. tower timeout or
//! `tokio::time::timeout` around the call). That is the caller's
//! responsibility; this crate has no timeout option. The inner service's own
//! allocations before it returns its response are not bounded either.
//!
//! When built with [`RotatingHandlerBuilder`], every verified answer
//! (including signed rejections) is signed by the provider-selected rotating
//! key: the signer is chosen before the signature is computed and a fresh
//! completion-sample final gate re-confirms eligibility, and any authorization
//! or final-gate failure answers with the unsigned 503
//! `rotation_state_unavailable` — no other key is ever used. The static
//! profile is unchanged. The `jack.server.key` tool itself is dispatched
//! through the verifier builder's server-key option (verify.rs), not here.
//!
//! With the profile set on [`HandlerBuilder::with_profile`] or
//! [`RotatingHandlerBuilder::with_profile`] to [`Profile::Modern`] or
//! [`Profile::Both`] the layer decides the request era after verification
//! (spec 04 section 3) and applies the header rules `S1`-`S12`: mirror headers
//! are validated, session headers are stripped, and a violation is refused with
//! the signed JSON-RPC shape of `S10`. The default [`Profile::Legacy`] runs no
//! rule of section 5 and stays byte-identical to 0.1.x.
//!
//! A [`StreamLayer`] replaces the v1 `501 streaming_unsupported` with a signed
//! `s1` stream (spec 05) when the modern client sent `Jack-Accept: s1`; the
//! default [`JackLayer`] is unchanged and keeps answering the 501.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, Bytes};
use http::header::CONTENT_TYPE;
use http::{HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt, Full};
use serde_json::value::RawValue;
use tower_layer::Layer;
use tower_service::Service;

use crate::auth_header::{format_response_auth, ResponseAuth};
use crate::encoding::{encode_b64url, key_id};
use crate::modern::{IMPLEMENTATION_NAME, IMPLEMENTATION_VERSION};
use crate::server::modern::{
    classify_request, request_era, Era, ModernOutcome, ModernRequest, Profile,
};
use crate::server::response_keys::{ReleaseGuard, ResponseKeyRequest, ResponseKeys};
use crate::server::verify::{Authentication, Verifier, VerifyResult};
use crate::user_key::ServerSigningKey;

mod forward;
mod modern;
mod stream;
mod stream_layer;
mod wire;

pub use stream::{StreamCancellation, StreamHeartbeat};
pub use stream_layer::{StreamBody, StreamLayer, StreamLayerBuilder, StreamService};

use modern::header_fields;
use wire::{error_body, CallToolResult, RpcResponse, ServerInfo, ServerInfoMeta, TextContent};

/// Alias for boxed errors flowing through body polling; http-body's own alias
/// is not nameable because the `http-body` crate is not a direct dependency.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Default body limit applied when the handler builder's body limit is zero
/// (Go: defaultMaxBodyBytes).
const DEFAULT_MAX_BODY_BYTES: usize = 1 << 20;

/// Default inner-response limit applied when the handler builder's response limit is zero;
/// matches the client buffer default.
const DEFAULT_MAX_RESPONSE_BYTES: usize = 1 << 20;

/// One response-signing profile; the Go handler refuses any mixing, the two builders make mixing unrepresentable (Go: HandlerConfig.ServerKey vs ResponseKeys).
#[derive(Clone)]
enum SigningProfile {
    /// Static Ed25519 key; the existing current-v1 behavior.
    Static {
        key: Arc<ServerSigningKey>,
        kid: String,
    },
    /// Rotating authorization profile (Go: HandlerConfig.ResponseKeys).
    Rotating { keys: Arc<dyn ResponseKeys> },
}

/// Builds the static signing profile. The former config literal constructor is replaced because
/// this crate is unpublished.
pub struct HandlerBuilder {
    verifier: Arc<Verifier>,
    server_key: ServerSigningKey,
    max_body_bytes: usize,
    max_response_bytes: usize,
    profile: Profile,
}
impl HandlerBuilder {
    pub fn new(verifier: Arc<Verifier>, server_key: ServerSigningKey) -> Self {
        Self {
            verifier,
            server_key,
            max_body_bytes: 0,
            max_response_bytes: 0,
            profile: Profile::default(),
        }
    }
    pub fn max_body_bytes(mut self, v: usize) -> Self {
        self.max_body_bytes = v;
        self
    }
    pub fn max_response_bytes(mut self, v: usize) -> Self {
        self.max_response_bytes = v;
        self
    }
    pub fn with_profile(mut self, v: Profile) -> Self {
        self.profile = v;
        self
    }
    pub fn build(self) -> JackLayer {
        JackLayer::from_parts(
            self.verifier,
            SigningProfile::Static {
                kid: self.server_key.kid().to_owned(),
                key: Arc::new(self.server_key),
            },
            self.max_body_bytes,
            self.max_response_bytes,
            self.profile,
        )
    }
}

/// Replaces `RotatingHandlerConfig` literals and `JackLayer::rotating` because
/// this crate is unpublished.
pub struct RotatingHandlerBuilder {
    verifier: Arc<Verifier>,
    response_keys: Arc<dyn ResponseKeys>,
    max_body_bytes: usize,
    max_response_bytes: usize,
    profile: Profile,
}
impl RotatingHandlerBuilder {
    pub fn new(verifier: Arc<Verifier>, response_keys: Arc<dyn ResponseKeys>) -> Self {
        Self {
            verifier,
            response_keys,
            max_body_bytes: 0,
            max_response_bytes: 0,
            profile: Profile::default(),
        }
    }
    pub fn max_body_bytes(mut self, v: usize) -> Self {
        self.max_body_bytes = v;
        self
    }
    pub fn max_response_bytes(mut self, v: usize) -> Self {
        self.max_response_bytes = v;
        self
    }
    pub fn with_profile(mut self, v: Profile) -> Self {
        self.profile = v;
        self
    }
    pub fn build(self) -> JackLayer {
        JackLayer::from_parts(
            self.verifier,
            SigningProfile::Rotating {
                keys: self.response_keys,
            },
            self.max_body_bytes,
            self.max_response_bytes,
            self.profile,
        )
    }
}

/// Tower layer wrapping an unmodified MCP server (Go: `handler` + NewHandler).
/// Only authenticated and authorized requests reach the inner service and every
/// verified answer is signed. Its signing key has a redacted `Debug` form.
///
/// Build the static profile with [`HandlerBuilder`]:
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use mcp_jack::server::http::HandlerBuilder;
/// use mcp_jack::server::verify::VerifierBuilder;
///
/// let verifier = VerifierBuilder::new("https://mcp.example/mcp", Arc::new(state_store))
///     .try_build()?;
/// let layer = HandlerBuilder::new(Arc::new(verifier), server_key)
///     .max_body_bytes(0)
///     .max_response_bytes(0)
///     .build();
/// ```
/// A zero request-body or response-body limit selects its 1 MiB default; a nonzero value is used
/// as the limit, and a response exactly at the limit is accepted. Request overflow returns 413;
/// response overflow returns a signed 502 `response_too_large` and drops the inner body.
/// The response limit bounds bytes read, not time; empty frames do not count and are ignored
/// while awaiting further frames. The former config literals and `JackLayer::new` constructors
/// are replaced by builders because this crate is unpublished.
pub struct JackLayer {
    verifier: Arc<Verifier>,
    signing: SigningProfile,
    limit: usize,
    response_limit: usize,
    /// Deployment setting of the modern profile (spec 04 section 1); the
    /// default [`Profile::Legacy`] runs no rule of section 5.
    profile: Profile,
}

impl JackLayer {
    fn from_parts(
        verifier: Arc<Verifier>,
        signing: SigningProfile,
        max_body_bytes: usize,
        max_response_bytes: usize,
        profile: Profile,
    ) -> Self {
        Self {
            signing,
            verifier,
            limit: if max_body_bytes == 0 {
                DEFAULT_MAX_BODY_BYTES
            } else {
                max_body_bytes
            },
            response_limit: if max_response_bytes == 0 {
                DEFAULT_MAX_RESPONSE_BYTES
            } else {
                max_response_bytes
            },
            profile,
        }
    }
}

impl<S> Layer<S> for JackLayer {
    type Service = JackService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        JackService {
            verifier: Arc::clone(&self.verifier),
            signing: self.signing.clone(),
            limit: self.limit,
            response_limit: self.response_limit,
            profile: self.profile,
            inner,
        }
    }
}

/// The wrapped service produced by [`JackLayer`] (Go: `handler`). Cloning is
/// what tower's readiness protocol requires of the inner service anyway.
#[derive(Clone)]
pub struct JackService<S> {
    verifier: Arc<Verifier>,
    signing: SigningProfile,
    limit: usize,
    response_limit: usize,
    /// Modern-profile deployment setting of the layer that built this service.
    profile: Profile,
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
            signing: self.signing.clone(),
            limit: self.limit,
            response_limit: self.response_limit,
            profile: self.profile,
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
        // RFC 9110: a HEAD answer carries the status and headers of its GET
        // twin but no body. This single flag is handed to every writer, which
        // sends no body and signs over the empty body instead, so each refusal
        // path (plain rejection, signed reject, modern refusal, native,
        // forwarded) behaves the same.
        let head = parts.method == Method::HEAD;

        // The 0.1.x pre-authentication method gate. In the modern era it must
        // NOT run: spec 04 `S2` answers a non-`POST` request with a SIGNED 405
        // after authentication and after the era decision, and a legacy-era
        // request under `Profile::Both` is forwarded like any other.
        if self.profile == Profile::Legacy
            && parts.method != Method::GET
            && parts.method != Method::POST
        {
            return Ok(plain_error(
                head,
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
                    head,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "invalid_request",
                    "request body is too large",
                ));
            }
            Err(BodyReadError::Read) => {
                return Ok(plain_error(
                    head,
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "request body could not be read",
                ));
            }
        };

        // Never normalized: the signing string binds the target as received.
        // Only origin-form targets are signable (spec 01 section 3.1).
        let Some(target) = origin_form_target(&parts.uri) else {
            return Ok(plain_error(
                head,
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request target must be origin-form",
            ));
        };
        let method = parts.method.as_str().to_owned();

        // A non-UTF-8 header value cannot reach the verifier (Request.auth_values
        // holds Strings), so it gets the same rejection a grammar violation gets.
        // The scheme is examined first, on the raw bytes (spec 01 section 3):
        // a v2 scheme is unsupported_version even when the rest of the value
        // is obs-text that to_str below would reject.
        // Only a single header value qualifies: more than one is malformed_auth
        // first (spec 01 section 4 step 2), exactly as in the Go and TS parsers.
        let mut auth_values = Vec::new();
        let single = parts.headers.get_all("Jack-Auth").iter().count() == 1;
        for value in parts.headers.get_all("Jack-Auth") {
            if single && crate::auth_header::scheme_is_unsupported_version(value.as_bytes()) {
                let mut res = unsigned_rejection(
                    head,
                    401,
                    "unsupported_version",
                    "unsupported Jack-Auth version",
                );
                res.headers_mut()
                    .insert("WWW-Authenticate", HeaderValue::from_static("Jack-Auth"));
                return Ok(res);
            }
            match value.to_str() {
                Ok(v) => auth_values.push(v.to_owned()),
                Err(_) => {
                    let mut res = unsigned_rejection(
                        head,
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
            method: method.clone(),
            target: target.clone(),
            auth_values,
            body: buffered.to_vec(),
        };
        // The legacy profile keeps the one-shot path, byte-identical to 0.1.x.
        // The era-aware profiles split it: authentication and body
        // classification first, then the era decision and the rules `S1`-`S12`,
        // and only THEN the native dispatch or the forward — so a modern native
        // call with wrong mirrors can never commit state before its refusal.
        let response = if self.profile == Profile::Legacy {
            let mut res = self.verifier.verify(&vreq);
            let response = if !res.accepted {
                self.reject(&res, head)
            } else if res.native {
                self.native(&res, Era::Legacy, head)
            } else {
                self.forward(parts, buffered, &res, false, head).await?
            };
            // The durable admission is finished only after the response is
            // produced, on every path (Go middleware: `defer res.Done()`).
            res.finish_admission();
            response
        } else {
            match self.verifier.authenticate(&vreq) {
                Authentication::Refused(mut res) => {
                    // The verifier emits the 0.1.x generic body message on
                    // every profile, so the legacy bytes (and their
                    // signatures) stay untouched. On the era-aware profiles a
                    // body-classification refusal is replaced by the fixed
                    // message of spec 04 `S6` when the engine, asked with the
                    // same profile/method/target/headers/body, reports
                    // `ClassificationRefusal` AND the era it decides for the
                    // same request is modern. The classification runs BEFORE
                    // `S3`, so a legacy-era request under `Both` keeps the
                    // 0.1.x bytes even though its body triggers the same
                    // classification.
                    let response = if res.http_status == 400
                        && res.code == crate::error::codes::INVALID_REQUEST
                    {
                        let headers = header_fields(&parts.headers);
                        let request = ModernRequest {
                            method: &method,
                            target: &target,
                            headers: &headers,
                            body: &buffered,
                        };
                        match classify_request(self.profile, &request) {
                            ModernOutcome::ClassificationRefusal { message }
                                if request_era(self.profile, &request) == Era::Modern =>
                            {
                                self.invalid_request(&res, message, head)
                            }
                            // Header/era refusals are not body classification,
                            // and the verifier's refusal stands as it is; the
                            // same holds for a legacy-era classification.
                            _ => self.reject(&res, head),
                        }
                    } else {
                        self.reject(&res, head)
                    };
                    res.finish_admission();
                    response
                }
                Authentication::Pending(pending) => {
                    let headers = header_fields(&parts.headers);
                    let classified = classify_request(
                        self.profile,
                        &ModernRequest {
                            method: &method,
                            target: &target,
                            headers: &headers,
                            body: &buffered,
                        },
                    );
                    match classified {
                        // Unreachable after authentication classified the body;
                        // kept for parity with the engine. The pending request
                        // is answered here, so it must not be dispatched, and
                        // it carries no native effect.
                        ModernOutcome::ClassificationRefusal { message } => {
                            let mut res = pending.into_refusal_base();
                            let response = self.invalid_request(&res, message, head);
                            res.finish_admission();
                            response
                        }
                        ModernOutcome::Refuse(refusal) => {
                            let mut res = pending.into_refusal_base();
                            let response = self.refuse_modern(&res, &refusal, head);
                            res.finish_admission();
                            response
                        }
                        ModernOutcome::Forward { era, headers: _ } => {
                            // Only the modern era filters the inner header
                            // list: `S8` removes the session headers, and the
                            // forward path re-derives exactly that removal
                            // from the ORIGINAL entries so value bytes and
                            // repetition survive. The engine's header list
                            // above is validation input only. A legacy-era
                            // request under `Both` keeps the map as received,
                            // byte-identical to 0.1.x.
                            let modern = era == Era::Modern;
                            let mut res = self.verifier.dispatch(pending);
                            let response = if !res.accepted {
                                self.reject(&res, head)
                            } else if res.native {
                                self.native(&res, era, head)
                            } else {
                                self.forward(parts, buffered, &res, modern, head).await?
                            };
                            res.finish_admission();
                            response
                        }
                    }
                }
            }
        };
        Ok(response)
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
    fn reject(&self, res: &VerifyResult, head: bool) -> http::Response<Full<Bytes>> {
        // RFC 9110: a HEAD answer has no body; the status and Content-Type stay
        // those of the same refusal to a GET/POST and the signature (signed
        // branch) covers the empty body. signed_with_headers enforces the same
        // rule, so both branches agree.
        let body = if head {
            Bytes::new()
        } else {
            Bytes::from(error_body(&res.code, &res.message))
        };
        // Go sets WWW-Authenticate on every 401 BEFORE choosing the
        // signed/unsigned branch, so both branches share the header logic.
        let mut headers = http::HeaderMap::new();
        if res.http_status == 401 {
            headers.insert("WWW-Authenticate", HeaderValue::from_static("Jack-Auth"));
        }
        if res.nonce_recorded {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            return self.signed_with_headers(head, res.http_status, res, headers, body);
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
    /// In the modern era the result also carries `resultType: "complete"` and
    /// Jack `_meta` server info (spec 04 `C7`); a legacy-era result is the
    /// 0.1.x shape.
    fn native(&self, res: &VerifyResult, era: Era, head: bool) -> http::Response<Full<Bytes>> {
        let Some(structured) = &res.structured else {
            // Unreachable: native results always carry structured content, but
            // the fallback keeps the Go error path for refactors.
            return self.internal(res, head);
        };
        let text = match serde_json::to_string(structured) {
            Ok(text) => text,
            Err(_) => return self.internal(res, head),
        };
        let id = match res.rpc_id.as_deref() {
            // None serializes as null, matching Go's nil json.RawMessage.
            None => None,
            Some(raw) => match RawValue::from_string(raw.to_owned()) {
                Ok(id) => Some(id),
                Err(_) => return self.internal(res, head),
            },
        };
        // Spec 04 `C7`: only the modern era adds `resultType` and `_meta`, so a
        // 2025-11-25 client keeps receiving the 0.1.x bytes.
        let modern = era == Era::Modern;
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
                result_type: modern.then_some("complete"),
                meta: modern.then_some(ServerInfoMeta {
                    server_info: ServerInfo {
                        name: IMPLEMENTATION_NAME,
                        version: IMPLEMENTATION_VERSION,
                    },
                }),
            },
        };
        // Unreachable failure: serde cannot fail on String/&str fields.
        let body = serde_json::to_string(&payload).expect("static JSON-RPC shape serializes");
        self.signed(head, 200, res, body.into_bytes().into())
    }

    /// Go's fallback for a marshal failure: a signed 500 (Go: rejectInternal).
    fn internal(&self, res: &VerifyResult, head: bool) -> http::Response<Full<Bytes>> {
        self.signed(
            head,
            500,
            res,
            error_body("internal_error", "internal error").into(),
        )
    }

    /// Signs a response over a fresh header set holding only its own
    /// `Content-Type`; `Jack-Auth` is then added (Go: writeSigned).
    fn signed(
        &self,
        head: bool,
        status: u16,
        res: &VerifyResult,
        body: Bytes,
    ) -> http::Response<Full<Bytes>> {
        let mut headers = http::HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        self.signed_with_headers(head, status, res, headers, body)
    }

    /// Signs the response over its status, the request signature and the exact
    /// body bytes (spec 01 section 5) and attaches the Jack-Auth header
    /// (Go: writeSigned). The static profile's clock always comes from the
    /// verifier config; the rotating profile's timestamp comes from the
    /// provider-selected authorization (write_authorized).
    fn signed_with_headers(
        &self,
        head: bool,
        status: u16,
        res: &VerifyResult,
        headers: http::HeaderMap,
        body: Bytes,
    ) -> http::Response<Full<Bytes>> {
        // RFC 9110: a HEAD answer has no body. This is the one place that
        // enforces it: the status and headers stay those of the GET twin and
        // the signature covers the empty body (what every client hashes for a
        // HEAD). No other response byte changes.
        let body = if head { Bytes::new() } else { body };
        match &self.signing {
            SigningProfile::Static { key, kid } => {
                let now = self.verifier.now();
                let signing = crate::signing::response_signing_string(
                    status as i64,
                    &res.request_sig,
                    kid,
                    now,
                    &body,
                );
                let sig = key.sign(signing.as_bytes());
                let auth = format_response_auth(&ResponseAuth {
                    kid: kid.clone(),
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
            SigningProfile::Rotating { keys } => {
                self.write_authorized(head, keys, status, res, headers, body)
            }
        }
    }

    /// Rotating profile (Go: writeAuthorized): the signer is selected before
    /// the signature is computed, a fresh completion sample re-confirms
    /// eligibility at the final gate, and any failure discards the signature
    /// and answers with the UNSIGNED 503 refusal — no other key is ever used.
    fn write_authorized(
        &self,
        head: bool,
        keys: &Arc<dyn ResponseKeys>,
        status: u16,
        res: &VerifyResult,
        headers: http::HeaderMap,
        body: Bytes,
    ) -> http::Response<Full<Bytes>> {
        // Go refuse(): writeError(w, 503, ...) — UNSIGNED, Content-Type only,
        // no WWW-Authenticate, no Jack-Auth; the inner `headers` are discarded.
        // The shared writer still applies the HEAD rule (no body).
        let refuse = || {
            unsigned_rejection(
                head,
                503,
                "rotation_state_unavailable",
                "response authorization unavailable",
            )
        };
        // Borrowed view (Go copies the payload so the provider cannot mutate
        // what is signed; Rust borrowing prevents mutation by construction).
        let input = ResponseKeyRequest {
            status,
            tool: &res.tool,
            request_signature: &res.request_sig,
            body: &body,
        };
        let Ok(auth) = keys.authorize_response(&input) else {
            return refuse();
        };
        // Runs the release on EVERY path (success, refusal, unwind), mirroring
        // Go's `defer releaseResponseAuthorization`; it drops at function exit,
        // AFTER the final gate ran (Go releases after writeRaw).
        let _guard = ReleaseGuard::new(auth.release);
        // Go: the authorizeResponse wrapper rejects Timestamp < 0 ||
        // > maxDurableTimestamp; u64 makes negatives unrepresentable.
        if auth.timestamp > crate::rotation::MAX_TIMESTAMP {
            return refuse();
        }
        // Go: responsePublicKey — the length check is unrepresentable ([u8; 32]).
        let public = auth.signer.public_key();
        if crate::ed25519::validate_public_key(&public).is_err() {
            return refuse();
        }
        let kid = key_id(&public);
        // Go: responseSignature. The timestamp cast is safe after the range
        // check above.
        let message = crate::signing::response_signing_string(
            status as i64,
            &res.request_sig,
            &kid,
            auth.timestamp as i64,
            &body,
        );
        let Ok(sig) = auth.signer.sign(message.as_bytes()) else {
            return refuse();
        };
        let Ok(sig) = <[u8; 64]>::try_from(sig.as_slice()) else {
            return refuse();
        };
        // The provider cannot confirm another identity or change the message:
        // the signature must verify under the public key it pinned.
        if !crate::ed25519::verify(&public, message.as_bytes(), &sig) {
            return refuse();
        }
        // Go: finalResponseAuthorization — a fresh completion sample inside the
        // provider re-checks eligibility; a key retired meanwhile means the
        // computed signature is discarded and the response FAILS; no retry
        // with another key.
        if (auth.final_gate)().is_err() {
            return refuse();
        }
        let auth_header = format_response_auth(&ResponseAuth {
            kid,
            ts: auth.timestamp as i64,
            sig: encode_b64url(&sig),
        });
        let mut builder = http::Response::builder()
            .status(status)
            .header("Jack-Auth", auth_header);
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

/// The origin-form target exactly as received, or None for absolute-form,
/// authority-form or asterisk-form. The http crate drops a fragment while
/// parsing the request line, so it never reaches this check (spec 01 section 3.1).
fn origin_form_target(uri: &http::Uri) -> Option<String> {
    // Absolute-form has a scheme; authority-form has an authority and no
    // path. A genuine origin-form target has neither.
    if uri.scheme().is_some() || uri.authority().is_some() {
        return None;
    }
    let target = uri.path_and_query()?.as_str();
    is_origin_form_target(target).then(|| target.to_owned())
}

/// Origin-form starts with '/' and consists only of the bytes 0x21 to 0x7E
/// (spec 01 section 3.1).
fn is_origin_form_target(target: &str) -> bool {
    target.starts_with('/') && target.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Unsigned JSON error for requests that never reached authentication
/// (Go: writeError): Content-Type only, no WWW-Authenticate, no signature.
fn plain_error(
    head: bool,
    status: StatusCode,
    code: &str,
    message: &str,
) -> http::Response<Full<Bytes>> {
    unsigned_rejection(head, status.as_u16(), code, message)
}

/// Builds an unsigned JSON rejection body response (Go: writeRaw path). A
/// `HEAD` request gets the identical status and `Content-Type` and no body
/// (RFC 9110), the same rule every signed writer applies.
fn unsigned_rejection(
    head: bool,
    status: u16,
    code: &str,
    message: &str,
) -> http::Response<Full<Bytes>> {
    let body = if head {
        Bytes::new()
    } else {
        Bytes::from(error_body(code, message))
    };
    // Statuses here are protocol constants: construction cannot fail.
    http::Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(body))
        .expect("static status and header values cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_form_decision_on_target_text() {
        assert!(is_origin_form_target("/mcp"));
        assert!(is_origin_form_target("/mcp?q=%C3%A9"));
        for bad in [
            "*",
            "host:80",
            "http://h/mcp",
            "mcp",
            "",
            "/mcp?q=é",
            "/a b",
            "/ab",
        ] {
            assert!(!is_origin_form_target(bad), "target {bad:?}");
        }
    }

    #[test]
    fn non_origin_uris_have_no_target() {
        for bad in ["http://h/mcp", "https://h", "h:80", "*"] {
            let uri: http::Uri = bad.parse().expect("uri parses");
            assert_eq!(origin_form_target(&uri), None, "uri {bad:?}");
        }
        let uri: http::Uri = "/mcp?q=%C3%A9".parse().expect("uri parses");
        assert_eq!(origin_form_target(&uri).as_deref(), Some("/mcp?q=%C3%A9"));
    }
}
