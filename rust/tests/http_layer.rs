//! Port of Go server/middleware_test.go against JackLayer: every request
//! enters the spec 01 section 4 pipeline through the HTTP adapter, and the
//! tests pin where each request stops (method gate, body limit, verification
//! steps, admin gate, native dispatch) plus response signing per spec 01
//! section 5. On every forwarded accept the layer hands the wrapped service a
//! VerifiedIdentity request extension (spec 02 section 3); the admin flag
//! gates only jack.admin.* calls.
#![cfg(feature = "http")]

mod common;

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use common::fixtures;
use common::harness::{self, FIXTURE_AUD, FIXTURE_NOW};
use ed25519_dalek::SigningKey;
use http_body_util::Full;
use tower::{Layer, ServiceExt};

use mcp_jack::client::auth::sign_request;
use mcp_jack::client::signer::{InMemorySigner, Signer};
use mcp_jack::server::audit::{AuditSink, MemoryAuditSink};
use mcp_jack::server::http::{HandlerConfig, JackLayer, JackService};
use mcp_jack::server::identity::VerifiedIdentity;
use mcp_jack::server::native::{Native, NativeOptions};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::state::{MemoryState, RegistryEntry, StateStore};
use mcp_jack::server::verify::{Clock, Config, Verifier};

/// The boxed inner service behind every harness (S::Error = String).
type InnerBox =
    tower::util::BoxCloneService<http::Request<Full<Bytes>>, http::Response<Full<Bytes>>, String>;

/// Process-wide nonce source: the first 8 bytes are zero, the last 8 encode a
/// never-repeating counter (Go's atomic counter). Canonical 22-char b64url,
/// so nonce reuse across tests in one run is impossible.
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One signed request under test: keeps the request signature so responses
/// can be verified against it (Go's signedRequest result).
struct SentRequest {
    header_value: String,
    request_sig: String,
}

/// Signs like Go's signedRequest: unique nonce, fixture ts, exact target.
fn signed_request(signer: &InMemorySigner, method: &str, target: &str, body: &[u8]) -> SentRequest {
    let n = NONCE_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    let mut nonce = [0u8; 16];
    nonce[8..].copy_from_slice(&n.to_be_bytes());
    let signed = sign_request(
        signer,
        FIXTURE_AUD,
        method,
        target,
        body,
        &nonce,
        FIXTURE_NOW,
    )
    .unwrap_or_else(|e| panic!("sign_request: {e}"));
    SentRequest {
        header_value: signed.header_value,
        request_sig: signed.auth.sig,
    }
}

fn build_request(
    signed: &SentRequest,
    method: &str,
    target: &str,
    body: &[u8],
) -> http::Request<Full<Bytes>> {
    http::Request::builder()
        .method(method)
        .uri(target)
        .header("Jack-Auth", signed.header_value.as_str())
        .body(Full::new(Bytes::copy_from_slice(body)))
        .expect("static request parts")
}

fn build_unsigned_request(method: &str, target: &str, body: &[u8]) -> http::Request<Full<Bytes>> {
    http::Request::builder()
        .method(method)
        .uri(target)
        .body(Full::new(Bytes::copy_from_slice(body)))
        .expect("static request parts")
}

/// What the canned inner service observed (Go's counting wrap).
#[derive(Clone)]
struct InnerConfig {
    calls: Arc<AtomicUsize>,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    targets: Arc<Mutex<Vec<String>>>,
    /// The identity extension of each forwarded request, captured via a
    /// TYPED lookup (`req.extensions().get::<VerifiedIdentity>()`). The typed
    /// lookup returns exactly the one extension the layer inserted — a
    /// handler cannot insert a second: VerifiedIdentity has no public
    /// constructor (spec 02 section 3), so nothing outside the crate can
    /// build one to insert.
    identities: Arc<Mutex<Vec<Option<VerifiedIdentity>>>>,
}

impl InnerConfig {
    fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            bodies: Arc::new(Mutex::new(Vec::new())),
            targets: Arc::new(Mutex::new(Vec::new())),
            identities: Arc::new(Mutex::new(Vec::new())),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
    fn seen_bodies(&self) -> Vec<Vec<u8>> {
        self.bodies.lock().expect("bodies mutex").clone()
    }
    fn seen_targets(&self) -> Vec<String> {
        self.targets.lock().expect("targets mutex").clone()
    }
    fn seen_identities(&self) -> Vec<Option<VerifiedIdentity>> {
        self.identities.lock().expect("identities mutex").clone()
    }
}

/// The canned inner answer (Go's wrap parameter).
#[derive(Clone)]
struct InnerResponse {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    /// Extra headers the inner service appends to its answer.
    extra_headers: Vec<(&'static str, &'static str)>,
}

impl InnerResponse {
    fn ok_json(body: &[u8]) -> Self {
        Self {
            status: 200,
            content_type: "application/json",
            body: body.to_vec(),
            extra_headers: Vec::new(),
        }
    }
}

/// The harness around one JackService (Go newHarness).
struct TestHarness {
    service: JackService<InnerBox>,
    inner: InnerConfig,
    sink: Arc<MemoryAuditSink>,
    server_pub: [u8; 32],
}

fn seed_registry(state: &MemoryState) {
    // Same idiom as verify_conformance.rs; the fixture registry's admin flag
    // (absent = false) seeds straight through (spec 02 section 1).
    let registry = fixtures::load_registry().expect("load registry.json");
    state
        .update(&mut |edit| {
            for e in &registry.keys {
                edit.put_key(RegistryEntry {
                    kid: e.kid.clone(),
                    public_key: e.public_key.clone(),
                    name: e.name.clone(),
                    admin: e.admin,
                    not_before: e.not_before,
                    not_after: e.not_after,
                });
            }
            Ok(())
        })
        .expect("seed registry");
}

fn build_verifier(state: MemoryState, sink: Option<Arc<MemoryAuditSink>>) -> Arc<Verifier> {
    let now_clock: Clock = Arc::new(move || FIXTURE_NOW);
    Arc::new(
        Verifier::new(Config {
            aud: FIXTURE_AUD.to_string(),
            state: Arc::new(state),
            nonces: Arc::new(NonceStore::new()),
            audit: sink.map(|s| Arc::clone(&s) as Arc<dyn AuditSink>),
            native: Some(Arc::new(Native::new(NativeOptions::default()))),
            window_seconds: 30,
            now: now_clock,
        })
        .expect("verifier"),
    )
}

/// The keys.json "svc" signing key (Go testPrivateKey(t, "svc")).
fn server_signing_key() -> SigningKey {
    let keys = fixtures::load_keys().expect("load keys.json");
    let svc = keys
        .keys
        .iter()
        .find(|k| k.name == "svc")
        .unwrap_or_else(|| panic!("keys.json has no key named svc"));
    let seed: [u8; 32] = harness::hex_bytes(&svc.seed_hex)
        .try_into()
        .expect("svc seed is 32 bytes");
    SigningKey::from_bytes(&seed)
}

/// Builds the harness: fixture verifier, the keys.json "svc" server key, and
/// an inner service that records what it sees and answers `response`.
fn new_harness(max_body_bytes: usize, response: InnerResponse) -> TestHarness {
    new_harness_with(max_body_bytes, 0, response)
}

/// Like new_harness with an explicit response cap (0 = SDK default).
fn new_harness_with(
    max_body_bytes: usize,
    max_response_bytes: usize,
    response: InnerResponse,
) -> TestHarness {
    let state = MemoryState::new();
    seed_registry(&state);
    let sink = Arc::new(MemoryAuditSink::new());
    let verifier = build_verifier(state, Some(sink.clone()));
    let server_key = server_signing_key();
    let server_pub = *server_key.verifying_key().as_bytes();

    let inner = InnerConfig::new();
    let layer = JackLayer::new(HandlerConfig {
        verifier,
        server_key,
        max_body_bytes,
        max_response_bytes,
    });
    let recorder = inner.clone();
    let service = layer.layer(tower::util::BoxCloneService::new(tower::service_fn(
        move |req: http::Request<Full<Bytes>>| {
            let inner = recorder.clone();
            let response = response.clone();
            async move {
                // Full's error is Infallible, so collect() cannot fail here;
                // into_inner() is NOT used because an empty Full stores None
                // (the empty GET bodies several tests send).
                let (parts, body) = req.into_parts();
                let body_bytes = http_body_util::BodyExt::collect(body)
                    .await
                    .expect("Full body always collects")
                    .to_bytes();
                inner
                    .bodies
                    .lock()
                    .expect("bodies mutex")
                    .push(body_bytes.to_vec());
                inner
                    .identities
                    .lock()
                    .expect("identities mutex")
                    .push(parts.extensions.get::<VerifiedIdentity>().cloned());
                if let Some(pq) = parts.uri.path_and_query() {
                    inner
                        .targets
                        .lock()
                        .expect("targets mutex")
                        .push(pq.as_str().to_owned());
                }
                inner.calls.fetch_add(1, Ordering::SeqCst);
                let mut builder = http::Response::builder()
                    .status(response.status)
                    .header("Content-Type", response.content_type);
                for (name, value) in &response.extra_headers {
                    builder = builder.header(*name, *value);
                }
                Ok::<_, String>(
                    builder
                        .body(Full::new(Bytes::from(response.body)))
                        .expect("static response parts"),
                )
            }
        },
    )));

    TestHarness {
        service,
        inner,
        sink,
        server_pub,
    }
}

/// Sends `req` through the layered service: oneshot polls poll_ready (the
/// clone-and-swap readiness contract) before calling (Go's httptest path).
async fn send(
    svc: &JackService<InnerBox>,
    req: http::Request<Full<Bytes>>,
) -> Result<http::Response<Full<Bytes>>, String> {
    svc.clone().oneshot(req).await
}

/// Response view: status, all Jack-Auth values, body bytes, Content-Type.
struct GotResponse {
    status: u16,
    jack_auth: Vec<String>,
    www_authenticate: Option<String>,
    content_length: Option<String>,
    body: Bytes,
    content_type: Option<String>,
}

async fn inspect(res: http::Response<Full<Bytes>>) -> GotResponse {
    let status = res.status().as_u16();
    let content_type = res
        .headers()
        .get("Content-Type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let content_length = res
        .headers()
        .get("Content-Length")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let jack_auth = res
        .headers()
        .get_all("Jack-Auth")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_owned)
        .collect();
    let www_authenticate = res
        .headers()
        .get("WWW-Authenticate")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let (_, body) = res.into_parts();
    let body = http_body_util::BodyExt::collect(body)
        .await
        .expect("Full body always collects")
        .to_bytes();
    GotResponse {
        status,
        jack_auth,
        www_authenticate,
        content_length,
        body,
        content_type,
    }
}

fn error_code(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["error"]["code"].as_str().map(str::to_owned))
        .unwrap_or_else(|| panic!("no error code in body {:?}", String::from_utf8_lossy(body)))
}

fn error_message(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["error"]["message"].as_str().map(str::to_owned))
        .unwrap_or_else(|| {
            panic!(
                "no error message in body {:?}",
                String::from_utf8_lossy(body)
            )
        })
}

/// Mirrors Go assertSigned: verify_response checks the parsed kid against the
/// pinned server key itself, so a separate parse_response_auth assertion
/// would be redundant and is omitted.
fn assert_signed(got: &GotResponse, req_sig: &str, server_pub: &[u8; 32]) {
    let values: Vec<&str> = got.jack_auth.iter().map(String::as_str).collect();
    mcp_jack::signing::verify_response(
        server_pub,
        got.status as i64,
        &values,
        req_sig,
        &got.body,
        FIXTURE_NOW,
        30,
    )
    .unwrap_or_else(|e| panic!("response signature does not verify: {e}"));
}

const STATUS_BODY: &[u8] =
    br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"svc.status","arguments":{}}}"#;
const RESTART_BODY: &[u8] =
    br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"svc.restart","arguments":{}}}"#;
const LIST_BODY: &[u8] =
    br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.user.list","arguments":{}}}"#;
const INNER_OK_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;

/// Go TestMiddlewareForwardsAndSigns: an authorized alice tool call reaches
/// the inner service and the answer is signed.
///
/// Pipeline: verification steps pass -> accept. There is no policy step:
/// ANY authenticated key's ordinary tool call (svc.* included) forwards.
#[tokio::test]
async fn forwards_and_signs() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "POST", "/mcp?x=1", STATUS_BODY);
    let got = inspect(
        send(
            &h.service,
            build_request(&signed, "POST", "/mcp?x=1", STATUS_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(got.body.as_ref(), INNER_OK_BODY);
    assert_eq!(h.inner.calls(), 1);
    assert_eq!(h.inner.seen_bodies(), vec![STATUS_BODY.to_vec()]);
    assert_eq!(h.inner.seen_targets(), vec!["/mcp?x=1".to_string()]);
    assert_signed(&got, &signed.request_sig, &h.server_pub);
    assert_eq!(got.content_type.as_deref(), Some("application/json"));
}

/// Go TestMiddlewareUnauthenticatedIsRejectedUnsigned: no Jack-Auth header.
///
/// Pipeline: stops at step 1 (missing_auth) before the key lookup; the nonce
/// is never recorded, so the 401 is unsigned and carries WWW-Authenticate.
#[tokio::test]
async fn unauthenticated_rejected_unsigned() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let got = inspect(
        send(
            &h.service,
            build_unsigned_request("POST", "/mcp", STATUS_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 401);
    assert_eq!(error_code(&got.body), "missing_auth");
    assert_eq!(
        got.jack_auth,
        Vec::<String>::new(),
        "unsigned 401 has no Jack-Auth"
    );
    assert_eq!(
        got.www_authenticate.as_deref(),
        Some("Jack-Auth"),
        "401 carries WWW-Authenticate (Go parity)"
    );
    assert_eq!(got.content_type.as_deref(), Some("application/json"));
    assert_eq!(h.inner.calls(), 0);
}

/// Go TestMiddlewareSignsAuthorizationRejection, reworked for the
/// admin-only wrapper: the admin flag gates only jack.admin.*, so alice's
/// svc.restart call is now ACCEPTED and forwarded; the answer is signed and
/// no WWW-Authenticate is ever attached to a signed (post-nonce) response.
#[tokio::test]
async fn lifecycle_tool_forwards_and_signs() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "POST", "/mcp", RESTART_BODY);
    let got = inspect(
        send(
            &h.service,
            build_request(&signed, "POST", "/mcp", RESTART_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(got.body.as_ref(), INNER_OK_BODY);
    assert_signed(&got, &signed.request_sig, &h.server_pub);
    // len==1 proves the response is signed; the 401-only WWW-Authenticate
    // claim is carried by the next assert.
    assert_eq!(got.jack_auth.len(), 1);
    assert!(
        got.www_authenticate.is_none(),
        "signed answers never carry WWW-Authenticate"
    );
    assert_eq!(h.inner.calls(), 1);
    assert_eq!(h.inner.seen_bodies(), vec![RESTART_BODY.to_vec()]);
}

/// The admin gate (spec 02 section 4): alice (non-admin) calling a
/// jack.admin.* tool gets a signed 403 admin_required via HTTP; the inner
/// service is never called and the audit sink records the failure.
///
/// Counterfactual: revert to deny-by-default or any scope-check scheme and
/// this test fails — ordinary tools forward (see
/// lifecycle_tool_forwards_and_signs), so a 403 here can only come from the
/// admin flag gate.
#[tokio::test]
async fn admin_tool_denied_for_non_admin() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let alice_kid = alice.kid().to_string();
    let signed = signed_request(&alice, "POST", "/mcp", LIST_BODY);
    let got = inspect(
        send(
            &h.service,
            build_request(&signed, "POST", "/mcp", LIST_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 403);
    assert_eq!(error_code(&got.body), "admin_required");
    assert_signed(&got, &signed.request_sig, &h.server_pub);
    assert_eq!(
        got.jack_auth.len(),
        1,
        "the nonce was recorded, so the 403 is signed"
    );
    assert!(
        got.www_authenticate.is_none(),
        "403s never carry WWW-Authenticate"
    );
    assert_eq!(h.inner.calls(), 0, "the inner service is never called");

    let events = h.sink.events();
    assert_eq!(events.len(), 1, "exactly one audit event");
    assert_eq!(events[0].tool, "jack.admin.user.list");
    assert_eq!(events[0].outcome, "failure");
    assert_eq!(events[0].code, "admin_required");
    assert_eq!(events[0].actor_name, "alice");
    assert_eq!(events[0].actor_kid, alice_kid);
    assert_eq!(events[0].time, FIXTURE_NOW);
}

/// Go TestMiddlewareRefusesStreams: GET forwarding succeeds but an SSE answer
/// cannot be signed, so the layer refuses it.
///
/// Pipeline: GET skips body classification, verification passes and the
/// request forwards; the inner 200 text/event-stream hits the layer's stream
/// guard -> 501 streaming_unsupported, signed.
#[tokio::test]
async fn refuses_streams() {
    let h = new_harness(
        0,
        InnerResponse {
            status: 200,
            content_type: "text/event-stream",
            body: b"data: x\n\n".to_vec(),
            extra_headers: Vec::new(),
        },
    );
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "GET", "/mcp", b"");
    let got = inspect(
        send(&h.service, build_request(&signed, "GET", "/mcp", b""))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 501);
    assert_eq!(error_code(&got.body), "streaming_unsupported");
    assert_signed(&got, &signed.request_sig, &h.server_pub);
    assert_eq!(h.inner.calls(), 1);
}

/// Go TestMiddlewareBodyLimit: an oversized body is refused before
/// authentication.
///
/// Pipeline: the method gate passes but the body-limit read (Go
/// io.ReadAll(MaxBytesReader), before verify step 1) fails -> 413
/// invalid_request, unsigned.
#[tokio::test]
async fn body_limit_rejects_oversized() {
    let h = new_harness(64, InnerResponse::ok_json(INNER_OK_BODY));
    let svc = h.service;
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{{\"pad\":\"{}\"}}}}",
        "x".repeat(200)
    )
    .into_bytes();
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "POST", "/mcp", &body);
    let got = inspect(
        send(&svc, build_request(&signed, "POST", "/mcp", &body))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 413);
    assert_eq!(error_code(&got.body), "invalid_request");
    assert_eq!(error_message(&got.body), "request body is too large");
    assert_eq!(h.inner.calls(), 0);
    assert_eq!(
        got.jack_auth,
        Vec::<String>::new(),
        "pre-auth 413 is unsigned"
    );
    assert!(got.www_authenticate.is_none(), "413 is not a 401");
    assert_eq!(got.content_type.as_deref(), Some("application/json"));
}

/// Exactly-limit bodies pass Go's http.MaxBytesReader; the port must too.
///
/// Pipeline: same as body_limit_rejects_oversized but the buffered length
/// equals the limit, so verification passes and the request forwards -> 200,
/// signed.
#[tokio::test]
async fn body_limit_exact_boundary_passes() {
    let h = new_harness(64, InnerResponse::ok_json(INNER_OK_BODY));
    let svc = h.service;
    let base = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{\"pad\":\"\"}}";
    let pad = 64 - base.len();
    assert!(pad > 0, "base ping body must leave room for padding");
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{{\"pad\":\"{}\"}}}}",
        "x".repeat(pad)
    )
    .into_bytes();
    assert_eq!(body.len(), 64);
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "POST", "/mcp", &body);
    let got = inspect(
        send(&svc, build_request(&signed, "POST", "/mcp", &body))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_signed(&got, &signed.request_sig, &h.server_pub);
    assert_eq!(h.inner.calls(), 1);
    let seen = h.inner.seen_bodies();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].len(), 64);
    assert_eq!(seen[0], body);
}

/// Go TestMiddlewareMethodNotAllowed: PUT never enters verification.
///
/// Pipeline: stops at the method gate before verify step 1 -> 405
/// method_not_allowed, unsigned.
#[tokio::test]
async fn method_not_allowed() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "PUT", "/mcp", STATUS_BODY);
    let got = inspect(
        send(
            &h.service,
            build_request(&signed, "PUT", "/mcp", STATUS_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 405);
    assert_eq!(error_code(&got.body), "method_not_allowed");
    assert_eq!(got.jack_auth, Vec::<String>::new());
    assert!(got.www_authenticate.is_none(), "405 is not a 401");
    assert_eq!(h.inner.calls(), 0);
}

/// Go TestMiddlewareAnswersNativeToolsItself: the real Native answers
/// jack.admin.user.list and the layer signs its JSON-RPC result.
///
/// Pipeline: verification passes (root holds admin), the jack.* tool is
/// dispatched natively -> 200, signed, the inner service never sees the
/// request.
#[tokio::test]
async fn answers_native_tools_itself() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let svc = h.service;
    let root = harness::signer_by_name("root");
    let root_kid = root.kid().to_string();
    // Derived from keys.json, not from the response.
    let alice_kid = harness::signer_by_name("alice").kid().to_string();
    let signed = signed_request(&root, "POST", "/mcp", LIST_BODY);
    let got = inspect(
        send(&svc, build_request(&signed, "POST", "/mcp", LIST_BODY))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(h.inner.calls(), 0);
    assert_signed(&got, &signed.request_sig, &h.server_pub);
    assert_eq!(got.content_type.as_deref(), Some("application/json"));

    let v: serde_json::Value = serde_json::from_slice(&got.body).expect("body is JSON");
    assert_eq!(v["id"], 1, "id echoes the request id");
    assert_eq!(v["result"]["isError"], false);
    let content = v["result"]["content"].as_array().expect("content array");
    assert_eq!(content.len(), 1, "exactly one content item");
    assert_eq!(content[0]["type"], "text");
    let structured = &v["result"]["structuredContent"];
    let text = content[0]["text"].as_str().expect("text is a string");
    assert_eq!(
        text,
        serde_json::to_string(structured).expect("structured serializes"),
        "the text item is the marshaled structured content (Go parity)"
    );
    let users = structured["users"].as_array().expect("users array");
    let alice_entry = users
        .iter()
        .find(|u| u["name"] == "alice")
        .expect("alice is listed");
    assert_eq!(alice_entry["kid"], serde_json::Value::String(alice_kid));

    let events = h.sink.events();
    assert_eq!(events.len(), 1, "exactly one audit event");
    assert_eq!(events[0].tool, "jack.admin.user.list");
    assert_eq!(events[0].outcome, "success");
    assert_eq!(events[0].actor_name, "root");
    assert_eq!(events[0].actor_kid, root_kid);
    assert_eq!(events[0].time, FIXTURE_NOW);
    assert_eq!(events[0].target, "", "user.list sets no audit target");
}

/// No Go analogue (ServeHTTP cannot error): inner failures propagate
/// unchanged.
///
/// Pipeline: never reached — the inner service itself returns Err, which the
/// layer must pass through as-is.
#[tokio::test]
async fn inner_service_error_propagates() {
    let state = MemoryState::new();
    seed_registry(&state);
    let layer = JackLayer::new(HandlerConfig {
        verifier: build_verifier(state, None),
        server_key: server_signing_key(),
        max_body_bytes: 0,
        max_response_bytes: 0,
    });
    let svc = layer.layer(tower::service_fn(
        |_req: http::Request<Full<Bytes>>| async move {
            Err::<http::Response<Full<Bytes>>, _>("boom".to_string())
        },
    ));
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "GET", "/mcp", b"");
    let err = svc
        .oneshot(build_request(&signed, "GET", "/mcp", b""))
        .await
        .expect_err("inner error must propagate");
    assert_eq!(err, "boom");
}

/// Go parity for "never normalize": the target is signed and forwarded
/// exactly as received.
///
/// Pipeline: verification passes (the signature binds the raw target string)
/// and the GET forwards; a normalizing layer would break the signature
/// first, so this test fails the moment normalization is introduced.
#[tokio::test]
async fn request_target_not_normalized() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let target = "/mcp?x=%7e&y=a%2Fb";
    let signed = signed_request(&alice, "GET", target, b"");
    let got = inspect(
        send(&h.service, build_request(&signed, "GET", target, b""))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_signed(&got, &signed.request_sig, &h.server_pub);
    assert_eq!(h.inner.calls(), 1);
    assert_eq!(h.inner.seen_targets(), vec![target.to_string()]);
}

// ---------------------------------------------------------------------------
// Identity hand-off (spec 02 section 3): every forwarded accept carries a
// VerifiedIdentity extension built by the layer from the verifier result;
// native jack.* calls and rejections never reach the inner service, so no
// identity exists for them.
// ---------------------------------------------------------------------------

/// Alice (non-admin) sends an ordinary tool call: the wrapped service observes
/// the typed extension with exactly her registry snapshot {kid, "alice",
/// false}. The typed lookup cannot see more than the one extension the layer
/// inserted (no public constructor -> no duplicate insertion).
#[tokio::test]
async fn identity_extension_forwarded_to_wrapped_service() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let alice_kid = alice.kid().to_string();
    let signed = signed_request(&alice, "POST", "/mcp", STATUS_BODY);
    let got = inspect(
        send(
            &h.service,
            build_request(&signed, "POST", "/mcp", STATUS_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    let seen = h.inner.seen_identities();
    assert_eq!(seen.len(), 1, "exactly one forwarded request");
    let id = seen[0]
        .as_ref()
        .expect("forwarded accept carries the identity extension");
    assert_eq!(id.kid(), alice_kid);
    assert_eq!(id.name(), "alice");
    assert!(!id.admin());
}

/// The admin caller's identity keeps admin()==true on an ORDINARY tool call
/// (the flag gates only jack.admin.*): mirrors the fixture
/// accept-admin-identity vector.
#[tokio::test]
async fn identity_admin_flag_true_forwarded() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let root = harness::signer_by_name("root");
    let root_kid = root.kid().to_string();
    let signed = signed_request(&root, "POST", "/mcp", STATUS_BODY);
    let got = inspect(
        send(
            &h.service,
            build_request(&signed, "POST", "/mcp", STATUS_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    let seen = h.inner.seen_identities();
    assert_eq!(seen.len(), 1);
    let id = seen[0].as_ref().expect("identity extension present");
    assert_eq!(id.kid(), root_kid);
    assert_eq!(id.name(), "root");
    assert!(id.admin());
}

/// No identity anywhere outside forwarded accepts: the native root
/// jack.admin.user.list answer never touches the inner service, and an
/// unknown-key rejection (401) stops before any dispatch.
#[tokio::test]
async fn identity_absent_on_native_and_rejects() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let root = harness::signer_by_name("root");
    let signed = signed_request(&root, "POST", "/mcp", LIST_BODY);
    let got = inspect(
        send(
            &h.service,
            build_request(&signed, "POST", "/mcp", LIST_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(h.inner.calls(), 0, "native dispatch never calls the inner");

    // A key NOT in the registry: signed with a locally built signer that was
    // never seeded into the harness store (same idiom as the harness'
    // UNRELATED_SEED_HEX; a local constant is fine).
    const UNKNOWN_SEED_HEX: &str =
        "b7e2c41d08a95f36c7d0e4b8a16f3925dc8047ab6e1c5f92384d0bec7a6f1520";
    let stranger = harness::seed_signer(UNKNOWN_SEED_HEX);
    let signed = signed_request(&stranger, "POST", "/mcp", STATUS_BODY);
    let got = inspect(
        send(
            &h.service,
            build_request(&signed, "POST", "/mcp", STATUS_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 401);
    assert_eq!(error_code(&got.body), "unknown_key");
    assert_eq!(h.inner.calls(), 0, "rejections never call the inner");
    assert!(
        h.inner.seen_identities().is_empty(),
        "no identity exists for native calls or rejections"
    );
}

/// SERVER-AUTHENTICATED (spec 02 section 3): forged identity material in the
/// request bytes — an "identity" member in the arguments plus X-Jack-Kid /
/// X-Jack-Admin / X-Jack-Name headers — cannot influence the extension. The
/// inner service still sees exactly the registry snapshot for alice.
#[tokio::test]
async fn identity_unspoofable_by_remote_data() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let alice_kid = alice.kid().to_string();
    let root = harness::signer_by_name("root");
    let root_kid = root.kid().to_string();
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"svc.status","arguments":{"identity":{"kid":"root-kid-forged","name":"root","admin":true}}}}"#;
    let signed = signed_request(&alice, "POST", "/mcp", body);
    let req = http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Jack-Auth", signed.header_value.as_str())
        .header("X-Jack-Kid", root_kid.as_str())
        .header("X-Jack-Admin", "true")
        .header("X-Jack-Name", "root")
        .body(Full::new(Bytes::copy_from_slice(body)))
        .expect("static request parts");
    let got = inspect(send(&h.service, req).await.expect("no inner error")).await;
    assert_eq!(got.status, 200);
    let seen = h.inner.seen_identities();
    assert_eq!(seen.len(), 1);
    let id = seen[0].as_ref().expect("identity extension present");
    // Exactly the registry snapshot — the extension is constructed only by
    // the layer from the verifier result (no public constructor), so request
    // bytes cannot influence it.
    assert_eq!(id.kid(), alice_kid);
    assert_eq!(id.name(), "alice");
    assert!(!id.admin());
}

/// Coordinates the first request with the handler's identity signal. The
/// request future is owned here: every error path drops it, and the timeout
/// caller can cancel it without leaving a detached task behind.
/// Cancellation is terminal, not resumable: it drops the owned request future
/// and its in-flight handler work; no detached task remains.
/// cancel-safe: NO — cancellation is terminal; the owned request is dropped, not retried.
async fn request_after_identity<F, C>(
    request: F,
    entered: tokio::sync::oneshot::Receiver<Option<VerifiedIdentity>>,
    release: tokio::sync::oneshot::Sender<()>,
    before_release: C,
) -> Result<(VerifiedIdentity, F::Output), &'static str>
where
    F: std::future::Future,
    C: FnOnce(&VerifiedIdentity) -> Result<(), &'static str>,
{
    tokio::pin!(request);
    let identity = tokio::select! {
        signal = entered => match signal {
            Ok(Some(identity)) => identity,
            Ok(None) => {
                if release.send(()).is_err() {
                    return Err("handler received no verified identity; release gate was already closed");
                }
                return Err("handler received no verified identity");
            }
            Err(_) => {
                let _ = release.send(());
                return Err("first handler identity signal was dropped");
            }
        },
        _ = &mut request => {
            return Err("first request completed before the handler identity signal");
        }
    };

    if let Err(error) = before_release(&identity) {
        let _ = release.send(());
        return Err(error);
    }
    if release.send(()).is_err() {
        return Err("handler release gate closed before release");
    }
    let response = request.await;
    Ok((identity, response))
}

/// SNAPSHOT LIFECYCLE (spec 02 section 3): an in-flight handler keeps the
/// identity snapshot from verification time even while the registry changes
/// under it; the NEXT request observes the change.
#[tokio::test]
async fn identity_snapshot_lifecycle_across_registry_change() {
    // Built manually like new_harness, keeping a handle to the MemoryState.
    let state = Arc::new(MemoryState::new());
    seed_registry(&state);
    let verifier = {
        let now_clock: Clock = Arc::new(move || FIXTURE_NOW);
        Arc::new(
            Verifier::new(Config {
                aud: FIXTURE_AUD.to_string(),
                state: state.clone() as Arc<dyn StateStore>,
                nonces: Arc::new(NonceStore::new()),
                audit: None,
                native: Some(Arc::new(Native::new(NativeOptions::default()))),
                window_seconds: 30,
                now: now_clock,
            })
            .expect("verifier"),
        )
    };
    let layer = JackLayer::new(HandlerConfig {
        verifier,
        server_key: server_signing_key(),
        max_body_bytes: 0,
        max_response_bytes: 0,
    });

    let entered: Arc<Mutex<Option<tokio::sync::oneshot::Sender<Option<VerifiedIdentity>>>>> =
        Arc::new(Mutex::new(None));
    let gate: Arc<Mutex<Option<tokio::sync::oneshot::Receiver<()>>>> = Arc::new(Mutex::new(None));
    let retained: Arc<Mutex<Vec<Option<VerifiedIdentity>>>> = Arc::new(Mutex::new(Vec::new()));
    let svc = layer.layer(tower::util::BoxCloneService::new(tower::service_fn({
        let entered = Arc::clone(&entered);
        let gate = Arc::clone(&gate);
        let retained = Arc::clone(&retained);
        move |req: http::Request<Full<Bytes>>| {
            let entered = Arc::clone(&entered);
            let gate = Arc::clone(&gate);
            let retained = Arc::clone(&retained);
            async move {
                let entered_tx = entered.lock().expect("entered mutex").take();
                let parked_rx = gate.lock().expect("gate mutex").take();
                if let Some(tx) = entered_tx {
                    // Always report handler entry, including a missing extension.
                    let _ = tx.send(req.extensions().get::<VerifiedIdentity>().cloned());
                }
                if let Some(rx) = parked_rx {
                    let _ = rx.await;
                }
                // Read the actual request extension only AFTER the test releases
                // the parked handler and changes the registry.
                retained
                    .lock()
                    .expect("retained identities mutex")
                    .push(req.extensions().get::<VerifiedIdentity>().cloned());
                Ok::<_, String>(
                    http::Response::builder()
                        .header("Content-Type", "application/json")
                        .body(Full::new(Bytes::from(INNER_OK_BODY.to_vec())))
                        .expect("static response parts"),
                )
            }
        }
    })));

    let alice = harness::signer_by_name("alice");
    let alice_kid = alice.kid().to_string();

    // The outer timeout bounds the identity handshake, parked-handler release
    // and completion, plus the subsequent request. The first request future is
    // polled directly and dropped on every failure/timeout path.
    let flow = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        *entered.lock().expect("entered mutex") = Some(entered_tx);
        *gate.lock().expect("gate mutex") = Some(release_rx);

        // First request: handler parks with alice's admin=false snapshot.
        let signed = signed_request(&alice, "POST", "/mcp", STATUS_BODY);
        let request = svc
            .clone()
            .oneshot(build_request(&signed, "POST", "/mcp", STATUS_BODY));
        let (in_flight, first_response) =
            request_after_identity(request, entered_rx, release_tx, |identity| {
                // Mutate the registry only after the handler has signalled
                // entry and while it is still parked.
                let mut entry = state.lookup(&alice_kid).ok_or("alice is not registered")?;
                entry.admin = true;
                let promoted = entry;
                state
                    .update(&mut |edit| {
                        edit.put_key(promoted.clone());
                        Ok(())
                    })
                    .map_err(|_| "registry update failed")?;

                // The signal's snapshot was false before promotion.
                if identity.admin() {
                    return Err("handler-entry identity was already promoted");
                }
                Ok(())
            })
            .await?;
        let first_response = first_response.map_err(|_| "first request returned an inner error")?;
        if first_response.status() != 200 {
            return Err("first request returned an unexpected status");
        }

        // Second signature is fresh (including its nonce) and uses the same
        // FIXTURE_NOW clock through signed_request and the verifier fixture.
        let signed = signed_request(&alice, "POST", "/mcp", STATUS_BODY);
        let second_response = svc
            .clone()
            .oneshot(build_request(&signed, "POST", "/mcp", STATUS_BODY))
            .await
            .map_err(|_| "second request returned an inner error")?;
        if second_response.status() != 200 {
            return Err("second request returned an unexpected status");
        }

        Ok::<_, &'static str>(in_flight)
    })
    .await
    .expect("identity snapshot lifecycle must finish within its deadline")
    .expect("identity handshake and requests must succeed");

    assert_eq!(flow.kid(), alice_kid);
    assert_eq!(flow.name(), "alice");
    assert!(
        !flow.admin(),
        "the handler-entry snapshot predates promotion"
    );

    let retained = retained.lock().expect("retained identities mutex").clone();
    assert_eq!(retained.len(), 2);
    let first_retained = retained[0]
        .as_ref()
        .expect("first handler retained its request identity");
    assert_eq!(first_retained.kid(), alice_kid);
    assert_eq!(first_retained.name(), "alice");
    assert!(
        !first_retained.admin(),
        "the actual request extension remains the pre-promotion snapshot after release"
    );
    let second_retained = retained[1]
        .as_ref()
        .expect("subsequent handler received an identity");
    assert!(
        second_retained.admin(),
        "subsequent requests see the registry change"
    );
}

#[tokio::test]
async fn identity_snapshot_handshake_cancellation_drops_request_future() {
    struct DropWitness(Arc<AtomicBool>);
    impl Drop for DropWitness {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let dropped = Arc::new(AtomicBool::new(false));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<Option<VerifiedIdentity>>();
    let (release_tx, _release_rx) = tokio::sync::oneshot::channel();
    let request = {
        let dropped = Arc::clone(&dropped);
        async move {
            let _witness = DropWitness(dropped);
            std::future::pending::<()>().await
        }
    };

    let timed_out = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        request_after_identity(request, entered_rx, release_tx, |_| Ok(())),
    )
    .await;
    drop(entered_tx);

    assert!(
        timed_out.is_err(),
        "identity handshake should remain pending"
    );
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn identity_snapshot_handshake_rejects_missing_identity_and_early_completion() {
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    entered_tx.send(None).expect("test receiver is present");
    let parked_request = async move {
        let _ = release_rx.await;
        "parked request"
    };
    let missing = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        request_after_identity(parked_request, entered_rx, release_tx, |_| Ok(())),
    )
    .await
    .expect("missing-identity coordination must be bounded");
    assert_eq!(
        missing.unwrap_err(),
        "handler received no verified identity"
    );

    let (_entered_tx, entered_rx) = tokio::sync::oneshot::channel::<Option<VerifiedIdentity>>();
    let (release_tx, _release_rx) = tokio::sync::oneshot::channel();
    let early = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        request_after_identity(
            std::future::ready("completed too early"),
            entered_rx,
            release_tx,
            |_| Ok(()),
        ),
    )
    .await
    .expect("early-completion coordination must be bounded");
    assert_eq!(
        early.unwrap_err(),
        "first request completed before the handler identity signal"
    );
}

/// Availability (spec 02 section 3): a GET that a handler runs forwards with
/// the identity extension.
#[tokio::test]
async fn get_forwards_with_identity() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let alice_kid = alice.kid().to_string();
    let signed = signed_request(&alice, "GET", "/mcp", b"");
    let got = inspect(
        send(&h.service, build_request(&signed, "GET", "/mcp", b""))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(h.inner.calls(), 1);
    let seen = h.inner.seen_identities();
    assert_eq!(seen.len(), 1);
    let id = seen[0].as_ref().expect("GET forwards carry the identity");
    assert_eq!(id.kid(), alice_kid);
    assert_eq!(id.name(), "alice");
    assert!(!id.admin());
}

/// A plain response-object JSON-RPC body forwards like any other ordinary
/// traffic and carries the identity: mirrors the fixture accept-response-object.
#[tokio::test]
async fn response_object_forwards_with_identity() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let alice_kid = alice.kid().to_string();
    let signed = signed_request(&alice, "POST", "/mcp", INNER_OK_BODY);
    let got = inspect(
        send(
            &h.service,
            build_request(&signed, "POST", "/mcp", INNER_OK_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(got.body.as_ref(), INNER_OK_BODY);
    assert_eq!(h.inner.calls(), 1);
    let seen = h.inner.seen_identities();
    assert_eq!(seen.len(), 1);
    let id = seen[0].as_ref().expect("identity extension present");
    assert_eq!(id.kid(), alice_kid);
    assert_eq!(id.name(), "alice");
    assert!(!id.admin());
}

// ---------------------------------------------------------------------------
// Readiness contract: a clone drops readiness state, so tower requires the
// instance readied by poll_ready to be the one `call` invokes.
// ---------------------------------------------------------------------------

/// Inner service that panics if `call` runs on an instance whose poll_ready
/// was not the last readiness method invoked on it (catches
/// clone-after-ready).
struct NeedsReady {
    calls: Arc<AtomicUsize>,
    ready: bool,
}

impl Clone for NeedsReady {
    fn clone(&self) -> Self {
        // tower: a clone may have dropped readiness state, so it starts NOT
        // ready.
        Self {
            calls: Arc::clone(&self.calls),
            ready: false,
        }
    }
}

impl tower::Service<http::Request<Full<Bytes>>> for NeedsReady {
    type Response = http::Response<Full<Bytes>>;
    type Error = String;
    type Future = std::future::Ready<Result<http::Response<Full<Bytes>>, String>>;
    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), String>> {
        self.ready = true;
        std::task::Poll::Ready(Ok(()))
    }
    fn call(&mut self, _req: http::Request<Full<Bytes>>) -> Self::Future {
        if !std::mem::replace(&mut self.ready, false) {
            panic!("inner.call() without poll_ready() on this instance (clone-after-ready)");
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(http::Response::builder()
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from_static(b"{}")))
            .expect("static response")))
    }
}

/// The readied inner instance must be the one that serves the request.
///
/// Pipeline: verification passes and the GET forwards. oneshot polls poll_ready on the JackService, which forwards to the inner
/// instance's poll_ready (ready=true on THAT instance); call must move THAT
/// instance into the future. The second request exercises the fresh-clone
/// cycle left behind by the first call's replace. Old code cloned the service
/// inside call, so the inner clone started ready=false -> panic -> test
/// failure.
#[tokio::test]
async fn readiness_ready_instance_is_called() {
    let state = MemoryState::new();
    seed_registry(&state);
    let layer = JackLayer::new(HandlerConfig {
        verifier: build_verifier(state, None),
        server_key: server_signing_key(),
        max_body_bytes: 0,
        max_response_bytes: 0,
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let svc = layer.layer(NeedsReady {
        calls: Arc::clone(&calls),
        ready: false,
    });
    let alice = harness::signer_by_name("alice");
    for _ in 0..2 {
        let signed = signed_request(&alice, "GET", "/mcp", b"");
        let res = svc
            .clone()
            .oneshot(build_request(&signed, "GET", "/mcp", b""))
            .await
            .expect("no inner error");
        assert_eq!(res.status(), 200);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

/// An inner Jack-Auth header must be REPLACED, not appended (Go header.Set).
///
/// Pipeline: verification passes and the GET forwards; the signed
/// answer must carry exactly one Jack-Auth (ours) and no inner Content-Length.
/// Old code appended, yielding two Jack-Auth headers -> the len==1 assert
/// fails.
#[tokio::test]
async fn inner_jack_auth_is_replaced_not_appended() {
    let h = new_harness(
        0,
        InnerResponse {
            status: 200,
            content_type: "application/json",
            body: INNER_OK_BODY.to_vec(),
            extra_headers: vec![
                ("Jack-Auth", "v1 kid=bogus,ts=1,sig=bogus"),
                ("Content-Length", "999"),
            ],
        },
    );
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "GET", "/mcp", b"");
    let got = inspect(
        send(&h.service, build_request(&signed, "GET", "/mcp", b""))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(
        got.jack_auth.len(),
        1,
        "exactly one Jack-Auth — Go header.Set parity"
    );
    assert_signed(&got, &signed.request_sig, &h.server_pub);
    assert_eq!(got.content_length, None, "inner Content-Length is dropped");
}

/// The SSE refusal must not buffer (or even poll) the inner body.
///
/// Pipeline: verification passes and the GET forwards; the inner 200
/// text/event-stream is refused by the stream guard BEFORE the body is read,
/// so an endless (always-pending Channel) body cannot hang the response and
/// is dropped unread. Old code buffered first -> the timeout fires -> test
/// failure.
#[tokio::test]
async fn refuses_endless_stream_without_buffering() {
    let state = MemoryState::new();
    seed_registry(&state);
    let layer = JackLayer::new(HandlerConfig {
        verifier: build_verifier(state, None),
        server_key: server_signing_key(),
        max_body_bytes: 0,
        max_response_bytes: 0,
    });
    let (mut sender, body) = http_body_util::Channel::<Bytes>::new(1);
    let cell = Arc::new(Mutex::new(Some(body)));
    let svc = layer.layer(tower::service_fn(
        move |_req: http::Request<Full<Bytes>>| {
            // Channel is not Clone; hand the single body out of a shared cell.
            let body = cell
                .lock()
                .expect("body cell")
                .take()
                .expect("one inner request");
            async move {
                Ok::<_, String>(
                    http::Response::builder()
                        .header("Content-Type", "text/event-stream")
                        .body(body)
                        .expect("static response"),
                )
            }
        },
    ));
    let server_pub = *server_signing_key().verifying_key().as_bytes();
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "GET", "/mcp", b"");
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        svc.oneshot(build_request(&signed, "GET", "/mcp", b"")),
    )
    .await
    .expect("SSE refusal must not wait on the endless body")
    .expect("request accepted");
    let got = inspect(res).await;
    assert_eq!(got.status, 501);
    assert_eq!(error_code(&got.body), "streaming_unsupported");
    assert_signed(&got, &signed.request_sig, &server_pub);
    // The body was dropped unread: the producer can no longer enqueue frames.
    assert!(
        sender
            .send_data(Bytes::from_static(b"data: never\n\n"))
            .await
            .is_err(),
        "the endless body must be dropped without polling"
    );
}

// ---------------------------------------------------------------------------
// Response cap (HandlerConfig::max_response_bytes). Probes are channels,
// counters and drop flags, never sleeps. Every overflow test is red on the
// pre-cap code (limit usize::MAX): it answered the upstream status and full
// body instead of the signed 502.
// ---------------------------------------------------------------------------

const OVERFLOW_BODY: &str = concat!(
    r#"{"error":{"code":"response_too_large","#,
    r#""message":"upstream response exceeds the configured limit"}}"#
);

/// A response seen from the layer: headers are captured before the body is
/// consumed, plus the request signature it must be bound to.
struct Observed {
    got: GotResponse,
    headers: http::HeaderMap,
    sent: SentRequest,
}

impl Observed {
    fn header_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.headers.keys().map(|k| k.as_str().to_owned()).collect();
        names.sort();
        names
    }
}

async fn observe(res: http::Response<Full<Bytes>>, sent: SentRequest) -> Observed {
    let headers = res.headers().clone();
    Observed {
        got: inspect(res).await,
        headers,
        sent,
    }
}

/// One signed GET /mcp through the harness service.
async fn get_via(h: &TestHarness) -> Observed {
    let alice = harness::signer_by_name("alice");
    let sent = signed_request(&alice, "GET", "/mcp", b"");
    let res = send(&h.service, build_request(&sent, "GET", "/mcp", b""))
        .await
        .expect("no inner error");
    observe(res, sent).await
}

/// Upstream answer carrying headers that must NOT survive an overflow.
fn upstream_of(len: usize) -> InnerResponse {
    InnerResponse {
        status: 201,
        content_type: "text/plain",
        body: vec![b'x'; len],
        extra_headers: vec![("X-Upstream", "1"), ("Set-Cookie", "sid=1")],
    }
}

/// The overflow answer: signed 502 bound to the ORIGINAL request signature,
/// a fresh Content-Type-only header set and no upstream byte.
fn assert_overflow_answer(o: &Observed, server_pub: &[u8; 32]) {
    assert_eq!(o.got.status, 502);
    assert_eq!(error_code(&o.got.body), "response_too_large");
    assert_eq!(o.got.body.as_ref(), OVERFLOW_BODY.as_bytes());
    assert_eq!(o.header_names(), vec!["content-type", "jack-auth"]);
    assert_eq!(o.got.content_type.as_deref(), Some("application/json"));
    assert_signed(&o.got, &o.sent.request_sig, server_pub);
    // A different (never-sent) request has a different signature; the answer
    // must not verify against it.
    let other = signed_request(&harness::signer_by_name("alice"), "GET", "/mcp", b"");
    assert_ne!(other.request_sig, o.sent.request_sig);
    let values: Vec<&str> = o.got.jack_auth.iter().map(String::as_str).collect();
    assert!(
        mcp_jack::signing::verify_response(
            server_pub,
            502,
            &values,
            &other.request_sig,
            &o.got.body,
            FIXTURE_NOW,
            30,
        )
        .is_err(),
        "overflow answer must be bound to its own request only"
    );
}

/// An ordinary upstream answer passes untouched and is signed.
fn assert_passed_through(o: &Observed, expected_body: &[u8], server_pub: &[u8; 32]) {
    assert_eq!(o.got.status, 201);
    assert_eq!(o.got.body.as_ref(), expected_body);
    assert_eq!(o.got.content_type.as_deref(), Some("text/plain"));
    assert_eq!(
        o.headers.get("x-upstream").map(|v| v.as_bytes()),
        Some(&b"1"[..])
    );
    assert_eq!(
        o.headers.get("set-cookie").map(|v| v.as_bytes()),
        Some(&b"sid=1"[..])
    );
    assert_eq!(o.got.content_length, None);
    assert_signed(&o.got, &o.sent.request_sig, server_pub);
}

/// Cap 8: cap-1 and exactly cap bytes in a single frame pass byte for byte.
///
/// Red-before: n/a (passes before too); it pins the exact-boundary side so
/// the overflow tests below cannot be satisfied by rejecting everything.
#[tokio::test]
async fn response_cap_minus_one_and_exact_pass() {
    for len in [7usize, 8] {
        let h = new_harness_with(0, 8, upstream_of(len));
        let o = get_via(&h).await;
        assert_passed_through(&o, &vec![b'x'; len], &h.server_pub);
    }
}

/// Cap 8: cap+1 bytes in a single frame overflow into the signed 502.
///
/// Red-before: old code returned 201 with the 9 upstream bytes.
#[tokio::test]
async fn response_cap_plus_one_overflows() {
    let h = new_harness_with(0, 8, upstream_of(9));
    let o = get_via(&h).await;
    assert_overflow_answer(&o, &h.server_pub);
    assert_eq!(h.inner.calls(), 1);
    assert!(o.headers.get("x-upstream").is_none());
    assert!(o.headers.get("set-cookie").is_none());
}

/// max_response_bytes 0 means 1 MiB: 1<<20 passes, one more byte overflows.
///
/// Red-before (overflow half): old code had no response limit and answered 201.
#[tokio::test]
async fn default_response_limit_is_one_mib() {
    let h = new_harness_with(0, 0, upstream_of(1 << 20));
    let o = get_via(&h).await;
    assert_passed_through(&o, &vec![b'x'; 1 << 20], &h.server_pub);

    let h = new_harness_with(0, 0, upstream_of((1 << 20) + 1));
    let o = get_via(&h).await;
    assert_overflow_answer(&o, &h.server_pub);
}

/// A configured limit replaces the default in both directions.
///
/// Red-before: the configured-small half (see response_cap_plus_one_overflows)
/// answered 201; the configured-large half guards against ignoring the field.
#[tokio::test]
async fn configured_limit_replaces_default() {
    let h = new_harness_with(0, (1 << 20) + 1, upstream_of((1 << 20) + 1));
    let o = get_via(&h).await;
    assert_passed_through(&o, &vec![b'x'; (1 << 20) + 1], &h.server_pub);

    let h = new_harness_with(0, 8, upstream_of(9));
    let o = get_via(&h).await;
    assert_eq!(o.got.status, 502);
}

/// The request cap does not limit the response.
#[tokio::test]
async fn small_request_cap_does_not_limit_response() {
    let h = new_harness_with(64, 0, upstream_of(2000));
    let o = get_via(&h).await;
    assert_passed_through(&o, &vec![b'x'; 2000], &h.server_pub);
}

/// The response cap does not limit the request.
#[tokio::test]
async fn small_response_cap_does_not_limit_request() {
    let h = new_harness_with(
        0,
        8,
        InnerResponse {
            status: 200,
            content_type: "application/json",
            body: b"{}".to_vec(),
            extra_headers: Vec::new(),
        },
    );
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":{{"pad":"{}"}}}}"#,
        "x".repeat(200)
    )
    .into_bytes();
    let alice = harness::signer_by_name("alice");
    let sent = signed_request(&alice, "POST", "/mcp", &body);
    let res = send(&h.service, build_request(&sent, "POST", "/mcp", &body))
        .await
        .expect("no inner error");
    let o = observe(res, sent).await;
    assert_eq!(o.got.status, 200);
    assert_eq!(o.got.body.as_ref(), b"{}");
    assert_eq!(h.inner.seen_bodies(), vec![body]);
}

/// What the end of a probed upstream body looks like.
#[derive(Clone, Copy)]
enum Tail {
    /// The producer finished normally.
    End,
    /// The producer failed after its frames.
    Fail,
    /// The producer stays open and idle (an unfinished body).
    KeepOpen,
}

/// Counts consumed frames and records when the body (which owns it through
/// its map_frame closure) is dropped.
struct Probe {
    polled: Arc<AtomicUsize>,
    dropped: Arc<std::sync::atomic::AtomicBool>,
}

impl Probe {
    fn record(&self) {
        self.polled.fetch_add(1, Ordering::SeqCst);
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

struct Streamed {
    observed: Observed,
    /// Frames the adapter pulled out of the upstream body.
    polled: usize,
    /// The upstream body was dropped by the time the answer was produced.
    dropped: bool,
    /// For Tail::KeepOpen: the producer's send failed (receiver gone).
    source_closed: Option<bool>,
    server_pub: [u8; 32],
}

/// Runs one GET through a layer whose inner service answers 201 with a
/// channel body holding `frames`. http_body_util is the only body source
/// available (http_body is not a direct dependency, so no hand-written Body):
/// Channel gives per-frame control, BodyExt::map_frame adds the counter and
/// the drop observer. Frames are queued before the call so the run needs no
/// scheduling luck. The timeout is only a hang guard for code that waits on
/// an unfinished body forever; nothing synchronizes on it.
async fn send_streamed(
    max_response_bytes: usize,
    content_type: &'static str,
    frames: &[&[u8]],
    tail: Tail,
) -> Streamed {
    let state = MemoryState::new();
    seed_registry(&state);
    let layer = JackLayer::new(HandlerConfig {
        verifier: build_verifier(state, None),
        server_key: server_signing_key(),
        max_body_bytes: 0,
        max_response_bytes,
    });
    let (mut sender, channel) =
        http_body_util::Channel::<Bytes, std::io::Error>::new(frames.len() + 1);
    for frame in frames {
        sender
            .send_data(Bytes::copy_from_slice(frame))
            .await
            .expect("frame fits the channel buffer");
    }
    let polled = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let probe = Probe {
        polled: Arc::clone(&polled),
        dropped: Arc::clone(&dropped),
    };
    let body = http_body_util::BodyExt::map_frame(channel, move |frame| {
        probe.record();
        frame
    });
    let mut open_sender = None;
    match tail {
        Tail::End => drop(sender),
        Tail::Fail => sender.abort(std::io::Error::other("upstream reset")),
        Tail::KeepOpen => open_sender = Some(sender),
    }
    // Channel is not Clone; hand the single body out of a shared cell.
    let cell = Arc::new(Mutex::new(Some(body)));
    let svc = layer.layer(tower::service_fn(
        move |_req: http::Request<Full<Bytes>>| {
            let body = cell
                .lock()
                .expect("body cell")
                .take()
                .expect("one inner request");
            async move {
                Ok::<_, String>(
                    http::Response::builder()
                        .status(201)
                        .header("Content-Type", content_type)
                        .header("X-Upstream", "1")
                        .header("Set-Cookie", "sid=1")
                        .body(body)
                        .expect("static response"),
                )
            }
        },
    ));
    let alice = harness::signer_by_name("alice");
    let sent = signed_request(&alice, "GET", "/mcp", b"");
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        svc.oneshot(build_request(&sent, "GET", "/mcp", b"")),
    )
    .await
    .expect("the adapter must not wait on an upstream body it should have dropped")
    .expect("no inner error");
    let observed = observe(res, sent).await;
    let source_closed = match open_sender.as_mut() {
        Some(s) => Some(s.send_data(Bytes::from_static(b"late")).await.is_err()),
        None => None,
    };
    Streamed {
        observed,
        polled: polled.load(Ordering::SeqCst),
        dropped: dropped.load(Ordering::SeqCst),
        source_closed,
        server_pub: *server_signing_key().verifying_key().as_bytes(),
    }
}

/// Several frames summing to exactly the cap pass with exact bytes.
///
/// Red-before: n/a (passes before too); the exact-boundary control.
#[tokio::test]
async fn multi_frame_exact_cap_passes() {
    let r = send_streamed(8, "text/plain", &[b"aaaa", b"bbbb"], Tail::End).await;
    assert_passed_through(&r.observed, b"aaaabbbb", &r.server_pub);
    assert_eq!(r.polled, 2);
}

/// The total crosses the cap on the last frame (4+4+1).
///
/// Red-before: old code answered 201 with the 9 bytes.
#[tokio::test]
async fn multi_frame_total_cap_plus_one_overflows() {
    let r = send_streamed(8, "text/plain", &[b"aaaa", b"bbbb", b"c"], Tail::End).await;
    assert_overflow_answer(&r.observed, &r.server_pub);
    assert_eq!(r.polled, 3);
    assert!(r.dropped);
}

/// A later frame crosses the cap and the frames after it are never consumed.
///
/// Red-before: old code consumed all 3 frames (polled == 3, status 201).
#[tokio::test]
async fn multi_frame_later_frame_crosses_cap_and_stops_polling() {
    let r = send_streamed(8, "text/plain", &[b"aaaa", b"bbbbb", b"c"], Tail::End).await;
    assert_overflow_answer(&r.observed, &r.server_pub);
    assert_eq!(r.polled, 2, "the frame after the overflow must stay unread");
    assert!(r.dropped, "the upstream body must be dropped on overflow");
}

/// An unfinished producer is released on overflow: its sender sees the
/// receiver gone, and the queued tail frames were never consumed.
///
/// Red-before: old code consumed every queued frame and then awaited the idle
/// producer forever (the hang guard in send_streamed fails the test).
#[tokio::test]
async fn overflow_drops_unfinished_source() {
    let r = send_streamed(
        8,
        "text/plain",
        &[b"aaaaaa", b"bbbbbb", b"cccccc", b"dddddd"],
        Tail::KeepOpen,
    )
    .await;
    assert_overflow_answer(&r.observed, &r.server_pub);
    assert_eq!(r.polled, 2);
    assert!(r.dropped);
    assert_eq!(
        r.source_closed,
        Some(true),
        "the producer must see a closed receiver"
    );
}

/// SSE precedence: an event-stream larger than the cap is still the signed
/// 501 and its body is dropped without being read.
///
/// Red-before: n/a (SSE precedence already held); guards the ordering of the
/// stream check and the cap.
#[tokio::test]
async fn sse_precedence_over_response_cap() {
    let big = [b'd'; 100];
    let r = send_streamed(
        8,
        "text/event-stream; charset=utf-8",
        &[&big, &big, &big],
        Tail::KeepOpen,
    )
    .await;
    assert_eq!(r.observed.got.status, 501);
    assert_eq!(error_code(&r.observed.got.body), "streaming_unsupported");
    assert_signed(&r.observed.got, &r.observed.sent.request_sig, &r.server_pub);
    assert_eq!(r.polled, 0, "the SSE body must not be read at all");
    assert!(r.dropped);
    assert_eq!(r.source_closed, Some(true));
}

/// A read error before the cap is reached stays the signed 500, not a 502.
///
/// Red-before: n/a (500 already held); distinguishes the two failure kinds.
#[tokio::test]
async fn read_error_before_overflow_is_500() {
    let r = send_streamed(8, "text/plain", &[b"aaaa"], Tail::Fail).await;
    let got = &r.observed.got;
    assert_eq!(got.status, 500);
    assert_eq!(error_code(&got.body), "internal_error");
    assert_signed(got, &r.observed.sent.request_sig, &r.server_pub);
    assert_eq!(r.observed.header_names(), vec!["content-type", "jack-auth"]);
    assert!(r.dropped);
}
