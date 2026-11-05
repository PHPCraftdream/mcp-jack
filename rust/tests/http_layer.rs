//! Port of Go server/middleware_test.go against JackLayer: every request
//! enters the spec 01 section 4 pipeline through the HTTP adapter, and the
//! tests pin where each request stops (method gate, body limit, verification
//! steps, policy, native dispatch) plus response signing per spec 01 section 5.
#![cfg(feature = "http")]

mod common;

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
use mcp_jack::server::native::{Native, NativeOptions};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::policy::Policy;
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
}

impl InnerConfig {
    fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            bodies: Arc::new(Mutex::new(Vec::new())),
            targets: Arc::new(Mutex::new(Vec::new())),
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
    // Same idiom as verify_conformance.rs; kind null in the fixture means
    // "human" (spec 02 section 1).
    let registry = fixtures::load_registry().expect("load registry.json");
    state
        .update(&mut |edit| {
            for e in &registry.keys {
                edit.put_key(RegistryEntry {
                    kid: e.kid.clone(),
                    public_key: e.public_key.clone(),
                    name: e.name.clone(),
                    kind: e.kind.clone().unwrap_or_else(|| "human".to_string()),
                    scopes: e.scopes.clone(),
                    not_before: e.not_before,
                    not_after: e.not_after,
                });
            }
            Ok(())
        })
        .expect("seed registry");
}

fn build_verifier(state: MemoryState, sink: Option<Arc<MemoryAuditSink>>) -> Arc<Verifier> {
    let policy_bytes =
        std::fs::read(fixtures::fixture_path("policy.json")).expect("read policy.json");
    let policy = Arc::new(Policy::parse(&policy_bytes).expect("policy parses"));
    let now_clock: Clock = Arc::new(move || FIXTURE_NOW);
    Arc::new(
        Verifier::new(Config {
            aud: FIXTURE_AUD.to_string(),
            state: Arc::new(state),
            nonces: Arc::new(NonceStore::new()),
            policy,
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
/// Pipeline: steps 1-8 pass (method POST, body fits, header parses, kid
/// resolves, ts in window, signature verifies, nonce recorded), step 9 policy
/// accepts (svc.* requires scope read; alice holds read) -> accept.
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

/// Go TestMiddlewareSignsAuthorizationRejection: alice calls a lifecycle-
/// gated tool; the 403 is signed because the nonce was recorded.
///
/// Pipeline: steps 1-8 pass; step 9 policy rejects (svc.restart requires
/// scope lifecycle, alice holds only read) -> 403 insufficient_scope, signed.
#[tokio::test]
async fn authorization_rejection_signed() {
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
    assert_eq!(got.status, 403);
    assert_eq!(error_code(&got.body), "insufficient_scope");
    assert_signed(&got, &signed.request_sig, &h.server_pub);
    // len==1 proves the response is signed; the 401-only WWW-Authenticate
    // claim is carried by the next assert.
    assert_eq!(got.jack_auth.len(), 1);
    assert!(
        got.www_authenticate.is_none(),
        "403s never carry WWW-Authenticate"
    );
    assert_eq!(h.inner.calls(), 0);
}

/// Go TestMiddlewareRefusesStreams: GET forwarding succeeds but an SSE answer
/// cannot be signed, so the layer refuses it.
///
/// Pipeline: GET skips body classification, steps 1-8 pass and step 9
/// accepts; the inner 200 text/event-stream hits the layer's stream guard ->
/// 501 streaming_unsupported, signed.
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
/// equals the limit, so steps 1-8 pass and step 9 forwards -> 200, signed.
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
/// Pipeline: steps 1-8 pass (root holds admin), step 9 native dispatch
/// succeeds -> 200, signed, the inner service never sees the request.
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
/// Pipeline: steps 1-8 pass (the signature binds the raw target string), step
/// 9 GET accepts -> forwarded; a normalizing layer would break the signature
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
/// Pipeline: steps 1-8 pass (GET accepts at step 9) and the request forwards.
/// oneshot polls poll_ready on the JackService, which forwards to the inner
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
/// Pipeline: steps 1-8 pass, step 9 GET accepts -> forwarded; the signed
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
/// Pipeline: steps 1-8 pass, step 9 GET accepts -> forwarded; the inner 200
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
