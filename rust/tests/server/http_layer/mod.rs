//! Port of Go server/middleware_test.go against JackLayer: every request
//! enters the spec 01 section 4 pipeline through the HTTP adapter, and the
//! tests pin where each request stops (method gate, body limit, verification
//! steps, admin gate, native dispatch) plus response signing per spec 01
//! section 5. On every forwarded accept the layer hands the wrapped service a
//! VerifiedIdentity request extension (spec 02 section 3); the admin flag
//! gates only jack.admin.* calls.
#![cfg(feature = "http")]

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::common::fixtures;
use crate::common::harness::{self, FIXTURE_AUD, FIXTURE_NOW};
use bytes::Bytes;
use http_body_util::Full;
use mcp_jack::user_key::ServerSigningKey;
use tower::{Layer, ServiceExt};

use mcp_jack::client::auth::sign_request;
use mcp_jack::client::signer::{InMemorySigner, Signer};
use mcp_jack::server::audit::{AuditSink, MemoryAuditSink};
use mcp_jack::server::http::{HandlerConfig, JackLayer, JackService};
use mcp_jack::server::identity::VerifiedIdentity;
use mcp_jack::server::modern::Profile;
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
fn server_signing_key() -> ServerSigningKey {
    let keys = fixtures::load_keys().expect("load keys.json");
    let svc = keys
        .keys
        .iter()
        .find(|k| k.name == "svc")
        .unwrap_or_else(|| panic!("keys.json has no key named svc"));
    let seed: [u8; 32] = harness::hex_bytes(&svc.seed_hex)
        .try_into()
        .expect("svc seed is 32 bytes");
    ServerSigningKey::from_bytes(&seed)
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

mod core;
mod identity;
mod readiness_and_caps;
