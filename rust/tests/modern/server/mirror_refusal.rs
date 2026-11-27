//! End-to-end mirror refusal through the HTTP layer (spec 04 `S6`, `S10`).
//!
//! A modern-profile `jack.*` call whose `Mcp-Name` mirror disagrees with the
//! signed body is refused with the signed `400` / `-32020` answer *before* the
//! native tool runs, so no state changes and no audit event is written. The
//! positive control shows the same call with correct mirrors running the tool
//! exactly once and answering the modern `resultType: "complete"` result.
#![cfg(feature = "http")]

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use mcp_jack::user_key::ServerSigningKey;
use tower::{Layer, ServiceExt};

use mcp_jack::client::auth::sign_request;
use mcp_jack::client::signer::InMemorySigner;
use mcp_jack::error::JackError;
use mcp_jack::server::audit::{AuditSink, MemoryAuditSink};
use mcp_jack::server::http::{HandlerConfig, JackLayer, JackService};
use mcp_jack::server::modern::Profile;
use mcp_jack::server::native::{Native, NativeOptions};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::state::{MemoryState, RegistryEntry, StateStore};
use mcp_jack::server::verify::{Clock, Config, NativeCall, NativeResult, NativeTools, Verifier};

use crate::server::common::fixtures;
use crate::server::common::harness::{self, FIXTURE_AUD, FIXTURE_NOW};

/// The boxed inner service behind the harness (S::Error = String).
type InnerBox =
    tower::util::BoxCloneService<http::Request<Full<Bytes>>, http::Response<Full<Bytes>>, String>;

/// Process-wide nonce source: the last 8 bytes encode a never-repeating
/// counter (the same idiom as the other HTTP harnesses).
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The audited native tool under test; `root` is the fixture administrator.
const ADMIN_LIST_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.user.list","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;

/// The canned inner answer; a native call never reaches it.
const INNER_OK_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;

/// The fixed `S6` message of a `Mcp-Name` that disagrees with the body.
const NAME_MISMATCH_MESSAGE: &str = "Header mismatch: Mcp-Name does not match the body value";

/// A [`NativeTools`] adapter that counts every native call and delegates to the
/// real [`Native`] implementation.
struct CountingNative {
    inner: Native,
    calls: Arc<AtomicUsize>,
}

impl NativeTools for CountingNative {
    fn call(&self, c: &mut NativeCall) -> Result<NativeResult, JackError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.call(c)
    }
}

/// One signed request under test: keeps the request signature so the response
/// can be verified against it.
struct SentRequest {
    header_value: String,
    request_sig: String,
}

fn signed_request(signer: &InMemorySigner, body: &[u8]) -> SentRequest {
    let n = NONCE_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    let mut nonce = [0u8; 16];
    nonce[8..].copy_from_slice(&n.to_be_bytes());
    let signed = sign_request(
        signer,
        FIXTURE_AUD,
        "POST",
        "/mcp",
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
    headers: &[(&str, &str)],
    body: &[u8],
) -> http::Request<Full<Bytes>> {
    let mut builder = http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Jack-Auth", signed.header_value.as_str());
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder
        .body(Full::new(Bytes::copy_from_slice(body)))
        .expect("static request parts")
}

fn seed_registry(state: &MemoryState) {
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

fn build_verifier(
    state: MemoryState,
    native: Arc<dyn NativeTools>,
    audit: Arc<dyn AuditSink>,
) -> Arc<Verifier> {
    let now: Clock = Arc::new(move || FIXTURE_NOW);
    Arc::new(
        Verifier::new(Config {
            aud: FIXTURE_AUD.to_string(),
            state: Arc::new(state),
            nonces: Arc::new(NonceStore::new()),
            audit: Some(audit),
            native: Some(native),
            window_seconds: 30,
            now,
        })
        .expect("verifier"),
    )
}

/// The keys.json "svc" signing key (the server's response key).
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

/// The harness around one `Modern`-profile service: the counting native tool,
/// the audit sink, the call counter of the wrapped service and the pinned
/// server public key.
struct TestHarness {
    service: JackService<InnerBox>,
    native_calls: Arc<AtomicUsize>,
    audit: Arc<MemoryAuditSink>,
    inner_calls: Arc<AtomicUsize>,
    server_pub: [u8; 32],
}

impl TestHarness {
    fn native_calls(&self) -> usize {
        self.native_calls.load(Ordering::SeqCst)
    }

    fn inner_calls(&self) -> usize {
        self.inner_calls.load(Ordering::SeqCst)
    }
}

fn modern_harness() -> TestHarness {
    let state = MemoryState::new();
    seed_registry(&state);
    let native_calls = Arc::new(AtomicUsize::new(0));
    let native = Arc::new(CountingNative {
        inner: Native::new(NativeOptions::default()),
        calls: Arc::clone(&native_calls),
    });
    let audit = Arc::new(MemoryAuditSink::new());
    let verifier = build_verifier(state, native, Arc::clone(&audit) as Arc<dyn AuditSink>);

    let inner_calls = Arc::new(AtomicUsize::new(0));
    let recorder = Arc::clone(&inner_calls);
    let inner = tower::util::BoxCloneService::new(tower::service_fn(
        move |_req: http::Request<Full<Bytes>>| {
            let recorder = Arc::clone(&recorder);
            async move {
                recorder.fetch_add(1, Ordering::SeqCst);
                Ok::<_, String>(
                    http::Response::builder()
                        .status(200)
                        .header("Content-Type", "application/json")
                        .body(Full::new(Bytes::from_static(INNER_OK_BODY)))
                        .expect("static response parts"),
                )
            }
        },
    ));
    let layer = JackLayer::new(HandlerConfig {
        verifier,
        server_key: server_signing_key(),
        max_body_bytes: 0,
        max_response_bytes: 0,
    })
    .with_profile(Profile::Modern);
    TestHarness {
        service: layer.layer(inner),
        native_calls,
        audit,
        inner_calls,
        server_pub: *server_signing_key().verifying_key().as_bytes(),
    }
}

/// Response view: status, all Jack-Auth values, body bytes and Content-Type.
struct GotResponse {
    status: u16,
    jack_auth: Vec<String>,
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
    let jack_auth = res
        .headers()
        .get_all("Jack-Auth")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_owned)
        .collect();
    let (_, body) = res.into_parts();
    let body = http_body_util::BodyExt::collect(body)
        .await
        .expect("Full body always collects")
        .to_bytes();
    GotResponse {
        status,
        jack_auth,
        body,
        content_type,
    }
}

/// Mirrors Go assertSigned: `verify_response` checks the parsed kid against the
/// pinned server key itself.
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

fn json_body(got: &GotResponse) -> serde_json::Value {
    serde_json::from_slice(&got.body).unwrap_or_else(|e| {
        panic!(
            "body is not JSON ({e}): {:?}",
            String::from_utf8_lossy(&got.body)
        )
    })
}

/// Spec 04 `S6`: a `Mcp-Name` that disagrees with the signed body is a signed
/// `400` `-32020`, and the native tool never runs (no state change, no audit).
#[tokio::test]
async fn a_wrong_name_mirror_is_refused_before_the_native_tool_runs() {
    let harness = modern_harness();
    let root = harness::signer_by_name("root");
    let signed = signed_request(&root, ADMIN_LIST_BODY);
    let got = inspect(
        harness
            .service
            .clone()
            .oneshot(build_request(
                &signed,
                &[
                    ("MCP-Protocol-Version", "2026-07-28"),
                    ("Mcp-Method", "tools/call"),
                    ("Mcp-Name", "jack.admin.user.get"),
                    ("Content-Type", "application/json"),
                ],
                ADMIN_LIST_BODY,
            ))
            .await
            .expect("no inner error"),
    )
    .await;

    assert_eq!(got.status, 400);
    assert_eq!(got.content_type.as_deref(), Some("application/json"));
    assert_signed(&got, &signed.request_sig, &harness.server_pub);

    let body = json_body(&got);
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 1);
    assert_eq!(body["error"]["code"], -32020);
    assert_eq!(body["error"]["message"], NAME_MISMATCH_MESSAGE);
    assert!(
        body.get("result").is_none(),
        "a refusal carries no result: {body}"
    );

    assert_eq!(harness.native_calls(), 0, "the native tool must not run");
    assert_eq!(harness.inner_calls(), 0, "nothing was forwarded");
    assert!(
        harness.audit.events().is_empty(),
        "no audit event may be recorded: {:?}",
        harness.audit.events()
    );
}

/// The positive control: the same call with correct mirrors runs the audited
/// native tool exactly once and answers the modern result shape.
#[tokio::test]
async fn correct_mirrors_run_the_native_tool_once() {
    let harness = modern_harness();
    let root = harness::signer_by_name("root");
    let signed = signed_request(&root, ADMIN_LIST_BODY);
    let got = inspect(
        harness
            .service
            .clone()
            .oneshot(build_request(
                &signed,
                &[
                    ("MCP-Protocol-Version", "2026-07-28"),
                    ("Mcp-Method", "tools/call"),
                    ("Mcp-Name", "jack.admin.user.list"),
                    ("Content-Type", "application/json"),
                ],
                ADMIN_LIST_BODY,
            ))
            .await
            .expect("no inner error"),
    )
    .await;

    assert_eq!(got.status, 200);
    assert_eq!(got.content_type.as_deref(), Some("application/json"));
    assert_signed(&got, &signed.request_sig, &harness.server_pub);

    let body = json_body(&got);
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 1);
    let result = body["result"].as_object().expect("result is an object");
    assert_eq!(result["resultType"], "complete");
    assert!(
        result["structuredContent"].is_object(),
        "structuredContent is an object: {body}"
    );

    assert_eq!(harness.native_calls(), 1, "exactly one native call");
    assert_eq!(harness.inner_calls(), 0, "a native call is never forwarded");
    let events = harness.audit.events();
    assert_eq!(events.len(), 1, "one audit event: {events:?}");
    assert_eq!(events[0].tool, "jack.admin.user.list");
    assert_eq!(events[0].outcome, mcp_jack::server::audit::AUDIT_SUCCESS);
}
