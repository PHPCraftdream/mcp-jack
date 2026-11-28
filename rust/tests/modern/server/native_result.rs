//! Spec 04 `C7` (`native_result_era_shape`): the era-dependent shape of a
//! protocol-native `jack.*` result and the era independence of error answers.
//!
//! The modern era adds `resultType: "complete"` and
//! `result._meta["io.modelcontextprotocol/serverInfo"]` to the 0.1.x result;
//! a legacy-era request keeps the 0.1.x bytes (no `resultType`, no `_meta`),
//! and an error response carries no `resultType` in either era. A native call
//! is answered by the verifier, so the wrapped service never sees it.
#![cfg(feature = "http")]

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::server::common::fixtures;
use crate::server::common::harness::{self, FIXTURE_AUD, FIXTURE_NOW};
use bytes::Bytes;
use http_body_util::Full;
use mcp_jack::user_key::ServerSigningKey;
use tower::{Layer, ServiceExt};

use mcp_jack::client::auth::sign_request;
use mcp_jack::client::signer::{InMemorySigner, Signer};
use mcp_jack::server::http::{HandlerBuilder, JackLayer, JackService};
use mcp_jack::server::modern::Profile;
use mcp_jack::server::native::{Native, NativeOptions};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::state::{MemoryState, RegistryEntry, StateStore};
use mcp_jack::server::verify::{Clock, VerifierBuilder};

/// The boxed inner service behind the harness (S::Error = String).
type InnerBox =
    tower::util::BoxCloneService<http::Request<Full<Bytes>>, http::Response<Full<Bytes>>, String>;

/// Process-wide nonce source: the first 8 bytes are zero, the last 8 encode a
/// never-repeating counter. Two requests of one test therefore cannot replay
/// each other, exactly like the `http_layer` harness.
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One signed request under test: keeps the request signature so the response
/// can be verified against it.
struct SentRequest {
    header_value: String,
    request_sig: String,
}

/// Signs like the `http_layer` harness: unique nonce, fixture ts, exact target.
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

/// Builds the signed request, adding `headers` after `Jack-Auth`.
fn build_request(
    signed: &SentRequest,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> http::Request<Full<Bytes>> {
    let mut builder = http::Request::builder()
        .method(method)
        .uri(target)
        .header("Jack-Auth", signed.header_value.as_str());
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder
        .body(Full::new(Bytes::copy_from_slice(body)))
        .expect("static request parts")
}

/// The harness around one JackService: the layers under test, the call
/// counter of the wrapped service and the pinned server public key.
struct TestHarness {
    service: JackService<InnerBox>,
    calls: Arc<AtomicUsize>,
    server_pub: [u8; 32],
}

impl TestHarness {
    /// How often the wrapped service was reached. A native call is answered by
    /// the verifier, so any call here would be a bug.
    fn inner_calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

fn seed_registry(state: &MemoryState) {
    // The fixture registry: alice, bob, carol and the rest are non-admin;
    // only `root` carries `admin: true`.
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

/// Fixture verifier, the keys.json "svc" server key and an inner service that
/// counts its calls and answers a fixed JSON body.
fn new_harness(layer: JackLayer) -> TestHarness {
    let calls = Arc::new(AtomicUsize::new(0));
    let recorder = Arc::clone(&calls);
    let service = layer.layer(tower::util::BoxCloneService::new(tower::service_fn(
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
    )));
    TestHarness {
        service,
        calls,
        server_pub: *server_signing_key().verifying_key().as_bytes(),
    }
}

fn handler_config() -> HandlerBuilder {
    let state = MemoryState::new();
    seed_registry(&state);
    let now: Clock = Arc::new(move || FIXTURE_NOW);
    let verifier = Arc::new(
        VerifierBuilder::new(FIXTURE_AUD, Arc::new(state))
            .nonces(Arc::new(NonceStore::new()))
            .native_tools(Some(Arc::new(Native::new(NativeOptions::default()))))
            .window_seconds(30)
            .now(now)
            .try_build()
            .expect("verifier"),
    );
    HandlerBuilder::new(verifier, server_signing_key())
}

/// Default profile: `HandlerBuilder::new(...).build()` without a profile option, i.e. the
/// 0.1.x behaviour (spec 04 section 1).
fn legacy_harness() -> TestHarness {
    new_harness(handler_config().build())
}

/// Modern profile: era rules of spec 04 section 5 apply, the era is always
/// modern.
fn modern_harness() -> TestHarness {
    new_harness(handler_config().with_profile(Profile::Modern).build())
}

/// Sends `req` through the layered service.
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

/// Mirrors Go assertSigned: verify_response checks the parsed kid against the
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

/// The modern-era body: the mirror `_meta` carries the protocol version the
/// `MCP-Protocol-Version` header repeats.
const MODERN_WHOAMI_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.whoami","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
/// The same body without the mirror `_meta` (0.1.x shape).
const LEGACY_WHOAMI_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.whoami","arguments":{}}}"#;
/// A modern-era admin call; alice is a fixture caller WITHOUT `admin: true`.
const MODERN_ADMIN_LIST_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.user.list","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#;
/// The canned inner answer; no native test may ever see it.
const INNER_OK_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;

/// The three mirror headers of a modern `tools/call`, plus Content-Type.
const MODERN_HEADERS: [(&str, &str); 4] = [
    ("MCP-Protocol-Version", "2026-07-28"),
    ("Mcp-Method", "tools/call"),
    ("Mcp-Name", "jack.whoami"),
    ("Content-Type", "application/json"),
];

/// Spec 04 `C7`: a native result is the 0.1.x result plus `resultType` and
/// Jack `_meta` in the modern era, exactly the 0.1.x result in the legacy era,
/// and an error response carries no `resultType` at all.
#[tokio::test]
async fn native_result_era_shape() {
    let alice = harness::signer_by_name("alice");
    let alice_kid = alice.kid().to_string();

    // 1. Modern profile: the native result gains `resultType` and `_meta`.
    let modern = modern_harness();
    let signed = signed_request(&alice, "POST", "/mcp", MODERN_WHOAMI_BODY);
    let got = inspect(
        send(
            &modern.service,
            build_request(&signed, "POST", "/mcp", &MODERN_HEADERS, MODERN_WHOAMI_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(got.content_type.as_deref(), Some("application/json"));
    assert_signed(&got, &signed.request_sig, &modern.server_pub);
    assert_eq!(
        modern.inner_calls(),
        0,
        "a native call is answered by the verifier, never forwarded"
    );

    let body = json_body(&got);
    let result = body["result"].as_object().expect("result is an object");
    assert_eq!(result["resultType"], "complete");
    let server_info = &result["_meta"]["io.modelcontextprotocol/serverInfo"];
    assert_eq!(server_info["name"], "mcp-jack");
    assert_eq!(server_info["version"], env!("CARGO_PKG_VERSION"));
    // The 0.1.x members are still there, with the seeded caller's identity.
    assert_eq!(result["isError"], false);
    let structured = result["structuredContent"]
        .as_object()
        .expect("structuredContent is an object");
    assert_eq!(structured["kid"], alice_kid.as_str());
    assert_eq!(structured["name"], "alice");
    assert_eq!(structured["admin"], false);
    let content = result["content"].as_array().expect("content is an array");
    assert_eq!(content.len(), 1, "exactly one content item");
    assert_eq!(content[0]["type"], "text");

    // 2. Legacy profile (the default, no `with_profile`): the 0.1.x bytes,
    //    i.e. exactly `content`, `isError` and `structuredContent`.
    let legacy = legacy_harness();
    let signed = signed_request(&alice, "POST", "/mcp", LEGACY_WHOAMI_BODY);
    let got = inspect(
        send(
            &legacy.service,
            build_request(
                &signed,
                "POST",
                "/mcp",
                &[("Content-Type", "application/json")],
                LEGACY_WHOAMI_BODY,
            ),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_signed(&got, &signed.request_sig, &legacy.server_pub);
    assert_eq!(
        legacy.inner_calls(),
        0,
        "native calls never reach the inner service"
    );

    let body = json_body(&got);
    let result = body["result"].as_object().expect("result is an object");
    let mut keys: Vec<&str> = result.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["content", "isError", "structuredContent"],
        "the legacy-era result is the 0.1.x shape"
    );
    assert!(
        result.get("resultType").is_none(),
        "no resultType in the legacy era"
    );
    assert!(result.get("_meta").is_none(), "no _meta in the legacy era");
    assert_eq!(result["isError"], false);
    let structured = result["structuredContent"]
        .as_object()
        .expect("structuredContent is an object");
    assert_eq!(structured["kid"], alice_kid.as_str());

    // 3. Error responses carry no `resultType`. The admin gate runs inside the
    //    verifier, before the era rules, so the denial is the spec 01 section
    //    4 rejection envelope (only the `S10` refusals of the modern rules are
    //    full JSON-RPC errors with a `jsonrpc` member).
    let modern = modern_harness();
    let signed = signed_request(&alice, "POST", "/mcp", MODERN_ADMIN_LIST_BODY);
    let got = inspect(
        send(
            &modern.service,
            build_request(
                &signed,
                "POST",
                "/mcp",
                &[
                    ("MCP-Protocol-Version", "2026-07-28"),
                    ("Mcp-Method", "tools/call"),
                    ("Mcp-Name", "jack.admin.user.list"),
                    ("Content-Type", "application/json"),
                ],
                MODERN_ADMIN_LIST_BODY,
            ),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 403);
    assert_signed(&got, &signed.request_sig, &modern.server_pub);
    assert_eq!(
        modern.inner_calls(),
        0,
        "a denied native call is answered by the verifier, never forwarded"
    );

    let body = json_body(&got);
    let error = body["error"].as_object().expect("an error object");
    assert_eq!(
        error["code"].as_str(),
        Some("admin_required"),
        "the error carries a string code"
    );
    assert!(
        error.get("resultType").is_none(),
        "the error object carries no resultType"
    );
    assert!(
        body.get("resultType").is_none(),
        "the error response body carries no resultType"
    );
}
