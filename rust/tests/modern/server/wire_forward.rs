//! Spec 04 `S8`/`S9` forwarding fidelity and the era-dependent `tools/call`
//! classification message.
//!
//! The modern forward path rebuilds the inner header list from the received
//! entries, so a header value carrying opaque bytes (`0x80..`) keeps those
//! exact bytes, every value of a repeated name is kept in its received order,
//! and only the session headers (`Mcp-Session-Id`, `Last-Event-ID`) disappear.
//! It claims no global order across different names (an `http::HeaderMap`
//! groups values by name) and no original field-name casing (`HeaderName`
//! lowercases every name). The
//! `tools/call` classification message follows the era the engine decides for
//! the request, not the deployment profile: under `Both` a legacy-era request
//! keeps the 0.1.x bytes while a modern-era request gets the fixed message.
#![cfg(feature = "http")]

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::server::common::fixtures;
use crate::server::common::harness::{self, FIXTURE_AUD, FIXTURE_NOW};
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use http::HeaderValue;
use http_body_util::Full;
use tower::{Layer, ServiceExt};

use mcp_jack::client::auth::sign_request;
use mcp_jack::client::signer::InMemorySigner;
use mcp_jack::server::http::{HandlerConfig, JackLayer, JackService};
use mcp_jack::server::modern::Profile;
use mcp_jack::server::native::{Native, NativeOptions};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::state::{MemoryState, RegistryEntry, StateStore};
use mcp_jack::server::verify::{Clock, Config, Verifier};

/// The boxed inner service behind the harness (S::Error = String).
type InnerBox =
    tower::util::BoxCloneService<http::Request<Full<Bytes>>, http::Response<Full<Bytes>>, String>;

/// Process-wide nonce source: the first 8 bytes are zero, the last 8 encode a
/// never-repeating counter (the same idiom as the other HTTP harnesses).
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One signed request under test.
struct SentRequest {
    header_value: String,
}

/// Signs like the other harnesses: unique nonce, fixture ts, exact target.
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
    }
}

/// Builds a signed `POST /mcp` request; `headers` are appended in order after
/// `Jack-Auth`, so a name repeated in the slice is sent twice.
fn build_request(
    signed: &SentRequest,
    headers: &[(&str, HeaderValue)],
    body: &[u8],
) -> http::Request<Full<Bytes>> {
    let mut builder = http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Jack-Auth", signed.header_value.as_str());
    for (name, value) in headers {
        builder = builder.header(*name, value.clone());
    }
    builder
        .body(Full::new(Bytes::copy_from_slice(body)))
        .expect("static request parts")
}

/// One forwarded request's headers as the inner service iterated them:
/// `(lowercase name, raw value bytes)` pairs in order.
type HeaderList = Vec<(String, Vec<u8>)>;

/// What the wrapped service observed.
#[derive(Default)]
struct Seen {
    calls: AtomicUsize,
    /// One entry per forwarded request.
    headers: Mutex<Vec<HeaderList>>,
}

impl Seen {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// The header list of the last forwarded request.
    fn last_headers(&self) -> HeaderList {
        self.headers
            .lock()
            .expect("headers mutex")
            .pop()
            .expect("the inner service saw no request")
    }
}

/// Values of every header named `name` (HeaderName lowercased them), in order.
fn values(headers: &HeaderList, name: &str) -> Vec<Vec<u8>> {
    headers
        .iter()
        .filter(|(n, _)| n == name)
        .map(|(_, v)| v.clone())
        .collect()
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

fn build_verifier(state: MemoryState) -> Arc<Verifier> {
    let now_clock: Clock = Arc::new(move || FIXTURE_NOW);
    Arc::new(
        Verifier::new(Config {
            aud: FIXTURE_AUD.to_string(),
            state: Arc::new(state),
            nonces: Arc::new(NonceStore::new()),
            audit: None,
            native: Some(Arc::new(Native::new(NativeOptions::default()))),
            window_seconds: 30,
            now: now_clock,
        })
        .expect("verifier"),
    )
}

/// The keys.json "svc" signing key (the server's response key).
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

/// Fixture verifier, the keys.json "svc" server key, `profile`, and an inner
/// service that records what it received and answers a fixed JSON body.
fn new_harness(profile: Profile, seen: Arc<Seen>) -> JackService<InnerBox> {
    let state = MemoryState::new();
    seed_registry(&state);
    let layer = JackLayer::new(HandlerConfig {
        verifier: build_verifier(state),
        server_key: server_signing_key(),
        max_body_bytes: 0,
        max_response_bytes: 0,
    })
    .with_profile(profile);
    layer.layer(tower::util::BoxCloneService::new(tower::service_fn(
        move |req: http::Request<Full<Bytes>>| {
            let seen = Arc::clone(&seen);
            async move {
                let captured = req
                    .headers()
                    .iter()
                    .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                    .collect();
                seen.headers.lock().expect("headers mutex").push(captured);
                seen.calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, String>(
                    http::Response::builder()
                        .status(200)
                        .header("Content-Type", "application/json")
                        .body(Full::new(Bytes::from_static(INNER_OK_BODY)))
                        .expect("static response parts"),
                )
            }
        },
    )))
}

/// Sends `req` through the layered service.
async fn send(
    svc: &JackService<InnerBox>,
    req: http::Request<Full<Bytes>>,
) -> Result<http::Response<Full<Bytes>>, String> {
    svc.clone().oneshot(req).await
}

/// Response view: status, body bytes and Content-Type.
struct GotResponse {
    status: u16,
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
    let (_, body) = res.into_parts();
    let body = http_body_util::BodyExt::collect(body)
        .await
        .expect("Full body always collects")
        .to_bytes();
    GotResponse {
        status,
        body,
        content_type,
    }
}

/// A modern-era forwarded `svc.status` call: the body and the three mirror
/// headers agree on `2026-07-28`.
const MODERN_STATUS_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"svc.status","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#;
/// The same call without the mirror `_meta` (0.1.x shape).
const LEGACY_STATUS_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"svc.status","arguments":{}}}"#;
/// The canned inner answer.
const INNER_OK_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;

/// The three mirror headers of a modern `svc.status` call, plus Content-Type.
fn mirror_headers() -> Vec<(&'static str, HeaderValue)> {
    vec![
        (
            "MCP-Protocol-Version",
            HeaderValue::from_static("2026-07-28"),
        ),
        ("Mcp-Method", HeaderValue::from_static("tools/call")),
        ("Mcp-Name", HeaderValue::from_static("svc.status")),
        ("Content-Type", HeaderValue::from_static("application/json")),
    ]
}

/// Spec 04 `S8`/`S9`: the inner service receives the surviving header entries
/// — opaque value bytes untouched, every value of a repeated name in its
/// received order — minus exactly the session headers. Only the per-name
/// guarantees are asserted here: neither the cross-name interleaving nor the
/// field-name casing survives an `http::HeaderMap`, and the forwarding
/// contract does not claim them.
#[tokio::test]
async fn forwards_original_value_bytes_and_repetitions() {
    let seen = Arc::new(Seen::default());
    let svc = new_harness(Profile::Modern, Arc::clone(&seen));
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "POST", "/mcp", MODERN_STATUS_BODY);

    let opaque = HeaderValue::from_bytes(b"\x80\xff").expect("obs-text is a valid header value");
    let mut headers = mirror_headers();
    headers.push(("X-Opaque", opaque));
    headers.push(("X-Repeat", HeaderValue::from_static("one")));
    headers.push(("X-Repeat", HeaderValue::from_static("two")));
    headers.push(("Mcp-Session-Id", HeaderValue::from_static("session-1")));
    headers.push(("Last-Event-ID", HeaderValue::from_static("resume-7")));

    let got = inspect(
        send(&svc, build_request(&signed, &headers, MODERN_STATUS_BODY))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200, "the modern-era request forwards");

    let forwarded = seen.last_headers();
    assert_eq!(
        values(&forwarded, "x-opaque"),
        vec![b"\x80\xff".to_vec()],
        "opaque header bytes reach the wrapped service unchanged"
    );
    assert_eq!(
        values(&forwarded, "x-repeat"),
        vec![b"one".to_vec(), b"two".to_vec()],
        "every value of a repeated name is kept, in its received order"
    );
    assert!(
        values(&forwarded, "mcp-session-id").is_empty(),
        "S8 removes Mcp-Session-Id"
    );
    assert!(
        values(&forwarded, "last-event-id").is_empty(),
        "S8 removes Last-Event-ID"
    );
}

/// The forwarding guarantee is per name, not across names. `X-A: one`,
/// `X-B: two`, `X-A: three` arrives as three values, but the rebuilt
/// `http::HeaderMap` groups the values of one name: the forwarded list holds
/// the two `x-a` values adjacently, so the received `x-a, x-b, x-a`
/// interleaving is NOT reproduced — exactly the limit the module documentation
/// of `server/http/forward.rs` declares. Header-name casing is not observable
/// either, since `HeaderName` lowercases every name before the test sees it.
#[tokio::test]
async fn forwarding_preserves_values_and_per_name_order_only() {
    let seen = Arc::new(Seen::default());
    let svc = new_harness(Profile::Modern, Arc::clone(&seen));
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "POST", "/mcp", MODERN_STATUS_BODY);

    let mut headers = mirror_headers();
    headers.push(("X-A", HeaderValue::from_static("one")));
    headers.push(("X-B", HeaderValue::from_static("two")));
    headers.push(("X-A", HeaderValue::from_static("three")));

    let got = inspect(
        send(&svc, build_request(&signed, &headers, MODERN_STATUS_BODY))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200, "the modern-era request forwards");

    let forwarded = seen.last_headers();
    assert_eq!(
        values(&forwarded, "x-a"),
        vec![b"one".to_vec(), b"three".to_vec()],
        "the values of one name keep their received order"
    );
    assert_eq!(
        values(&forwarded, "x-b"),
        vec![b"two".to_vec()],
        "every other name is forwarded unchanged"
    );

    // `http::HeaderMap` groups its values by name, so the two `x-a` values are
    // necessarily adjacent in the forwarded list. This grouping is the map
    // invariant, not a forwarding choice, and it is precisely why the module
    // claims no global (cross-name) order.
    let x_a_positions: Vec<usize> = forwarded
        .iter()
        .enumerate()
        .filter_map(|(i, (name, _))| (name == "x-a").then_some(i))
        .collect();
    assert_eq!(x_a_positions.len(), 2, "both `x-a` values are forwarded");
    assert_eq!(
        x_a_positions[1],
        x_a_positions[0] + 1,
        "values are grouped by name, so the two `x-a` values are adjacent"
    );
    assert!(
        !forwarded
            .windows(3)
            .any(|w| w[0].0 == "x-a" && w[1].0 == "x-b" && w[2].0 == "x-a"),
        "the received cross-name interleaving x-a, x-b, x-a is not reproduced"
    );
}

/// The legacy profile forwards the received map untouched (0.1.x): nothing is
/// filtered and opaque bytes survive there too.
#[tokio::test]
async fn legacy_profile_forwards_the_map_untouched() {
    let seen = Arc::new(Seen::default());
    let svc = new_harness(Profile::Legacy, Arc::clone(&seen));
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "POST", "/mcp", LEGACY_STATUS_BODY);

    let opaque = HeaderValue::from_bytes(b"\x80\xff").expect("obs-text is a valid header value");
    let headers = [
        ("Content-Type", HeaderValue::from_static("application/json")),
        ("X-Opaque", opaque),
        ("Mcp-Session-Id", HeaderValue::from_static("session-1")),
        ("Last-Event-ID", HeaderValue::from_static("resume-7")),
    ];
    let got = inspect(
        send(&svc, build_request(&signed, &headers, LEGACY_STATUS_BODY))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);

    let forwarded = seen.last_headers();
    assert_eq!(values(&forwarded, "x-opaque"), vec![b"\x80\xff".to_vec()]);
    assert_eq!(
        values(&forwarded, "mcp-session-id"),
        vec![b"session-1".to_vec()],
        "the legacy path drops no header"
    );
    assert_eq!(
        values(&forwarded, "last-event-id"),
        vec![b"resume-7".to_vec()],
        "the legacy path drops no header"
    );
}

/// The same `tools/call` body without a modern signal renders identically
/// under `Profile::Legacy` and `Profile::Both`; a modern signal switches the
/// message to the vector text.
#[tokio::test]
async fn tools_call_message_follows_request_era() {
    let alice = harness::signer_by_name("alice");
    // A `tools/call` without a string `params.name`, and no modern signal.
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":7}}"#;
    let signed = signed_request(&alice, "POST", "/mcp", body);
    let only_content_type = [("Content-Type", HeaderValue::from_static("application/json"))];

    let legacy_seen = Arc::new(Seen::default());
    let legacy = new_harness(Profile::Legacy, legacy_seen);
    let got_legacy = inspect(
        send(&legacy, build_request(&signed, &only_content_type, body))
            .await
            .expect("no inner error"),
    )
    .await;

    let both_seen = Arc::new(Seen::default());
    let both = new_harness(Profile::Both, Arc::clone(&both_seen));
    let got_both = inspect(
        send(&both, build_request(&signed, &only_content_type, body))
            .await
            .expect("no inner error"),
    )
    .await;

    assert_eq!(got_legacy.status, 400);
    assert_eq!(got_both.status, 400);
    assert_eq!(
        got_legacy.body, got_both.body,
        "a legacy-era request under Both keeps the 0.1.x bytes"
    );
    assert_eq!(
        String::from_utf8_lossy(&got_legacy.body),
        r#"{"error":{"code":"invalid_request","message":"the body is not an acceptable JSON-RPC object"}}"#
    );
    assert_eq!(got_both.content_type.as_deref(), Some("application/json"));
    assert_eq!(both_seen.calls(), 0, "the refusal never forwards");

    // The same body with a modern signal (`MCP-Protocol-Version` + `_meta`)
    // is a modern-era request, so the fixed vector message applies.
    let modern_body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":7,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#;
    let signed = signed_request(&alice, "POST", "/mcp", modern_body);
    let modern_headers = [
        (
            "MCP-Protocol-Version",
            HeaderValue::from_static("2026-07-28"),
        ),
        ("Content-Type", HeaderValue::from_static("application/json")),
    ];
    let modern_seen = Arc::new(Seen::default());
    let modern = new_harness(Profile::Both, Arc::clone(&modern_seen));
    let got_modern = inspect(
        send(
            &modern,
            build_request(&signed, &modern_headers, modern_body),
        )
        .await
        .expect("no inner error"),
    )
    .await;

    assert_eq!(got_modern.status, 400);
    let value: serde_json::Value =
        serde_json::from_slice(&got_modern.body).expect("the refusal body is JSON");
    assert_eq!(
        value["error"]["message"].as_str(),
        Some("tools/call requires a string params.name")
    );
    assert_eq!(modern_seen.calls(), 0, "the refusal never forwards");
}
