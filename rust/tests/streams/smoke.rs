//! End-to-end wiring of [`StreamLayer`]: a `Jack-Accept: s1` modern request
//! opens a signed 2.1 stream whose frames verify with the public stream
//! verifier, while a request without the opt-in — and every legacy deployment
//! — keeps the byte-identical signed 501.
#![cfg(feature = "http")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use mcp_jack::user_key::ServerSigningKey;
use tower::util::BoxCloneService;
use tower::{Layer, ServiceExt};

use crate::common::fixtures;
use crate::common::harness::{self, FIXTURE_AUD, FIXTURE_NOW};

use mcp_jack::client::auth::{sign_request, SignedRequest};
use mcp_jack::client::signer::InMemorySigner;
use mcp_jack::encoding::key_id;
use mcp_jack::server::http::{
    StreamBody, StreamCancellation, StreamHeartbeat, StreamLayer, StreamLayerBuilder,
};
use mcp_jack::server::modern::Profile;
use mcp_jack::server::native::{Native, NativeOptions};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::state::{MemoryState, RegistryEntry, StateStore};
use mcp_jack::server::stream::StreamOptions;
use mcp_jack::server::verify::{Clock, Verifier, VerifierBuilder};
use mcp_jack::stream::{StreamVerifier, StreamVerifierConfig};

/// Process-wide nonce source (the same idiom as the other HTTP harnesses).
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The opening `tools/call`, modern-era (`_meta` mirrors the protocol version).
const REQUEST_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"svc.status","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#;

/// Two ordinary handler messages.
const SSE_BODY: &[u8] = b"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/events/heartbeat\"}\n\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/events/heartbeat\"}\n\n";

/// The v1 501 of a handler that answered `text/event-stream` without an opt-in.
const STREAMING_501: &[u8] =
    br#"{"error":{"code":"streaming_unsupported","message":"streaming responses cannot be signed in v0.1"}}"#;

/// What the wrapped service observed in its request extensions.
#[derive(Default)]
struct Seen {
    calls: AtomicU64,
    heartbeat: Mutex<Option<u64>>,
    cancellation: Mutex<Option<bool>>,
    cancellation_token: Mutex<Option<StreamCancellation>>,
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

fn build_verifier(state: MemoryState, now: i64) -> Arc<Verifier> {
    let now_clock: Clock = Arc::new(move || now);
    Arc::new(
        VerifierBuilder::new(FIXTURE_AUD.to_string(), Arc::new(state))
            .nonces(Arc::new(NonceStore::new()))
            .audit(None)
            .native_tools(Some(Arc::new(Native::new(NativeOptions::default()))))
            .window_seconds(30)
            .now(now_clock)
            .try_build()
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

fn layer(profile: Profile, now: i64) -> StreamLayer {
    layer_with_options(profile, now, StreamOptions::default())
}

fn layer_with_options(profile: Profile, now: i64, streams: StreamOptions) -> StreamLayer {
    let state = MemoryState::new();
    seed_registry(&state);
    StreamLayerBuilder::new(build_verifier(state, now), server_signing_key())
        .streams(streams)
        .max_body_bytes(0)
        .max_response_bytes(0)
        .profile(profile)
        .build()
}

/// The boxed inner service behind the harness (S::Error = String).
type InnerBox =
    tower::util::BoxCloneService<http::Request<Full<Bytes>>, http::Response<Full<Bytes>>, String>;

/// The wrapped service: records the stream extensions and answers two SSE events.
fn inner(seen: Arc<Seen>) -> InnerBox {
    BoxCloneService::new(tower::service_fn(move |req: http::Request<Full<Bytes>>| {
        let seen = Arc::clone(&seen);
        async move {
            seen.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(heartbeat) = req.extensions().get::<StreamHeartbeat>() {
                *seen.heartbeat.lock().expect("heartbeat mutex") = Some(heartbeat.granted_ms);
            }
            if let Some(cancellation) = req.extensions().get::<StreamCancellation>() {
                *seen.cancellation.lock().expect("cancellation mutex") =
                    Some(cancellation.is_cancelled());
                *seen
                    .cancellation_token
                    .lock()
                    .expect("cancellation token mutex") = Some(cancellation.clone());
            }
            Ok::<_, String>(
                http::Response::builder()
                    .status(200)
                    .header("Content-Type", "text/event-stream")
                    .body(Full::new(Bytes::from_static(SSE_BODY)))
                    .expect("static response parts"),
            )
        }
    }))
}

fn signed_request(signer: &InMemorySigner, now: i64) -> SignedRequest {
    let n = NONCE_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    let mut nonce = [0u8; 16];
    nonce[8..].copy_from_slice(&n.to_be_bytes());
    sign_request(
        signer,
        FIXTURE_AUD,
        "POST",
        "/mcp",
        REQUEST_BODY,
        &nonce,
        now,
    )
    .unwrap_or_else(|e| panic!("sign_request: {e}"))
}

/// The mirror headers of a modern `svc.status` call; `accept` adds the 1.1 opt-in.
fn build_request(signed: &SignedRequest, accept: bool) -> http::Request<Full<Bytes>> {
    let mut builder = http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Jack-Auth", signed.header_value.as_str())
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "svc.status")
        .header("Content-Type", "application/json");
    if accept {
        builder = builder.header("Jack-Accept", "s1");
    }
    builder
        .body(Full::new(Bytes::from_static(REQUEST_BODY)))
        .expect("static request parts")
}

async fn body_bytes(body: StreamBody) -> Bytes {
    body.collect()
        .await
        .expect("channel body collects")
        .to_bytes()
}

/// 1.1, 2.1, 3.5 and 3.7: an opted-in modern request opens a signed stream
/// whose open header and three frames verify under the pinned `svc` key.
#[tokio::test]
async fn opted_in_modern_request_opens_a_verified_stream() {
    let now = FIXTURE_NOW;
    let seen = Arc::new(Seen::default());
    let service = layer(Profile::Modern, now).layer(inner(Arc::clone(&seen)));
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, now);

    let response = service
        .oneshot(build_request(&signed, true))
        .await
        .expect("no inner error");
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response
            .headers()
            .get("Content-Type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream"),
        "2.1 success shape"
    );
    let auth: Vec<&str> = response
        .headers()
        .get_all("Jack-Auth")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    assert_eq!(auth.len(), 1, "exactly one open header");
    assert!(
        auth[0].starts_with("s1 "),
        "open header carries the s1 scheme"
    );

    let status = response.status().as_u16();
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().expect("ASCII header value").to_owned(),
            )
        })
        .collect();
    let body = body_bytes(response.into_body()).await;

    let public = server_signing_key().verifying_key().to_bytes();
    let mut config = StreamVerifierConfig::pinned(key_id(&public), public, signed.auth.sig.clone());
    config.now = Arc::new(move || now);
    let mut verifier = StreamVerifier::new(config);
    verifier
        .open(status, &headers)
        .expect("the open header verifies");
    let step = verifier.push(&body, 0);
    assert!(step.terminal.is_none(), "no terminal failure");
    assert_eq!(step.messages.len(), 2, "two handler messages");
    let end = verifier.finish(None);
    assert!(end.terminal.is_none(), "the end frame completed the stream");
    assert_eq!(
        verifier.frames_verified(),
        3,
        "two messages plus the end frame"
    );

    assert_eq!(
        *seen.heartbeat.lock().expect("heartbeat mutex"),
        Some(15_000),
        "3.5 grant with the default window"
    );
    assert_eq!(
        *seen.cancellation.lock().expect("cancellation mutex"),
        Some(false),
        "the handler sees a live (uncancelled) stream context"
    );
}

/// 3.8: a notification at a full stream limit reaches the handler and gets
/// 202, without taking a slot or turning the handler's SSE answer into a stream.
#[tokio::test]
async fn notification_at_capacity_gets_202_without_stream_slot() {
    const NOTIFICATION: &[u8] = br#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#;
    let now = FIXTURE_NOW;
    let seen = Arc::new(Seen::default());
    let options = StreamOptions {
        max_concurrent_streams: 1,
        ..StreamOptions::default()
    };
    let layer = layer_with_options(Profile::Modern, now, options);
    let registry = layer.registry();
    let held = registry
        .try_acquire("alice", 1)
        .expect("occupy alice's only stream slot");
    let service = layer.layer(inner(Arc::clone(&seen)));
    let alice = harness::signer_by_name("alice");
    let n = NONCE_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    let mut nonce = [0u8; 16];
    nonce[8..].copy_from_slice(&n.to_be_bytes());
    let signed = sign_request(
        &alice,
        FIXTURE_AUD,
        "POST",
        "/mcp",
        NOTIFICATION,
        &nonce,
        now,
    )
    .unwrap_or_else(|e| panic!("sign_request: {e}"));
    let request = http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Jack-Auth", signed.header_value.as_str())
        .header("Jack-Accept", "s1")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "notifications/initialized")
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from_static(NOTIFICATION)))
        .expect("notification request");

    let response = service.oneshot(request).await.expect("no inner error");
    assert_eq!(response.status().as_u16(), 202);
    assert_eq!(
        response
            .headers()
            .get("Content-Type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let auth = response
        .headers()
        .get("Jack-Auth")
        .and_then(|value| value.to_str().ok())
        .expect("202 is signed");
    assert!(auth.starts_with("v1 "), "notification has no stream opener");
    assert!(body_bytes(response.into_body()).await.is_empty());
    assert_eq!(
        seen.calls.load(Ordering::SeqCst),
        1,
        "handler ran despite capacity"
    );
    assert_eq!(registry.active("alice"), 1, "notification took no slot");
    drop(held);
}

#[tokio::test]
async fn default_builder_keeps_signed_501_for_opted_in_stream_response() {
    let now = FIXTURE_NOW;
    let state = MemoryState::new();
    seed_registry(&state);
    let layer = StreamLayerBuilder::new(build_verifier(state, now), server_signing_key()).build();
    let seen = Arc::new(Seen::default());
    let service = layer.layer(inner(Arc::clone(&seen)));
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, now);

    let response = service
        .oneshot(build_request(&signed, true))
        .await
        .expect("no inner error");
    assert_eq!(response.status().as_u16(), 501);
    let auth = response
        .headers()
        .get("Jack-Auth")
        .and_then(|value| value.to_str().ok())
        .expect("the 501 is signed");
    assert!(auth.starts_with("v1 "), "legacy refusal, not stream open");
    assert_eq!(
        body_bytes(response.into_body()).await.as_ref(),
        STREAMING_501
    );
    assert_eq!(seen.calls.load(Ordering::SeqCst), 1);
    assert_eq!(*seen.heartbeat.lock().expect("heartbeat mutex"), None);
    assert_eq!(*seen.cancellation.lock().expect("cancellation mutex"), None);
}

#[tokio::test]
async fn default_builder_uses_one_mib_http_body_limits() {
    let now = FIXTURE_NOW;
    let state = MemoryState::new();
    seed_registry(&state);
    let layer = StreamLayerBuilder::new(build_verifier(state, now), server_signing_key()).build();
    let seen = Arc::new(Seen::default());
    let service = layer.layer(inner(Arc::clone(&seen)));
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, now);
    let mut request = build_request(&signed, false);
    *request.body_mut() = Full::new(Bytes::from(vec![b'x'; (1 << 20) + 1]));

    let response = service
        .oneshot(request)
        .await
        .expect("body overflow is an HTTP response");
    assert_eq!(response.status().as_u16(), 413);
    assert_eq!(
        seen.calls.load(Ordering::SeqCst),
        0,
        "oversized body is rejected before dispatch"
    );
}

#[tokio::test]
async fn default_builder_uses_one_mib_response_limit() {
    let now = FIXTURE_NOW;
    let state = MemoryState::new();
    seed_registry(&state);
    let layer = StreamLayerBuilder::new(build_verifier(state, now), server_signing_key()).build();
    let large_response = BoxCloneService::new(tower::service_fn(
        |_req: http::Request<Full<Bytes>>| async move {
            Ok::<_, String>(
                http::Response::builder()
                    .status(200)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(vec![b'x'; (1 << 20) + 1])))
                    .expect("large response parts"),
            )
        },
    ));
    let service = layer.layer(large_response);
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, now);

    let response = service
        .oneshot(build_request(&signed, false))
        .await
        .expect("response overflow is an HTTP response");
    assert_eq!(response.status().as_u16(), 502);
    let auth = response
        .headers()
        .get("Jack-Auth")
        .and_then(|value| value.to_str().ok())
        .expect("the response-limit refusal is signed");
    assert!(auth.starts_with("v1 "));
}

#[tokio::test]
async fn request_without_opt_in_keeps_the_501() {
    let now = FIXTURE_NOW;
    let seen = Arc::new(Seen::default());
    let service = layer(Profile::Modern, now).layer(inner(Arc::clone(&seen)));
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, now);

    let response = service
        .oneshot(build_request(&signed, false))
        .await
        .expect("no inner error");
    assert_eq!(response.status().as_u16(), 501);
    let auth = response
        .headers()
        .get("Jack-Auth")
        .and_then(|value| value.to_str().ok())
        .expect("the 501 is signed");
    assert!(auth.starts_with("v1 "), "signed v1 refusal");
    let body = body_bytes(response.into_body()).await;
    assert_eq!(body.as_ref(), STREAMING_501, "byte-identical 501 body");
    assert_eq!(seen.calls.load(Ordering::SeqCst), 1);
}

/// 2.3: authentication reserves the nonce before opening the response stream.
#[tokio::test]
async fn replay_is_refused_after_stream_open_without_reading_first_body() {
    let now = FIXTURE_NOW;
    let seen = Arc::new(Seen::default());
    let mut service = layer(Profile::Modern, now).layer(inner(Arc::clone(&seen)));
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, now);

    let first = (&mut service)
        .oneshot(build_request(&signed, true))
        .await
        .expect("first request reaches the handler");
    assert_eq!(first.status().as_u16(), 200);
    let auth = first
        .headers()
        .get("Jack-Auth")
        .and_then(|value| value.to_str().ok())
        .expect("stream open is authenticated");
    assert!(auth.starts_with("s1 "), "stream open uses s1");
    drop(first);

    let replay = (&mut service)
        .oneshot(build_request(&signed, true))
        .await
        .expect("replay refusal is an HTTP response");
    assert_eq!(replay.status().as_u16(), 401);
    // A replayed_nonce refusal is in the unsigned 401 family of spec 01 section 5.
    assert!(
        replay.headers().get("Jack-Auth").is_none(),
        "replay refusal is unsigned"
    );
    let body = body_bytes(replay.into_body()).await;
    let value: serde_json::Value = serde_json::from_slice(&body).expect("JSON refusal body");
    assert_eq!(value["error"]["code"], "replayed_nonce");
    assert_eq!(seen.calls.load(Ordering::SeqCst), 1, "handler invoked once");
}

/// 3.7: dropping an open HTTP response cancels the handler's shared stream token.
#[tokio::test]
async fn dropping_open_stream_cancels_handler_token() {
    let now = FIXTURE_NOW;
    let seen = Arc::new(Seen::default());
    let (mut sender, body) = http_body_util::Channel::<Bytes>::new(1);
    sender
        .send_data(Bytes::from_static(b"data: one\n\n"))
        .await
        .expect("queue first event");
    // Keep the sender alive so the source body remains pending after its first event.
    let body = Arc::new(Mutex::new(Some(body)));
    let handler_body = Arc::clone(&body);
    let handler_seen = Arc::clone(&seen);
    let handler =
        BoxCloneService::new(tower::service_fn(move |req: http::Request<Full<Bytes>>| {
            let seen = Arc::clone(&handler_seen);
            let body = handler_body
                .lock()
                .expect("handler body mutex")
                .take()
                .expect("single streaming request");
            async move {
                seen.calls.fetch_add(1, Ordering::SeqCst);
                if let Some(cancellation) = req.extensions().get::<StreamCancellation>() {
                    *seen.cancellation.lock().expect("cancellation mutex") =
                        Some(cancellation.is_cancelled());
                    *seen
                        .cancellation_token
                        .lock()
                        .expect("cancellation token mutex") = Some(cancellation.clone());
                }
                Ok::<_, String>(
                    http::Response::builder()
                        .status(200)
                        .header("Content-Type", "text/event-stream")
                        .body(body)
                        .expect("stream response"),
                )
            }
        }));
    let service = layer(Profile::Modern, now).layer(handler);
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, now);

    let response = service
        .oneshot(build_request(&signed, true))
        .await
        .expect("open response");
    assert_eq!(response.status().as_u16(), 200);
    assert!(response.headers().get("Jack-Auth").is_some());
    drop(response);

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if seen
                .cancellation_token
                .lock()
                .expect("cancellation token mutex")
                .as_ref()
                .is_some_and(StreamCancellation::is_cancelled)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pump observes dropped response");
    assert!(seen
        .cancellation_token
        .lock()
        .expect("cancellation token mutex")
        .as_ref()
        .expect("handler retained cancellation token")
        .is_cancelled());
    drop(sender);
}

#[tokio::test]
async fn legacy_profile_keeps_the_501() {
    let now = FIXTURE_NOW;
    let seen = Arc::new(Seen::default());
    let service = layer(Profile::Legacy, now).layer(inner(Arc::clone(&seen)));
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, now);

    let response = service
        .oneshot(build_request(&signed, true))
        .await
        .expect("no inner error");
    assert_eq!(response.status().as_u16(), 501);
    let body = body_bytes(response.into_body()).await;
    assert_eq!(body.as_ref(), STREAMING_501, "byte-identical 501 body");
    assert_eq!(seen.calls.load(Ordering::SeqCst), 1);
}
