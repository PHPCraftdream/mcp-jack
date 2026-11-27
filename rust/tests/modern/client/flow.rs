//! The `C9` era flow against a REAL `Both`-profile [`JackLayer`] of this crate,
//! looped back through a stub [`Transport`].
//!
//! The client probes with a modern `server/discover`; the layer forwards it to
//! the wrapped service, which answers `405`, so the verified verdict is
//! `fallback_initialize`. The client then runs the legacy handshake (`initialize`
//! → negotiated version → `notifications/initialized`), carries the version and
//! the `Mcp-Session-Id` the layer forwarded back, and calls `jack.whoami`,
//! which the verifier answers natively in the legacy era.

#![cfg(feature = "http")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use serde_json::{json, Value};
use tower::{Layer, ServiceExt};

use mcp_jack::client::url::request_target;
use mcp_jack::client::{
    Client, ClientEra, Config, HttpRequest, HttpResponse, Transport, TransportError,
};
use mcp_jack::server::http::{HandlerConfig, JackLayer, JackService};
use mcp_jack::server::modern::Profile;
use mcp_jack::server::native::{Native, NativeOptions};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::state::{MemoryState, RegistryEntry, StateStore};
use mcp_jack::server::verify::{Clock, Config as VerifyConfig, Verifier};

use crate::server::common::fixtures;
use crate::server::common::harness::{self, FIXTURE_AUD, FIXTURE_NOW};

/// The boxed inner service behind the harness (S::Error = String).
type InnerBox =
    tower::util::BoxCloneService<http::Request<Full<Bytes>>, http::Response<Full<Bytes>>, String>;

/// Process-wide nonce source: the last 8 bytes encode a never-repeating
/// counter, so the verifier never sees a replayed nonce.
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One request the loopback saw, for assertions.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Seen {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).expect("request body is JSON")
    }

    fn id(&self) -> Option<i64> {
        self.json().get("id").and_then(Value::as_i64)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A synchronous [`Transport`] that drives a real [`JackService`] on a Tokio
/// runtime: the client signs, the layer verifies, signs its answer and the
/// client verifies it back.
struct LoopbackTransport {
    runtime: tokio::runtime::Runtime,
    service: Mutex<JackService<InnerBox>>,
    seen: Mutex<Vec<Seen>>,
}

impl LoopbackTransport {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("seen mutex").clone()
    }

    fn methods(&self) -> Vec<String> {
        self.seen().into_iter().map(|seen| seen.method).collect()
    }
}

impl Transport for LoopbackTransport {
    fn round_trip(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        let target = request_target(&req.url).map_err(|e| TransportError::Client(e.to_string()))?;
        let body = String::from_utf8(req.body.clone()).expect("utf-8 request body");
        let parsed: Value = serde_json::from_str(&body).expect("request body is JSON");
        self.seen.lock().expect("seen mutex").push(Seen {
            method: parsed["method"].as_str().unwrap_or("").to_owned(),
            headers: req.headers.clone(),
            body,
        });

        let mut builder = http::Request::builder()
            .method(req.method.as_str())
            .uri(target);
        for (name, value) in &req.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let request = builder
            .body(Full::new(Bytes::from(req.body)))
            .map_err(|e| TransportError::Client(format!("loopback request: {e}")))?;

        let service = self.service.lock().expect("service mutex").clone();
        let response = self
            .runtime
            .block_on(service.oneshot(request))
            .map_err(TransportError::Transport)?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().unwrap_or("").to_owned(),
                )
            })
            .collect();
        let body = self
            .runtime
            .block_on(BodyExt::collect(response.into_body()))
            .expect("Full body collects")
            .to_bytes()
            .to_vec();
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
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

/// The keys.json "svc" signing key (the layer's response key).
fn server_signing_key() -> mcp_jack::user_key::ServerSigningKey {
    let keys = fixtures::load_keys().expect("load keys.json");
    let svc = keys
        .keys
        .iter()
        .find(|k| k.name == "svc")
        .unwrap_or_else(|| panic!("keys.json has no key named svc"));
    let seed: [u8; 32] = harness::hex_bytes(&svc.seed_hex)
        .try_into()
        .expect("svc seed is 32 bytes");
    mcp_jack::user_key::ServerSigningKey::from_bytes(&seed)
}

/// The wrapped service: a legacy upstream that refuses `server/discover` with
/// `405`, performs the 2025-11-25 handshake and assigns a session id.
fn inner_service() -> InnerBox {
    tower::util::BoxCloneService::new(tower::service_fn(
        |req: http::Request<Full<Bytes>>| async move {
            let (_, body) = req.into_parts();
            let bytes = BodyExt::collect(body)
                .await
                .expect("Full body collects")
                .to_bytes();
            let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            let id = parsed.get("id").and_then(Value::as_i64);
            match parsed["method"].as_str().unwrap_or("") {
                "server/discover" => Ok::<_, String>(
                    http::Response::builder()
                        .status(405)
                        .header("Content-Type", "application/json")
                        .body(Full::new(Bytes::from_static(
                            br#"{"error":{"code":"invalid_request","message":"method not allowed"}}"#,
                        )))
                        .expect("static response parts"),
                ),
                "initialize" => {
                    let body = format!(
                        r#"{{"jsonrpc":"2.0","id":{},"result":{{"protocolVersion":"2025-11-25","capabilities":{{}},"serverInfo":{{"name":"legacy-upstream","version":"1"}}}}}}"#,
                        id.unwrap_or(0)
                    );
                    Ok(http::Response::builder()
                        .status(200)
                        .header("Content-Type", "application/json")
                        .header("Mcp-Session-Id", "sess-both")
                        .body(Full::new(Bytes::from(body)))
                        .expect("response parts"))
                }
                "notifications/initialized" => Ok(http::Response::builder()
                    .status(202)
                    .body(Full::new(Bytes::new()))
                    .expect("response parts")),
                other => panic!("the legacy upstream saw an unexpected method {other}"),
            }
        },
    ))
}

fn handler_config() -> HandlerConfig {
    let state = MemoryState::new();
    seed_registry(&state);
    let now: Clock = Arc::new(move || FIXTURE_NOW);
    let verifier = Arc::new(
        Verifier::new(VerifyConfig {
            aud: FIXTURE_AUD.to_string(),
            state: Arc::new(state),
            nonces: Arc::new(NonceStore::new()),
            audit: None,
            native: Some(Arc::new(Native::new(NativeOptions::default()))),
            window_seconds: 30,
            now,
        })
        .expect("verifier"),
    );
    HandlerConfig {
        verifier,
        server_key: server_signing_key(),
        max_body_bytes: 0,
        max_response_bytes: 0,
    }
}

/// An `Auto` client wired to a real `Both` profile layer through the loopback.
fn both_client(runtime: tokio::runtime::Runtime) -> (Client, Arc<LoopbackTransport>) {
    let layer = JackLayer::new(handler_config()).with_profile(Profile::Both);
    let transport = Arc::new(LoopbackTransport {
        runtime,
        service: Mutex::new(layer.layer(inner_service())),
        seen: Mutex::new(Vec::new()),
    });
    let nonce: mcp_jack::client::NonceSource = Arc::new(|| {
        let n = NONCE_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
        let mut nonce = vec![0u8; 16];
        nonce[8..].copy_from_slice(&n.to_be_bytes());
        Ok(nonce)
    });
    let now: Clock = Arc::new(move || FIXTURE_NOW);
    let client = Client::new(Config {
        base_url: format!("{FIXTURE_AUD}/mcp"),
        aud: FIXTURE_AUD.to_string(),
        signer: Arc::new(harness::signer_by_name("alice")),
        server_key: *server_signing_key().verifying_key().as_bytes(),
        transport: Arc::clone(&transport) as Arc<dyn Transport>,
        now: Some(now),
        nonce: Some(nonce),
        window_seconds: 30,
    })
    .expect("valid config")
    .with_era(ClientEra::Auto);
    (client, transport)
}

#[test]
fn auto_fallback_against_a_real_both_profile_layer() {
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let (client, transport) = both_client(runtime);

    let structured = client
        .call_tool_raw("jack.whoami", None)
        .expect("the fallback answers the native call");
    assert_eq!(structured["name"], "alice");
    assert_eq!(structured["admin"], false);

    assert_eq!(
        transport.methods(),
        [
            "server/discover",
            "initialize",
            "notifications/initialized",
            "tools/call"
        ]
    );

    let seen = transport.seen();
    // The probe is modern; the layer's `S3` sees the header and the `_meta`.
    assert_eq!(seen[0].header("MCP-Protocol-Version"), Some("2026-07-28"));
    assert_eq!(seen[0].header("Mcp-Method"), Some("server/discover"));
    assert_eq!(
        seen[0].json()["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
        "2026-07-28"
    );

    // `initialize` is the 2025-11-25 lifecycle request: no version header and
    // no `_meta`.
    assert_eq!(seen[1].header("MCP-Protocol-Version"), None);
    assert_eq!(
        seen[1].json()["params"]["protocolVersion"],
        "2025-11-25",
        "the handshake asks for the version this client implements"
    );
    assert_eq!(seen[1].json()["params"]["capabilities"], json!({}));

    // The notification repeats the negotiated version and the session the layer
    // forwarded back from the inner service.
    assert_eq!(seen[2].id(), None, "a notification carries no id");
    assert_eq!(seen[2].header("MCP-Protocol-Version"), Some("2025-11-25"));
    assert_eq!(seen[2].header("Mcp-Session-Id"), Some("sess-both"));

    // The operation is the 0.1.x body, carrying both headers.
    assert_eq!(seen[3].header("MCP-Protocol-Version"), Some("2025-11-25"));
    assert_eq!(seen[3].header("Mcp-Session-Id"), Some("sess-both"));
    assert_eq!(
        seen[3].body,
        format!(
            r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{"name":"jack.whoami","arguments":{{}}}}}}"#,
            seen[3].id().expect("id")
        )
    );
    assert!(
        seen[3].json()["params"].get("_meta").is_none(),
        "the legacy operation carries no `_meta`"
    );

    // The decision is cached: a second call neither probes nor handshakes.
    client
        .call_tool_raw("jack.whoami", None)
        .expect("second legacy call");
    assert_eq!(
        transport.methods(),
        [
            "server/discover",
            "initialize",
            "notifications/initialized",
            "tools/call",
            "tools/call"
        ]
    );
}
