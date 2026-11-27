//! `C6` projection through the real `Client`, against a REAL `Modern`-profile
//! [`JackLayer`] looped back through a stub [`Transport`].
//!
//! `refresh_tool_catalog()` runs the `C10` resync over the client's own
//! transport, so the next modern `tools/call` carries the `Mcp-Param-Region`
//! header of its annotated `region` argument. `reset_era()` (`C9`) drops that
//! catalog with the rest of the modern state, so the next call re-probes with
//! `server/discover` and projects nothing — a projection belongs to the era
//! that produced it (`C8`).
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

/// The wrapped modern upstream: it answers the probe, the two catalogs and the
/// weather call itself, so the layer only has to verify, classify and forward.
fn modern_upstream() -> InnerBox {
    tower::util::BoxCloneService::new(tower::service_fn(
        |req: http::Request<Full<Bytes>>| async move {
            let (_, body) = req.into_parts();
            let bytes = BodyExt::collect(body)
                .await
                .expect("Full body collects")
                .to_bytes();
            let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            let id = parsed.get("id").and_then(Value::as_i64).unwrap_or(0);
            let reply = match parsed["method"].as_str().unwrap_or("") {
                "server/discover" => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": "2026-07-28",
                        "supportedVersions": ["2026-07-28"],
                        "capabilities": {},
                        "serverInfo": {"name": "modern-upstream", "version": "1"},
                    },
                }),
                "tools/list" => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {"tools": [{
                        "name": "get_weather",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "region": {"type": "string", "x-mcp-header": "Region"},
                            },
                        },
                    }]},
                }),
                "events/list" => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {"events": []},
                }),
                "tools/call" => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{"type": "text", "text": "sunny"}],
                        "isError": false,
                        "structuredContent": {"forecast": "sunny"},
                    },
                }),
                other => panic!("the modern upstream saw an unexpected method {other}"),
            };
            Ok::<_, String>(
                http::Response::builder()
                    .status(200)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(reply.to_string())))
                    .expect("response parts"),
            )
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

/// An `Auto` client wired to a real `Modern` profile layer through the loopback.
fn modern_client(runtime: tokio::runtime::Runtime) -> (Client, Arc<LoopbackTransport>) {
    let layer = JackLayer::new(handler_config()).with_profile(Profile::Modern);
    let transport = Arc::new(LoopbackTransport {
        runtime,
        service: Mutex::new(layer.layer(modern_upstream())),
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
fn a_refreshed_tool_catalog_projects_and_reset_era_drops_it() {
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let (client, transport) = modern_client(runtime);

    // The probe resolves the modern era; the catalog is still empty here, so
    // this call projects nothing.
    let first = client
        .call_tool_raw_str("get_weather", Some(r#"{"region":"eu"}"#))
        .expect("the modern call");
    assert_eq!(first, json!({"forecast": "sunny"}));
    assert_eq!(transport.methods(), ["server/discover", "tools/call"]);

    // The `C10` resync fills the catalog over the client's own transport.
    client.refresh_tool_catalog().expect("tools/list resync");
    assert_eq!(
        transport.methods(),
        ["server/discover", "tools/call", "tools/list"]
    );

    let structured = client
        .call_tool_raw_str("get_weather", Some(r#"{"region":"eu"}"#))
        .expect("the projected call");
    assert_eq!(structured, json!({"forecast": "sunny"}));

    let seen = transport.seen();
    let projected = seen.last().expect("the projected tools/call");
    assert_eq!(projected.method, "tools/call");
    assert_eq!(
        projected.header("Mcp-Param-Region"),
        Some("eu"),
        "the catalog projects the annotated argument"
    );
    // The mirror headers still come first and the projection follows them.
    assert_eq!(projected.header("Mcp-Method"), Some("tools/call"));
    assert_eq!(projected.header("Mcp-Name"), Some("get_weather"));
    let names: Vec<&str> = projected
        .headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    let region = names
        .iter()
        .position(|name| *name == "Mcp-Param-Region")
        .expect("projected header is present");
    assert!(
        names[..region].contains(&"Mcp-Name"),
        "the mirrors precede the projection: {names:?}"
    );

    // `reset_era` (`C9` + `C8`) drops the catalog: the next call re-probes and
    // its `tools/call` carries no projected header at all.
    client.reset_era();
    let after = client
        .call_tool_raw_str("get_weather", Some(r#"{"region":"eu"}"#))
        .expect("the call after the reset");
    assert_eq!(after, json!({"forecast": "sunny"}));
    assert_eq!(
        transport.methods(),
        [
            "server/discover",
            "tools/call",
            "tools/list",
            "tools/call",
            "server/discover",
            "tools/call"
        ],
        "the reset forces a new probe"
    );

    let seen = transport.seen();
    let reprobe = &seen[4];
    assert_eq!(reprobe.method, "server/discover");
    let unprojected = seen.last().expect("the tools/call after the reset");
    assert_eq!(unprojected.method, "tools/call");
    assert_eq!(
        unprojected.header("Mcp-Param-Region"),
        None,
        "a catalog dropped by reset_era must not project"
    );
    assert_eq!(unprojected.header("Mcp-Method"), Some("tools/call"));
    assert_eq!(
        unprojected.json()["params"]["arguments"],
        json!({"region": "eu"}),
        "the arguments themselves are unchanged"
    );
}
