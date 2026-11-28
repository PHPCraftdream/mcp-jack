//! Standalone consumer smoke for the packaged mcp-jack Rust crate.
//!
//! CI harness: `expect(...)` with static labels is acceptable here; every
//! failure path prints only static labels, error classes/codes and Display
//! strings (none of which carry key material per the crate's own guarantees).
//! No unsafe; values of opaque product types are handled by inference, never
//! named. The optional `server-http` harness deps (ed25519-dalek, getrandom,
//! http, bytes, http-body-util, tower, futures) exist only to drive the real
//! packaged adapter and stay behind that feature; tokio (rt/net/time) is a
//! client-http-only harness dep for the deadline-bounded peer accept.

#![forbid(unsafe_code)]

#[cfg(feature = "client-http")]
use std::io::{Read, Write};
#[cfg(feature = "client-http")]
use std::net::TcpListener;
use std::sync::Arc;

#[cfg(target_os = "linux")]
mod rotation_store;

#[cfg(feature = "client-http")]
mod client_http;
#[cfg(feature = "server-http")]
mod server_layer;

use mcp_jack::auth_header::{ResponseAuth, format_response_auth};
use mcp_jack::client::error::ClientError as ClientErr;
use mcp_jack::client::rpc;
use mcp_jack::client::signer::Signer;
use mcp_jack::client::transport::{HttpRequest, HttpResponse, Transport, TransportError};
use mcp_jack::encoding::{encode_b64url, key_id};
#[cfg(feature = "server-http")]
use mcp_jack::server::identity::VerifiedIdentity;
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::state::{MemoryState, RegistryEntry, StateEdit, StateStore};
use mcp_jack::server::verify::{Request as VerifyRequest, Verifier, VerifierBuilder};
use mcp_jack::signing::response_signing_string;
use mcp_jack::user_key::{
    ClientSigningKey, ConnectionData, ExpectedIdentity, UserKeyError, client as uk_client,
    server as uk_server,
};

const AUD: &str = "https://svc.example.test";
/// Fixed verifier clock, shared by client and server sides of the loopback.
const NOW: i64 = 1_800_000_000;
/// The loopback base URL. Port 1 is never dialed: the LoopbackTransport only
/// uses the URL for the origin-form request target.
const BASE_URL: &str = "http://127.0.0.1:1/mcp";
#[cfg(feature = "server-http")]
const ADMIN_URL: &str = "http://127.0.0.1:1/mcp/admin";
const TOOL: &str = "consumer.echo";

fn check(cond: bool, label: &'static str) -> Result<(), String> {
    if cond { Ok(()) } else { Err(label.to_string()) }
}

fn expect_client_err<T>(
    result: Result<T, mcp_jack::client::error::ClientError>,
    label: &'static str,
) -> Result<mcp_jack::client::error::ClientError, String> {
    match result {
        Err(e) => Ok(e),
        Ok(_) => Err(label.to_string()),
    }
}

fn user_key_error(result: Result<Vec<u8>, UserKeyError>) -> Result<UserKeyError, String> {
    match result {
        Err(e) => Ok(e),
        Ok(_) => Err("expected a user key error, got success".to_string()),
    }
}

/// Server-side loopback: verifies the signed request with a real
/// [`Verifier`] and answers with a signed response, exactly like the
/// product's HTTP adapter minus sockets.
struct LoopbackTransport {
    verifier: Verifier,
    service_signer: Arc<ClientSigningKey>,
}

impl Transport for LoopbackTransport {
    fn round_trip(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        let target = mcp_jack::client::url::request_target(&req.url)
            .map_err(|e| TransportError::Client(e.to_string()))?;
        let auth_values: Vec<String> = req
            .header_values("jack-auth")
            .into_iter()
            .map(str::to_string)
            .collect();
        let verify_req = VerifyRequest {
            method: req.method.clone(),
            target,
            auth_values,
            body: req.body.clone(),
        };
        let result = self.verifier.verify(&verify_req);
        if !result.accepted {
            // Unsigned rejection; the client maps 401-without-header to
            // Unauthenticated and never parses the body.
            return Ok(HttpResponse {
                status: result.http_status,
                headers: vec![],
                body: vec![],
            });
        }
        // Exercise the verifier's immutable registry snapshot on an ordinary
        // MCP request; authorization beyond Jack's admin-only native tools is
        // owned by the consumer application.
        let identity = result.identity.as_ref().ok_or_else(|| {
            TransportError::Client("accepted request lacked verified identity".to_string())
        })?;
        if identity.kid() != result.kid || identity.name() != "consumer-smoke" || identity.admin() {
            return Err(TransportError::Client(
                "verifier returned an unexpected identity snapshot".to_string(),
            ));
        }
        // The rpc layer decodes the response `id` field but never compares it
        // to the request id (rust/src/client/rpc.rs: JsonRpcResponse.id is
        // decoded with #[allow(dead_code)] and unread on the happy path), so
        // a fixed id of 1 is safe in this harness.
        let body: &[u8] =
            br#"{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"echoed":true}}}"#;
        let kid = self.service_signer.kid().to_string();
        let msg = response_signing_string(200, &result.request_sig, &kid, NOW, body);
        let sig = self.service_signer.sign(msg.as_bytes());
        let header = format_response_auth(&ResponseAuth {
            kid,
            ts: NOW,
            sig: encode_b64url(&sig),
        });
        Ok(HttpResponse {
            status: 200,
            headers: vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Jack-Auth".to_string(), header),
            ],
            body: body.to_vec(),
        })
    }
}

/// Middleware that corrupts the request body before it reaches the server:
/// the request signature must then fail server-side verification.
struct BodyTamperTransport {
    inner: Arc<dyn Transport>,
}

impl Transport for BodyTamperTransport {
    fn round_trip(&self, mut req: HttpRequest) -> Result<HttpResponse, TransportError> {
        if let Some(first) = req.body.first_mut() {
            *first ^= 0x01;
        }
        self.inner.round_trip(req)
    }
}

fn register(state: &Arc<MemoryState>, entry: RegistryEntry) -> Result<(), String> {
    state
        .update(&mut |edit: &mut StateEdit| {
            edit.put_key(entry.clone());
            Ok(())
        })
        .map_err(|e| format!("state update rejected: {e}"))
}

fn verifier_for(state: Arc<MemoryState>) -> Result<Verifier, String> {
    VerifierBuilder::new(AUD, state)
        .nonces(Arc::new(NonceStore::new()))
        .audit(None)
        .native_tools(None)
        .window_seconds(0)
        .now(Arc::new(|| NOW))
        .try_build()
        .map_err(|e| format!("verifier config rejected: {e}"))
}

fn registry_entry(kid: String, public_key: String) -> RegistryEntry {
    RegistryEntry {
        kid,
        public_key,
        name: "consumer-smoke".to_string(),
        ..Default::default()
    }
}

fn section_a(key: &ClientSigningKey) -> Result<(), String> {
    eprintln!("smoke: core key lifecycle");
    let message = b"mcp-jack consumer core smoke message";
    let signature = key.sign(message);
    check(
        mcp_jack::ed25519::verify(&key.public_key(), message, &signature),
        "ed25519 verify must accept a correct signature",
    )?;
    check(
        !mcp_jack::ed25519::verify(&key.public_key(), b"a different message", &signature),
        "ed25519 verify must reject a changed message",
    )?;
    let mut flipped = signature;
    flipped[0] ^= 0x01;
    check(
        !mcp_jack::ed25519::verify(&key.public_key(), message, &flipped),
        "ed25519 verify must reject a bit-flipped signature",
    )?;
    check(
        !mcp_jack::ed25519::verify(&key.public_key(), message, &signature[..63]),
        "ed25519 verify must reject a truncated signature",
    )?;

    let envelope = uk_client::export_public_envelope(key)
        .map_err(|e| format!("export_public_envelope failed: {e}"))?;
    let server_key = uk_server::import_public_envelope(&envelope)
        .map_err(|e| format!("server import_public_envelope failed: {e}"))?;
    check(
        server_key.verify(message, &signature),
        "ServerPublicKey verify must accept",
    )?;
    check(
        !server_key.verify(b"other", &signature),
        "ServerPublicKey verify must reject a wrong message",
    )?;
    check(
        !server_key.verify(message, &signature[..63]),
        "ServerPublicKey verify must reject a truncated signature",
    )?;
    let identity = uk_client::import_public_envelope(&envelope)
        .map_err(|e| format!("client import_public_envelope failed: {e}"))?;
    let err = user_key_error(identity.sign(message))?;
    check(
        err.class() == Some("not_private"),
        "public identity sign must fail with class not_private",
    )
}

fn section_b(
    service_signer: &ClientSigningKey,
    wrong_pin: &ClientSigningKey,
) -> Result<(ConnectionData, ExpectedIdentity), String> {
    eprintln!("smoke: credential transfer");
    let server_public_key = encode_b64url(&service_signer.public_key());
    let server_kid = key_id(&service_signer.public_key());
    let connection = ConnectionData::new(BASE_URL, AUD, &server_public_key, &server_kid)
        .map_err(|e| format!("ConnectionData::new failed: {e}"))?;
    check(
        connection.url() == BASE_URL,
        "connection url field must round trip",
    )?;
    check(
        connection.aud() == AUD,
        "connection aud field must round trip",
    )?;
    check(
        connection.server_public_key() == server_public_key,
        "connection server_public_key field must round trip",
    )?;
    check(
        connection.server_kid() == server_kid,
        "connection server_kid field must round trip",
    )?;

    let issued = uk_server::issue_user_key_os(&connection)
        .map_err(|e| format!("issue_user_key_os failed: {e}"))?;
    let credential = issued.credential_bytes();

    let expected = ExpectedIdentity {
        url: BASE_URL.to_string(),
        aud: AUD.to_string(),
        server_public_key: server_public_key.clone(),
        server_kid: server_kid.clone(),
    };
    let imported = uk_client::import_credential(&credential, &expected)
        .map_err(|e| format!("import_credential with the matching identity failed: {e}"))?;
    check(
        imported.connection == connection,
        "imported connection data must equal the issued connection",
    )?;

    let wrong_expected = ExpectedIdentity {
        server_public_key: encode_b64url(&wrong_pin.public_key()),
        server_kid: key_id(&wrong_pin.public_key()),
        ..expected.clone()
    };
    let err = user_key_error(
        uk_client::import_credential(&credential, &wrong_expected).map(|_| Vec::new()),
    )?;
    check(
        err.class() == Some("server_identity_mismatch"),
        "wrong identity import must fail with class server_identity_mismatch",
    )?;
    Ok((connection, expected))
}

fn section_c(
    connection: &ConnectionData,
    expected: &ExpectedIdentity,
    state: Arc<MemoryState>,
    signer_arc: Arc<dyn Signer>,
    service_signer: Arc<ClientSigningKey>,
    wrong_pin: &ClientSigningKey,
) -> Result<(), String> {
    eprintln!("smoke: signed round trip over an in-process transport");
    let second_credential = {
        let issued = uk_server::issue_user_key_os(connection)
            .map_err(|e| format!("issue_user_key_os (second) failed: {e}"))?;
        let identity = issued.public_identity();
        let credential = issued.credential_bytes();
        let imported = uk_client::import_credential(&credential, expected)
            .map_err(|e| format!("import_credential (second) failed: {e}"))?;
        register(&state, registry_entry(identity.kid, identity.public_key))?;
        imported
    };

    let verifier = verifier_for(Arc::clone(&state))?;
    let loopback = Arc::new(LoopbackTransport {
        verifier,
        service_signer: Arc::clone(&service_signer),
    });

    // Happy path: signed ordinary MCP request, authenticated and forwarded,
    // with a signed response.
    // Pin the clock to NOW so request/response timestamps share the same 30s window.
    let mut cfg = connection.client_config(
        Arc::clone(&signer_arc),
        Arc::clone(&loopback) as Arc<dyn Transport>,
    );
    cfg.now = Some(Arc::new(|| NOW));
    let client = rpc::Client::new(cfg).map_err(|e| format!("client build failed: {e}"))?;
    let value = client
        .call_tool_raw_str(TOOL, Some("{}"))
        .map_err(|e| format!("call_tool failed: {e}"))?;
    check(
        matches!(value.get("echoed"), Some(v) if v.as_bool() == Some(true)),
        "structuredContent.echoed must be true",
    )?;

    // Client pinning the WRONG server key: the response is signed by the
    // service key, so response verification must fail with unknown_server_key.
    let cfg_wrong = rpc::Config {
        base_url: connection.url().to_string(),
        aud: connection.aud().to_string(),
        signer: Arc::new(second_credential.signer),
        server_key: wrong_pin.public_key(),
        transport: Arc::clone(&loopback) as Arc<dyn Transport>,
        now: Some(Arc::new(|| NOW)),
        nonce: None,
        window_seconds: 0,
    };
    let client_wrong =
        rpc::Client::new(cfg_wrong).map_err(|e| format!("client build failed: {e}"))?;
    let err = expect_client_err(
        client_wrong.call_tool_raw_str(TOOL, Some("{}")),
        "wrong-pinned client call must fail",
    )?;
    check(
        matches!(&err, ClientErr::Protocol(j) if j.code == "unknown_server_key"),
        "wrong-pinned client must fail with unknown_server_key",
    )?;

    // Tampered request body: server verification rejects the signature with
    // an unsigned 401, which the client must surface as Unauthenticated.
    let tamper_transport = Arc::new(BodyTamperTransport {
        inner: Arc::clone(&loopback) as Arc<dyn Transport>,
    });
    let cfg_tamper = rpc::Config {
        base_url: connection.url().to_string(),
        aud: connection.aud().to_string(),
        signer: Arc::clone(&signer_arc),
        server_key: service_signer.public_key(),
        transport: tamper_transport,
        now: Some(Arc::new(|| NOW)),
        nonce: None,
        window_seconds: 0,
    };
    let client_tamper =
        rpc::Client::new(cfg_tamper).map_err(|e| format!("client build failed: {e}"))?;
    let err = expect_client_err(
        client_tamper.call_tool_raw_str(TOOL, Some("{}")),
        "tampered call must fail",
    )?;
    check(
        matches!(err, ClientErr::Unauthenticated(_)),
        "tampered call must fail with the Unauthenticated variant",
    )
}

fn run() -> Result<(), String> {
    let key = ClientSigningKey::generate().map_err(|e| format!("key generate failed: {e}"))?;
    section_a(&key)?;
    let service_signer = Arc::new(
        ClientSigningKey::generate().map_err(|e| format!("service key generate failed: {e}"))?,
    );
    #[cfg(target_os = "linux")]
    rotation_store::verify(service_signer.as_ref())?;
    let wrong_pin =
        ClientSigningKey::generate().map_err(|e| format!("wrong-pin key generate failed: {e}"))?;
    let (connection, expected) = section_b(&service_signer, &wrong_pin)?;

    let issued = uk_server::issue_user_key_os(&connection)
        .map_err(|e| format!("issue_user_key_os failed: {e}"))?;
    let identity = issued.public_identity();
    let credential = issued.credential_bytes();
    let imported = uk_client::import_credential(&credential, &expected)
        .map_err(|e| format!("import_credential failed: {e}"))?;

    let state = Arc::new(MemoryState::new());
    register(&state, registry_entry(identity.kid, identity.public_key))?;
    let signer_arc: Arc<dyn Signer> = Arc::new(imported.signer);

    section_c(
        &connection,
        &expected,
        state,
        Arc::clone(&signer_arc),
        Arc::clone(&service_signer),
        &wrong_pin,
    )?;

    #[cfg(feature = "client-http")]
    client_http::section_d(Arc::clone(&signer_arc), service_signer.public_key())?;
    #[cfg(feature = "client-http")]
    client_http::section_f()?;
    #[cfg(feature = "server-http")]
    server_layer::section_e(Arc::clone(&signer_arc), &wrong_pin)?;
    Ok(())
}

fn main() {
    if let Err(label) = run() {
        // Static labels and product Display strings only: never key material.
        eprintln!("consumer smoke FAILED: {label}");
        std::process::exit(1);
    }
    eprintln!("consumer smoke: all sections passed");
}
