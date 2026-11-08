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

use mcp_jack::auth_header::{ResponseAuth, format_response_auth};
use mcp_jack::client::error::ClientError as ClientErr;
use mcp_jack::client::rpc;
use mcp_jack::client::signer::Signer;
use mcp_jack::client::transport::{HttpRequest, HttpResponse, Transport, TransportError};
use mcp_jack::encoding::{encode_b64url, key_id};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::policy::Policy;
use mcp_jack::server::state::{MemoryState, RegistryEntry, StateEdit, StateStore};
use mcp_jack::server::verify::{Config as VerifierConfig, Request as VerifyRequest, Verifier};
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
    let policy = Arc::new(
        Policy::parse(
            br#"{"version":1,"rules":[{"match":{"method":"tools/call","tool":"consumer.echo"},"scope":null}]}"#,
        )
        .map_err(|e| format!("policy parse failed: {e}"))?,
    );
    Verifier::new(VerifierConfig {
        aud: AUD.to_string(),
        state,
        nonces: Arc::new(NonceStore::new()),
        policy,
        audit: None,
        native: None,
        window_seconds: 0,
        now: Arc::new(|| NOW),
    })
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

    // Happy path: signed request, policy-allowed tool, signed response.
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

#[cfg(feature = "client-http")]
const PEER_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(feature = "client-http")]
const MAX_PEER_BODY_BYTES: usize = 1 << 20;
#[cfg(feature = "client-http")]
const PEER_ACCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
#[cfg(feature = "client-http")]
const CONTROL_ACCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

#[cfg(feature = "client-http")]
fn serve_one_401(stream: std::net::TcpStream) -> Result<(), String> {
    let mut stream = stream;
    // Bound every peer I/O operation: a stalled or lying peer must never
    // wedge the smoke job.
    stream
        .set_read_timeout(Some(PEER_IO_TIMEOUT))
        .map_err(|e| format!("peer read timeout setup failed: {e}"))?;
    stream
        .set_write_timeout(Some(PEER_IO_TIMEOUT))
        .map_err(|e| format!("peer write timeout setup failed: {e}"))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    // Bounded read: headers end at the first empty CRLF line. Any premature
    // close, stall or oversize request FAILS the peer verdict instead of
    // masquerading as the expected-401 success.
    let header_end;
    loop {
        let read = read_bounded(&mut stream, &mut chunk)?;
        if read == 0 {
            return Err("peer closed before complete request headers".to_string());
        }
        buf.extend_from_slice(&chunk[..read]);
        if buf.len() > 64 * 1024 {
            return Err("peer headers exceed the peer header cap".to_string());
        }
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
    }
    let headers = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
    let content_length: usize = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    // Refuse a lying content-length so our own buffer stays finite.
    if content_length > MAX_PEER_BODY_BYTES {
        return Err("peer content-length exceeds the peer body cap".to_string());
    }
    while buf.len() < header_end + content_length {
        let read = read_bounded(&mut stream, &mut chunk)?;
        if read == 0 {
            return Err("peer closed or stalled before complete request body".to_string());
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    // Only a COMPLETE request earns the response: one unsigned 401, then
    // close. The client must map this to Unauthenticated without parsing
    // anything; a truncated peer never reaches this point.
    stream
        .write_all(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
        .map_err(|e| format!("peer 401 write failed: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("peer flush failed: {e}"))
}

#[cfg(feature = "client-http")]
fn read_bounded(stream: &mut std::net::TcpStream, chunk: &mut [u8]) -> Result<usize, String> {
    match stream.read(chunk) {
        Ok(read) => Ok(read),
        // A timeout/WouldBlock means the peer stalled; fail the verdict.
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            Err("peer stalled: read timeout".to_string())
        }
        Err(e) => Err(format!("peer read failed: {e}")),
    }
}

#[cfg(feature = "client-http")]
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Deadline-bounded accept: blocks on an OS-timer readiness wait (tokio's
/// timer + mio's net backend), never a sleep/poll loop. The current-thread
/// runtime matches the SDK transport's own worker idiom
/// (rust/src/client/http_transport.rs:318-330).
#[cfg(feature = "client-http")]
fn accept_within(
    listener: std::net::TcpListener,
    timeout: std::time::Duration,
) -> Result<std::net::TcpStream, String> {
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("peer listener nonblocking setup failed: {e}"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("peer accept runtime failed: {e}"))?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::from_std(listener)
            .map_err(|e| format!("peer listener conversion failed: {e}"))?;
        let (stream, _peer) = tokio::time::timeout(timeout, listener.accept())
            .await
            .map_err(|_| {
                "peer accept exceeded its independent bound; no connection arrived within the accept wait"
                    .to_string()
            })?
            .map_err(|e| format!("peer accept failed: {e}"))?;
        let mut stream = stream
            .into_std()
            .map_err(|e| format!("peer stream conversion failed: {e}"))?;
        stream
            .set_nonblocking(false)
            .map_err(|e| format!("peer stream blocking-mode reset failed: {e}"))?;
        Ok(stream)
    })
}

/// The peer's whole lifecycle: a deadline-bounded accept followed by the
/// bounded serve, entirely inside one finite function.
#[cfg(feature = "client-http")]
fn peer_lifecycle_401(
    listener: std::net::TcpListener,
    accept_timeout: std::time::Duration,
) -> Result<(), String> {
    let stream = accept_within(listener, accept_timeout)?;
    serve_one_401(stream)
}

#[cfg(feature = "client-http")]
fn section_d(signer_arc: Arc<dyn Signer>, server_key: [u8; 32]) -> Result<(), String> {
    eprintln!("smoke: client-http over a real socket");
    let transport = mcp_jack::client::HttpTransport::builder()
        .build()
        .map_err(|e| format!("HttpTransport build failed: {e}"))?;
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("listener bind failed: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("listener addr failed: {e}"))?;
    check(
        addr.ip().is_loopback(),
        "listener must bind a loopback address",
    )?;
    // Accept lifecycle: the peer accept is deadline-bounded inside the peer
    // thread itself (tokio timeout, no release connect exists). A wedged SDK
    // call is the whole-job guard's concern (CI job timeout) and is
    // deliberately out of this fixture's scope.
    let (peer_tx, peer_rx) = std::sync::mpsc::channel();
    let peer = std::thread::spawn(move || {
        let _ = peer_tx.send(peer_lifecycle_401(listener, PEER_ACCEPT_TIMEOUT));
    });
    let (outcome_tx, outcome_rx) = std::sync::mpsc::channel();
    let client_thread = std::thread::spawn(move || {
        let outcome = (|| -> Result<(), String> {
            let cfg = rpc::Config {
                base_url: format!("http://{addr}/mcp"),
                aud: AUD.to_string(),
                signer: signer_arc,
                server_key,
                transport: Arc::new(transport),
                now: None,
                nonce: None,
                window_seconds: 0,
            };
            let client = rpc::Client::new(cfg).map_err(|e| format!("client build failed: {e}"))?;
            let err = expect_client_err(
                client.call_tool_raw_str(TOOL, Some("{}")),
                "unsigned 401 round trip must fail",
            )?;
            check(
                matches!(err, ClientErr::Unauthenticated(ref e) if e.status == 401),
                "unsigned 401 must surface as Unauthenticated with status 401",
            )
        })();
        let _ = outcome_tx.send(outcome);
    });
    let client_recv = outcome_rx
        .recv()
        .map_err(|_| "client phase dropped its channel".to_string());
    let peer_recv = peer_rx
        .recv()
        .map_err(|_| "peer lifecycle dropped its channel".to_string());
    let peer_join = peer
        .join()
        .map_err(|_| "peer lifecycle panicked".to_string());
    let client_join = client_thread
        .join()
        .map_err(|_| "client phase panicked".to_string());
    let client_outcome = client_recv?;
    let peer_verdict = peer_recv?;
    peer_join?;
    client_join?;
    // A failed peer verdict ALWAYS fails the section: a stalled or truncated
    // peer is never excused by an expected-401 client assertion. A wedged SDK
    // call (before its own transport deadline returns) is the whole-job
    // guard's concern: the client-thread join above is bounded by the SDK's
    // documented transport deadline, and a deadline regression degrades to
    // the CI job timeout.
    match peer_verdict {
        Err(e) => Err(format!("peer lifecycle failed: {e}")),
        Ok(()) => client_outcome,
    }
}

#[cfg(feature = "client-http")]
fn section_f() -> Result<(), String> {
    eprintln!("smoke: CI-executed lifecycle controls");

    // Control A: the nonconnecting accept bound fires on its own, with no
    // SDK involvement at all. This calls the SAME production operation
    // section_d uses (`accept_within`); if that function were ever changed
    // to unbounded waiting, this control would block and the CI job would
    // fail — deliberately nonvacuous.
    let listener_a =
        TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("control A bind failed: {e}"))?;
    let verdict_a = accept_within(listener_a, CONTROL_ACCEPT_TIMEOUT);
    check(
        matches!(&verdict_a, Err(m) if m.contains("independent bound")),
        "nonconnecting accept must fail via the production deadline-bound accept",
    )?;

    // Control B: a raw lying peer sends complete headers but only part of the
    // declared body and shuts down; the peer verdict must fail instead of
    // yielding the expected-401 success.
    let listener_b =
        TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("control B bind failed: {e}"))?;
    let addr_b = listener_b
        .local_addr()
        .map_err(|e| format!("control B addr failed: {e}"))?;
    let mut lying = std::net::TcpStream::connect(addr_b)
        .map_err(|e| format!("control B lying peer connect failed: {e}"))?;
    lying
        .set_write_timeout(Some(PEER_IO_TIMEOUT))
        .map_err(|e| format!("control B write timeout setup failed: {e}"))?;
    lying
        .write_all(b"POST /mcp HTTP/1.1\r\ncontent-length: 4\r\n\r\nbo")
        .map_err(|e| format!("control B lying peer write failed: {e}"))?;
    lying
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| format!("control B lying peer shutdown failed: {e}"))?;
    drop(lying);
    // The connection is already pending and its FIN gives serve_one_401 the
    // EOF, so the accept returns promptly.
    let stream_b = accept_within(listener_b, PEER_ACCEPT_TIMEOUT)
        .map_err(|e| format!("control B accept failed: {e}"))?;
    let msg = match serve_one_401(stream_b) {
        Err(m) => m,
        Ok(()) => {
            return Err("incomplete-body control unexpectedly succeeded".to_string());
        }
    };
    check(
        msg.contains("request body"),
        "incomplete-body control must fail with a request-body verdict",
    )
}

/// Blocking bridge from the SDK's synchronous [`Transport`] to a tower
/// `Service` as produced by the packaged `JackLayer` (feature `server-http`).
#[cfg(feature = "server-http")]
struct LayerTransport<S> {
    service: Arc<std::sync::Mutex<S>>,
}

#[cfg(feature = "server-http")]
impl<S> Transport for LayerTransport<S>
where
    S: tower::Service<
            http::Request<http_body_util::Full<bytes::Bytes>>,
            Response = http::Response<http_body_util::Full<bytes::Bytes>>,
            Error = std::convert::Infallible,
        > + Send
        + 'static,
{
    fn round_trip(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        use http_body_util::BodyExt as _;
        let target = mcp_jack::client::url::request_target(&req.url)
            .map_err(|e| TransportError::Client(e.to_string()))?;
        let mut builder = http::Request::builder()
            .method(req.method.as_str())
            .uri(target);
        for (name, value) in &req.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let http_req = builder
            .body(http_body_util::Full::new(bytes::Bytes::from(
                req.body.clone(),
            )))
            .map_err(|e| TransportError::Client(e.to_string()))?;

        let mut guard = match self.service.lock() {
            Ok(guard) => guard,
            Err(_) => {
                return Err(TransportError::Client(
                    "jack service lock poisoned".to_string(),
                ));
            }
        };
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        match tower::Service::poll_ready(&mut *guard, &mut cx) {
            std::task::Poll::Ready(Ok(())) => {}
            std::task::Poll::Ready(Err(e)) => match e {},
            std::task::Poll::Pending => {
                return Err(TransportError::Client("jack service not ready".to_string()));
            }
        }
        futures::executor::block_on(async {
            let response = tower::Service::call(&mut *guard, http_req).await;
            match response {
                Ok(res) => {
                    let status = res.status().as_u16();
                    let mut headers = Vec::new();
                    for (name, value) in res.headers() {
                        let value = value.to_str().map_err(|_| {
                            TransportError::Client("non-UTF-8 response header value".to_string())
                        })?;
                        headers.push((name.as_str().to_string(), value.to_string()));
                    }
                    let body = res
                        .into_body()
                        .collect()
                        .await
                        .map_err(|_| {
                            TransportError::Client("response body read failed".to_string())
                        })?
                        .to_bytes();
                    Ok(HttpResponse {
                        status,
                        headers,
                        body: body.to_vec(),
                    })
                }
                Err(e) => match e {},
            }
        })
    }
}

#[cfg(feature = "server-http")]
fn section_e(client_signer: Arc<dyn Signer>, wrong_pin: &ClientSigningKey) -> Result<(), String> {
    use bytes::Bytes;
    use ed25519_dalek::SigningKey;
    use http_body_util::Full;
    use mcp_jack::server::http::{HandlerConfig, JackLayer};
    use std::convert::Infallible;
    use tower::Layer as _;

    eprintln!("smoke: server-http drives the real packaged adapter");
    // The SDK deliberately exposes no seed export, so the consumer's service
    // key must come from its own randomness source.
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("os seed failed: {e}"))?;
    let service_key = SigningKey::from_bytes(&seed);
    let service_pub = *service_key.verifying_key().as_bytes();

    let state = Arc::new(MemoryState::new());
    register(
        &state,
        RegistryEntry {
            kid: client_signer.kid().to_string(),
            public_key: encode_b64url(&client_signer.public_key()),
            name: "consumer-smoke".to_string(),
            ..Default::default()
        },
    )?;
    let verifier = Arc::new(verifier_for(Arc::clone(&state))?);
    let layer = JackLayer::new(HandlerConfig {
        verifier,
        server_key: service_key,
        max_body_bytes: 0,
        max_response_bytes: 0,
    });
    // In-process inner service: the layer verifies, authorizes and signs; the
    // inner service echoes a static CallToolResult-shaped JSON-RPC response.
    let service = layer.layer(tower::service_fn(
        |_req: http::Request<Full<Bytes>>| async move {
            Ok::<_, Infallible>(http::Response::new(Full::new(Bytes::from_static(
                br#"{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"echoed":true}}}"#,
            ))))
        },
    ));
    let layer_transport: Arc<dyn Transport> = Arc::new(LayerTransport {
        service: Arc::new(std::sync::Mutex::new(service)),
    });

    // Happy path: the signed request flows through the real adapter and the
    // signed response verifies against the service key.
    let cfg = rpc::Config {
        base_url: BASE_URL.to_string(),
        aud: AUD.to_string(),
        signer: Arc::clone(&client_signer),
        server_key: service_pub,
        transport: Arc::clone(&layer_transport),
        now: Some(Arc::new(|| NOW)),
        nonce: None,
        window_seconds: 0,
    };
    let client = rpc::Client::new(cfg).map_err(|e| format!("client build failed: {e}"))?;
    let value = client
        .call_tool_raw_str(TOOL, Some("{}"))
        .map_err(|e| format!("adapter call failed: {e}"))?;
    check(
        matches!(value.get("echoed"), Some(v) if v.as_bool() == Some(true)),
        "adapter structuredContent.echoed must be true",
    )?;

    // Wrong server pin through the same adapter: response verification must
    // fail with unknown_server_key.
    let cfg_wrong = rpc::Config {
        base_url: BASE_URL.to_string(),
        aud: AUD.to_string(),
        signer: Arc::clone(&client_signer),
        server_key: wrong_pin.public_key(),
        transport: Arc::clone(&layer_transport),
        now: Some(Arc::new(|| NOW)),
        nonce: None,
        window_seconds: 0,
    };
    let client_wrong =
        rpc::Client::new(cfg_wrong).map_err(|e| format!("client build failed: {e}"))?;
    let err = expect_client_err(
        client_wrong.call_tool_raw_str(TOOL, Some("{}")),
        "adapter wrong-pinned call must fail",
    )?;
    check(
        matches!(&err, ClientErr::Protocol(j) if j.code == "unknown_server_key"),
        "adapter wrong-pinned client must fail with unknown_server_key",
    )?;

    // Tampered request body through the same adapter: verification rejects
    // with an unsigned 401, surfaced as Unauthenticated.
    let tamper_transport = Arc::new(BodyTamperTransport {
        inner: Arc::clone(&layer_transport),
    });
    let cfg_tamper = rpc::Config {
        base_url: BASE_URL.to_string(),
        aud: AUD.to_string(),
        signer: Arc::clone(&client_signer),
        server_key: service_pub,
        transport: tamper_transport,
        now: Some(Arc::new(|| NOW)),
        nonce: None,
        window_seconds: 0,
    };
    let client_tamper =
        rpc::Client::new(cfg_tamper).map_err(|e| format!("client build failed: {e}"))?;
    let err = expect_client_err(
        client_tamper.call_tool_raw_str(TOOL, Some("{}")),
        "adapter tampered call must fail",
    )?;
    check(
        matches!(err, ClientErr::Unauthenticated(_)),
        "adapter tampered call must fail with the Unauthenticated variant",
    )
}

fn run() -> Result<(), String> {
    let key = ClientSigningKey::generate().map_err(|e| format!("key generate failed: {e}"))?;
    section_a(&key)?;
    let service_signer = Arc::new(
        ClientSigningKey::generate().map_err(|e| format!("service key generate failed: {e}"))?,
    );
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
    section_d(Arc::clone(&signer_arc), service_signer.public_key())?;
    #[cfg(feature = "client-http")]
    section_f()?;
    #[cfg(feature = "server-http")]
    section_e(Arc::clone(&signer_arc), &wrong_pin)?;
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
