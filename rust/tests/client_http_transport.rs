//! CI-only integration tests for the NEW optional blocking HTTP/HTTPS client
//! `Transport` (`mcp_jack::client::HttpTransport`, feature `client-http`).
//!
//! Every test runs against a REAL server: a live hyper 1.x HTTP/1.1 server on
//! a 127.0.0.1 ephemeral port (plain and, for the TLS tests, wrapped in a
//! tokio-rustls acceptor with a runtime-generated rcgen certificate). The
//! harness fakes (`tests/common/harness.rs`) are reused only for the signing
//! primitives and fixture keys — no fake transport is involved, so these
//! tests exercise the actual wire behaviour of the Hyper/Tokio-backed adapter.
//!
//! Deterministic synchronization uses channels, with controlled trickle
//! producers for paced-body tests. No wall-clock assertions. Where the server
//! must stall, the client deadline bounds the failure path.
#![cfg(feature = "client-http")]

mod common;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use common::harness::{
    self, fixed_clock, rpc_result_body, signer_by_name, FIXTURE_AUD, FIXTURE_NOW,
};
use hyper::body::{Body as _, Bytes, Frame, Incoming, SizeHint};
use hyper_util::rt::TokioIo;
use mcp_jack::auth_header::parse_request_auth;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use tokio::task::JoinHandle;

/// Combined trait object for the plain/TLS IO branches (only one non-auto
/// trait is allowed in a `dyn`).
trait TestIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send {}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + ?Sized> TestIo for T {}

use mcp_jack::auth_header::RequestAuth;
use mcp_jack::client::http_transport::HttpTransport;
use mcp_jack::client::transport::{
    HttpRequest, SigningTransport, Transport, TransportError, MAX_BODY_BYTES,
};
use mcp_jack::client::url::request_target;
use mcp_jack::encoding::decode_b64url_fixed;
use mcp_jack::signing::request_signing_string;

// ---------------------------------------------------------------------------
// Certificate generation (rcgen 0.13, runtime-generated; all material is
// public test material, nothing is checked in).
// ---------------------------------------------------------------------------

/// Fresh P-256 key pair (rcgen's ring-backed generator).
fn gen_key() -> KeyPair {
    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("p-256 key pair")
}

/// A self-signed CA certificate + key (rcgen: `IsCa::Ca(BasicConstraints::
/// Unconstrained)` plus the key usages that let it sign and be verified).
fn gen_ca(common_name: &str) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("empty SAN list is valid");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    let key = gen_key();
    let cert = params.self_signed(&key).expect("self-signed CA");
    (cert, key)
}

/// A server certificate for `san` (an IP address string such as "127.0.0.1"
/// becomes an iPAddress SAN via `SanType::IpAddress`, a DNS name stays a
/// DnsName SAN) signed by `issuer`.
fn gen_leaf(
    san: &str,
    issuer: &rcgen::Certificate,
    issuer_key: &KeyPair,
) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec![san.to_string()]).expect("valid SAN");
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    // rustls' default verifier enforces the serverAuth EKU on server certs.
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params
        .distinguished_name
        .push(DnType::CommonName, "mcp-jack http-transport test");
    let key = gen_key();
    let cert = params
        .signed_by(&key, issuer, issuer_key)
        .expect("signed leaf");
    (cert, key)
}

/// DER bytes of a certificate (rcgen `Certificate::der()` -> `&CertificateDer`).
fn cert_der(cert: &rcgen::Certificate) -> Vec<u8> {
    cert.der().as_ref().to_vec()
}

/// The rustls pieces for a TLS server: chain [leaf, ca] and the leaf's
/// PKCS#8 private key.
fn server_tls_parts(
    leaf: &rcgen::Certificate,
    leaf_key: &KeyPair,
    ca: &rcgen::Certificate,
) -> (Vec<Vec<u8>>, Vec<u8>) {
    (vec![cert_der(leaf), cert_der(ca)], leaf_key.serialize_der())
}

/// A rustls `ServerConfig` with an EXPLICIT ring provider (rustls 0.23 has
/// no process-default provider; `ServerConfig::builder()` would panic).
fn tls_server_config(
    chain_der: Vec<Vec<u8>>,
    key_der_pkcs8: Vec<u8>,
) -> tokio_rustls::rustls::ServerConfig {
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let certs: Vec<CertificateDer<'static>> =
        chain_der.into_iter().map(CertificateDer::from).collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der_pkcs8));
    tokio_rustls::rustls::ServerConfig::builder_with_provider(
        tokio_rustls::rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(tokio_rustls::rustls::ALL_VERSIONS)
    .expect("ALL_VERSIONS is valid")
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .expect("server certificate chain")
}

// ---------------------------------------------------------------------------
// Live hyper 1.x server (mirrors src/bin/interop_server.rs lines ~311-360).
// ---------------------------------------------------------------------------

/// One server response as plain data; handlers build these.
struct WireResponse {
    status: u16,
    headers: Vec<(String, String)>,
    /// `BodyKind::Full` is an exact content-length body; `Chunks` is sent
    /// chunked (hyper adds Transfer-Encoding: chunked); `Truncated` aborts
    /// the chunked stream mid-body (the client sees a read error);
    /// `Stalled` writes the head and then parks the body on a `Notify`
    /// release gate (never sends a body byte until released);
    /// `ExactThenPark` announces a Content-Length, sends its chunks, then
    /// parks without ever completing the announced message.
    body: BodyKind,
}

enum BodyKind {
    Full(Vec<u8>),
    Chunks(Vec<Vec<u8>>),
    Truncated(Vec<Vec<u8>>),
    /// The head goes out immediately; the body stream stays pending until
    /// the test notifies the `Notify` gate (and the client deadline is the
    /// bounded failure guard if the test forgets).
    Stalled(Arc<tokio::sync::Notify>),
    /// Announces `announced` via an EXACT size hint (hyper derives
    /// `Content-Length: announced`) but sends only `chunks` and then parks
    /// until the gate is released: the announced message never completes.
    ExactThenPark {
        announced: u64,
        chunks: Vec<Vec<u8>>,
        gate: Arc<tokio::sync::Notify>,
    },
    /// A complete chunked body trickling one data frame per semaphore permit;
    /// the producer sends the final permit autonomously, ending cleanly at EOF.
    Trickle {
        gate: Arc<tokio::sync::Semaphore>,
        frames: Vec<Vec<u8>>,
    },
}

fn full(status: u16, headers: &[(&str, &str)], body: Vec<u8>) -> WireResponse {
    WireResponse {
        status,
        headers: headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect(),
        body: BodyKind::Full(body),
    }
}

/// The async handler type: receives the hyper request parts + body bytes and
/// returns the wire response.
type Handler = Arc<
    dyn Fn(http::request::Parts, Vec<u8>) -> Pin<Box<dyn Future<Output = WireResponse> + Send>>
        + Send
        + Sync,
>;

/// The hyper Service bridging: calls the handler with (parts, collected body).
struct Svc(Handler);

impl hyper::service::Service<http::Request<Incoming>> for Svc {
    type Response = http::Response<TestBody>;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: http::Request<Incoming>) -> Self::Future {
        let handler = self.0.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let bytes = collect_body(body).await;
            let wire = handler(parts, bytes).await;
            let mut builder = http::Response::builder().status(wire.status);
            for (name, value) in &wire.headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
            let body = match wire.body {
                BodyKind::Full(bytes) => TestBody::Full(Some(Bytes::from(bytes))),
                BodyKind::Chunks(chunks) => TestBody::Chunks {
                    // A complete chunked body: after the last chunk the
                    // stream ends cleanly, so hyper writes the terminating
                    // 0-chunk and the client sees a complete message.
                    chunks: bytes_of(chunks),
                    fail_after: false,
                },
                BodyKind::Truncated(chunks) => TestBody::Chunks {
                    // After the last chunk the stream ERRORS: hyper aborts
                    // the message mid-body and closes the connection, so the
                    // announced message is never completed.
                    chunks: bytes_of(chunks),
                    fail_after: true,
                },
                BodyKind::Stalled(gate) => TestBody::Stalled { gate, wait: None },
                BodyKind::ExactThenPark {
                    announced,
                    chunks,
                    gate,
                } => TestBody::ExactThenPark {
                    announced,
                    chunks: bytes_of(chunks),
                    gate,
                    wait: None,
                },
                BodyKind::Trickle { gate, frames } => TestBody::Trickle {
                    gate,
                    frames: bytes_of(frames),
                    wait: None,
                },
            };
            let resp = builder.body(body).expect("static response parts");
            Ok(resp)
        })
    }
}

/// Collects a `hyper::body::Incoming` into bytes without http-body-util
/// (which is only enabled behind the separate `http` feature): a tiny
/// poll_frame drain loop.
async fn collect_body(mut body: Incoming) -> Vec<u8> {
    let mut out = Vec::new();
    std::future::poll_fn(|cx: &mut Context<'_>| loop {
        match Pin::new(&mut body).poll_frame(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(None) => return Poll::Ready(()),
            Poll::Ready(Some(Err(_))) => return Poll::Ready(()),
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    out.extend_from_slice(data);
                }
            }
        }
    })
    .await;
    out
}

/// The concrete response body type: a tiny enum implementing
/// `hyper::body::Body` directly (no http-body-util/futures dependency —
/// those live behind the separate `http` feature; everything this file
/// needs must exist when ONLY `client-http` is enabled).
/// Stored permit-acquire future for `TestBody::Trickle`: created once so the
/// semaphore permit registration persists across pending polls (no lost
/// wakeup), and the permit result is awaited through the `Body::poll_frame`
/// state machine.
type TricklePermitWait = Pin<
    Box<
        dyn Future<Output = Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::AcquireError>>
            + Send,
    >,
>;

enum TestBody {
    /// Exactly one data frame (hyper derives the Content-Length from the
    /// exact size hint).
    Full(Option<Bytes>),
    /// Several data frames with unknown total length (the size hint is the
    /// DEFAULT, never exact): hyper frames this as Transfer-Encoding: chunked. With `fail_after` the stream ERRORS after
    /// the last chunk, aborting the message mid-body.
    Chunks {
        chunks: std::collections::VecDeque<Bytes>,
        fail_after: bool,
    },
    /// The head goes out immediately; the body resolves only when the
    /// release signal fires. The wait future is created ONCE and stored in
    /// the variant, so its `Notify` registration persists across pending
    /// polls — no registration churn and no lost wakeup (a freshly created
    /// `notified()` future on every poll could miss a permit stored between
    /// polls only if a NEW future replaced it; storing it makes observation
    /// deterministic).
    Stalled {
        gate: Arc<tokio::sync::Notify>,
        wait: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    },
    /// Announces `announced` (exact size hint -> Content-Length), yields the
    /// queued chunks, then parks exactly like `Stalled`: the announced
    /// message is never completed until the gate fires.
    ExactThenPark {
        announced: u64,
        chunks: std::collections::VecDeque<Bytes>,
        gate: Arc<tokio::sync::Notify>,
        wait: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    },
    /// Yields ONE queued data frame PER semaphore permit: every frame is
    /// gated on a freshly acquired permit (a stored permit releases the
    /// first frame immediately), and when the queue is empty the next
    /// permit ends the chunked body cleanly (None — unknown size hint, the
    /// default). The `wait` future is created once and stored, exactly like
    /// `Stalled`, so the semaphore registration persists across pending
    /// polls (no lost wakeup). A stored permit is consumed to emit EXACTLY
    /// ONE frame or EOF — no burst.
    Trickle {
        gate: Arc<tokio::sync::Semaphore>,
        frames: std::collections::VecDeque<Bytes>,
        wait: Option<TricklePermitWait>,
    },
}

impl hyper::body::Body for TestBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match &mut *self {
            TestBody::Full(data) => Poll::Ready(data.take().map(|d| Ok(Frame::data(d)))),
            TestBody::Chunks { chunks, fail_after } => match chunks.pop_front() {
                Some(bytes) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
                None if *fail_after => Poll::Ready(Some(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "test server aborts mid-body",
                )))),
                None => Poll::Ready(None),
            },
            TestBody::Stalled { gate, wait } => {
                if wait.is_none() {
                    // Create the wait future ONCE: its Notify registration
                    // persists across pending polls (no lost wakeup).
                    let g = Arc::clone(gate);
                    *wait = Some(Box::pin(async move { g.notified().await }));
                }
                let wait = wait.as_mut().expect("wait future stored above");
                match wait.as_mut().poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(()) => Poll::Ready(None),
                }
            }
            TestBody::ExactThenPark {
                chunks, gate, wait, ..
            } => {
                if let Some(bytes) = chunks.pop_front() {
                    return Poll::Ready(Some(Ok(Frame::data(bytes))));
                }
                if wait.is_none() {
                    let g = Arc::clone(gate);
                    *wait = Some(Box::pin(async move { g.notified().await }));
                }
                let wait = wait.as_mut().expect("wait future stored above");
                match wait.as_mut().poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(()) => Poll::Ready(None),
                }
            }
            TestBody::Trickle { gate, frames, wait } => {
                if wait.is_none() {
                    // Create the wait future ONCE: its semaphore
                    // registration persists across pending polls (no lost
                    // wakeup).
                    let g = Arc::clone(gate);
                    *wait = Some(Box::pin(async move { g.clone().acquire_owned().await }));
                }
                let w = wait.as_mut().expect("trickle wait future stored above");
                match w.as_mut().poll(cx) {
                    Poll::Pending => Poll::Pending,
                    // One permit acquired: emit exactly one frame, or end
                    // the body. NO permit, NO frame — never burst.
                    Poll::Ready(Ok(_permit)) => {
                        _permit.forget();
                        *wait = None;
                        if let Some(bytes) = frames.pop_front() {
                            Poll::Ready(Some(Ok(Frame::data(bytes))))
                        } else {
                            // The FINAL permit: clean EOF, one permit per
                            // outcome.
                            Poll::Ready(None)
                        }
                    }
                    // Impossible by construction (the semaphore is never
                    // closed): a fixture regression must fail loudly, not
                    // fake EOF.
                    Poll::Ready(Err(_)) => Poll::Ready(Some(Err(std::io::Error::other(
                        "trickle semaphore closed — fixture bug",
                    )))),
                }
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = SizeHint::default();
        match self {
            TestBody::Full(Some(data)) => hint.set_exact(data.len() as u64),
            TestBody::ExactThenPark { announced, .. } => {
                // An EXACT hint: hyper derives `Content-Length: announced`.
                hint.set_exact(*announced);
            }
            TestBody::Chunks { .. } => {
                // Unknown total length (DEFAULT hint): an exact hint would
                // make hyper send Content-Length instead of Transfer-Encoding:
                // chunked, silently defeating the chunked-framing tests.
            }
            _ => {}
        }
        hint
    }
}

fn bytes_of(chunks: Vec<Vec<u8>>) -> std::collections::VecDeque<Bytes> {
    chunks.into_iter().map(Bytes::from).collect()
}

/// Binds 127.0.0.1:0 and returns the listener plus its address.
async fn bind_loopback() -> (tokio::net::TcpListener, SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().expect("local addr");
    (listener, addr)
}

/// Independent wedge guard for `TestServerGuard::shutdown`: children exit
/// cooperatively via the watch stop signal (serve future dropped => socket
/// closed), so this bound is never the termination mechanism — it only
/// guarantees shutdown cannot wedge forever if one does.
const SHUTDOWN_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

type JoinOutcome = Result<(), tokio::task::JoinError>;

/// Bounded join of an OWNED tokio JoinHandle. Reports whether it completed
/// cooperatively or required abort; both paths await the task's termination.
async fn join_owned_bounded(handle: &mut JoinHandle<()>) -> (JoinOutcome, bool) {
    match tokio::time::timeout(SHUTDOWN_BOUND, &mut *handle).await {
        Ok(joined) => (joined, false),
        Err(_elapsed) => {
            handle.abort();
            (handle.await, true)
        }
    }
}

/// Frames emitted by the trickle body in the cumulative-deadline controls.
const TRICKLE_FRAMES: usize = 40;
/// Every gap is paced by the fixture, but scheduling/TLS buffering means
/// individual client reads need not align with those frame intervals.
const TRICKLE_INTERVAL: Duration = Duration::from_millis(80);

/// Joins the blocking client thread as the FINAL wait, after its peer has
/// been released under an owned, bounded guard. Deliberately NO timeout:
/// std threads cannot be killed, and dropping a `spawn_blocking` join
/// handle on expiry would detach exactly the work this suite promises to
/// finish (the previous helper's defect). Supported boundary, stated
/// exactly: the client threads in this file terminate once their peer
/// socket is released (their only unbounded waits are socket reads/writes,
/// which unblock when the peer closes). If a future regression keeps a
/// client spinning despite released peers, this join blocks and the test
/// hangs by design — hanging beats silently detaching a stuck thread; no
/// code here claims to kill arbitrary infinite Rust code.
async fn join_client_thread_after_release(
    client: std::thread::JoinHandle<()>,
) -> Result<(), String> {
    match tokio::task::spawn_blocking(move || client.join()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err("client thread panicked".to_string()),
        Err(e) => Err(format!("join task failed: {e}")),
    }
}

/// Guard for a spawned loopback server. Ownership contract:
///
/// - A `tokio::sync::watch` stop channel ENABLES cooperative termination:
///   the accept loop exits on the signal, and every per-connection child
///   drops its in-flight hyper serve/accept future on the signal, which
///   closes the socket (including children still parked inside a TLS
///   accept). Children therefore never linger on a keep-alive connection
///   whose peer socket is held open by the client's connection pool (the
///   root cause of a previous shutdown hang). The signal does NOT join
///   anything — it only makes the tasks WANT to finish.
/// - `shutdown().await` sends the stop signal, then JOINS the accept loop
///   and every per-connection handle under an independent 5 s bound
///   (`SHUTDOWN_BOUND`): the bounded await is the actual join. On bound
///   expiry the task is aborted and its termination awaited, so nothing is
///   left detached. The bound is a wedge guard around the join, NOT the
///   mechanism — children exit cooperatively via the watch signal.
/// - `Drop` is the panic/failure-path best-effort termination: it sends the
///   stop signal and aborts the accept loop and every handle, synchronously.
///   Drop NEVER joins (impossible: sync context, tokio JoinHandles cannot be
///   awaited) — aborted tasks are dropped by the runtime at their next poll
///   or at runtime teardown, closing their sockets there. `shutdown().await`
///   is the awaited cleanup path on success. No claim is made here that the
///   signal or Drop awaits anything.
struct TestServerGuard {
    accept: JoinHandle<()>,
    conns: Arc<std::sync::Mutex<Vec<JoinHandle<()>>>>,
    stop: tokio::sync::watch::Sender<bool>,
}

impl TestServerGuard {
    /// Sends the stop signal, then JOINS the accept loop and drains and
    /// JOINS every per-connection handle under `SHUTDOWN_BOUND`, so the test
    /// ends with NO detached task. On bound expiry the task is aborted and
    /// its termination awaited.
    async fn shutdown(mut self) -> ShutdownOutcome {
        let _ = self.stop.send(true);
        let (accept_result, accept_aborted) = join_owned_bounded(&mut self.accept).await;
        let conns: Vec<JoinHandle<()>> = self
            .conns
            .lock()
            .expect("conn handle mutex")
            .drain(..)
            .collect();
        let mut outcome = ShutdownOutcome {
            accept: accept_result,
            accept_aborted,
            children: Vec::with_capacity(conns.len()),
        };
        for mut handle in conns {
            let child = join_owned_bounded(&mut handle).await;
            outcome.children.push(child);
        }
        outcome
    }
}

#[derive(Debug)]
struct ShutdownOutcome {
    accept: JoinOutcome,
    accept_aborted: bool,
    children: Vec<(JoinOutcome, bool)>,
}

impl ShutdownOutcome {
    fn cooperative(&self) -> bool {
        matches!(self.accept, Ok(()))
            && !self.accept_aborted
            && self
                .children
                .iter()
                .all(|(result, aborted)| matches!(result, Ok(())) && !aborted)
    }
}

impl Drop for TestServerGuard {
    /// Best-effort termination on panic/failure paths. Drop runs in a sync
    /// context and cannot await tokio JoinHandles, so it aborts instead of
    /// joining; aborting a child drops its serve future, closing the socket.
    /// The awaited path is `shutdown().await` on success.
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.accept.abort();
        let handles: Vec<JoinHandle<()>> = self
            .conns
            .lock()
            .expect("conn handle mutex")
            .drain(..)
            .collect();
        for handle in handles {
            handle.abort();
        }
    }
}

/// Spawns the accept loop serving `handler` over hyper HTTP/1.1, optionally
/// wrapping each accepted TcpStream in TLS first. Returns a guard whose
/// `shutdown().await` JOINS the accept loop AND every per-connection task
/// under a bound (the stop signal also cancels children parked inside a TLS
/// accept — dropping the accept future closes the socket; TLS-accept-error
/// children just return; joining them is still correct).
fn spawn_server(
    listener: tokio::net::TcpListener,
    tls: Option<tokio_rustls::TlsAcceptor>,
    handler: Handler,
) -> TestServerGuard {
    spawn_server_observed(listener, tls, handler, None)
}

fn spawn_server_observed(
    listener: tokio::net::TcpListener,
    tls: Option<tokio_rustls::TlsAcceptor>,
    handler: Handler,
    handshake_started: Option<tokio::sync::mpsc::Sender<()>>,
) -> TestServerGuard {
    let conns: Arc<std::sync::Mutex<Vec<JoinHandle<()>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let accept_conns = Arc::clone(&conns);
    let accept = tokio::spawn(async move {
        loop {
            let result = tokio::select! {
                result = listener.accept() => result,
                _ = stop_rx.changed() => break,
            };
            let Ok((stream, _)) = result else {
                break;
            };
            let handler = handler.clone();
            let tls = tls.clone();
            let handshake_started = handshake_started.clone();
            let mut child_stop = stop_rx.clone();
            let handle = tokio::spawn(async move {
                tokio::select! {
                    _ = async {
                        let io: TokioIo<Box<dyn TestIo + Unpin>> = if let Some(acceptor) = tls {
                            let accept = acceptor.accept(stream);
                            tokio::pin!(accept);
                            let mut acknowledged = false;
                            let result = std::future::poll_fn(|cx| {
                                let poll = accept.as_mut().poll(cx);
                                if !acknowledged {
                                    acknowledged = true;
                                    if let Some(sender) = &handshake_started { let _ = sender.try_send(()); }
                                }
                                poll
                            }).await;
                            match result {
                                Ok(tls_stream) => TokioIo::new(Box::new(tls_stream)),
                                Err(_) => return,
                            }
                        } else {
                            TokioIo::new(Box::new(stream))
                        };
                        let serve = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, Svc(handler));
                        tokio::pin!(serve);
                        let _ = serve.as_mut().await;
                    } => {}
                    _ = child_stop.changed() => {}
                }
            });
            accept_conns.lock().expect("conn handle mutex").push(handle);
        }
    });
    TestServerGuard {
        accept,
        conns,
        stop: stop_tx,
    }
}

/// Plain-HTTP convenience wrapper.
fn spawn_plain(listener: tokio::net::TcpListener, handler: Handler) -> TestServerGuard {
    spawn_server(listener, None, handler)
}

/// TLS convenience wrapper.
fn spawn_tls(
    listener: tokio::net::TcpListener,
    config: tokio_rustls::rustls::ServerConfig,
    handler: Handler,
) -> TestServerGuard {
    spawn_server(
        listener,
        Some(tokio_rustls::TlsAcceptor::from(Arc::new(config))),
        handler,
    )
}

/// A second, passively counting listener: every accepted connection
/// increments the counter. Used to prove a refused request never touched the
/// network (the counterfactual: a broken adapter that follows the Location,
/// resolves "localhost", or injects headers WOULD connect and increment).
struct CountingListener {
    addr: SocketAddr,
    count: Arc<AtomicUsize>,
    handle: JoinHandle<()>,
}

impl CountingListener {
    async fn bind() -> Self {
        let (listener, addr) = bind_loopback().await;
        let count = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&count);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                c.fetch_add(1, Ordering::SeqCst);
                // Accept, count, and immediately close: this listener exists
                // only to prove no connection was made.
                drop(stream);
            }
        });
        Self {
            addr,
            count,
            handle,
        }
    }

    fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

impl Drop for CountingListener {
    // The child task only increments a counter and drops the accepted socket
    // immediately; it holds no state tests depend on, so abort (not join) is
    // sufficient here — unlike TestServerGuard, which joins everything.
    fn drop(&mut self) {
        self.handle.abort();
    }
}

// ---------------------------------------------------------------------------
// Signing plumbing (harness primitives on the live wire).
// ---------------------------------------------------------------------------

/// A harness TestServer used purely as signing/verification oracle: its
/// `client_keys` map (kid -> public key) verifies incoming requests and its
/// `sign_response` signs outgoing ones.
fn oracle() -> Arc<harness::TestServer> {
    harness::TestServer::new()
}

/// Verifies an incoming request per spec 01 section 4 exactly like the
/// harness TestServer does (parse, look up kid, rebuild the signing string
/// over the WIRE target, verify). Returns the parsed RequestAuth on success.
fn verify_request(
    oracle: &harness::TestServer,
    method: &str,
    wire_target: &str,
    headers: &http::HeaderMap,
    body: &[u8],
) -> Option<RequestAuth> {
    let values: Vec<&str> = headers
        .get_all("jack-auth")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if values.len() != 1 {
        // Spec 01 section 4 step 2: the header must appear exactly once.
        return None;
    }
    let auth = parse_request_auth(&values).ok()?;
    let client_pub = *oracle.client_keys.get(&auth.kid)?;
    let msg = request_signing_string(
        method,
        wire_target,
        oracle.aud,
        &auth.kid,
        auth.ts,
        &auth.nonce,
        body,
    );
    let sig = decode_b64url_fixed(&auth.sig, 64).ok()?;
    if !mcp_jack::ed25519::verify(&client_pub, msg.as_bytes(), &sig) {
        return None;
    }
    Some(auth)
}

/// The signed Jack-Auth response header value (spec 01 section 5) via the
/// harness oracle's signing key.
fn signed_response_header(
    oracle: &harness::TestServer,
    request_sig: &str,
    status: u16,
    body: &[u8],
) -> String {
    oracle.sign_response(request_sig, status, body)
}

/// An `HttpTransport` with a finite timeout and, when `ca_der` is given, an
/// exact root store replacement (the trusted test CA).
fn make_transport(timeout: Duration, ca_der: Option<Vec<u8>>) -> HttpTransport {
    let builder = HttpTransport::builder().timeout(timeout);
    let builder = match ca_der {
        Some(ca) => builder.trusted_certificates_der(vec![ca]),
        None => builder,
    };
    builder.build().expect("transport builds")
}

/// A `SigningTransport` over the given transport: alice signs, the oracle's
/// public key is pinned (the harness TestServer's `sign_response` — the key
/// that ACTUALLY signs every response these tests receive — so expected-success
/// tests verify against the real signer), plus the fixture clock and window
/// (mirrors the harness newTransport shape).
fn signing_transport(
    transport: HttpTransport,
    oracle: &Arc<harness::TestServer>,
) -> SigningTransport<HttpTransport> {
    SigningTransport {
        transport,
        aud: FIXTURE_AUD.to_string(),
        signer: Arc::new(signer_by_name("alice")),
        server_key: oracle.pub_key,
        now: fixed_clock(FIXTURE_NOW),
        nonce: Arc::new(|| Ok(vec![7u8; 16])),
        window_seconds: 30,
    }
}

/// A signed POST with a JSON body.
fn post(url: &str, body: &[u8]) -> HttpRequest {
    HttpRequest {
        method: "POST".to_string(),
        url: url.to_string(),
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: body.to_vec(),
    }
}

/// Wire target (origin-form path?query) of a hyper request's URI.
fn wire_target(parts: &http::request::Parts) -> String {
    parts.uri.to_string()
}

/// Response headers of a verified signed JSON answer.
fn signed_json_headers(
    oracle: &harness::TestServer,
    auth: &RequestAuth,
    status: u16,
    body: &[u8],
) -> Vec<(String, String)> {
    vec![
        (
            "Jack-Auth".to_string(),
            signed_response_header(oracle, &auth.sig, status, body),
        ),
        ("Content-Type".to_string(), "application/json".to_string()),
    ]
}

/// The handler shared by the positive-path tests: verifies the request per
/// spec 01 section 4 and answers a signed 200 with the harness RPC body
/// (unsigned 401 on any verification failure, exactly like the harness).
fn signed_ok_handler(oracle: Arc<harness::TestServer>) -> Handler {
    Arc::new(move |parts, body| {
        let oracle = Arc::clone(&oracle);
        Box::pin(async move {
            let target = wire_target(&parts);
            let want = rpc_result_body(&serde_json::json!({"ok": true}));
            match verify_request(
                &oracle,
                parts.method.as_ref(),
                &target,
                &parts.headers,
                &body,
            ) {
                Some(auth) => full(200, &[], want.clone())
                    .override_headers(signed_json_headers(&oracle, &auth, 200, &want)),
                None => full(
                    401,
                    &[("Content-Type", "application/json")],
                    br#"{"error":{"code":"unknown_key","message":"verification failed"}}"#.to_vec(),
                ),
            }
        })
    })
}

impl WireResponse {
    fn override_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.headers = headers;
        self
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

/// Contract: TLS certificate validation is always on and the trusted-CA
/// path works — `trusted_certificates_der` REPLACES the root store with the
/// given test CA, so a full SigningTransport round trip over the live TLS
/// server signs (alice) and verifies (pinned oracle public key — the key
/// whose harness `sign_response` signed the answer) end to end.
/// Counterfactual caught: a backend that skips TLS validation or breaks the
/// trusted-root replacement would fail the handshake or fail verification.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_positive_path_signed_round_trip() {
    let oracle = oracle();
    let (ca_cert, ca_key) = gen_ca("mcp-jack test ca");
    let (leaf, leaf_key) = gen_leaf("127.0.0.1", &ca_cert, &ca_key);
    let (chain, key_der) = server_tls_parts(&leaf, &leaf_key, &ca_cert);
    let (listener, addr) = bind_loopback().await;
    let server = spawn_tls(
        listener,
        tls_server_config(chain, key_der),
        signed_ok_handler(Arc::clone(&oracle)),
    );

    let transport = make_transport(Duration::from_secs(15), Some(cert_der(&ca_cert)));
    let st = signing_transport(transport, &oracle);
    let resp = st
        .round_trip(post(&format!("https://{addr}/mcp"), br#"{"ping":1}"#))
        .expect("signed round trip over trusted TLS must verify");
    assert_eq!(200, resp.status);
    assert_eq!(rpc_result_body(&serde_json::json!({"ok": true})), resp.body);

    let _ = server.shutdown().await;
}

/// Contract: plain HTTP is allowed only for a literal loopback host, and the
/// same signed round trip works there (http://127.0.0.1 is accepted by the
/// URL policy). Counterfactual caught: a backend that rewrote the scheme,
/// refused loopback http, or mangled the signed target would fail
/// verification on the server or the pinned-oracle-key response check on the
/// client.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_http_loopback_signed_round_trip() {
    let oracle = oracle();
    let (listener, addr) = bind_loopback().await;
    let server = spawn_plain(listener, signed_ok_handler(Arc::clone(&oracle)));

    let transport = make_transport(Duration::from_secs(15), None);
    let st = signing_transport(transport, &oracle);
    let resp = st
        .round_trip(post(&format!("http://{addr}/mcp"), br#"{"ping":1}"#))
        .expect("signed round trip over loopback http must verify");
    assert_eq!(200, resp.status);
    assert_eq!(rpc_result_body(&serde_json::json!({"ok": true})), resp.body);

    let _ = server.shutdown().await;
}

/// Contract: TLS validation cannot be bypassed — a server whose certificate
/// was signed by an UNRELATED CA is refused even though the SANs match,
/// because the client trusts only its own CA. The error must be a
/// Transport-level error (connection/TLS failure), not a Client/Protocol
/// error (nothing about the request was wrong).
/// Counterfactual caught: a backend that fell back to the default webpki
/// roots, ignored `trusted_certificates_der`, or disabled validation would
/// let the handshake succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_ca_refused_as_transport_error() {
    let oracle = oracle();
    // The client's trusted CA...
    let (client_ca, _client_ca_key) = gen_ca("client ca");
    // ...and an independent CA that actually signs the server cert.
    let (other_ca, other_ca_key) = gen_ca("unrelated ca");
    let (leaf, leaf_key) = gen_leaf("127.0.0.1", &other_ca, &other_ca_key);
    let (chain, key_der) = server_tls_parts(&leaf, &leaf_key, &other_ca);
    let (listener, addr) = bind_loopback().await;
    let server = spawn_tls(
        listener,
        tls_server_config(chain, key_der),
        signed_ok_handler(Arc::clone(&oracle)),
    );

    let transport = make_transport(Duration::from_secs(15), Some(cert_der(&client_ca)));
    let st = signing_transport(transport, &oracle);
    let err = st
        .round_trip(post(&format!("https://{addr}/mcp"), br#"{"ping":1}"#))
        .expect_err("unknown CA must be refused");
    assert!(
        matches!(err, TransportError::Transport(ref m) if !m.is_empty()),
        "unknown CA must be a Transport error, got: {err:?}"
    );

    let _ = server.shutdown().await;
}

/// Contract: hostname/IP-SAN validation is always on — a certificate from
/// the TRUSTED CA whose SANs do not include the dialed IP (127.0.0.1) is
/// still refused. Counterfactual caught: a backend that checked only the
/// chain (or skipped name verification) would accept this connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostname_san_mismatch_refused_as_transport_error() {
    let oracle = oracle();
    let (ca_cert, ca_key) = gen_ca("mcp-jack test ca");
    // Trusted CA, but the SAN names a DNS host, never 127.0.0.1.
    let (leaf, leaf_key) = gen_leaf("mcp.example.test", &ca_cert, &ca_key);
    let (chain, key_der) = server_tls_parts(&leaf, &leaf_key, &ca_cert);
    let (listener, addr) = bind_loopback().await;
    let server = spawn_tls(
        listener,
        tls_server_config(chain, key_der),
        signed_ok_handler(Arc::clone(&oracle)),
    );

    let transport = make_transport(Duration::from_secs(15), Some(cert_der(&ca_cert)));
    let st = signing_transport(transport, &oracle);
    let err = st
        .round_trip(post(&format!("https://{addr}/mcp"), br#"{"ping":1}"#))
        .expect_err("IP-SAN mismatch must be refused");
    assert!(
        matches!(err, TransportError::Transport(_)),
        "SAN mismatch must be a Transport error, got: {err:?}"
    );

    let _ = server.shutdown().await;
}

/// Contract: redirects are NEVER followed. The live server answers a signed
/// request with an unsigned 302 and then a 307 whose Location points at a
/// counting listener; SigningTransport refuses the redirect (Err(Client),
/// message names redirects) BEFORE any second request, so the counting
/// listener's connection count stays 0. The 3xx answer is deliberately
/// unsigned: `SigningTransport` refuses redirects before verification.
/// Counterfactual caught: a backend with auto-follow enabled would connect
/// to the Location and increment the counter.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_follow_302_and_307_destination_not_contacted() {
    let oracle = oracle();
    let counting = CountingListener::bind().await;
    let (listener, addr) = bind_loopback().await;
    let location = format!("http://{}/next", counting.addr);
    let handler: Handler = Arc::new(move |parts, _body| {
        let location = location.clone();
        Box::pin(async move {
            let status = match parts.uri.path() {
                "/r307" => 307,
                _ => 302,
            };
            full(status, &[("Location", &location)], Vec::new())
        })
    });
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(15), None);
    let st = signing_transport(transport, &oracle);
    for path in ["/r302", "/r307"] {
        let err = st
            .round_trip(post(&format!("http://{addr}{path}"), br#"{"ping":1}"#))
            .expect_err("redirect must be refused");
        match &err {
            TransportError::Client(m) => assert!(
                m.contains("redirect"),
                "redirect refusal must mention redirects, got: {m}"
            ),
            other => panic!("redirect must be Err(Client), got: {other:?}"),
        }
    }
    assert_eq!(
        0,
        counting.count(),
        "the redirect Location target must never be contacted"
    );

    let _ = server.shutdown().await;
    drop(counting);
}

/// Contract: 304 is NOT in the redirect set — a signed empty-body 304 goes
/// through the normal verification and is returned to the caller as Ok
/// (interop.md 9.2). Counterfactual caught: a backend (or guard) treating
/// 304 as a redirect/refusal would break conditional requests.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_304_verifies_as_ok() {
    let oracle = oracle();
    let (listener, addr) = bind_loopback().await;
    let handler: Handler = {
        let oracle = Arc::clone(&oracle);
        Arc::new(move |parts, body| {
            let oracle = Arc::clone(&oracle);
            Box::pin(async move {
                let target = wire_target(&parts);
                match verify_request(
                    &oracle,
                    parts.method.as_ref(),
                    &target,
                    &parts.headers,
                    &body,
                ) {
                    Some(auth) => {
                        let headers = signed_json_headers(&oracle, &auth, 304, &[]);
                        full(304, &[], Vec::new()).override_headers(headers)
                    }
                    None => full(401, &[], Vec::new()),
                }
            })
        })
    };
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(15), None);
    let st = signing_transport(transport, &oracle);
    let resp = st
        .round_trip(post(&format!("http://{addr}/mcp"), br#"{"ping":1}"#))
        .expect("signed 304 must verify");
    assert_eq!(304, resp.status);
    assert!(resp.body.is_empty(), "304 body must stay empty");

    let _ = server.shutdown().await;
}

/// Contract: a signed non-2xx (404 with a body) verifies normally and passes
/// through as Ok with its status preserved, while an UNSIGNED 401 is mapped
/// to Err(Unauthenticated) with the body never parsed (spec 01 section 5).
/// Counterfactual caught: a backend with http_status_as_error-style
/// behaviour (or a verification path that rejects every non-2xx) would turn
/// the signed 404 into an error instead of a verified response.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_2xx_signed_passes_and_unsigned_401_maps() {
    let oracle = oracle();
    let (listener, addr) = bind_loopback().await;
    let handler: Handler = {
        let oracle = Arc::clone(&oracle);
        Arc::new(move |parts, body| {
            let oracle = Arc::clone(&oracle);
            Box::pin(async move {
                let target = wire_target(&parts);
                let want = br#"{"error":{"code":"not_found","message":"gone"}}"#.to_vec();
                match parts.uri.path() {
                    "/signed404" => match verify_request(
                        &oracle,
                        parts.method.as_ref(),
                        &target,
                        &parts.headers,
                        &body,
                    ) {
                        Some(auth) => {
                            let headers = signed_json_headers(&oracle, &auth, 404, &want);
                            full(404, &[], want).override_headers(headers)
                        }
                        None => full(401, &[], Vec::new()),
                    },
                    // Unsigned on purpose: exercises the 401 mapping.
                    _ => full(
                        401,
                        &[("Content-Type", "application/json")],
                        br#"{"error":{"code":"unknown_key","message":"verification failed"}}"#
                            .to_vec(),
                    ),
                }
            })
        })
    };
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(15), None);
    let st = signing_transport(transport, &oracle);
    let resp = st
        .round_trip(post(&format!("http://{addr}/signed404"), br#"{"ping":1}"#))
        .expect("signed 404 must verify and pass through");
    assert_eq!(404, resp.status);
    assert_eq!(
        br#"{"error":{"code":"not_found","message":"gone"}}"#.to_vec(),
        resp.body
    );

    let err = st
        .round_trip(post(
            &format!("http://{addr}/unsigned401"),
            br#"{"ping":1}"#,
        ))
        .expect_err("unsigned 401 must map to Unauthenticated");
    assert!(
        matches!(err, TransportError::Unauthenticated(_)),
        "unsigned 401 must be Unauthenticated, got: {err:?}"
    );

    let _ = server.shutdown().await;
}

/// Contract: a `text/event-stream` response is refused (exactly
/// `TransportError::Streaming`) on the response HEADERS, before any body
/// byte is buffered. The server writes the SSE head and then parks its body
/// on a release channel; the client carries a 1 s deadline as the bounded
/// failure guard. Counterfactual caught: an adapter that buffered the body
/// before refusing would stall on the pending body until the 1 s deadline
/// and surface Err(Transport) instead of the immediate Streaming error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_refused_on_headers_before_body_buffering() {
    let oracle = oracle();
    let gate = Arc::new(tokio::sync::Notify::new());
    let (listener, addr) = bind_loopback().await;
    let handler_gate = Arc::clone(&gate);
    let handler: Handler = Arc::new(move |_parts, _body| {
        let gate = Arc::clone(&handler_gate);
        Box::pin(async move {
            // Head goes out immediately; body never arrives until released.
            full(200, &[("Content-Type", "text/event-stream")], Vec::new())
                .with_body(BodyKind::Stalled(gate))
        })
    });
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(1), None);
    let st = signing_transport(transport, &oracle);
    let err = st
        .round_trip(post(&format!("http://{addr}/mcp"), br#"{"ping":1}"#))
        .expect_err("SSE must be refused");
    assert_eq!(
        TransportError::Streaming,
        err,
        "the SSE refusal must be the exact Streaming error (got {err:?}); a body-buffering adapter would instead hit the 1 s deadline as Transport"
    );

    // Release the server so the test ends with every task finite.
    gate.notify_one();
    let _ = server.shutdown().await;
}

impl WireResponse {
    fn with_body(mut self, body: BodyKind) -> Self {
        self.body = body;
        self
    }
}

/// Contract: response bodies are capped WHILE reading at MAX_BODY_BYTES + 1.
/// MAX-1 and MAX bodies verify normally (Ok); a MAX+1 body is truncated by
/// the adapter's `take`-limited reader and then refused by SigningTransport
/// with the documented "response body exceeds" Client error. The oversized
/// answers are deliberately unsigned: the cap refusal happens before
/// verification. Counterfactual caught: an adapter that buffered without a
/// cap (unbounded memory) or truncated BELOW the cap (breaking MAX-sized
/// bodies) would fail one of these cases.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn body_cap_boundary_trio() {
    let oracle = oracle();
    let (listener, addr) = bind_loopback().await;
    let handler: Handler = {
        let oracle = Arc::clone(&oracle);
        Arc::new(move |parts, body| {
            let oracle = Arc::clone(&oracle);
            Box::pin(async move {
                let target = wire_target(&parts);
                let Some(auth) = verify_request(
                    &oracle,
                    parts.method.as_ref(),
                    &target,
                    &parts.headers,
                    &body,
                ) else {
                    return full(401, &[], Vec::new());
                };
                let len: usize = match parts.uri.path() {
                    "/max1" => MAX_BODY_BYTES - 1,
                    "/max" => MAX_BODY_BYTES,
                    // Deliberately unsigned: the cap check precedes
                    // verification, so an unsigned oversized answer still
                    // deterministically yields the cap Client error.
                    _ => return full(200, &[], vec![b'x'; MAX_BODY_BYTES + 1]),
                };
                let want = vec![b'x'; len];
                full(200, &[], want.clone())
                    .override_headers(signed_json_headers(&oracle, &auth, 200, &want))
            })
        })
    };
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(15), None);
    let st = signing_transport(transport, &oracle);

    let resp = st
        .round_trip(post(&format!("http://{addr}/max1"), br#"{"ping":1}"#))
        .expect("MAX-1 body must verify");
    assert_eq!(MAX_BODY_BYTES - 1, resp.body.len());

    let resp = st
        .round_trip(post(&format!("http://{addr}/max"), br#"{"ping":1}"#))
        .expect("MAX body must verify");
    assert_eq!(MAX_BODY_BYTES, resp.body.len());

    let err = st
        .round_trip(post(&format!("http://{addr}/over"), br#"{"ping":1}"#))
        .expect_err("MAX+1 body must be refused");
    match &err {
        TransportError::Client(m) => assert!(
            m.contains("response body exceeds"),
            "cap refusal must mention the cap, got: {m}"
        ),
        other => panic!("oversize body must be Err(Client), got: {other:?}"),
    }

    let _ = server.shutdown().await;
}

/// Contract: the cap applies while READING, independent of framing — a
/// chunked (unknown-length) MAX+1 body split across two chunks is still
/// capped to MAX+1 bytes by the `take`-limited reader, and SigningTransport
/// refuses it with the same Client error. Counterfactual caught: an adapter
/// that only honoured content-length (or concatenated chunk boundaries
/// incorrectly) would either accept the oversized chunked body or error at
/// the transport level instead of yielding the cap error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chunked_oversize_body_capped_while_reading() {
    let oracle = oracle();
    let (listener, addr) = bind_loopback().await;
    let handler: Handler = Arc::new(move |_parts, _body| {
        Box::pin(async move {
            // MAX+1 bytes across two chunks, no Content-Length: hyper uses
            // Transfer-Encoding: chunked. Unsigned (cap precedes verify).
            full(200, &[], Vec::new()).with_body(BodyKind::Chunks(vec![
                vec![b'x'; MAX_BODY_BYTES / 2],
                vec![b'x'; MAX_BODY_BYTES - MAX_BODY_BYTES / 2 + 1],
            ]))
        })
    });
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(15), None);
    let st = signing_transport(transport, &oracle);
    let err = st
        .round_trip(post(&format!("http://{addr}/mcp"), br#"{"ping":1}"#))
        .expect_err("chunked MAX+1 body must be refused");
    match &err {
        TransportError::Client(m) => assert!(
            m.contains("response body exceeds"),
            "chunked cap refusal must mention the cap, got: {m}"
        ),
        other => panic!("chunked oversize must be Err(Client), got: {other:?}"),
    }

    let _ = server.shutdown().await;
}

/// Contract: the cap bounds READING against a producer that NEVER finishes.
/// The server sends `Content-Length: MAX_BODY_BYTES + 2` but only MAX+1
/// body bytes, then parks forever (the announced message never completes).
/// The adapter must stop reading at the `take(MAX_BODY_BYTES + 1)` cap and
/// refuse with the "response body exceeds" Client error WITHOUT waiting for
/// the announced-but-never-sent remainder.
/// Counterfactual: without the adapter's `take(MAX+1)`, the adapter would
/// block reading the missing final two bytes of the announced length and
/// eventually surface `Err(Transport)` from the 5 s deadline — so this test
/// fails for an adapter that buffers past the cap against a producer that
/// never finishes its message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn body_cap_stops_reading_held_open_producer() {
    let oracle = oracle();
    let gate = Arc::new(tokio::sync::Notify::new());
    let (listener, addr) = bind_loopback().await;
    let handler_gate = Arc::clone(&gate);
    let handler_oracle = Arc::clone(&oracle);
    let handler: Handler = Arc::new(move |parts, body| {
        let gate = Arc::clone(&handler_gate);
        let oracle = Arc::clone(&handler_oracle);
        Box::pin(async move {
            // Signed-ok handshake proves the failure is the CAP, not a
            // verification problem.
            let target = wire_target(&parts);
            let Some(auth) = verify_request(
                &oracle,
                parts.method.as_ref(),
                &target,
                &parts.headers,
                &body,
            ) else {
                return full(401, &[], Vec::new());
            };
            full(200, &[], Vec::new())
                .with_body(BodyKind::ExactThenPark {
                    announced: MAX_BODY_BYTES as u64 + 2,
                    chunks: vec![vec![b'x'; MAX_BODY_BYTES + 1]],
                    gate,
                })
                .override_headers(signed_json_headers(&oracle, &auth, 200, &[]))
        })
    });
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(5), None);
    let st = signing_transport(transport, &oracle);
    let err = st
        .round_trip(post(&format!("http://{addr}/mcp"), br#"{"ping":1}"#))
        .expect_err("an over-cap body from a never-finishing producer must be refused");
    match &err {
        TransportError::Client(m) => assert!(
            m.contains("response body exceeds"),
            "the cap refusal must fire without waiting for the announced remainder, got: {m}"
        ),
        other => panic!(
            "held-open over-cap producer must yield Err(Client), got: {other:?} (a cap-less adapter would block until the deadline as Err(Transport))"
        ),
    }

    // Release the parked producer so the guard's shutdown() can join it.
    gate.notify_one();
    let _ = server.shutdown().await;
}

/// Contract: status and ALL response headers are preserved untouched,
/// including REPEATED Jack-Auth values in wire order — nothing is merged,
/// reordered or dropped. Two observations:
///
/// a) DIRECT adapter use (`HttpTransport::round_trip`, no signing wrapper):
///    the server sends two Jack-Auth values (first signed-valid, second
///    junk) and the adapter returns Ok with BOTH values in wire order.
/// b) `SigningTransport` over the same server: verification sees two values
///    and fails with Err(Protocol) whose message names the header being
///    present more than once.
///
/// Counterfactual (why (b) is the preservation proof): if the adapter
/// DROPPED duplicate Jack-Auth values, verification would silently pass
/// with the single surviving value — the Protocol error itself proves both
/// values reached verification.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_jack_auth_response_headers_preserved() {
    let oracle = oracle();
    let (listener, addr) = bind_loopback().await;
    let handler: Handler = {
        let oracle = Arc::clone(&oracle);
        Arc::new(move |parts, body| {
            let oracle = Arc::clone(&oracle);
            Box::pin(async move {
                let target = wire_target(&parts);
                let want = rpc_result_body(&serde_json::json!({"ok": true}));
                match verify_request(
                    &oracle,
                    parts.method.as_ref(),
                    &target,
                    &parts.headers,
                    &body,
                ) {
                    Some(auth) => {
                        let valid = signed_response_header(&oracle, &auth.sig, 200, &want);
                        full(200, &[("Content-Type", "application/json")], want.clone())
                            .with_headers(vec![
                                ("Jack-Auth".to_string(), valid),
                                ("Jack-Auth".to_string(), "v1 kid=xx,ts=1,sig=yy".to_string()),
                            ])
                    }
                    None => full(401, &[], Vec::new()),
                }
            })
        })
    };
    let server = spawn_plain(listener, handler);

    // Hand-sign the request exactly like SigningTransport does (same signer,
    // aud, nonce and clock pins), so the handler takes the duplicate-header
    // branch and the first response value is signed-valid.
    let url = format!("http://{addr}/mcp");
    let target = request_target(&url).expect("policy-valid url has a target");
    let req_body = br#"{"ping":1}"#.to_vec();
    let signed = mcp_jack::client::auth::sign_request(
        &signer_by_name("alice"),
        FIXTURE_AUD,
        "POST",
        &target,
        &req_body,
        &[7u8; 16],
        FIXTURE_NOW,
    )
    .expect("hand-signed request");
    let mut request = post(&url, &req_body);
    request
        .headers
        .push(("Jack-Auth".to_string(), signed.header_value));

    // (a) DIRECT adapter use: duplicates survive in wire order, Ok response.
    let transport = make_transport(Duration::from_secs(15), None);
    let resp = transport
        .round_trip(request)
        .expect("the direct adapter must return the duplicated headers untouched");
    assert_eq!(200, resp.status);
    let values = resp.header_values("Jack-Auth");
    assert_eq!(2, values.len(), "both Jack-Auth values must survive");
    assert_eq!(
        "v1 kid=xx,ts=1,sig=yy", values[1],
        "second junk value preserved verbatim"
    );
    // The first value must be the signed-valid one for THIS request.
    let want_first = signed_response_header(
        &oracle,
        &signed.auth.sig,
        200,
        &rpc_result_body(&serde_json::json!({"ok": true})),
    );
    assert_eq!(
        want_first, values[0],
        "first value is the signed-valid one, in wire order"
    );

    // (b) SigningTransport over the same server: verification sees TWO
    // values and fails with Protocol — the proof of preservation (see the
    // counterfactual in the doc comment above).
    let st = signing_transport(make_transport(Duration::from_secs(15), None), &oracle);
    let err = st
        .round_trip(post(&url, &req_body))
        .expect_err("duplicated Jack-Auth must fail verification");
    match &err {
        TransportError::Protocol(e) => assert!(
            e.message.contains("more than once"),
            "the Protocol error must name the duplicate Jack-Auth header, got: {e:?}"
        ),
        other => panic!("duplicates must be Err(Protocol), got: {other:?}"),
    }

    let _ = server.shutdown().await;
}

impl WireResponse {
    fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.headers = headers;
        self
    }
}

/// Contract: the request line is byte-exact — the origin-form target on the
/// wire is identical to the signed target (percent escapes, query and dot
/// segments preserved, nothing normalized), and fragments are stripped
/// before sending (spec 01 section 3.1). The live server echoes back the
/// received method and raw request target; the client compares byte
/// equality against `mcp_jack::client::url::request_target` of the dialed
/// URL. Counterfactual caught: a backend that percent-decoded, removed dot
/// segments (`/../`), or appended the fragment would produce a different
/// echo than the signed target.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn origin_form_target_byte_exact_and_fragment_stripped() {
    let (listener, addr) = bind_loopback().await;
    let handler: Handler = Arc::new(|parts, _body| {
        Box::pin(async move {
            let echo = format!("{} {}", parts.method.as_str(), wire_target(&parts));
            full(200, &[("Content-Type", "text/plain")], echo.into_bytes())
        })
    });
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(15), None);

    // Dot segments + percent escapes + query preserved verbatim.
    let url = format!("http://{addr}/a%20b/../c?x=%2F&q=1");
    let req = HttpRequest {
        method: "POST".to_string(),
        url: url.clone(),
        headers: Vec::new(),
        body: Vec::new(),
    };
    let resp = transport
        .round_trip(req)
        .expect("direct adapter round trip must reach the server");
    let signed_target = request_target(&url).expect("policy-valid url has a target");
    let echo = String::from_utf8(resp.body).expect("echo is utf-8");
    assert_eq!(
        format!("POST {signed_target}"),
        echo,
        "the wire request line must be byte-identical to the signed target (dot segments, percent escapes, query preserved)"
    );

    // Fragment stripped before sending: the server must see /frag, never
    // /frag#nope.
    let url = format!("http://{addr}/frag#nope");
    let req = HttpRequest {
        method: "GET".to_string(),
        url: url.clone(),
        headers: Vec::new(),
        body: Vec::new(),
    };
    let resp = transport
        .round_trip(req)
        .expect("fragment request must reach the server");
    let echo = String::from_utf8(resp.body).expect("echo is utf-8");
    assert_eq!(
        format!("GET {}", request_target(&url).expect("target")),
        echo,
        "the fragment must be stripped from the wire request"
    );

    let _ = server.shutdown().await;
}

/// Contract: the destination policy is enforced LOCALLY by the adapter even
/// on direct use — `http://localhost:<port>/` is refused (plain http is
/// allowed only for a literal 127.x.y.z / [::1] host) BEFORE any I/O, even
/// though "localhost" resolves to the very counting listener bound on
/// 127.0.0.1. Counterfactual caught: an adapter that skipped the local
/// policy check would resolve localhost, connect, and increment the
/// counter.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_use_policy_http_localhost_refused_before_io() {
    let counting = CountingListener::bind().await;
    let transport = make_transport(Duration::from_secs(15), None);
    let err = transport
        .round_trip(HttpRequest {
            method: "GET".to_string(),
            url: format!("http://localhost:{}/", counting.addr.port()),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .expect_err("http://localhost must be refused");
    match &err {
        TransportError::Client(m) => assert!(
            m.contains("https required"),
            "policy refusal must carry the https-required message, got: {m}"
        ),
        other => panic!("policy refusal must be Err(Client), got: {other:?}"),
    }
    assert_eq!(
        0,
        counting.count(),
        "a policy-refused request must never touch the network"
    );
    drop(counting);
}

/// Contract: unrepresentable input is refused BEFORE any I/O — a header
/// value containing CR/LF (header injection), an invalid method (space), and
/// a CONNECT method (authority-form target can never match the signed
/// origin-form target) each produce a local Client error and never contact
/// the counting listener. Counterfactual caught: an adapter that passed such values to
/// its HTTP backend would either inject a second header onto the wire
/// (server-side request smuggling shape) or connect before failing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn header_injection_and_bad_method_refused_before_io() {
    let counting = CountingListener::bind().await;
    let base = format!("https://{}", counting.addr);
    let transport = make_transport(Duration::from_secs(15), None);

    let err = transport
        .round_trip(HttpRequest {
            method: "POST".to_string(),
            url: format!("{base}/mcp"),
            headers: vec![("X-Benign".to_string(), "ok\r\nX-Evil: 1".to_string())],
            body: Vec::new(),
        })
        .expect_err("CR/LF header value must be refused");
    assert!(
        matches!(&err, TransportError::Client(m) if m.contains("header value")),
        "injection refusal must be a Client header-value error, got: {err:?}"
    );

    let err = transport
        .round_trip(HttpRequest {
            method: "BAD METHOD".to_string(),
            url: format!("{base}/mcp"),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .expect_err("invalid method must be refused");
    assert!(
        matches!(&err, TransportError::Client(m) if m.contains("invalid method")),
        "bad-method refusal must be a Client error, got: {err:?}"
    );

    // CONNECT is refused before any I/O: its authority-form target could
    // never match the signed origin-form target, so the adapter refuses it
    // locally and the counting listener stays untouched.
    let err = transport
        .round_trip(HttpRequest {
            method: "CONNECT".to_string(),
            url: format!("{base}/mcp"),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .expect_err("CONNECT must be refused before any I/O");
    assert!(
        matches!(&err, TransportError::Client(m) if m.contains("CONNECT")),
        "CONNECT refusal must be a Client error naming CONNECT, got: {err:?}"
    );

    assert_eq!(
        0,
        counting.count(),
        "input-refused requests must never touch the network"
    );
    drop(counting);
}

/// Contract: a connection/read error mid-response leaves the transport
/// usable — after the server aborts the FIRST response mid-body (the head
/// promises more bytes than arrive), the SAME `HttpTransport` instance
/// completes a fresh signed round trip against the SAME server1 endpoint
/// (the handler is stateful: request 1 truncates, requests >= 2 answer a
/// signed 200, so both round trips hit one address).
///
/// What this PROVES: the failed request does not corrupt or poison the
/// agent/pool state — a subsequent signed request on the same instance to
/// the same endpoint succeeds.
///
/// What this does NOT prove (stated honestly): that the failed request's
/// socket was closed and its thread released. ureq's pool checkout probes
/// liveness (pool.rs `get` -> `is_open`) before handing out a pooled
/// connection, so even a leaked dead socket would be evicted rather than
/// reused, and this test could not distinguish eviction from correct
/// release. The hard peer-side evidence for socket release on the failure
/// path is `timeout_failure_socket_released_peer_observes_eof` above/below,
/// which observes EOF from the peer itself (ureq drops the BodyHandler
/// without pooling on read errors — reuse only happens for fulfilled bodies
/// via `ended()`).
///
/// Counterfactual caught: a backend that leaked per-request state into the
/// agent would fail the second request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_error_cleanup_and_transport_reusable() {
    let oracle = oracle();
    // ONE stateful server: request 1 truncates the response mid-body;
    // requests >= 2 are a healthy signed endpoint. The second round trip
    // goes to the SAME address on the SAME transport, proving reuse after a
    // failed request against the very endpoint that failed.
    let (listener, addr) = bind_loopback().await;
    let handler_oracle = Arc::clone(&oracle);
    let served = Arc::new(AtomicUsize::new(0));
    let handler_served = Arc::clone(&served);
    let handler: Handler = Arc::new(move |parts, body| {
        let oracle = Arc::clone(&handler_oracle);
        let served = Arc::clone(&handler_served);
        Box::pin(async move {
            let n = served.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                return full(200, &[("Content-Type", "application/json")], Vec::new()).with_body(
                    BodyKind::Truncated(vec![
                        b"this chunk arrives".to_vec(),
                        b" but the message never completes".to_vec(),
                    ]),
                );
            }
            let target = wire_target(&parts);
            let want = rpc_result_body(&serde_json::json!({"ok": true}));
            match verify_request(
                &oracle,
                parts.method.as_ref(),
                &target,
                &parts.headers,
                &body,
            ) {
                Some(auth) => full(200, &[], want.clone())
                    .override_headers(signed_json_headers(&oracle, &auth, 200, &want)),
                None => full(
                    401,
                    &[("Content-Type", "application/json")],
                    br#"{"error":{"code":"unknown_key","message":"verification failed"}}"#.to_vec(),
                ),
            }
        })
    });
    let server1 = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(15), None);
    let err = transport
        .round_trip(post(&format!("http://{addr}/mcp"), br#"{"ping":1}"#))
        .expect_err("a truncated response must be a transport error");
    assert!(
        matches!(err, TransportError::Transport(_)),
        "mid-body close must be Err(Transport), got: {err:?}"
    );

    // SAME transport, SAME server1 address: a fresh signed round trip must
    // succeed against the very endpoint that just failed.
    let st = signing_transport(transport, &oracle);
    let resp = st
        .round_trip(post(&format!("http://{addr}/mcp"), br#"{"ping":1}"#))
        .expect("the same transport must still work after a failed request");
    assert_eq!(200, resp.status);
    assert_eq!(rpc_result_body(&serde_json::json!({"ok": true})), resp.body);
    server1.shutdown().await;
}

/// Contract: the overall timeout is finite and enforced across every phase —
/// the server reads the request and then parks (never responds until
/// released); the client carries a 1 s `timeout(...)` deadline, so the call
/// RETURNS bounded with Err(Transport) whose Display names the timeout. An
/// INDEPENDENT 3 s guard (blocking thread + mpsc recv_timeout) fails the
/// test if the mechanism under test is broken, instead of hanging CI. No
/// wall-clock duration is asserted. Counterfactual caught: a backend without
/// a global deadline (or one applying it only to connect) would hang until
/// the independent guard fires.
///
/// Ownership: the client thread's termination is proven by a final join of the
/// ACTUAL `std::thread` (`join_client_thread_after_release`) AFTER the parked
/// peer has been released and the server shut down — the supported failure
/// boundary is documented on the helper; the
/// timeout-error and timeout-substring assertions run only after that
/// cleanup. A channel send or notification is NOT a join — only the real
/// `thread::join` proves the thread has fully terminated, so no thread,
/// server task, or parked peer is ever left detached.
///
/// NOTE: the drip/freeing sequence in the body below is unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeout_deadline_bounds_a_stalled_server() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let (listener, addr) = bind_loopback().await;
    let handler_gate = Arc::clone(&gate);
    let handler: Handler = Arc::new(move |_parts, _body| {
        let gate = Arc::clone(&handler_gate);
        Box::pin(async move {
            // Park before answering anything.
            gate.notified().await;
            full(200, &[], b"too late".to_vec())
        })
    });
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(1), None);
    // Run the blocking round trip on its own thread; the independent
    // recv_timeout guard below must fire BEFORE any hang becomes a CI kill.
    let (tx, rx) = std::sync::mpsc::channel();
    let url = format!("http://{addr}/mcp");
    let client = std::thread::spawn(move || {
        let result = transport.round_trip(post(&url, br#"{"ping":1}"#));
        let _ = tx.send(result);
    });
    match rx.recv_timeout(Duration::from_secs(3)) {
        Ok(result) => {
            // Deadline works: release the parked server FIRST so shutdown()
            // can join every task, join the ACTUAL client thread under a
            // bound, and ONLY THEN run the error-type and timeout-substring
            // assertions.
            gate.notify_one();
            let _ = server.shutdown().await;
            join_client_thread_after_release(client)
                .await
                .expect("client thread must terminate after peer release");
            let err = result.expect_err("a stalled server must hit the deadline");
            assert!(
                matches!(err, TransportError::Transport(_)),
                "the deadline must surface as Err(Transport), got: {err:?}"
            );
            assert!(
                err.to_string().to_lowercase().contains("timeout"),
                "the deadline error must name the timeout (ureq: \"timeout: ...\"), got: {err}"
            );
        }
        Err(_) => {
            // Guard fired: the deadline is broken. Clean up FIRST (bounded
            // peer release + server teardown), join the ACTUAL client thread,
            // and only then fail.
            gate.notify_one();
            let _ = server.shutdown().await;
            join_client_thread_after_release(client)
                .await
                .expect("client thread must terminate after peer release even though the deadline is broken");
            panic!("the deadline did not bound the call: independent 3 s guard fired");
        }
    }
}

/// Contract: the global timeout bounds the TLS HANDSHAKE itself — a server
/// that accepts the TCP connection and then never speaks (no TLS accept at
/// all) leaves the client stalled inside the handshake's first read, which
/// ureq bounds with the remaining global budget, surfacing
/// Err(Transport) naming the timeout. The independent 3 s guard (blocking
/// thread + mpsc recv_timeout) fails the test instead of hanging CI if the
/// deadline is not applied to the handshake phase. No wall-clock duration
/// is asserted. Counterfactual caught: a backend that applied its deadline
/// only to connect (or not at all during rustls complete_io) would hang
/// here until the independent guard fires.
///
/// Ownership: the client thread's termination is proven by a final join of the
/// ACTUAL `std::thread` (`join_client_thread_after_release`) AFTER the parked
/// accept task is released and joined (closing the socket,
/// unblocking the client's handshake read) — the supported failure
/// boundary is documented on the helper; the timeout assertions run only
/// after that cleanup. A channel send or notification is NOT a join — only
/// the real `thread::join` proves the thread has fully terminated, so no
/// thread or task is left detached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_handshake_stall_bounded_by_deadline() {
    let (ca_cert, _ca_key) = gen_ca("mcp-jack test ca");
    let ca_der = cert_der(&ca_cert);
    let gate = Arc::new(tokio::sync::Notify::new());
    // A PLAIN listener: accepts one connection and parks — no TLS accept,
    // no response, ever (until released).
    let (listener, addr) = bind_loopback().await;
    let listener_gate = Arc::clone(&gate);
    let mut parker = tokio::spawn(async move {
        if let Ok((_stream, _)) = listener.accept().await {
            listener_gate.notified().await;
            // _stream drops here, closing the socket.
        }
    });

    let transport = make_transport(Duration::from_secs(1), Some(ca_der));
    let (tx, rx) = std::sync::mpsc::channel();
    let url = format!("https://{addr}/mcp");
    let client = std::thread::spawn(move || {
        let result = transport.round_trip(post(&url, br#"{"ping":1}"#));
        let _ = tx.send(result);
    });
    match rx.recv_timeout(Duration::from_secs(3)) {
        Ok(result) => {
            // Release the parked accept task FIRST (closing the socket
            // unblocks the client's handshake read), join it under a bound,
            // then the FINAL join of the ACTUAL client thread AFTER the
            // owned, bounded peer release — and ONLY THEN the error-type and
            // timeout-substring assertions.
            gate.notify_one();
            let _ = join_owned_bounded(&mut parker).await;
            join_client_thread_after_release(client)
                .await
                .expect("client thread must terminate after peer release");
            let err = result.expect_err("a stalled TLS handshake must hit the deadline");
            assert!(
                matches!(err, TransportError::Transport(_)),
                "the handshake deadline must surface as Err(Transport), got: {err:?}"
            );
            assert!(
                err.to_string().to_lowercase().contains("timeout"),
                "the handshake deadline error must name the timeout, got: {err}"
            );
        }
        Err(_) => {
            // Guard fired: the deadline is broken. Clean up FIRST — release
            // the parked accept task (closing the socket unblocks the
            // client's handshake read) and join it, then the FINAL join of
            // the ACTUAL client thread AFTER the owned, bounded peer release
            // — and only then fail.
            gate.notify_one();
            let _ = join_owned_bounded(&mut parker).await;
            join_client_thread_after_release(client)
                .await
                .expect("client thread must terminate after peer release even though the deadline is broken");
            panic!("the deadline did not bound the TLS handshake: independent 3 s guard fired");
        }
    }
}

/// Contract: the adapter adds NOTHING to the wire beyond the caller's
/// headers (plus framing) — no User-Agent, no Accept, no Accept-Encoding
/// reach the server, and the caller's Jack-Auth appears exactly once. The
/// live server echoes every received header name into the body. Counterfactual
/// caught: a backend that auto-injected ureq/http defaults would show
/// user-agent/accept/accept-encoding in the echo.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_exactness_no_auto_headers_and_single_jack_auth() {
    let (listener, addr) = bind_loopback().await;
    let handler: Handler = Arc::new(|parts, _body| {
        Box::pin(async move {
            // `keys()` DEDUPLICATES, so the jack-auth count is echoed
            // separately via get_all: otherwise a duplicated header would be
            // unobservable (the exactly-once assertion could never fail).
            let jack_auth_count = parts.headers.get_all("jack-auth").iter().count();
            let names: Vec<&str> = parts.headers.keys().map(|k| k.as_str()).collect();
            full(
                200,
                &[("Content-Type", "text/plain")],
                format!("{};jack-auth={}", names.join(","), jack_auth_count).into_bytes(),
            )
        })
    });
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(15), None);
    let req = HttpRequest {
        method: "POST".to_string(),
        url: format!("http://{addr}/mcp"),
        headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            (
                "Jack-Auth".to_string(),
                "v1 kid=x,ts=1,nonce=y,sig=z".to_string(),
            ),
        ],
        body: br#"{"ping":1}"#.to_vec(),
    };
    let resp = transport
        .round_trip(req)
        .expect("direct adapter round trip must reach the server");
    let names = String::from_utf8(resp.body).expect("echo is utf-8");
    let (names, jack_auth) = names
        .split_once(";jack-auth=")
        .expect("the echo carries the jack-auth count");
    for banned in ["user-agent", "accept", "accept-encoding"] {
        assert!(
            !names.split(',').any(|n| n.eq_ignore_ascii_case(banned)),
            "no auto {banned} header may reach the wire, got: {names}"
        );
    }
    assert_eq!(
        1,
        jack_auth.parse::<usize>().expect("jack-auth count echoes"),
        "the caller's Jack-Auth must appear exactly once on the wire (counted via get_all, not the deduplicated keys), got: {names}"
    );

    let _ = server.shutdown().await;
}

/// Contract: the adapter's LOCAL pre-I/O refusals fire before ANY network
/// contact — caller framing headers (`Content-Length` / `Transfer-Encoding`),
/// a nonempty body on a non-POST/PUT/PATCH method, a duplicate `Host`, and
/// non-UTF-8 `Host` / `Authorization` values each yield an immediate
/// `TransportError::Client` naming the guard, and the counting listener's
/// connection count stays 0 across ALL sub-cases.
/// Counterfactual caught: a backend that deferred these checks to ureq-proto's
/// `analyze()` (which rejects duplicate/non-UTF-8 Host/Authorization only
/// AFTER connect) would connect and increment the counter; one that sent a
/// disagreeing framing header would also reach the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn framing_and_shape_refusals_never_touch_network() {
    let counting = CountingListener::bind().await;
    let base = format!("https://{}", counting.addr);
    let transport = make_transport(Duration::from_secs(15), None);

    // a) A caller Content-Length disagreeing with a nonempty body would
    //    silently drop the body (request-smuggling surface).
    let err = transport
        .round_trip(HttpRequest {
            method: "POST".to_string(),
            url: format!("{base}/mcp"),
            headers: vec![("Content-Length".to_string(), "0".to_string())],
            body: b"real bytes".to_vec(),
        })
        .expect_err("caller Content-Length must be refused");
    assert!(
        matches!(&err, TransportError::Client(m) if m.contains("framing header")),
        "Content-Length refusal must name the framing header guard, got: {err:?}"
    );

    // b) Same for Transfer-Encoding: framing is derived from the raw body.
    let err = transport
        .round_trip(HttpRequest {
            method: "POST".to_string(),
            url: format!("{base}/mcp"),
            headers: vec![("Transfer-Encoding".to_string(), "chunked".to_string())],
            body: b"real bytes".to_vec(),
        })
        .expect_err("caller Transfer-Encoding must be refused");
    assert!(
        matches!(&err, TransportError::Client(m) if m.contains("framing header")),
        "Transfer-Encoding refusal must name the framing header guard, got: {err:?}"
    );

    // c) More than one Host header: ureq-proto rejects it only AFTER connect.
    let err = transport
        .round_trip(HttpRequest {
            method: "POST".to_string(),
            url: format!("{base}/mcp"),
            headers: vec![
                (
                    "Host".to_string(),
                    format!("127.0.0.1:{}", counting.addr.port()),
                ),
                ("Host".to_string(), "127.0.0.1:9".to_string()),
            ],
            body: Vec::new(),
        })
        .expect_err("duplicate Host must be refused");
    assert!(
        matches!(&err, TransportError::Client(m) if m.contains("duplicate Host header")),
        "duplicate Host refusal must name the duplicate Host guard, got: {err:?}"
    );

    // d) A non-UTF-8 Host value: the obs-text byte 0x80 IS a valid
    //    HeaderValue, so only the adapter's explicit UTF-8 guard catches it
    //    before any I/O (the backend rejects it after connecting).
    let err = transport
        .round_trip(HttpRequest {
            method: "POST".to_string(),
            url: format!("{base}/mcp"),
            headers: vec![("Host".to_string(), "127.0.0.1:1\u{80}".to_string())],
            body: Vec::new(),
        })
        .expect_err("non-UTF-8 Host must be refused");
    assert!(
        matches!(&err, TransportError::Client(m) if m.contains("must be UTF-8")),
        "non-UTF-8 Host refusal must name the UTF-8 guard, got: {err:?}"
    );

    // e) Same guard for a non-UTF-8 Authorization value.
    let err = transport
        .round_trip(HttpRequest {
            method: "POST".to_string(),
            url: format!("{base}/mcp"),
            headers: vec![("Authorization".to_string(), "Basic\u{80}x".to_string())],
            body: Vec::new(),
        })
        .expect_err("non-UTF-8 Authorization must be refused");
    assert!(
        matches!(&err, TransportError::Client(m) if m.contains("must be UTF-8")),
        "non-UTF-8 Authorization refusal must name the UTF-8 guard, got: {err:?}"
    );

    // f) A nonempty body on GET: the backend would silently omit it.
    let err = transport
        .round_trip(HttpRequest {
            method: "GET".to_string(),
            url: format!("{base}/mcp"),
            headers: Vec::new(),
            body: b"silent victim".to_vec(),
        })
        .expect_err("GET with a body must be refused");
    assert!(
        matches!(&err, TransportError::Client(m) if m.contains("request body")),
        "GET-with-body refusal must name the request body guard, got: {err:?}"
    );

    assert_eq!(
        0,
        counting.count(),
        "every locally refused request must be rejected before ANY network contact"
    );
    drop(counting);
}

/// Contract: extension methods are transmitted EXACTLY — the adapter enables
/// ureq's `allow_non_standard_methods(true)`, so a WebDAV-style PROPFIND is
/// sent verbatim on the request line and the live server echoes
/// "PROPFIND /mcp" byte-exactly. Counterfactual caught: a backend that
/// rejected extension methods (ureq's default method/version check, which
/// fires only AFTER DNS/TCP connect — making the earlier version waste I/O
/// and refuse late) fails this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn extension_method_propfind_transmitted_exactly() {
    let (listener, addr) = bind_loopback().await;
    let handler: Handler = Arc::new(|parts, _body| {
        Box::pin(async move {
            let echo = format!("{} {}", parts.method.as_str(), wire_target(&parts));
            full(200, &[("Content-Type", "text/plain")], echo.into_bytes())
        })
    });
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(15), None);
    let resp = transport
        .round_trip(HttpRequest {
            method: "PROPFIND".to_string(),
            url: format!("http://{addr}/mcp"),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .expect("a PROPFIND extension method must be transmitted, not refused");
    let echo = String::from_utf8(resp.body).expect("echo is utf-8");
    assert_eq!(
        "PROPFIND /mcp", echo,
        "the extension method must reach the wire exactly as written"
    );

    let _ = server.shutdown().await;
}

/// Trusted TLS positive control: a finite paced body reaches autonomous EOF
/// and returns all four exact frames. Cleanup (including the real std-thread
/// join) completes before any behavioral assertion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_trickling_body_completes_with_sufficient_deadline() {
    let (ca, ca_key) = gen_ca("paced TLS CA");
    let (leaf, leaf_key) = gen_leaf("127.0.0.1", &ca, &ca_key);
    let (chain, key) = server_tls_parts(&leaf, &leaf_key, &ca);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let (listener, addr) = bind_loopback().await;
    let handler_gate = Arc::clone(&gate);
    let handler: Handler = Arc::new(move |_parts, _body| {
        let gate = Arc::clone(&handler_gate);
        Box::pin(async move {
            full(200, &[], Vec::new()).with_body(BodyKind::Trickle {
                gate,
                frames: (0..4).map(|_| vec![b'.'; 64]).collect(),
            })
        })
    });
    let server = spawn_tls(listener, tls_server_config(chain, key), handler);
    let transport = make_transport(Duration::from_secs(10), Some(cert_der(&ca)));
    let drip_gate = Arc::clone(&gate);
    let mut drip = tokio::spawn(async move {
        for _ in 0..4 {
            drip_gate.add_permits(1);
            tokio::time::sleep(TRICKLE_INTERVAL).await;
        }
        drip_gate.add_permits(1); // autonomous clean EOF
    });
    let (tx, rx) = std::sync::mpsc::channel();
    let client = std::thread::spawn(move || {
        let result = transport.round_trip(post(&format!("https://{addr}/mcp"), b"request"));
        let _ = tx.send(result);
    });
    let received =
        tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(6))).await;
    let shutdown = server.shutdown().await;
    let (drip_result, drip_aborted) = join_owned_bounded(&mut drip).await;
    let client_join = join_client_thread_after_release(client).await;
    let received = received
        .expect("receiver task")
        .expect("client result before 6 s guard");
    assert!(
        matches!(drip_result, Ok(())) && !drip_aborted,
        "drip did not finish: {drip_result:?}, aborted={drip_aborted}"
    );
    assert!(shutdown.cooperative(), "server shutdown: {shutdown:?}");
    assert_eq!(client_join, Ok(()));
    let response = received.expect("trusted TLS paced response succeeds");
    assert_eq!(response.body, vec![b'.'; 256]);
}

/// A paced TLS body keeps making progress past the one-second cumulative
/// budget. Its autonomous EOF means a broken deadline still finishes; the
/// independent receive guard only bounds a regression hang.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_overall_deadline_bounds_trickling_chunked_body() {
    let (ca, ca_key) = gen_ca("paced TLS CA");
    let (leaf, leaf_key) = gen_leaf("127.0.0.1", &ca, &ca_key);
    let (chain, key) = server_tls_parts(&leaf, &leaf_key, &ca);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let (listener, addr) = bind_loopback().await;
    let handler_gate = Arc::clone(&gate);
    let handler: Handler = Arc::new(move |_parts, _body| {
        let gate = Arc::clone(&handler_gate);
        Box::pin(async move {
            full(200, &[], Vec::new()).with_body(BodyKind::Trickle {
                gate,
                frames: (0..TRICKLE_FRAMES).map(|_| vec![b'.'; 64]).collect(),
            })
        })
    });
    let server = spawn_tls(listener, tls_server_config(chain, key), handler);
    let transport = make_transport(Duration::from_secs(1), Some(cert_der(&ca)));
    let drip_gate = Arc::clone(&gate);
    let mut drip = tokio::spawn(async move {
        for _ in 0..TRICKLE_FRAMES {
            drip_gate.add_permits(1);
            tokio::time::sleep(TRICKLE_INTERVAL).await;
        }
        drip_gate.add_permits(1); // autonomous clean EOF
    });
    let (tx, rx) = std::sync::mpsc::channel();
    let client = std::thread::spawn(move || {
        let result = transport.round_trip(post(&format!("https://{addr}/mcp"), b"request"));
        let _ = tx.send(result);
    });
    let received =
        tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(6))).await;
    let shutdown = server.shutdown().await;
    let (drip_result, drip_aborted) = join_owned_bounded(&mut drip).await;
    let client_join = join_client_thread_after_release(client).await;
    let received = received
        .expect("receiver task")
        .expect("result before independent 6 s guard");
    let result = received;
    assert!(
        matches!(drip_result, Ok(())) && !drip_aborted,
        "drip did not finish: {drip_result:?}, aborted={drip_aborted}"
    );
    assert_eq!(client_join, Ok(()));
    assert!(shutdown.cooperative(), "server shutdown: {shutdown:?}");
    let err = result.expect_err("cumulative TLS body deadline must fire");
    assert!(
        matches!(&err, TransportError::Transport(m) if m.to_lowercase().contains("timeout")),
        "expected actual timeout, got {err:?}"
    );
}

/// Calling the synchronous transport from a current-thread Tokio runtime is
/// supported; an independently owned fixture runtime serves the socket. Its
/// finite self-release guard bounds a deadline-removal regression.
#[tokio::test]
async fn synchronous_transport_call_on_current_thread_runtime() {
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server_thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("fixture runtime");
        runtime.block_on(async move {
            let (listener, addr) = bind_loopback().await;
            let handler: Handler = Arc::new(|_parts, _body| {
                Box::pin(async move { full(200, &[], b"served".to_vec()) })
            });
            let server = spawn_plain(listener, handler);
            let _ = ready_tx.send(addr);
            tokio::select! {
                _ = stop_rx => {}
                _ = tokio::time::sleep(Duration::from_secs(10)) => {}
            }
            server.shutdown().await
        })
    });
    let ready =
        tokio::task::spawn_blocking(move || ready_rx.recv_timeout(Duration::from_secs(5))).await;
    let addr = match ready {
        Ok(Ok(addr)) => Some(addr),
        _ => None,
    };
    let response = addr.map(|addr| {
        let transport = make_transport(Duration::from_secs(5), None);
        transport.round_trip(HttpRequest {
            method: "GET".to_string(),
            url: format!("http://{addr}/"),
            headers: Vec::new(),
            body: Vec::new(),
        })
    });
    let _ = stop_tx.send(());
    let joined = tokio::task::spawn_blocking(move || server_thread.join()).await;
    let server_outcome = joined.expect("server join task").expect("server thread");
    let ready_ok = addr.is_some();
    let shutdown_ok = server_outcome.cooperative();
    let response = response.and_then(Result::ok);
    assert!(ready_ok, "independent fixture server did not become ready");
    assert!(shutdown_ok, "fixture shutdown: {server_outcome:?}");
    assert_eq!(response.expect("synchronous call succeeds").body, b"served");
}

/// The trickle body needs one permit per data frame and one more for EOF.
#[test]
fn trickle_requires_fresh_permit_for_each_frame_and_eof() {
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let mut body = TestBody::Trickle {
        gate: Arc::clone(&gate),
        frames: [Bytes::from_static(b"first"), Bytes::from_static(b"second")]
            .into_iter()
            .collect(),
        wait: None,
    };
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);

    assert!(matches!(
        Pin::new(&mut body).poll_frame(&mut cx),
        Poll::Pending
    ));

    gate.add_permits(1);
    let first = Pin::new(&mut body).poll_frame(&mut cx);
    match first {
        Poll::Ready(Some(Ok(frame))) => {
            assert_eq!(frame.into_data().unwrap(), Bytes::from_static(b"first"))
        }
        other => panic!("expected first data frame, got {other:?}"),
    }
    assert_eq!(gate.available_permits(), 0);
    assert!(matches!(
        Pin::new(&mut body).poll_frame(&mut cx),
        Poll::Pending
    ));

    gate.add_permits(1);
    let second = Pin::new(&mut body).poll_frame(&mut cx);
    match second {
        Poll::Ready(Some(Ok(frame))) => {
            assert_eq!(frame.into_data().unwrap(), Bytes::from_static(b"second"))
        }
        other => panic!("expected second data frame, got {other:?}"),
    }
    assert_eq!(gate.available_permits(), 0);
    assert!(matches!(
        Pin::new(&mut body).poll_frame(&mut cx),
        Poll::Pending
    ));

    gate.add_permits(1);
    assert!(matches!(
        Pin::new(&mut body).poll_frame(&mut cx),
        Poll::Ready(None)
    ));
    assert_eq!(gate.available_permits(), 0);
}
/// Positive control: four paced 64-byte frames complete successfully, yielding
/// the exact 256-byte response.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trickling_body_completes_with_sufficient_deadline() {
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let (listener, addr) = bind_loopback().await;
    let handler_gate = Arc::clone(&gate);
    let handler: Handler = Arc::new(move |_parts, _body| {
        let gate = Arc::clone(&handler_gate);
        Box::pin(async move {
            full(
                200,
                &[("Content-Type", "application/octet-stream")],
                Vec::new(),
            )
            .with_body(BodyKind::Trickle {
                gate,
                frames: (0..4).map(|_| vec![b'.'; 64]).collect(),
            })
        })
    });
    let server = spawn_plain(listener, handler);
    let transport = make_transport(Duration::from_secs(10), None);

    let drip_gate = Arc::clone(&gate);
    let mut drip = tokio::spawn(async move {
        for _ in 0..4 {
            drip_gate.add_permits(1);
            tokio::time::sleep(TRICKLE_INTERVAL).await;
        }
        drip_gate.add_permits(1);
    });

    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let client = std::thread::spawn(move || {
        let result = transport.round_trip(post(&format!("http://{addr}/mcp"), b"request"));
        let _ = result_tx.send(result);
    });
    let received =
        tokio::task::spawn_blocking(move || result_rx.recv_timeout(Duration::from_secs(5))).await;

    let shutdown = server.shutdown().await;
    let (drip_result, drip_aborted) = join_owned_bounded(&mut drip).await;
    let client_join = join_client_thread_after_release(client).await;

    let received = received.expect("client result receiver task");
    let result = received
        .expect("client result arrived before independent 5 s guard")
        .expect("result channel");
    assert!(
        matches!(drip_result, Ok(())) && !drip_aborted,
        "drip producer did not finish cleanly: {drip_result:?}, aborted={drip_aborted}"
    );
    assert!(
        shutdown.cooperative(),
        "server did not shut down cooperatively: {shutdown:?}"
    );
    assert_eq!(client_join, Ok(()), "client thread did not join cleanly");
    let response = result;
    assert_eq!(response.body, vec![b'.'; 256]);
}

/// A finite trickle with controlled nominal spacing. Scheduling may delay
/// individual permits; shutdown independently closes the owned fixture if
/// the client does not finish as expected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overall_deadline_bounds_trickling_chunked_body() {
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let (listener, addr) = bind_loopback().await;
    let handler_gate = Arc::clone(&gate);
    let handler: Handler = Arc::new(move |_parts, _body| {
        let gate = Arc::clone(&handler_gate);
        Box::pin(async move {
            // Chunked framing (unknown size hint, default), one 64-byte frame
            // per permit, ~80 ms apart: progress on every read.
            full(200, &[("Content-Type", "application/json")], Vec::new()).with_body(
                BodyKind::Trickle {
                    gate,
                    frames: (0..TRICKLE_FRAMES).map(|_| vec![b'.'; 64]).collect(),
                },
            )
        })
    });
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(1), None);

    // The drip: one permit per frame, paced; the FINAL permit ends the body.
    // Sent AUTONOMOUSLY, before any client result: a resettable-idle backend
    // receives the complete body (~3.3 s) and returns Ok — failing the
    // expect_err below; removing the deadline cannot hang the call because
    // EOF always arrives.
    let drip_gate = Arc::clone(&gate);
    let mut drip = tokio::spawn(async move {
        for _ in 0..TRICKLE_FRAMES {
            drip_gate.add_permits(1);
            tokio::time::sleep(TRICKLE_INTERVAL).await;
        }
        drip_gate.add_permits(1);
    });

    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let client = std::thread::spawn(move || {
        let result = transport.round_trip(post(&format!("http://{addr}/mcp"), br#"{"ping":1}"#));
        let _ = result_tx.send(result);
    });
    let received =
        tokio::task::spawn_blocking(move || result_rx.recv_timeout(Duration::from_secs(6))).await;

    // Always release and join owned work before asserting the client result.
    let shutdown = server.shutdown().await;
    let (drip_result, drip_aborted) = join_owned_bounded(&mut drip).await;
    let client_join = join_client_thread_after_release(client).await;
    let received = received.expect("client result receiver task");
    let result = received.expect("client result arrived before independent 6 s guard");
    let err = result.expect_err("a trickling body must hit the cumulative deadline");
    assert!(
        matches!(&err, TransportError::Transport(ref m) if m.to_lowercase().contains("timeout")),
        "the cumulative deadline must surface as Err(Transport) naming the timeout, got: {err:?}"
    );
    assert!(
        matches!(drip_result, Ok(())) && !drip_aborted,
        "drip producer did not finish cleanly: {drip_result:?}, aborted={drip_aborted}"
    );
    assert_eq!(client_join, Ok(()), "client thread did not join cleanly");
    assert!(
        shutdown.cooperative(),
        "server did not shut down cooperatively: {shutdown:?}"
    );
}

/// Socket release is checked by the peer's cooperative EOF outcome; the
/// fallback assertion rejects any non-closure result. The peer drains queued
/// request bytes (positive data is NOT closure evidence) before waiting for
/// EOF or read error. The client-side error assertions run after peer outcome
/// collection; the peer handle is retained across bounded join/abort fallback.
/// guard expired, failing the outcome assertion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeout_failure_socket_released_peer_observes_eof() {
    // tokio's `io-util` extension traits are NOT enabled under this feature
    // set, so the peer task drives the socket through the AsyncRead/AsyncWrite
    // trait poll methods directly (tiny poll_fn loops).
    use tokio::io::{AsyncRead, AsyncWrite};

    /// Writes the whole fixture; a real write error or zero-progress write is
    /// returned, never swallowed: the caller must not mistake a fixture failure
    /// for client closure.
    async fn peer_write_all(
        stream: &mut tokio::net::TcpStream,
        mut data: &[u8],
    ) -> std::io::Result<()> {
        std::future::poll_fn(|cx| loop {
            let n = match std::task::ready!(Pin::new(&mut *stream).poll_write(cx, data)) {
                Ok(n) => n,
                Err(e) => return Poll::Ready(Err(e)),
            };
            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "peer fixture write made no progress",
                )));
            }
            data = &data[n..];
            if data.is_empty() {
                return Poll::Ready(Ok(()));
            }
        })
        .await
    }
    /// One read result. Positive data is the client's queued REQUEST bytes —
    /// never closure evidence; only a TRUE zero-length read is EOF. No inner
    /// timeout: the single absolute guard around the drain loop owns timing.
    /// `ReadBuf` + `poll_read` because `io-util` is not enabled.
    enum PeerRead {
        Data,
        Eof,
        Error,
    }
    async fn peer_read_one(stream: &mut tokio::net::TcpStream) -> PeerRead {
        let mut buf = [0u8; 512];
        let mut rb = tokio::io::ReadBuf::new(&mut buf);
        match std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_read(cx, &mut rb)).await {
            Ok(()) => {
                let n = rb.filled().len();
                if n == 0 {
                    PeerRead::Eof
                } else {
                    PeerRead::Data
                }
            }
            Err(_) => PeerRead::Error,
        }
    }

    /// What the single owned peer task observed.
    #[derive(Debug, PartialEq, Eq)]
    enum PeerOutcome {
        /// The client closed the socket (true zero-length EOF or read error)
        /// after the queued request bytes were drained — the success signal:
        /// the failure path released the connection.
        ClientClosed,
        /// The peer's own absolute 10 s guard expired — the client KEPT
        /// the failed socket open (the retained-socket failure signal,
        /// asserted against).
        ClientKeptSocket,
        /// The fixture write errored or the write bound expired — a peer/
        /// fixture problem, NEVER evidence of client closure.
        PeerWriteFailed,
        /// The client never even connected (deadline broken long before).
        NoConnection,
    }

    // Fixed head+partial-body fixture: announces 64 body bytes, sends 5,
    // keeps the socket open WITHOUT closing.
    let fixture: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 64\r\n\r\nshort";

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().expect("local addr");

    // ONE owned peer task: accept once, write the fixture, then drain the
    // client's queued request bytes and read until the client closes
    // (true EOF/error) or the absolute 10 s guard fires.
    let mut peer = tokio::spawn(async move {
        let (mut stream, _) =
            match tokio::time::timeout(Duration::from_secs(10), listener.accept()).await {
                Ok(Ok(accepted)) => accepted,
                _ => return PeerOutcome::NoConnection,
            };
        match tokio::time::timeout(
            Duration::from_secs(10),
            peer_write_all(&mut stream, fixture),
        )
        .await
        {
            Ok(Ok(())) => {}
            // Write error or bound expiry: NOT evidence of client closure.
            Ok(Err(_)) => return PeerOutcome::PeerWriteFailed,
            Err(_) => return PeerOutcome::PeerWriteFailed,
        }
        // ONE absolute guard around the ENTIRE drain loop — never extended
        // per read: draining the queued request bytes plus waiting for the
        // client's release must fit inside a single bound.
        let drain = async {
            loop {
                match peer_read_one(&mut stream).await {
                    // The client's queued request bytes: DATA, not closure
                    // evidence.
                    PeerRead::Data => continue,
                    // True zero-length read or read error: the CLIENT
                    // released its failed socket — the release signal this
                    // test asserts.
                    PeerRead::Eof | PeerRead::Error => return PeerOutcome::ClientClosed,
                }
            }
        };
        match tokio::time::timeout(Duration::from_secs(10), drain).await {
            Ok(outcome) => outcome,
            // The absolute guard expired: the client kept the socket open.
            Err(_) => PeerOutcome::ClientKeptSocket,
        }
    });

    let transport = make_transport(Duration::from_secs(1), None);
    let result = transport.round_trip(post(&format!("http://{addr}/mcp"), br#"{"ping":1}"#));

    // Collect the peer outcome FIRST (handle RETAINED across the join
    // bound; abort+await fallback so nothing is detached), and only then
    // run the client-side error assertions.
    let outcome = match tokio::time::timeout(Duration::from_secs(15), &mut peer).await {
        Ok(joined) => joined.expect("peer task must not panic"),
        Err(_) => {
            peer.abort();
            let _ = (&mut peer).await;
            panic!("peer did not terminate within its own absolute guard");
        }
    };
    let err = result.expect_err("an announced-but-missing body must hit the deadline");
    assert!(
        matches!(&err, TransportError::Transport(ref m) if m.to_lowercase().contains("timeout")),
        "the deadline must surface as Err(Transport) naming the timeout, got: {err:?}"
    );
    assert_eq!(
        PeerOutcome::ClientClosed,
        outcome,
        "the peer must observe the client closing its FAILED socket (release on the error path); \
         ClientKeptSocket = the peer's absolute 10 s guard expired (socket retained), \
         PeerWriteFailed = the fixture write failed or its bound expired (a real, distinguishable \
         outcome — never counted as client closure), \
         NoConnection = the client never connected; got: {outcome:?}"
    );
}

/// Contract: `TestServerGuard::shutdown()` terminates a child parked INSIDE a
/// TLS accept. The child's stop-select only runs between polls, so the TLS
/// accept phase must live INSIDE the select — previously it ran outside,
/// meaning the stop signal was never observed while a handshake parked and
/// `shutdown` joined the child forever. The regression signal: the outer
/// shutdown bound firing and the parked client socket never seeing EOF.
/// Counterfactual caught: an accept/TLS phase outside the child's stop-select
/// keeps the child alive past the stop signal; the outer shutdown bound fires
/// and this test FAILS instead of hanging.
/// Determinism: the client connects and sends NOTHING, so the handshake read
/// parks forever inside `TlsAcceptor::accept`; every wait is bounded with a
/// RETAINED handle and an abort+await fallback. No wall-clock assertion —
/// only that cooperative shutdown completes under the independent bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_joins_child_parked_in_tls_accept() {
    use tokio::io::AsyncRead;

    /// One read result from the raw client socket. Positive data (the server
    /// never sends any before the handshake completes) is NOT closure
    /// evidence; only a TRUE zero-length read or a read error ends the loop.
    /// `ReadBuf` + `poll_read` because `io-util` is not enabled.
    enum RawRead {
        /// The socket produced bytes: data, not closure evidence.
        Data,
        /// True zero-length read: the peer closed its end.
        Eof,
        /// A read error.
        Error,
    }
    /// One read through the trait poll methods; no timeout inside — the
    /// caller's single absolute guard owns timing.
    async fn raw_read_one(stream: &mut tokio::net::TcpStream) -> RawRead {
        let mut buf = [0u8; 512];
        let mut rb = tokio::io::ReadBuf::new(&mut buf);
        match std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_read(cx, &mut rb)).await {
            Ok(()) => {
                if rb.filled().is_empty() {
                    RawRead::Eof
                } else {
                    RawRead::Data
                }
            }
            Err(_) => RawRead::Error,
        }
    }

    /// What the raw client task ultimately observed.
    #[derive(Debug, PartialEq, Eq)]
    enum RawPeerEnd {
        /// The server dropped the parked child, closing the socket: the
        /// success signal this test asserts.
        Eof,
        /// The read errored (treated as closure evidence for a dying child).
        Error,
    }

    let (ca_cert, ca_key) = gen_ca("mcp-jack test ca");
    let (leaf, leaf_key) = gen_leaf("127.0.0.1", &ca_cert, &ca_key);
    let (chain, key_der) = server_tls_parts(&leaf, &leaf_key, &ca_cert);
    let (listener, addr) = bind_loopback().await;
    // Handler content is irrelevant: the handshake never completes because
    // the client sends nothing, so the child parks inside the TLS accept.
    let (handshake_tx, mut handshake_rx) = tokio::sync::mpsc::channel(1);
    let server = spawn_server_observed(
        listener,
        Some(tokio_rustls::TlsAcceptor::from(Arc::new(
            tls_server_config(chain, key_der),
        ))),
        signed_ok_handler(oracle()),
        Some(handshake_tx),
    );

    // Raw client (owned, RETAINED handle): connect, prove the TCP accept
    // happened, then read until a TRUE zero-length read or error. NO timeout
    // inside the task — the main body wraps every wait in a bound.
    let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
    let mut client = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("raw client connect");
        let _ = tx.send(());
        loop {
            match raw_read_one(&mut stream).await {
                // Positive reads are NOT closure evidence — keep reading.
                RawRead::Data => continue,
                RawRead::Eof => return RawPeerEnd::Eof,
                RawRead::Error => return RawPeerEnd::Error,
            }
        }
    });

    let connected = tokio::time::timeout(Duration::from_secs(5), &mut rx).await;
    let connected_ok = matches!(connected, Ok(Ok(())));
    let ack = tokio::time::timeout(Duration::from_secs(5), handshake_rx.recv()).await;
    let shutdown_outcome = server.shutdown().await;
    let client_join = tokio::time::timeout(Duration::from_secs(10), &mut client).await;
    let client_end = match client_join {
        Ok(Ok(end)) => Some(end),
        Ok(Err(_)) => None,
        Err(_) => {
            client.abort();
            let _ = (&mut client).await;
            None
        }
    };
    assert!(connected_ok, "raw client connect failed");
    assert!(
        matches!(ack, Ok(Some(()))),
        "TLS accept was not first-polled: {ack:?}"
    );
    assert!(
        shutdown_outcome.cooperative(),
        "TLS child shutdown was not cooperative: {shutdown_outcome:?}"
    );
    assert_eq!(
        shutdown_outcome.children.len(),
        1,
        "expected exactly one child"
    );
    assert_eq!(client_end, Some(RawPeerEnd::Eof));
}

/// Contract: dropping the `TestServerGuard` WITHOUT calling `shutdown()` —
/// the shape of the panic/unwind failure path — terminates a child parked
/// forever inside its handler. Honest semantics: Drop ABORTS (it runs in a
/// sync context and cannot join); the abort is OBSERVED as socket closure
/// from the peer side. Nothing here claims Drop joins or awaits anything.
/// Counterfactual caught: a Drop that failed to abort children (or a child
/// ignoring the stop signal) leaves the parked child's socket open; the raw
/// client never sees EOF and its bound fires, failing the test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guard_drop_on_unwind_path_aborts_parked_child() {
    use tokio::io::{AsyncRead, AsyncWrite};

    /// One read result from the raw client socket. Positive data (the
    /// response the aborted child never sends) is NOT closure evidence; only
    /// a TRUE zero-length read or a read error ends the loop. `ReadBuf` +
    /// `poll_read` because `io-util` is not enabled.
    enum RawRead {
        Data,
        Eof,
        Error,
    }
    async fn raw_read_one(stream: &mut tokio::net::TcpStream) -> RawRead {
        let mut buf = [0u8; 512];
        let mut rb = tokio::io::ReadBuf::new(&mut buf);
        match std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_read(cx, &mut rb)).await {
            Ok(()) => {
                if rb.filled().is_empty() {
                    RawRead::Eof
                } else {
                    RawRead::Data
                }
            }
            Err(_) => RawRead::Error,
        }
    }

    /// What the raw client task ultimately observed.
    #[derive(Debug, PartialEq, Eq)]
    enum RawPeerEnd {
        /// The child was aborted at its next poll (serve future + socket
        /// dropped): the success signal this test asserts.
        Eof,
        /// The read errored.
        Error,
    }

    let (listener, addr) = bind_loopback().await;
    // Handler that proves it was entered, then parks FOREVER on a Notify it
    // was built with (never notified): exactly the shape of a hung handler.
    let handler_gate = Arc::new(tokio::sync::Notify::new());
    // Entered signal: bounded mpsc, capacity 1 — its Sender is Clone, so an
    // `Fn` handler can signal per call.
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::channel(1);
    let handler: Handler = Arc::new(move |_parts, _body| {
        // mpsc Sender is Clone, so an `Fn` handler can signal per call.
        let entered = entered_tx.clone();
        let gate = Arc::clone(&handler_gate);
        Box::pin(async move {
            // Receiver is alive by construction: the main body waits on it
            // before the unwind, so this resolves against the capacity-1 slot.
            let _ = entered.send(()).await;
            gate.notified().await;
            unreachable!("the gate is never notified; the handler must stay parked")
        })
    });
    let server = spawn_plain(listener, handler);

    // Raw client (owned, RETAINED handle): connect, write ONE complete POST
    // request (Content-Length: 0, so hyper finishes reading and calls the
    // parked handler), then read until a TRUE zero-length read or error.
    let request: &[u8] = b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n";
    let mut client = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("raw client connect");
        let mut pending = request;
        std::future::poll_fn(|cx| loop {
            let n = std::task::ready!(Pin::new(&mut stream).poll_write(cx, pending))
                .expect("raw client write");
            if n == 0 {
                panic!("raw client write made no progress");
            }
            pending = &pending[n..];
            if pending.is_empty() {
                return Poll::Ready(());
            }
        })
        .await;
        loop {
            match raw_read_one(&mut stream).await {
                // Positive reads are NOT closure evidence — keep reading.
                RawRead::Data => continue,
                RawRead::Eof => return RawPeerEnd::Eof,
                RawRead::Error => return RawPeerEnd::Error,
            }
        }
    });
    // Bounded, RETAINED wait for the entered signal: the child is now parked
    // forever inside the handler.
    let entered = tokio::time::timeout(Duration::from_secs(5), entered_rx.recv()).await;

    // Simulated test failure while the guard is alive: Drop must run during
    // unwind and abort the parked child. AssertUnwindSafe: the guard is not
    // structurally unwind-safe, the test only relies on Drop running.
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = server; // Drop runs during unwind, not before it.
        panic!("simulated test failure before cleanup");
    }));

    // Collect the raw client's end AFTER the unwind: retained handle +
    // abort+await fallback, bounded. The parked child is aborted at its next
    // poll, dropping the serve future and closing the socket.
    let client_join = tokio::time::timeout(Duration::from_secs(10), &mut client).await;
    let client_end = match client_join {
        Ok(Ok(end)) => Some(end),
        Ok(Err(_)) => None,
        Err(_) => {
            client.abort();
            let _ = (&mut client).await;
            None
        }
    };
    let payload_matches = unwound.err().is_some_and(|payload| {
        payload.downcast_ref::<&str>() == Some(&"simulated test failure before cleanup")
            || payload
                .downcast_ref::<String>()
                .is_some_and(|s| s == "simulated test failure before cleanup")
    });
    let entered_ok = entered.is_ok() && entered.as_ref().is_ok_and(|r| r.is_some());
    assert!(entered_ok, "handler never entered (fixture bug)");
    assert!(payload_matches, "simulated panic payload differed");

    // Assertion only after the cleanup: Drop aborted (never joined) the
    // parked child and its socket was observed closed from the peer side.
    assert_eq!(
        Some(RawPeerEnd::Eof),
        client_end,
        "dropping the guard on the unwind path must ABORT the parked child, closing its \
         socket; Error = the read errored instead of a clean EOF"
    );
}

/// Read TLS records until rustls has consumed the whole ClientHello and has
/// queued a real server flight. TCP reads may split that one handshake message.
async fn collect_rustls_server_flight(
    stream: &mut tokio::net::TcpStream,
    conn: &mut tokio_rustls::rustls::ServerConnection,
) -> Result<Vec<u8>, String> {
    use std::io::Cursor;
    use tokio::io::AsyncReadExt;
    let mut input = [0u8; 4096];
    while !conn.wants_write() {
        let n = stream.read(&mut input).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("client closed before complete ClientHello".to_string());
        }
        let mut cursor = Cursor::new(&input[..n]);
        let mut consumed = 0usize;
        while consumed < n {
            let read = conn.read_tls(&mut cursor).map_err(|e| e.to_string())?;
            if read == 0 {
                return Err("rustls consumed no ClientHello bytes".to_string());
            }
            consumed += read;
            conn.process_new_packets().map_err(|e| e.to_string())?;
        }
    }
    let mut flight = Vec::new();
    conn.write_tls(&mut flight).map_err(|e| e.to_string())?;
    if flight.is_empty() {
        return Err("rustls generated an empty server flight".to_string());
    }
    Ok(flight)
}

enum HandshakePeerOutcome {
    Closed,
    GuardExpired,
}

/// A real rustls flight is sent in finite paced writes. After the flight, a
/// short bounded drain distinguishes client closure from peer-guard expiry;
/// an idle-only client that waits for HTTP cannot pass merely by timing out.
/// Accept, TLS input, flight generation, fragmentation, and drain share one
/// absolute peer lifetime bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_handshake_fragment_deadline_is_absolute() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const PEER_BOUND: Duration = Duration::from_secs(10);
    const RECEIVE_GUARD: Duration = Duration::from_secs(6);
    const JOIN_GUARD: Duration = Duration::from_secs(12);
    const FRAGMENTS: usize = 40;
    const GAP: Duration = Duration::from_millis(80);

    let (ca, ca_key) = gen_ca("fragment deadline CA");
    let (leaf, leaf_key) = gen_leaf("127.0.0.1", &ca, &ca_key);
    let (chain, key) = server_tls_parts(&leaf, &leaf_key, &ca);
    let config = std::sync::Arc::new(tls_server_config(chain, key));
    let (listener, addr) = bind_loopback().await;
    let mut peer = tokio::spawn(async move {
        let bounded = tokio::time::timeout(PEER_BOUND, async move {
            let (mut stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
            let mut conn =
                tokio_rustls::rustls::ServerConnection::new(config).map_err(|e| e.to_string())?;
            let flight = collect_rustls_server_flight(&mut stream, &mut conn).await?;
            let flight_len = flight.len();
            let chunk_size = flight.len().div_ceil(FRAGMENTS).max(1);
            // A write failure ends transmission but is not closure evidence;
            // proceed to drain queued bytes until the client truly closes.
            for part in flight.chunks(chunk_size).take(FRAGMENTS) {
                if stream.write_all(part).await.is_err() {
                    break;
                }
                tokio::time::sleep(GAP).await;
            }
            // The short absolute drain guard is NOT closure evidence: a client
            // still waiting for HTTP after completing TLS must fail the oracle.
            let mut buf = [0u8; 1024];
            let drained = tokio::time::timeout(Duration::from_millis(200), async {
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => return HandshakePeerOutcome::Closed,
                        Ok(_) => continue,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => return HandshakePeerOutcome::Closed,
                    }
                }
            })
            .await
            .unwrap_or(HandshakePeerOutcome::GuardExpired);
            Ok::<(usize, HandshakePeerOutcome), String>((flight_len, drained))
        })
        .await;
        match bounded {
            Ok(Ok(outcome)) => Ok(outcome),
            Ok(Err(e)) => Err(e),
            Err(_) => Ok((0, HandshakePeerOutcome::GuardExpired)),
        }
    });

    let transport = make_transport(Duration::from_secs(1), Some(cert_der(&ca)));
    let (client_tx, client_rx) = std::sync::mpsc::channel();
    let client = std::thread::spawn(move || {
        let result = transport.round_trip(post(&format!("https://{addr}/mcp"), b"request"));
        let _ = client_tx.send(result);
    });

    // Collect the independent client result before joining the still-running
    // peer. Retain the JoinHandle through bounded wait and abort+await fallback.
    let received = tokio::task::spawn_blocking(move || client_rx.recv_timeout(RECEIVE_GUARD)).await;
    let peer_result = match tokio::time::timeout(JOIN_GUARD, &mut peer).await {
        Ok(joined) => joined,
        Err(_) => {
            peer.abort();
            peer.await
        }
    };
    let client_join = join_client_thread_after_release(client).await;

    let received = received.ok().and_then(Result::ok);
    let peer_result = match peer_result {
        Ok(Ok(result)) => Some(result),
        Ok(Err(e)) => {
            assert_eq!(client_join, Ok(()), "client thread did not join");
            panic!("peer fixture failed: {e}");
        }
        Err(e) => {
            assert_eq!(client_join, Ok(()), "client thread did not join");
            panic!("peer task failed or was aborted: {e}");
        }
    };
    assert_eq!(client_join, Ok(()), "client thread did not join");
    let (flight_len, peer_outcome) = peer_result.expect("peer result collected");
    assert!(flight_len > 0, "rustls generated no server flight");
    let err = received
        .expect("client result before independent receive guard")
        .expect_err("incomplete handshake must fail");
    assert!(
        matches!(&err, TransportError::Transport(m) if m.to_lowercase().contains("timeout")),
        "expected handshake timeout, got {err:?}"
    );
    assert!(
        matches!(peer_outcome, HandshakePeerOutcome::Closed),
        "peer did not observe client closure"
    );
}
