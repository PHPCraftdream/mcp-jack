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

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::common::harness::{
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
// Live hyper 1.x server (mirrors interop/rust/src/bin/interop_server.rs).
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

impl WireResponse {
    fn with_body(mut self, body: BodyKind) -> Self {
        self.body = body;
        self
    }
}

impl WireResponse {
    fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.headers = headers;
        self
    }
}

mod request_wire;
mod responses;
mod trickle_and_shutdown;
