//! Blocking HTTP/HTTPS transport using Hyper HTTP/1, Tokio, Hickory DNS and rustls.
//! System DNS configuration, hosts, and trust roots are snapshotted at build
//! time. Each round trip creates a private runtime on an owned worker thread;
//! the worker joins its resolver and HTTP-driver tasks before returning.

use crate::client::{
    error::ClientError,
    transport::{HttpRequest, HttpResponse, Transport, TransportError},
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::task::JoinSet;
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, ServerName},
    ClientConfig, RootCertStore,
};

const DEFAULT_TIMEOUT_SECONDS: u64 = 15;
const MAX_OWNED_TASKS: usize = 64;

/// Blocking HTTP/HTTPS transport. No redirects, proxy, insecure TLS, or retries.
pub struct HttpTransport {
    timeout: Duration,
    roots: Arc<RootCertStore>,
    dns: DnsSnapshot,
}
/// Builder for [`HttpTransport`].
pub struct HttpTransportBuilder {
    timeout: Duration,
    roots: Vec<Vec<u8>>,
}
#[derive(Clone)]
struct DnsSnapshot {
    config: hickory_resolver::config::ResolverConfig,
    options: hickory_resolver::config::ResolverOpts,
    hosts: Arc<hickory_resolver::Hosts>,
}
impl Default for HttpTransportBuilder {
    fn default() -> Self {
        Self::new()
    }
}
impl HttpTransportBuilder {
    fn new() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
            roots: Vec::new(),
        }
    }
    /// Sets the absolute round-trip deadline; zero is rejected by `build`.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    /// Replaces the default WebPKI roots with the supplied DER certificates.
    pub fn trusted_certificates_der(mut self, ders: Vec<Vec<u8>>) -> Self {
        self.roots = ders;
        self
    }
    /// Snapshots local resolver configuration, hosts, and certificate roots.
    pub fn build(self) -> Result<HttpTransport, ClientError> {
        if self.timeout.is_zero() {
            return Err(ClientError::Client(
                "jack client: http transport: timeout must be greater than zero".into(),
            ));
        }
        let (config, mut options) =
            hickory_resolver::system_conf::read_system_conf().map_err(|e| {
                ClientError::Client(format!(
                    "jack client: http transport: system DNS configuration: {e}"
                ))
            })?;
        let hosts = hickory_resolver::Hosts::from_system().map_err(|e| {
            ClientError::Client(format!(
                "jack client: http transport: system hosts file: {e}"
            ))
        })?;
        options.use_hosts_file = hickory_resolver::config::ResolveHosts::Never;
        options.cache_size = 0;
        options.num_concurrent_reqs = 1;
        options.attempts = 1;
        let mut roots = RootCertStore::empty();
        if self.roots.is_empty() {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        } else {
            for der in self.roots {
                roots.add(CertificateDer::from(der)).map_err(|e| {
                    ClientError::Client(format!(
                        "jack client: http transport: invalid trusted certificate: {e}"
                    ))
                })?;
            }
        }
        Ok(HttpTransport {
            timeout: self.timeout,
            roots: Arc::new(roots),
            dns: DnsSnapshot {
                config,
                options,
                hosts: Arc::new(hosts),
            },
        })
    }
}
impl HttpTransport {
    /// Creates a transport with the 15-second default deadline.
    pub fn new() -> Result<Self, ClientError> {
        Self::builder().build()
    }
    /// Returns a builder with the default timeout and trust roots.
    pub fn builder() -> HttpTransportBuilder {
        HttpTransportBuilder::new()
    }
}
impl Default for HttpTransport {
    fn default() -> Self {
        Self::new().expect("default HttpTransport configuration is valid")
    }
}

#[derive(Clone)]
struct TaskHandle(Arc<Mutex<TaskState>>);
struct TaskState {
    closed: bool,
    overflow: bool,
    tasks: JoinSet<Result<(), TransportError>>,
}
impl hickory_resolver::proto::runtime::Spawn for TaskHandle {
    fn spawn_bg<F>(&mut self, f: F)
    where
        F: Future<Output = Result<(), hickory_resolver::proto::ProtoError>> + Send + 'static,
    {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed {
            return;
        }
        if state.tasks.len() >= MAX_OWNED_TASKS {
            state.overflow = true;
            return;
        }
        state.tasks.spawn(async move {
            f.await.map_err(|e| {
                TransportError::Transport(format!("jack client: http transport: DNS task: {e}"))
            })
        });
    }
}
#[derive(Clone)]
struct OwnedRuntime(
    hickory_resolver::proto::runtime::TokioRuntimeProvider,
    TaskHandle,
);
impl hickory_resolver::proto::runtime::RuntimeProvider for OwnedRuntime {
    type Handle = TaskHandle;
    type Timer=<hickory_resolver::proto::runtime::TokioRuntimeProvider as hickory_resolver::proto::runtime::RuntimeProvider>::Timer;
    type Udp=<hickory_resolver::proto::runtime::TokioRuntimeProvider as hickory_resolver::proto::runtime::RuntimeProvider>::Udp;
    type Tcp=<hickory_resolver::proto::runtime::TokioRuntimeProvider as hickory_resolver::proto::runtime::RuntimeProvider>::Tcp;
    fn create_handle(&self) -> Self::Handle {
        self.1.clone()
    }
    fn connect_tcp(
        &self,
        a: SocketAddr,
        b: Option<SocketAddr>,
        c: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        hickory_resolver::proto::runtime::RuntimeProvider::connect_tcp(&self.0, a, b, c)
    }
    fn bind_udp(
        &self,
        a: SocketAddr,
        b: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        hickory_resolver::proto::runtime::RuntimeProvider::bind_udp(&self.0, a, b)
    }
}
async fn drain(owner: &Arc<Mutex<TaskState>>) -> Result<(), TransportError> {
    let (mut tasks, overflow) = {
        let mut state = owner.lock().unwrap_or_else(|e| e.into_inner());
        state.closed = true;
        (
            std::mem::replace(&mut state.tasks, JoinSet::new()),
            state.overflow,
        )
    };
    tasks.abort_all();
    let mut panic = None;
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            if !error.is_cancelled() && panic.is_none() {
                panic = Some(error.to_string());
            }
        }
    }
    if let Some(error) = panic {
        return Err(TransportError::Transport(format!(
            "jack client: http transport: owned task failed: {error}"
        )));
    }
    if overflow {
        return Err(TransportError::Transport(
            "jack client: http transport: owned task limit exceeded".into(),
        ));
    }
    Ok(())
}
trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

impl Transport for HttpTransport {
    fn round_trip(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        let started = Instant::now();
        let deadline = started.checked_add(self.timeout).ok_or_else(|| {
            TransportError::Client("jack client: http transport: deadline overflow".into())
        })?;
        crate::client::url::validate_base_url(&req.url)
            .map_err(|e| TransportError::Client(e.to_string()))?;
        let target = crate::client::url::request_target(&req.url)
            .map_err(|e| TransportError::Client(e.to_string()))?;
        let absolute = req
            .url
            .split('#')
            .next()
            .unwrap_or(&req.url)
            .parse::<http::Uri>()
            .map_err(|e| {
                TransportError::Client(format!("jack client: http transport: invalid url: {e}"))
            })?;
        let method = http::Method::from_bytes(req.method.as_bytes()).map_err(|e| {
            TransportError::Client(format!("jack client: http transport: invalid method: {e}"))
        })?;
        if method == http::Method::CONNECT {
            return Err(TransportError::Client(
                "jack client: http transport: CONNECT is refused".into(),
            ));
        }
        if !req.body.is_empty() && !["POST", "PUT", "PATCH"].contains(&method.as_str()) {
            return Err(TransportError::Client(format!(
                "jack client: http transport: request body is refused for method {method}"
            )));
        }
        let mut pairs = Vec::with_capacity(req.headers.len());
        for (name, value) in &req.headers {
            if name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("transfer-encoding")
            {
                return Err(TransportError::Client(format!(
                    "jack client: http transport: caller framing header {name} is refused"
                )));
            }
            let name = http::HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
                TransportError::Client(format!(
                    "jack client: http transport: invalid header name: {e}"
                ))
            })?;
            let value = http::HeaderValue::from_bytes(value.as_bytes()).map_err(|e| {
                TransportError::Client(format!(
                    "jack client: http transport: invalid header value: {e}"
                ))
            })?;
            if (name == http::header::HOST || name == http::header::AUTHORIZATION)
                && value.to_str().is_err()
            {
                return Err(TransportError::Client(format!(
                    "jack client: http transport: {name} header value must be UTF-8"
                )));
            }
            pairs.push((name, value));
        }
        if pairs
            .iter()
            .filter(|(name, _)| name == http::header::HOST)
            .count()
            > 1
        {
            return Err(TransportError::Client(
                "jack client: http transport: duplicate Host header is refused".into(),
            ));
        }
        let authority = absolute
            .authority()
            .ok_or_else(|| {
                TransportError::Client("jack client: http transport: missing authority".into())
            })?
            .as_str()
            .to_owned();
        let mut request = http::Request::builder()
            .method(method)
            .uri(target)
            .body(Full::new(Bytes::from(req.body)))
            .map_err(|e| TransportError::Client(format!("jack client: http transport: {e}")))?;
        for (name, value) in pairs {
            request.headers_mut().append(name, value);
        }
        if !request.headers().contains_key(http::header::HOST) {
            request.headers_mut().insert(
                http::header::HOST,
                http::HeaderValue::from_str(&authority).map_err(|e| {
                    TransportError::Client(format!(
                        "jack client: http transport: invalid Host: {e}"
                    ))
                })?,
            );
        }
        let roots = self.roots.clone();
        let dns = self.dns.clone();
        let worker = std::thread::Builder::new()
            .name("jack-http-round-trip".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| {
                        TransportError::Transport(format!(
                            "jack client: http transport: runtime: {e}"
                        ))
                    })?;
                runtime.block_on(run(request, absolute, deadline, roots, dns))
            })
            .map_err(|e| {
                TransportError::Transport(format!("jack client: http transport: worker: {e}"))
            })?;
        worker.join().map_err(|panic| {
            TransportError::Transport(format!(
                "jack client: http transport: worker panicked: {}",
                panic
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("unknown panic")
            ))
        })?
    }
}
/// The operation is terminal: dropping it drops in-flight I/O, then the owned
/// task registry is closed, aborted, and joined. It is not retryable or resumable.
async fn run(
    request: http::Request<Full<Bytes>>,
    destination: http::Uri,
    deadline: Instant,
    roots: Arc<RootCertStore>,
    dns: DnsSnapshot,
) -> Result<HttpResponse, TransportError> {
    let owner = Arc::new(Mutex::new(TaskState {
        closed: false,
        overflow: false,
        tasks: JoinSet::new(),
    }));
    let operation_owner = owner.clone();
    let mut operation = tokio::spawn(async move {
        let provider = OwnedRuntime(
            hickory_resolver::proto::runtime::TokioRuntimeProvider::new(),
            TaskHandle(operation_owner.clone()),
        );
        let mut resolver = hickory_resolver::Resolver::builder_with_config(
            dns.config,
            hickory_resolver::name_server::GenericConnector::new(provider),
        )
        .with_options(dns.options)
        .build();
        resolver.set_hosts(dns.hosts);
        perform(request, destination, roots, resolver, operation_owner).await
    });
    let operation_result =
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), &mut operation)
            .await
        {
            Ok(Ok(result)) => Some(result),
            Ok(Err(error)) => Some(Err(TransportError::Transport(format!(
                "jack client: http transport: operation task failed: {error}"
            )))),
            Err(_) => {
                operation.abort();
                let joined = operation.await;
                Some(Err(match joined {
                    Err(error) if error.is_cancelled() => TransportError::Transport(
                        "jack client: http transport: absolute round-trip timeout exceeded".into(),
                    ),
                    Err(error) => TransportError::Transport(format!(
                    "jack client: http transport: operation task failed during timeout: {error}"
                )),
                    Ok(Err(error)) => error,
                    Ok(Ok(_)) => TransportError::Transport(
                        "jack client: http transport: absolute round-trip timeout exceeded".into(),
                    ),
                }))
            }
        };
    let cleanup = drain(&owner).await;
    match operation_result.expect("operation result is always set") {
        Err(error) => {
            let _ = cleanup;
            Err(error)
        }
        Ok(response) => {
            cleanup?;
            Ok(response)
        }
    }
}

async fn perform(
    request: http::Request<Full<Bytes>>,
    destination: http::Uri,
    roots: Arc<RootCertStore>,
    resolver: hickory_resolver::Resolver<
        hickory_resolver::name_server::GenericConnector<OwnedRuntime>,
    >,
    owner: Arc<Mutex<TaskState>>,
) -> Result<HttpResponse, TransportError> {
    let auth = destination.authority().ok_or_else(|| {
        TransportError::Client("jack client: http transport: missing authority".into())
    })?;
    let raw = auth.host();
    let host = raw.trim_start_matches('[').trim_end_matches(']');
    let port = auth
        .port_u16()
        .unwrap_or(if destination.scheme_str() == Some("https") {
            443
        } else {
            80
        });
    let addresses: Vec<IpAddr> = if let Ok(ip) = host.parse() {
        vec![ip]
    } else {
        let query = if host.ends_with('.') {
            host.to_owned()
        } else {
            format!("{host}.")
        };
        resolver
            .lookup_ip(query)
            .await
            .map_err(|e| {
                TransportError::Transport(format!("jack client: http transport: DNS: {e}"))
            })?
            .iter()
            .collect()
    };
    if addresses.is_empty() {
        return Err(TransportError::Transport(
            "jack client: http transport: DNS returned no addresses".into(),
        ));
    }
    let mut stream = None;
    let mut last = None;
    for ip in addresses.into_iter().take(16) {
        match tokio::net::TcpStream::connect(SocketAddr::new(ip, port)).await {
            Ok(value) => {
                stream = Some(value);
                break;
            }
            Err(error) => last = Some(error),
        }
    }
    let stream = stream.ok_or_else(|| {
        TransportError::Transport(format!(
            "jack client: http transport: connect: {}",
            last.map(|e| e.to_string())
                .unwrap_or_else(|| "no address".into())
        ))
    })?;
    let io: Box<dyn Io> = if destination.scheme_str() == Some("https") {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .map_err(|e| {
                TransportError::Transport(format!("jack client: http transport: TLS config: {e}"))
            })?
            .with_root_certificates((*roots).clone())
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let name = ServerName::try_from(host.to_owned()).map_err(|e| {
            TransportError::Transport(format!("jack client: http transport: TLS server name: {e}"))
        })?;
        Box::new(
            tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(name, stream)
                .await
                .map_err(|e| {
                    TransportError::Transport(format!("jack client: http transport: TLS: {e}"))
                })?,
        )
    } else {
        Box::new(stream)
    };
    let (mut sender, connection) = http1::handshake::<_, Full<Bytes>>(TokioIo::new(io))
        .await
        .map_err(|e| {
            TransportError::Transport(format!("jack client: http transport: HTTP handshake: {e}"))
        })?;
    {
        let mut state = owner.lock().unwrap_or_else(|e| e.into_inner());
        if state.tasks.len() >= MAX_OWNED_TASKS {
            state.overflow = true;
        } else {
            state.tasks.spawn(async move {
                connection.await.map_err(|e| {
                    TransportError::Transport(format!(
                        "jack client: http transport: HTTP driver: {e}"
                    ))
                })
            });
        }
    }
    if owner.lock().unwrap_or_else(|e| e.into_inner()).overflow {
        return Err(TransportError::Transport(
            "jack client: http transport: owned task limit exceeded".into(),
        ));
    }
    let response = sender.send_request(request).await.map_err(|e| {
        TransportError::Transport(format!("jack client: http transport: HTTP request: {e}"))
    })?;
    let status = response.status().as_u16();
    if response
        .headers()
        .get_all(http::header::CONTENT_TYPE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| crate::client::transport::media_type(v) == "text/event-stream")
    {
        return Err(TransportError::Streaming);
    }
    let mut headers = Vec::new();
    for (name, value) in response.headers().iter() {
        let value = value.to_str().map_err(|_| {
            TransportError::Transport(format!(
                "jack client: http transport: non-UTF-8 response header {name}"
            ))
        })?;
        headers.push((name.as_str().to_owned(), value.to_owned()));
    }
    let cap = crate::client::transport::MAX_BODY_BYTES;
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| {
            TransportError::Transport(format!("jack client: http transport: response body: {e}"))
        })?;
        if let Ok(data) = frame.into_data() {
            let remaining = cap.saturating_add(1).saturating_sub(bytes.len());
            bytes.extend_from_slice(&data[..data.len().min(remaining)]);
            if bytes.len() > cap {
                break;
            }
        }
    }
    Ok(HttpResponse {
        status,
        headers,
        body: bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::{
        config::{NameServerConfig, ResolverConfig, ResolverOpts},
        proto::{op::Message, xfer::Protocol},
    };
    use std::net::UdpSocket;
    use tokio::sync::{mpsc, oneshot};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stalled_dns_obeys_deadline_and_releases_socket() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
        let (seen_tx, mut seen_rx) = mpsc::channel(1);
        let mut peer_task = tokio::spawn(async move {
            let mut bytes = [0u8; 2048];
            tokio::time::timeout(Duration::from_secs(5), async {
                if let Ok((size, source)) = peer.recv_from(&mut bytes).await {
                    let _ = seen_tx.send((bytes[..size].to_vec(), source)).await;
                    let _ = (&mut stop_rx).await;
                }
            })
            .await
        });
        let config = ResolverConfig::from_parts(
            None,
            vec![],
            vec![NameServerConfig::new(peer_addr, Protocol::Udp)],
        );
        let mut options = ResolverOpts::default();
        options.use_hosts_file = hickory_resolver::config::ResolveHosts::Never;
        options.cache_size = 0;
        options.attempts = 1;
        options.num_concurrent_reqs = 1;
        options.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4Only;
        options.timeout = Duration::from_secs(10);
        let transport = HttpTransport {
            timeout: Duration::from_millis(200),
            roots: Arc::new(RootCertStore::empty()),
            dns: DnsSnapshot {
                config,
                options,
                hosts: Arc::new(hickory_resolver::Hosts::default()),
            },
        };
        let request = HttpRequest {
            method: "GET".into(),
            url: "https://dns-timeout.test:443/".into(),
            headers: vec![],
            body: vec![],
        };
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let client = std::thread::spawn(move || {
            let _ = result_tx.send(transport.round_trip(request));
        });
        let result =
            tokio::task::spawn_blocking(move || result_rx.recv_timeout(Duration::from_secs(2)))
                .await;
        let observed = tokio::time::timeout(Duration::from_secs(5), seen_rx.recv()).await;
        let _ = stop_tx.send(());
        let peer_result = tokio::time::timeout(Duration::from_secs(2), &mut peer_task).await;
        let peer_aborted = if peer_result.is_err() {
            peer_task.abort();
            let _ = peer_task.await;
            true
        } else {
            false
        };
        let join_result = tokio::task::spawn_blocking(move || client.join()).await;
        let parsed = observed.ok().flatten().and_then(|(bytes, source)| {
            Message::from_vec(&bytes)
                .ok()
                .map(|message| (message, source))
        });
        assert!(matches!(peer_result, Ok(Ok(Ok(())))) && !peer_aborted);
        assert!(matches!(join_result, Ok(Ok(()))));
        assert!(
            matches!(result, Ok(Ok(Err(TransportError::Transport(message)))) if message.contains("absolute round-trip timeout exceeded"))
        );
        let (message, source) = parsed.expect("valid captured DNS query");
        assert_eq!(message.queries()[0].name().to_utf8(), "dns-timeout.test.");
        assert!(UdpSocket::bind(source).is_ok());
    }

    struct DropMark(Arc<std::sync::atomic::AtomicBool>);
    impl Drop for DropMark {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn task_owner_drain_aborts_and_closes_spawn_control() {
        let owner = Arc::new(Mutex::new(TaskState {
            closed: false,
            overflow: false,
            tasks: JoinSet::new(),
        }));
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (entered_tx, entered_rx) = oneshot::channel();
        let mark = DropMark(dropped.clone());
        let mut handle = TaskHandle(owner.clone());
        hickory_resolver::proto::runtime::Spawn::spawn_bg(&mut handle, async move {
            let _mark = mark;
            let _ = entered_tx.send(());
            std::future::pending::<Result<(), hickory_resolver::proto::ProtoError>>().await
        });
        let entered = tokio::time::timeout(Duration::from_secs(1), entered_rx).await;
        let drained = drain(&owner).await;
        assert!(matches!(entered, Ok(Ok(()))));
        assert!(drained.is_ok());
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        let state = owner.lock().unwrap();
        assert!(state.closed);
        assert!(state.tasks.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn private_dns_resolves_and_trusted_tls_round_trip_succeeds() {
        use hickory_resolver::proto::{
            op::{MessageType, Query},
            rr::{Name, RData, Record, RecordType},
        };
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        let params = CertificateParams::new(vec!["dns-positive.test".into()]).unwrap();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let cert_der = cert.der().as_ref().to_vec();
        let server_config = tokio_rustls::rustls::ServerConfig::builder_with_provider(
            tokio_rustls::rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(tokio_rustls::rustls::ALL_VERSIONS)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
        let dns = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_addr = dns.local_addr().unwrap();
        let (stop_dns, mut stop_dns_rx) = oneshot::channel::<()>();
        let (query_tx, mut query_rx) = mpsc::channel(1);
        let mut dns_task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), async {
                let mut buf = [0u8; 2048];
                tokio::select! {
                    received = dns.recv_from(&mut buf) => if let Ok((len, peer)) = received {
                        let request = Message::from_vec(&buf[..len]).unwrap();
                        let _ = query_tx.send(request.queries()[0].name().to_utf8()).await;
                        let name = Name::from_ascii("dns-positive.test.").unwrap();
                        let mut reply = Message::new();
                        reply.set_id(request.id()).set_message_type(MessageType::Response).set_recursion_desired(true).set_recursion_available(true);
                        reply.add_query(Query::query(name.clone(), RecordType::A));
                        reply.add_answer(Record::from_rdata(name, 30, RData::A(hickory_resolver::proto::rr::rdata::A(std::net::Ipv4Addr::LOCALHOST))));
                        let _ = dns.send_to(&reply.to_vec().unwrap(), peer).await;
                    },
                    _ = &mut stop_dns_rx => {},
                }
            }).await
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let (stop_tls, mut stop_tls_rx) = oneshot::channel::<()>();
        let mut tls_task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), async {
                tokio::select! {
                    _ = &mut stop_tls_rx => Ok::<(), Box<dyn std::error::Error + Send + Sync>>(()),
                    accepted = async {
                        let (stream, _) = listener.accept().await?;
                        let stream = acceptor.accept(stream).await?;
                        let service = hyper::service::service_fn(|_: hyper::Request<hyper::body::Incoming>| async {
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(Bytes::from_static(b"dns-tls-ok"))))
                        });
                        hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service).await?;
                        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
                    } => accepted,
                }
            }).await
        });
        let config = ResolverConfig::from_parts(
            None,
            vec![],
            vec![NameServerConfig::new(dns_addr, Protocol::Udp)],
        );
        let mut options = ResolverOpts::default();
        options.use_hosts_file = hickory_resolver::config::ResolveHosts::Never;
        options.cache_size = 0;
        options.attempts = 1;
        options.num_concurrent_reqs = 1;
        options.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4Only;
        options.timeout = Duration::from_secs(3);
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(cert_der)).unwrap();
        let transport = HttpTransport {
            timeout: Duration::from_secs(3),
            roots: Arc::new(roots),
            dns: DnsSnapshot {
                config,
                options,
                hosts: Arc::new(hickory_resolver::Hosts::default()),
            },
        };
        let request = HttpRequest {
            method: "GET".into(),
            url: format!("https://dns-positive.test:{port}/"),
            headers: vec![],
            body: vec![],
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let client = std::thread::spawn(move || {
            let _ = tx.send(transport.round_trip(request));
        });
        let result =
            tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(4))).await;
        let query_name = tokio::time::timeout(Duration::from_secs(1), query_rx.recv()).await;
        let _ = stop_dns.send(());
        let _ = stop_tls.send(());
        let dns_result = tokio::time::timeout(Duration::from_secs(1), &mut dns_task).await;
        let dns_aborted = if dns_result.is_err() {
            dns_task.abort();
            let _ = dns_task.await;
            true
        } else {
            false
        };
        let tls_result = tokio::time::timeout(Duration::from_secs(1), &mut tls_task).await;
        let tls_aborted = if tls_result.is_err() {
            tls_task.abort();
            let _ = tls_task.await;
            true
        } else {
            false
        };
        let client_join = tokio::task::spawn_blocking(move || client.join()).await;
        assert!(matches!(client_join, Ok(Ok(()))));
        assert!(matches!(dns_result, Ok(Ok(Ok(())))) && !dns_aborted);
        assert!(matches!(tls_result, Ok(Ok(Ok(Ok(()))))) && !tls_aborted);
        assert_eq!(query_name, Ok(Some("dns-positive.test.".into())));
        let response = result
            .expect("result receiver task")
            .expect("client result channel")
            .expect("successful HTTP round trip");
        assert_eq!(response.body, b"dns-tls-ok");
    }
}
