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
    late_spawn: bool,
    tasks: JoinSet<Result<(), TransportError>>,
}
impl hickory_resolver::net::runtime::Spawn for TaskHandle {
    // hickory-net 0.26.1 background DNS futures return unit; lookup errors are
    // surfaced by lookup_ip, while driver join errors are collected here.
    fn spawn_bg(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed {
            state.late_spawn = true;
            return;
        }
        if state.tasks.len() >= MAX_OWNED_TASKS {
            state.overflow = true;
            return;
        }
        state.tasks.spawn(async move {
            future.await;
            Ok(())
        });
    }
}
#[derive(Clone)]
struct OwnedRuntime(
    hickory_resolver::net::runtime::TokioRuntimeProvider,
    TaskHandle,
);
impl hickory_resolver::net::runtime::RuntimeProvider for OwnedRuntime {
    type Handle = TaskHandle;
    type Timer = <hickory_resolver::net::runtime::TokioRuntimeProvider as hickory_resolver::net::runtime::RuntimeProvider>::Timer;
    type Udp = <hickory_resolver::net::runtime::TokioRuntimeProvider as hickory_resolver::net::runtime::RuntimeProvider>::Udp;
    type Tcp = <hickory_resolver::net::runtime::TokioRuntimeProvider as hickory_resolver::net::runtime::RuntimeProvider>::Tcp;
    fn create_handle(&self) -> Self::Handle {
        self.1.clone()
    }
    fn connect_tcp(
        &self,
        a: SocketAddr,
        b: Option<SocketAddr>,
        c: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        hickory_resolver::net::runtime::RuntimeProvider::connect_tcp(&self.0, a, b, c)
    }
    fn bind_udp(
        &self,
        a: SocketAddr,
        b: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        hickory_resolver::net::runtime::RuntimeProvider::bind_udp(&self.0, a, b)
    }
}

fn record_task_result(
    failures: &mut Vec<String>,
    result: Result<Result<(), TransportError>, tokio::task::JoinError>,
) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => failures.push(format!("owned task returned an error: {error}")),
        Err(error) if !error.is_cancelled() => failures.push(format!("owned task failed: {error}")),
        Err(_) => {}
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
    let mut failures = Vec::new();
    // Collect failures already completed before aborting still-running children.
    while let Some(result) = tasks.try_join_next() {
        record_task_result(&mut failures, result);
    }
    tasks.abort_all();
    while let Some(result) = tasks.join_next().await {
        record_task_result(&mut failures, result);
    }
    if overflow {
        failures.push("owned task limit exceeded".into());
    }
    if owner.lock().unwrap_or_else(|e| e.into_inner()).late_spawn {
        failures.push("task spawn attempted after owner closure".into());
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(TransportError::Transport(format!(
            "jack client: http transport: cleanup failed: {}",
            failures.join("; ")
        )))
    }
}

fn map_resolver_build_error(error: impl std::fmt::Display) -> TransportError {
    TransportError::Transport(format!("jack client: http transport: resolver: {error}"))
}
fn append_cleanup_failure(primary: TransportError, cleanup: TransportError) -> TransportError {
    let suffix = format!("; cleanup failure: {cleanup}");
    match primary {
        TransportError::Transport(message) => TransportError::Transport(message + &suffix),
        TransportError::Client(message) => TransportError::Client(message + &suffix),
        // Typed errors have no secondary-diagnostic channel; keep their primary
        // classification and payload rather than flattening them into Transport.
        TransportError::Streaming => TransportError::Streaming,
        TransportError::Unauthenticated(error) => TransportError::Unauthenticated(error),
        TransportError::Protocol(error) => TransportError::Protocol(error),
    }
}

fn finish_operation<T>(
    operation: Result<T, TransportError>,
    cleanup: Result<(), TransportError>,
) -> Result<T, TransportError> {
    match (operation, cleanup) {
        (Ok(response), Ok(())) => Ok(response),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(primary), Ok(())) => Err(primary),
        (Err(primary), Err(cleanup)) => Err(append_cleanup_failure(primary, cleanup)),
    }
}

trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

fn checked_deadline(started: Instant, timeout: Duration) -> Result<Instant, TransportError> {
    started.checked_add(timeout).ok_or_else(|| {
        TransportError::Client("jack client: http transport: deadline overflow".into())
    })
}

impl Transport for HttpTransport {
    fn round_trip(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        let started = Instant::now();
        let deadline = checked_deadline(started, self.timeout)?;
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

/// The operation is terminal: the spawned operation is aborted and joined at
/// the deadline, followed by abort-and-join of every registered child task.
/// cancel-safe: NO — dropping this future would bypass its owned-task joins.
async fn run_owned<T, F>(
    owner: Arc<Mutex<TaskState>>,
    deadline: Instant,
    operation_future: F,
) -> Result<T, TransportError>
where
    T: Send + 'static,
    F: Future<Output = Result<T, TransportError>> + Send + 'static,
{
    let mut operation = tokio::spawn(operation_future);
    let operation_result =
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), &mut operation)
            .await
        {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(TransportError::Transport(format!(
                "jack client: http transport: operation task failed: {error}"
            ))),
            Err(_) => {
                operation.abort();
                let joined = operation.await;
                Err(match joined {
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
                })
            }
        };
    let cleanup = drain(&owner).await;
    finish_operation(operation_result, cleanup)
}

/// This awaits the complete HTTP operation under the shared absolute deadline.
/// cancel-safe: NO — dropping it would discard the operation's owned cleanup.
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
        late_spawn: false,
        tasks: JoinSet::new(),
    }));
    let operation_owner = owner.clone();
    run_owned(owner, deadline, async move {
        let provider = OwnedRuntime(
            hickory_resolver::net::runtime::TokioRuntimeProvider::new(),
            TaskHandle(operation_owner.clone()),
        );
        let mut resolver = hickory_resolver::Resolver::builder_with_config(dns.config, provider)
            .with_options(dns.options)
            .build()
            .map_err(map_resolver_build_error)?;
        resolver.set_hosts(dns.hosts);
        perform(request, destination, roots, resolver, operation_owner).await
    })
    .await
}

async fn perform(
    request: http::Request<Full<Bytes>>,
    destination: http::Uri,
    roots: Arc<RootCertStore>,
    resolver: hickory_resolver::Resolver<OwnedRuntime>,
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
        if state.closed {
            state.late_spawn = true;
        } else if state.tasks.len() >= MAX_OWNED_TASKS {
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
    {
        let state = owner.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed || state.overflow {
            return Err(TransportError::Transport(
                "jack client: http transport: owned task limit exceeded".into(),
            ));
        }
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
    use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
    use hickory_resolver::proto::{
        op::{Message, OpCode},
        serialize::binary::{BinEncodable, BinEncoder},
    };
    use std::net::UdpSocket;
    use tokio::sync::{mpsc, oneshot};

    fn owner() -> Arc<Mutex<TaskState>> {
        Arc::new(Mutex::new(TaskState {
            closed: false,
            overflow: false,
            late_spawn: false,
            tasks: JoinSet::new(),
        }))
    }

    fn test_dns_config(peer: SocketAddr) -> ResolverConfig {
        let mut nameserver = NameServerConfig::udp(peer.ip());
        nameserver.connections[0].port = peer.port();
        ResolverConfig::from_parts(None, vec![], vec![nameserver])
    }

    fn test_task_state(overflow: bool) -> Arc<Mutex<TaskState>> {
        Arc::new(Mutex::new(TaskState {
            closed: false,
            overflow,
            late_spawn: false,
            tasks: JoinSet::new(),
        }))
    }

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
        let config = test_dns_config(peer_addr);
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
        assert_eq!(message.queries[0].name().to_utf8(), "dns-timeout.test.");
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
        let owner = owner();
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (entered_tx, entered_rx) = oneshot::channel();
        let mark = DropMark(dropped.clone());
        let mut handle = TaskHandle(owner.clone());
        hickory_resolver::net::runtime::Spawn::spawn_bg(&mut handle, async move {
            let _mark = mark;
            let _ = entered_tx.send(());
            std::future::pending::<()>().await;
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

    #[tokio::test]
    async fn owned_task_error_and_primary_error_survive_cleanup() {
        let owner = owner();
        let (completed_tx, completed_rx) = oneshot::channel();
        owner.lock().unwrap().tasks.spawn(async move {
            let _ = completed_tx.send(());
            Err(TransportError::Transport("driver failure".into()))
        });
        completed_rx
            .await
            .expect("failing task completed before cleanup");
        let cleanup = drain(&owner).await;
        assert!(
            matches!(cleanup, Err(TransportError::Transport(message)) if message.contains("driver failure"))
        );

        let result = finish_operation::<HttpResponse>(
            Err(TransportError::Transport("primary operation error".into())),
            Err(TransportError::Transport("task cleanup error".into())),
        );
        assert_eq!(
            result,
            Err(TransportError::Transport(
                "primary operation error; cleanup failure: task cleanup error".into()
            ))
        );

        let client_transport_result = finish_operation::<()>(
            Err(TransportError::Client("client primary error".into())),
            Err(TransportError::Transport("client cleanup error".into())),
        );
        assert_eq!(
            client_transport_result,
            Err(TransportError::Client(
                "client primary error; cleanup failure: client cleanup error".into()
            ))
        );
        let client_result = client_transport_result.map_err(ClientError::from);
        assert_eq!(
            client_result,
            Err(ClientError::Client(
                "client primary error; cleanup failure: client cleanup error".into()
            ))
        );
    }

    #[test]
    fn typed_primary_classification_and_payload_survive_cleanup() {
        let cleanup = TransportError::Transport("cleanup diagnostic".into());

        let streaming =
            finish_operation::<()>(Err(TransportError::Streaming), Err(cleanup.clone()));
        assert_eq!(streaming, Err(TransportError::Streaming));
        assert_eq!(
            streaming.map_err(ClientError::from),
            Err(ClientError::Streaming)
        );

        let unauthenticated =
            TransportError::Unauthenticated(crate::client::error::UnauthenticatedResponseError {
                status: 401,
            });
        let result = finish_operation::<()>(Err(unauthenticated.clone()), Err(cleanup.clone()));
        assert_eq!(result, Err(unauthenticated));
        assert_eq!(
            ClientError::from(result.unwrap_err()),
            ClientError::Unauthenticated(crate::client::error::UnauthenticatedResponseError {
                status: 401,
            })
        );

        let protocol_payload = crate::error::JackError::new(0, "bad_signature", "exact payload");
        let protocol = TransportError::Protocol(protocol_payload.clone());
        let result = finish_operation::<()>(Err(protocol.clone()), Err(cleanup));
        assert_eq!(result, Err(protocol));
        let client_error = ClientError::from(result.unwrap_err());
        assert_eq!(
            client_error,
            ClientError::Protocol(protocol_payload.clone())
        );
        let source =
            std::error::Error::source(&client_error).expect("protocol source is preserved");
        assert_eq!(
            source.downcast_ref::<crate::error::JackError>(),
            Some(&protocol_payload)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_owned_joins_failed_and_pending_tasks_with_typed_primary() {
        let owner = owner();

        let (failed_tx, failed_rx) = oneshot::channel();
        owner.lock().unwrap().tasks.spawn(async move {
            let _ = failed_tx.send(());
            Err(TransportError::Transport("completed child failure".into()))
        });
        failed_rx
            .await
            .expect("child completed before operation ends");

        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let marker = DropMark(dropped.clone());
        let (pending_tx, pending_rx) = oneshot::channel();
        owner.lock().unwrap().tasks.spawn(async move {
            let _marker = marker;
            let _ = pending_tx.send(());
            std::future::pending::<()>().await;
            Ok(())
        });
        pending_rx
            .await
            .expect("pending child started before cleanup");

        let result = run_owned::<(), _>(
            owner.clone(),
            Instant::now() + Duration::from_secs(60),
            async { Err(TransportError::Streaming) },
        )
        .await;
        assert_eq!(result, Err(TransportError::Streaming));
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        let state = owner.lock().unwrap();
        assert!(state.closed);
        assert!(state.tasks.is_empty());
    }

    #[test]
    fn deadline_overflow_is_reported_instead_of_wrapping_or_panicking() {
        let error = checked_deadline(Instant::now(), Duration::MAX).unwrap_err();
        assert!(
            matches!(error, TransportError::Client(message) if message.contains("deadline overflow"))
        );
    }

    #[tokio::test]
    async fn closed_spawn_and_task_overflow_are_reported() {
        let closed_owner = owner();
        assert!(drain(&closed_owner).await.is_ok());
        let mut handle = TaskHandle(closed_owner.clone());
        hickory_resolver::net::runtime::Spawn::spawn_bg(&mut handle, async {});
        let late_spawn = drain(&closed_owner).await;
        assert!(matches!(
            late_spawn,
            Err(TransportError::Transport(message)) if message.contains("after owner closure")
        ));

        let overflow_state = test_task_state(true);
        let overflow = drain(&overflow_state).await;
        assert!(matches!(
            overflow,
            Err(TransportError::Transport(message)) if message.contains("task limit exceeded")
        ));

        let overflow_owner = owner();
        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (started_tx, mut started_rx) = mpsc::channel(MAX_OWNED_TASKS);
        let mut handle = TaskHandle(overflow_owner.clone());
        for _ in 0..=MAX_OWNED_TASKS {
            let dropped = dropped.clone();
            let started_tx = started_tx.clone();
            hickory_resolver::net::runtime::Spawn::spawn_bg(&mut handle, async move {
                struct CountDrop(Arc<std::sync::atomic::AtomicUsize>);
                impl Drop for CountDrop {
                    fn drop(&mut self) {
                        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                }
                let _drop = CountDrop(dropped);
                let _ = started_tx.send(()).await;
                std::future::pending::<()>().await;
            });
        }
        drop(started_tx);
        for _ in 0..MAX_OWNED_TASKS {
            started_rx.recv().await.expect("each admitted task starts");
        }
        {
            let state = overflow_owner.lock().unwrap();
            assert_eq!(state.tasks.len(), MAX_OWNED_TASKS);
            assert!(state.overflow);
        }
        let cleanup = drain(&overflow_owner).await;
        assert!(matches!(
            cleanup,
            Err(TransportError::Transport(message)) if message.contains("task limit exceeded")
        ));
        assert_eq!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            MAX_OWNED_TASKS
        );
    }

    #[tokio::test]
    async fn simulated_resolver_error_mapper_and_cleanup_unit_joins_owned_tasks() {
        let owner = owner();
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let marker = DropMark(dropped.clone());
        let task_owner = owner.clone();
        let result = run_owned::<(), _>(
            owner,
            Instant::now() + Duration::from_secs(60),
            async move {
                let (entered_tx, entered_rx) = oneshot::channel();
                hickory_resolver::net::runtime::Spawn::spawn_bg(
                    &mut TaskHandle(task_owner),
                    async move {
                        let _marker = marker;
                        let _ = entered_tx.send(());
                        std::future::pending::<()>().await;
                    },
                );
                entered_rx
                    .await
                    .expect("owned task started before injecting the mapped resolver error");
                let injected_error = hickory_resolver::net::NetError::from(
                    "injected mapped resolver error".to_owned(),
                );
                Err(map_resolver_build_error(injected_error))
            },
        )
        .await;
        assert!(
            matches!(result, Err(TransportError::Transport(message)) if message.contains("injected mapped resolver error"))
        );
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn injected_hosts_snapshot_is_used_when_system_hosts_are_disabled() {
        let owner = owner();
        let provider = OwnedRuntime(
            hickory_resolver::net::runtime::TokioRuntimeProvider::new(),
            TaskHandle(owner.clone()),
        );
        let mut options = ResolverOpts::default();
        options.use_hosts_file = hickory_resolver::config::ResolveHosts::Never;
        options.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4Only;
        options.cache_size = 0;
        let mut resolver = hickory_resolver::Resolver::builder_with_config(
            ResolverConfig::from_parts(None, vec![], vec![]),
            provider,
        )
        .with_options(options)
        .build()
        .expect("empty upstream configuration builds");
        let mut hosts = hickory_resolver::Hosts::default();
        hosts
            .read_hosts_conf(&b"127.0.0.42 hosts-only.test\n"[..])
            .expect("fixture hosts parse");
        resolver.set_hosts(Arc::new(hosts));
        let result = resolver
            .lookup_ip("hosts-only.test.")
            .await
            .expect("injected hosts resolves without upstream DNS");
        assert_eq!(
            result.iter().collect::<Vec<_>>(),
            vec!["127.0.0.42".parse::<IpAddr>().unwrap()]
        );
        assert!(drain(&owner).await.is_ok());
    }

    // Pinned Hickory source: `BinEncoder` uses a Vec candidate table capped at
    // 64; `Name::emit` separately caps compression attempts at 120. Not DNSSEC evidence.
    #[test]
    fn encoder_caps_compression_candidates_and_compression_attempts() {
        let mut bytes = Vec::new();
        let mut ranges = Vec::new();
        {
            let mut encoder = BinEncoder::new(&mut bytes);
            for index in 0..65 {
                let name =
                    hickory_resolver::proto::rr::Name::from_ascii(format!("candidate-{index}."))
                        .expect("valid fixture name");
                let start = encoder.offset();
                name.emit(&mut encoder).expect("encode candidate");
                ranges.push((start, encoder.offset() - 1));
            }
            assert_eq!(
                encoder.get_label_pointer(ranges[0].0, ranges[0].1),
                Some(ranges[0].0 as u16)
            );
            assert_eq!(
                encoder.get_label_pointer(ranges[63].0, ranges[63].1),
                Some(ranges[63].0 as u16)
            );
            assert_eq!(encoder.get_label_pointer(ranges[64].0, ranges[64].1), None);
        }

        let mut bytes = Vec::new();
        {
            let mut encoder = BinEncoder::new(&mut bytes);
            let first = hickory_resolver::proto::rr::Name::from_ascii("n0.").unwrap();
            first.emit(&mut encoder).expect("encode first name");
            for _ in 1..119 {
                first.emit(&mut encoder).expect("encode repeated name");
            }
            let start = encoder.offset();
            first.emit(&mut encoder).expect("encode repeated name");
            let encoded = encoder.slice_of(start, encoder.offset());
            assert_eq!(encoded, &[0xc0, 0]);

            let start = encoder.offset();
            first.emit(&mut encoder).expect("encode repeated name");
            let encoded = encoder.slice_of(start, encoder.offset());
            assert_eq!(encoded, &[2, b'n', b'0', 0]);
        }
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
                        let _ = query_tx.send(request.queries[0].name().to_utf8()).await;
                        let name = Name::from_ascii("dns-positive.test.").unwrap();
                        let mut reply = Message::new(
                            request.metadata.id,
                            MessageType::Response,
                            OpCode::Query,
                        );
                        reply.metadata.recursion_desired = true;
                        reply.metadata.recursion_available = true;
                        reply.add_query(Query::query(name.clone(), RecordType::A));
                        reply.add_answer(Record::from_rdata(name, 30, RData::A(hickory_resolver::proto::rr::rdata::A::new(127, 0, 0, 1))));
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
        let config = test_dns_config(dns_addr);
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
