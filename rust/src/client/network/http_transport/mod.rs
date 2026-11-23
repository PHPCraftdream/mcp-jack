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
    // Every Content-Type field line takes part (see is_event_stream). The
    // decision is byte-based: a non-UTF-8 line is lossily decoded so a
    // text/event-stream member still refuses, matching Go and TypeScript.
    let content_types: Vec<String> = response
        .headers()
        .get_all(http::header::CONTENT_TYPE)
        .iter()
        .map(|value| match value.to_str() {
            Ok(text) => text.to_owned(),
            // Lossy decoding keeps every ASCII media type intact; the
            // replacement character only ever lands on the invalid bytes.
            Err(_) => String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect();
    if crate::client::transport::is_event_stream(content_types.iter().map(String::as_str)) {
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

#[cfg(feature = "client-http")]
mod stream;

#[cfg(test)]
mod tests;
