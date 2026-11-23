//! The real TLS/TCP webhook transport of spec 06 sections 1 and 6.
//!
//! This file needs `hyper`, `tokio`, `tokio-rustls` and `hickory-resolver`,
//! which the crate enables only through its `client-http` feature; it is
//! therefore gated on `client-http` on top of the `http` gate of the parent
//! module. A build with `http` alone keeps the pure orchestration and the
//! receiver adapters and leaves this network implementation out.
//!
//! Both types mirror the blocking idiom of
//! `crate::client::network::http_transport`: the system DNS configuration,
//! hosts file and trust roots are snapshotted at build time, and every call
//! builds a private current-thread Tokio runtime and blocks on it. The
//! transport connects to [`ConnectTarget::address`] and never re-resolves,
//! presents [`ConnectTarget::host_header`] in `Host`, verifies the
//! certificate against [`ConnectTarget::sni`] (or against the IP literal,
//! with no SNI extension), never follows a redirect, and maps every failure
//! to one of the three R1.9 network categories.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, ServerName},
    ClientConfig, RootCertStore,
};

use crate::webhook::delivery::LastError;
use crate::webhook::http::transport::{
    declared_length, HostResolver, TransportFailure, TransportRequest, TransportResponse,
    WebhookTransport,
};
use crate::webhook::ssrf::url::check_url;
use crate::webhook::WebhookError;

/// The DNS snapshot of the platform resolver, taken once at build time.
#[derive(Clone)]
struct DnsSnapshot {
    config: hickory_resolver::config::ResolverConfig,
    options: hickory_resolver::config::ResolverOpts,
    hosts: Arc<hickory_resolver::Hosts>,
}

/// The R6.8 host resolver over the platform's own DNS configuration.
///
/// The construction mirrors `HttpTransport`: the resolver configuration, the
/// hosts file and the options are snapshotted once, the hosts file is not
/// consulted by the resolver itself (the snapshot carries it), the cache is
/// disabled and one attempt is made, so an answer is either the platform's
/// live answer or an error. An IP literal is returned as its own answer
/// without touching DNS, matching R6.8's "an IP literal is its own name".
pub struct SystemResolver {
    dns: DnsSnapshot,
}

impl SystemResolver {
    /// Snapshots the platform DNS configuration and hosts file.
    pub fn new() -> Result<Self, WebhookError> {
        let (config, mut options) =
            hickory_resolver::system_conf::read_system_conf().map_err(|_| resolver_error())?;
        let hosts = hickory_resolver::Hosts::from_system().map_err(|_| resolver_error())?;
        options.use_hosts_file = hickory_resolver::config::ResolveHosts::Never;
        options.cache_size = 0;
        options.num_concurrent_reqs = 1;
        options.attempts = 1;
        Ok(Self {
            dns: DnsSnapshot {
                config,
                options,
                hosts: Arc::new(hosts),
            },
        })
    }
}

impl HostResolver for SystemResolver {
    fn resolve(&self, host: &str, _port: u16) -> Result<Vec<IpAddr>, WebhookError> {
        if let Ok(address) = host.parse::<IpAddr>() {
            return Ok(vec![address]);
        }
        let query = if host.ends_with('.') {
            host.to_owned()
        } else {
            format!("{host}.")
        };
        let dns = self.dns.clone();
        let addresses = run_resolver(async move {
            let mut resolver = hickory_resolver::Resolver::<
                hickory_resolver::net::runtime::TokioRuntimeProvider,
            >::builder_with_config(
                dns.config,
                hickory_resolver::net::runtime::TokioRuntimeProvider::new(),
            )
            .with_options(dns.options)
            .build()
            .map_err(|_| resolver_error())?;
            resolver.set_hosts(dns.hosts);
            match resolver.lookup_ip(query).await {
                Ok(lookup) => {
                    let found: Vec<IpAddr> = lookup.iter().collect();
                    Ok(found)
                }
                Err(_) => Err(resolver_error()),
            }
        })?;
        if addresses.is_empty() {
            return Err(resolver_error());
        }
        Ok(addresses)
    }
}

/// The TLS delivery transport of spec 06 sections 1 and 6.
pub struct HttpsTransport {
    roots: Arc<RootCertStore>,
}

impl HttpsTransport {
    /// Builds a transport that trusts the WebPKI roots.
    pub fn new() -> Result<Self, WebhookError> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Ok(Self {
            roots: Arc::new(roots),
        })
    }

    /// Builds a transport that trusts exactly the supplied DER certificates.
    pub fn with_roots(certificates_der: Vec<Vec<u8>>) -> Result<Self, WebhookError> {
        let mut roots = RootCertStore::empty();
        for der in certificates_der {
            roots
                .add(CertificateDer::from(der))
                .map_err(|_| tls_config_error())?;
        }
        Ok(Self {
            roots: Arc::new(roots),
        })
    }
}

impl WebhookTransport for HttpsTransport {
    fn send(&self, request: &TransportRequest) -> Result<TransportResponse, TransportFailure> {
        let parts = check_url(&request.url).map_err(|_| refused())?;
        let target = if parts.query.is_empty() {
            parts.path.clone()
        } else {
            format!("{}?{}", parts.path, parts.query)
        };
        let method =
            ::http::Method::from_bytes(request.method.as_bytes()).map_err(|_| refused())?;
        if method == ::http::Method::CONNECT {
            return Err(refused());
        }
        let mut builder = ::http::Request::builder().method(method).uri(target);
        for (name, value) in &request.headers {
            if name.eq_ignore_ascii_case("host")
                || name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("transfer-encoding")
            {
                return Err(refused());
            }
            let name = ::http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| refused())?;
            let value = ::http::HeaderValue::from_bytes(value.as_bytes()).map_err(|_| refused())?;
            builder = builder.header(name, value);
        }
        let host =
            ::http::HeaderValue::from_str(&request.connect.host_header).map_err(|_| refused())?;
        let mut http_request = builder
            .body(Full::new(Bytes::from(request.body.clone())))
            .map_err(|_| refused())?;
        http_request
            .headers_mut()
            .insert(::http::header::HOST, host);
        let address: IpAddr = request.connect.address.parse().map_err(|_| refused())?;
        let server_name = match &request.connect.sni {
            Some(name) => ServerName::try_from(name.clone()).map_err(|_| tls())?,
            // An IP literal is verified as an address and rustls sends no SNI
            // extension for this variant (spec 06 R6.8).
            None => ServerName::IpAddress(address.into()),
        };
        let roots = Arc::clone(&self.roots);
        let connect_timeout = request.connect_timeout;
        let response_timeout = request.response_timeout;
        let max_body_bytes = request.max_body_bytes;
        let port = parts.port;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| refused())?;
        runtime.block_on(run(
            http_request,
            address,
            port,
            server_name,
            roots,
            connect_timeout,
            response_timeout,
            max_body_bytes,
        ))
    }
}

/// Runs one attempt: connect to the validated address, verify against the
/// chosen name, send one HTTP/1.1 request and read at most the body cap.
#[allow(clippy::too_many_arguments)]
async fn run(
    http_request: ::http::Request<Full<Bytes>>,
    address: IpAddr,
    port: u16,
    server_name: ServerName<'static>,
    roots: Arc<RootCertStore>,
    connect_timeout: Duration,
    response_timeout: Duration,
    max_body_bytes: usize,
) -> Result<TransportResponse, TransportFailure> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .map_err(|_| tls())?
        .with_root_certificates((*roots).clone())
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let target = SocketAddr::new(address, port);
    let setup = async {
        let stream = tokio::net::TcpStream::connect(target)
            .await
            .map_err(|_| refused())?;
        let peer = stream.peer_addr().map_err(|_| refused())?;
        // R6.9: the connected peer must be the validated address, never a
        // second answer of a fresh lookup.
        if peer.ip() != address {
            return Err(refused());
        }
        let tls = connector
            .connect(server_name, stream)
            .await
            .map_err(|_| tls())?;
        http1::handshake::<_, Full<Bytes>>(TokioIo::new(tls))
            .await
            .map_err(|_| refused())
    };
    // The R1.6 connect phase: TCP, TLS and the HTTP/1.1 handshake, 10 s.
    let (mut sender, connection) = match tokio::time::timeout(connect_timeout, setup).await {
        Ok(result) => result?,
        Err(_) => return Err(timeout()),
    };
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    // The R1.6 response phase: the request and its answer, 10 s.
    let result = match tokio::time::timeout(
        response_timeout,
        read_response(&mut sender, http_request, max_body_bytes),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(timeout()),
    };
    driver.abort();
    let _ = driver.await;
    result
}

/// Sends the request and reads the response, never following a redirect.
async fn read_response(
    sender: &mut http1::SendRequest<Full<Bytes>>,
    request: ::http::Request<Full<Bytes>>,
    max_body_bytes: usize,
) -> Result<TransportResponse, TransportFailure> {
    let response = sender.send_request(request).await.map_err(|_| refused())?;
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get(::http::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_retry_after);
    let declared = declared_length(response.headers());
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| refused())?;
        if let Ok(data) = frame.into_data() {
            let remaining = max_body_bytes.saturating_sub(bytes.len());
            let take = data.len().min(remaining);
            bytes.extend_from_slice(&data[..take]);
            if bytes.len() >= max_body_bytes {
                break;
            }
        }
    }
    Ok(TransportResponse {
        status,
        retry_after,
        body: bytes,
        declared_length: declared,
    })
}

/// Parses a `Retry-After` delay in whole seconds; an HTTP-date is ignored
/// by yielding `None` (spec 06 R1.8).
fn parse_retry_after(text: &str) -> Option<i64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Builds a `connection_refused` transport failure.
fn refused() -> TransportFailure {
    TransportFailure {
        error: LastError::ConnectionRefused,
    }
}

/// Builds a `timeout` transport failure.
fn timeout() -> TransportFailure {
    TransportFailure {
        error: LastError::Timeout,
    }
}

/// Builds a `tls_error` transport failure.
fn tls() -> TransportFailure {
    TransportFailure {
        error: LastError::TlsError,
    }
}

/// Builds the fixed DNS failure; its code is the R1.9 category a DNS
/// failure maps to and its message never names the host.
fn resolver_error() -> WebhookError {
    WebhookError::new(
        500,
        "connection_refused",
        "the webhook host could not be resolved",
    )
}

/// Builds the fixed TLS configuration failure.
fn tls_config_error() -> WebhookError {
    WebhookError::new(
        500,
        "tls_error",
        "the TLS client configuration could not be built",
    )
}

/// Runs a resolver future on a private current-thread runtime.
fn run_resolver<F, T>(future: F) -> Result<T, WebhookError>
where
    F: std::future::Future<Output = Result<T, WebhookError>>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| resolver_error())?;
    runtime.block_on(future)
}
