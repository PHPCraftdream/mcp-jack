//! The real TLS/TCP webhook transport of spec 06 sections 1 and 6.
//!
//! This file needs `hyper`, `tokio`, `tokio-rustls` and `hickory-resolver`,
//! which the crate enables only through its `client-http` feature; it is
//! therefore gated on `client-http` on top of the `http` gate of the parent
//! module. A build with `http` alone keeps the pure orchestration and the
//! receiver adapters and leaves this network implementation out.
//!
//! Both types, and the [`HttpCardTransport`] that reuses them for the R7.2
//! card fetch, mirror the blocking idiom of
//! `crate::client::network::http_transport`: the system DNS configuration,
//! hosts file and trust roots are snapshotted at build time, and every call
//! builds a private current-thread Tokio runtime and blocks on it. The
//! transport connects to [`ConnectTarget::address`] and never re-resolves,
//! presents [`ConnectTarget::host_header`] in `Host`, verifies the
//! certificate against [`ConnectTarget::sni`] (or against the IP literal,
//! with no SNI extension), never follows a redirect, bounds the WHOLE attempt
//! by the absolute [`TransportRequest::deadline`] (R1.6), reports a connected
//! peer that differs from the validated address as its own failure (R6.9), and
//! maps every other failure to one of the three R1.9 network categories.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, ServerName},
    ClientConfig, RootCertStore,
};

use crate::webhook::card::discovery::MAX_CARD_BYTES;
use crate::webhook::card::source::{CardResponse, CardTransport, CARD_FETCH_SECONDS};
use crate::webhook::delivery::LastError;
use crate::webhook::http::transport::{
    capture_body, declared_length, prepare, resolve_answers, HostResolver, TransportFailure,
    TransportRequest, TransportResponse, WebhookTransport,
};
use crate::webhook::ssrf::url::check_url;
use crate::webhook::WebhookError;

/// The whole-lookup budget [`SystemResolver::resolve`] delegates with, in
/// seconds (spec 06 R1.6, R6.8).
const RESOLVE_TIMEOUT_SECONDS: u64 = 10;

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
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, WebhookError> {
        self.resolve_within(host, port, Duration::from_secs(RESOLVE_TIMEOUT_SECONDS))
    }

    /// Resolves `host` within `budget` (spec 06 R6.8).
    ///
    /// An IP literal is its own answer and never touches DNS. The lookup runs
    /// inside `tokio::time::timeout`, so a lookup that spends the budget is
    /// the fixed `timeout` error rather than a `connection_refused` one
    /// (spec 06 R1.6, R1.9).
    fn resolve_within(
        &self,
        host: &str,
        _port: u16,
        budget: Duration,
    ) -> Result<Vec<IpAddr>, WebhookError> {
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
            match tokio::time::timeout(budget, resolver.lookup_ip(query)).await {
                Ok(Ok(lookup)) => Ok(lookup.iter().collect::<Vec<IpAddr>>()),
                Ok(Err(_)) => Err(resolver_error()),
                Err(_) => Err(resolver_timeout()),
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
        let max_body_bytes = request.max_body_bytes;
        let port = parts.port;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| refused())?;
        // R1.6: the ONE absolute deadline of this attempt was stamped at the
        // caller's entry, so the DNS lookups and the request build are already
        // charged to it. The budget is sampled here — after the request and
        // the runtime are built — and the whole attempt, the connect phase and
        // the response phase are each clamped to what is left.
        let remaining = request.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(timeout());
        }
        let connect_timeout = request.connect_timeout.min(remaining);
        let response_timeout = request.response_timeout.min(remaining);
        runtime.block_on(async {
            match tokio::time::timeout(
                remaining,
                run(
                    http_request,
                    address,
                    port,
                    server_name,
                    roots,
                    connect_timeout,
                    response_timeout,
                    max_body_bytes,
                ),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(timeout()),
            }
        })
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
        // second answer of a fresh lookup. A differing peer is its own
        // failure, so the sender can make it final instead of retrying it.
        if peer.ip() != address {
            return Err(TransportFailure::peer_mismatch());
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
    // R7.2: the raw `Cache-Control` value, `None` when the header is absent
    // or not UTF-8, so the card cache lifetime is derived from what the
    // receiver actually announced.
    let cache_control = response
        .headers()
        .get(::http::header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let declared = declared_length(response.headers());
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    let mut overflow = declared.is_some_and(|length| length > max_body_bytes as u64);
    // R1.2, R5.9: read one byte past the cap, so an oversized body is
    // reported as overflow instead of being silently truncated to look
    // complete.
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| refused())?;
        if let Ok(data) = frame.into_data() {
            if capture_body(&mut bytes, &data, max_body_bytes) {
                overflow = true;
                break;
            }
        }
    }
    Ok(TransportResponse {
        status,
        retry_after,
        body: bytes,
        declared_length: declared,
        overflow,
        cache_control,
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
    TransportFailure::network(LastError::ConnectionRefused)
}

/// Builds a `timeout` transport failure.
fn timeout() -> TransportFailure {
    TransportFailure::network(LastError::Timeout)
}

/// Builds a `tls_error` transport failure.
fn tls() -> TransportFailure {
    TransportFailure::network(LastError::TlsError)
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

/// Builds the fixed DNS budget failure; its `timeout` code is the R1.9
/// category a spent whole-attempt budget maps to (spec 06 R1.6, R1.9).
fn resolver_timeout() -> WebhookError {
    WebhookError::new(500, "timeout", "the webhook host lookup ran out of time")
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

/// The `Accept` value of one R7.2 card fetch (spec 06 R7.2).
const ACCEPT_CARD: &str = "application/mcp-server-card+json";

/// The status of a card rejection: R7.2 assigns the fetch refusals no HTTP
/// answer, so no wire status is reported (spec 06 R7.2).
const NO_HTTP_STATUS: u16 = 0;

/// Fetches the Server Card over the hardened delivery path
/// (spec 06 R7.2).
///
/// The transport, the resolver and the operator override ranges are the
/// sender's own, so a card fetch follows the same R6.8-R6.10 decision, the
/// same R6.9 peer check and the same body cap as a delivery; only the method,
/// the URL, the `Accept` value and the verdict differ (spec 06 R7.2, R6.8).
/// Nothing is retried and no redirect is followed: a `3xx` comes back as its
/// status and the R7.2 decision refuses it (spec 06 R7.2).
pub struct HttpCardTransport {
    /// The hardened dialer of the sender (spec 06 R6.8-R6.10).
    transport: Arc<dyn WebhookTransport>,
    /// The R6.8 resolver that answers the card host twice (spec 06 R6.8).
    resolver: Arc<dyn HostResolver>,
    /// The operator override ranges of R6.11.
    allowed_ranges: Vec<String>,
}

impl HttpCardTransport {
    /// Builds a card transport over the sender's transport and resolver and
    /// the operator override ranges of R6.11.
    pub fn new(
        transport: Arc<dyn WebhookTransport>,
        resolver: Arc<dyn HostResolver>,
        allowed_ranges: Vec<String>,
    ) -> Self {
        Self {
            transport,
            resolver,
            allowed_ranges,
        }
    }
}

impl CardTransport for HttpCardTransport {
    /// Fetches `url` with the R7.2 deadline, `Accept` value and body cap
    /// (spec 06 R7.2).
    ///
    /// The whole fetch — DNS, connect, TLS, the request write and the
    /// response read — is bounded by ONE absolute [`CARD_FETCH_SECONDS`]
    /// deadline stamped here, and the elapsed wall clock is measured from the
    /// same entry, so the R7.2 `timeout` verdict sees the real cost. The host
    /// is resolved twice (validation and the R6.9 recheck), the section 6
    /// decision of [`prepare`] surfaces as its own error, a transport failure
    /// maps to its R1.9 code, and the 65536-byte cap is the R1.2 read cap, so
    /// a body that crossed it is reported through `overflow` rather than
    /// silently truncated (spec 06 R1.2, R1.6, R1.9, R6.8-R6.10, R7.2).
    ///
    /// The `Cache-Control` value the transport read is copied into
    /// [`CardResponse::cache_control`], so the R7.2 cache lifetime comes from
    /// the receiver's own header (spec 06 R7.2).
    fn fetch_card(&self, url: &str) -> Result<CardResponse, WebhookError> {
        let endpoint = match check_url(url) {
            Ok(endpoint) => endpoint,
            Err(_) => return Err(card_not_https()),
        };
        let started = Instant::now();
        let deadline = started + Duration::from_secs(CARD_FETCH_SECONDS);
        let (answers, recheck) = resolve_answers(&self.resolver, &endpoint, deadline)?;
        let prepared = prepare(
            url,
            &answers,
            &recheck,
            &self.allowed_ranges,
            "GET",
            vec![("Accept".to_owned(), ACCEPT_CARD.to_owned())],
            Vec::new(),
            MAX_CARD_BYTES,
            deadline,
        )?;
        let response = match self.transport.send(&prepared.request) {
            Ok(response) => response,
            Err(failure) => return Err(card_network_error(&failure)),
        };
        let elapsed_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        Ok(CardResponse {
            status: response.status,
            body: response.body,
            declared_length: response.declared_length,
            overflow: response.overflow,
            cache_control: response.cache_control,
            elapsed_ms,
        })
    }
}

/// Builds the `not_https` rejection of a card url that is not `https`
/// (spec 06 R7.2).
fn card_not_https() -> WebhookError {
    WebhookError::with_reason(
        NO_HTTP_STATUS,
        crate::webhook::codes::NOT_HTTPS,
        "url",
        "the card url is not an https url",
    )
}

/// Maps one R1.9 transport category to the code of a failed card fetch
/// (spec 06 R1.9, R7.2).
fn card_network_error(failure: &TransportFailure) -> WebhookError {
    let last_error = failure.error;
    WebhookError::with_reason(
        NO_HTTP_STATUS,
        last_error.as_str(),
        last_error.as_str(),
        "the card fetch failed before a response was read",
    )
}
