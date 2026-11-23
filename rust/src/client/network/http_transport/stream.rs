use super::*;
use crate::client::{
    stream::{ChunkRead, StreamBody, StreamResponse, StreamSource},
    transport::HttpRequest,
};
use http_body_util::BodyExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use tokio::sync::oneshot;

type StreamHead = Result<(u16, Vec<(String, String)>), TransportError>;
type StreamHeadSender = SyncSender<StreamHead>;

struct StreamWorkerContext {
    request: http::Request<Full<Bytes>>,
    destination: http::Uri,
    deadline: Instant,
    roots: Arc<RootCertStore>,
    dns: DnsSnapshot,
    head: StreamHeadSender,
    chunks: SyncSender<Result<Option<Vec<u8>>, TransportError>>,
    cancel: oneshot::Receiver<()>,
}

struct StreamPerformContext {
    request: http::Request<Full<Bytes>>,
    destination: http::Uri,
    roots: Arc<RootCertStore>,
    resolver: hickory_resolver::Resolver<OwnedRuntime>,
    owner: Arc<Mutex<TaskState>>,
    deadline: Instant,
    head: StreamHeadSender,
    chunks: SyncSender<Result<Option<Vec<u8>>, TransportError>>,
    head_sent: Arc<AtomicBool>,
    cancel: oneshot::Receiver<()>,
}

struct ChannelBody {
    receiver: Receiver<Result<Option<Vec<u8>>, TransportError>>,
    cancel: Option<oneshot::Sender<()>>,
}
impl StreamBody for ChannelBody {
    fn next_chunk(&mut self, deadline: Instant) -> Result<ChunkRead, TransportError> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match self.receiver.recv_timeout(remaining) {
            Ok(Ok(Some(bytes))) => Ok(ChunkRead::Data(bytes)),
            Ok(Ok(None)) => Ok(ChunkRead::End),
            Ok(Err(error)) => Err(error),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(ChunkRead::Timeout),
            Err(mpsc::RecvTimeoutError::Disconnected) => Ok(ChunkRead::End),
        }
    }
}
impl Drop for ChannelBody {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
    }
}

impl StreamSource for HttpTransport {
    fn open_stream(&self, req: HttpRequest) -> Result<StreamResponse, TransportError> {
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
        let mut request = http::Request::builder()
            .method(method)
            .uri(target)
            .body(Full::new(Bytes::from(req.body)))
            .map_err(|e| TransportError::Client(format!("jack client: http transport: {e}")))?;
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
            request.headers_mut().append(name, value);
        }
        let authority = absolute
            .authority()
            .ok_or_else(|| {
                TransportError::Client("jack client: http transport: missing authority".into())
            })?
            .as_str()
            .to_owned();
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
        let (head_tx, head_rx) = mpsc::sync_channel(1);
        let (body_tx, body_rx) = mpsc::sync_channel(1);
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let roots = self.roots.clone();
        let dns = self.dns.clone();
        let worker = std::thread::Builder::new()
            .name("jack-http-stream".into())
            .spawn(move || {
                let result = (|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| {
                            TransportError::Transport(format!(
                                "jack client: http transport: runtime: {e}"
                            ))
                        })?;
                    runtime.block_on(stream_worker(StreamWorkerContext {
                        request,
                        destination: absolute,
                        deadline,
                        roots,
                        dns,
                        head: head_tx,
                        chunks: body_tx,
                        cancel: cancel_rx,
                    }))
                })();
                result
            })
            .map_err(|e| {
                TransportError::Transport(format!("jack client: http transport: worker: {e}"))
            })?;
        match head_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Ok((status, headers))) => {
                // The worker owns the live connection. The body receiver's drop makes its send fail,
                // causing the worker to leave the read loop, abort child tasks and close the socket.
                drop(worker);
                Ok(StreamResponse {
                    status,
                    headers,
                    body: Box::new(ChannelBody {
                        receiver: body_rx,
                        cancel: Some(cancel_tx),
                    }),
                })
            }
            Ok(Err(error)) => {
                let _ = worker.join();
                Err(error)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                drop(body_rx);
                let _ = worker.join();
                Err(TransportError::Transport(
                    "jack client: http transport: absolute stream-open timeout exceeded".into(),
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = worker.join();
                Err(TransportError::Transport(
                    "jack client: http transport: stream worker stopped before response headers"
                        .into(),
                ))
            }
        }
    }
}

async fn stream_worker(context: StreamWorkerContext) -> Result<(), TransportError> {
    let StreamWorkerContext {
        request,
        destination,
        deadline,
        roots,
        dns,
        head,
        chunks,
        cancel,
    } = context;
    let owner = Arc::new(Mutex::new(TaskState {
        closed: false,
        overflow: false,
        late_spawn: false,
        tasks: JoinSet::new(),
    }));
    let operation_owner = owner.clone();
    let head_sent = Arc::new(AtomicBool::new(false));
    let result_head_sent = head_sent.clone();
    let mut result = tokio::spawn(async move {
        let provider = OwnedRuntime(
            hickory_resolver::net::runtime::TokioRuntimeProvider::new(),
            TaskHandle(operation_owner.clone()),
        );
        let mut resolver = hickory_resolver::Resolver::builder_with_config(dns.config, provider)
            .with_options(dns.options)
            .build()
            .map_err(map_resolver_build_error)?;
        resolver.set_hosts(dns.hosts);
        stream_perform(StreamPerformContext {
            request,
            destination,
            roots,
            resolver,
            owner: operation_owner,
            deadline,
            head,
            chunks,
            head_sent: result_head_sent,
            cancel,
        })
        .await
    });
    let operation = match tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        &mut result,
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => Err(TransportError::Transport(format!(
            "jack client: http transport: stream operation failed: {e}"
        ))),
        Err(_) if head_sent.load(Ordering::Acquire) => match result.await {
            Ok(result) => result,
            Err(e) => Err(TransportError::Transport(format!(
                "jack client: http transport: stream operation failed: {e}"
            ))),
        },
        Err(_) => {
            result.abort();
            let _ = result.await;
            Err(TransportError::Transport(
                "jack client: http transport: absolute stream-open timeout exceeded".into(),
            ))
        }
    };
    finish_operation(operation, drain(&owner).await)
}

async fn stream_perform(context: StreamPerformContext) -> Result<(), TransportError> {
    let StreamPerformContext {
        request,
        destination,
        roots,
        resolver,
        owner,
        deadline,
        head,
        chunks,
        head_sent,
        mut cancel,
    } = context;
    let auth = destination.authority().ok_or_else(|| {
        TransportError::Client("jack client: http transport: missing authority".into())
    })?;
    let host = auth.host().trim_start_matches('[').trim_end_matches(']');
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
    let mut stream = None;
    let mut last = None;
    for ip in addresses.into_iter().take(16) {
        match tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            tokio::net::TcpStream::connect(SocketAddr::new(ip, port)),
        )
        .await
        {
            Ok(Ok(value)) => {
                stream = Some(value);
                break;
            }
            Ok(Err(e)) => last = Some(e),
            Err(_) => break,
        }
    }
    let stream = stream.ok_or_else(|| {
        TransportError::Transport(format!(
            "jack client: http transport: connect: {}",
            last.map(|e| e.to_string())
                .unwrap_or_else(|| "deadline exceeded or no address".into())
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
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, stream),
            )
            .await
            .map_err(|_| {
                TransportError::Transport("jack client: http transport: TLS timeout".into())
            })?
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
        state.tasks.spawn(async move {
            connection.await.map_err(|e| {
                TransportError::Transport(format!("jack client: http transport: HTTP driver: {e}"))
            })
        });
    }
    let response = sender.send_request(request).await.map_err(|e| {
        TransportError::Transport(format!("jack client: http transport: HTTP request: {e}"))
    })?;
    let status = response.status().as_u16();
    let mut headers = Vec::new();
    for (name, value) in response.headers() {
        headers.push((
            name.as_str().to_owned(),
            value
                .to_str()
                .map_err(|_| {
                    TransportError::Transport(format!(
                        "jack client: http transport: non-UTF-8 response header {name}"
                    ))
                })?
                .to_owned(),
        ));
    }
    if head.send(Ok((status, headers))).is_err() {
        return Ok(());
    }
    head_sent.store(true, Ordering::Release);
    let mut body = response.into_body();
    loop {
        let frame = tokio::select! {
            frame = body.frame() => frame,
            _ = &mut cancel => return Ok(()),
        };
        match frame {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    if chunks.send(Ok(Some(data.to_vec()))).is_err() {
                        break;
                    }
                }
            }
            Some(Err(e)) => {
                let _ = chunks.send(Err(TransportError::Transport(format!(
                    "jack client: http transport: response body: {e}"
                ))));
                break;
            }
            None => {
                let _ = chunks.send(Ok(None));
                break;
            }
        }
    }
    Ok(())
}
