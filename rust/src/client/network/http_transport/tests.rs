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
        tokio::task::spawn_blocking(move || result_rx.recv_timeout(Duration::from_secs(2))).await;
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

    let streaming = finish_operation::<()>(Err(TransportError::Streaming), Err(cleanup.clone()));
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
    let source = std::error::Error::source(&client_error).expect("protocol source is preserved");
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
            let injected_error =
                hickory_resolver::net::NetError::from("injected mapped resolver error".to_owned());
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
            let name = hickory_resolver::proto::rr::Name::from_ascii(format!("candidate-{index}."))
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
    let result = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(4))).await;
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
