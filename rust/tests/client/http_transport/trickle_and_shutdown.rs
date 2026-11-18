use super::*;

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

// ---------------------------------------------------------------------------
// Bounded reader for the adapter's fixed POST, used by
// timeout_failure_socket_released_peer_observes_eof: parse before answering.
// ---------------------------------------------------------------------------

/// Upper bound for the buffered fixture request. The adapter's fixed POST is
/// ~100 bytes; anything past this bound is a fixture regression, so the
/// accumulation stays bounded to `PEER_REQUEST_MAX` plus one read chunk.
const PEER_REQUEST_MAX: usize = 8 * 1024;

/// Parse state of the accumulated request bytes.
#[derive(Debug, PartialEq, Eq)]
enum PeerRequestParse {
    /// No complete `\r\n\r\n` head terminator buffered yet.
    PartialHead,
    /// Head parsed; the request completes at `body_end` total bytes (head
    /// plus declared Content-Length, checked arithmetic).
    PartialBody { body_end: usize },
    /// Head and declared body fully buffered.
    Complete,
    /// Content-Length missing, duplicated, unparsable, or declaring a body
    /// beyond `PEER_REQUEST_MAX`: a fixture regression, never silently
    /// treated as a zero-length body.
    Malformed,
}

/// Parses the adapter's fixed POST shape (origin-form request line, header
/// lines, exactly one Content-Length). Byte-level on purpose: the fixture
/// must reject malformed input without depending on UTF-8 validity.
fn peer_request_parse(received: &[u8]) -> PeerRequestParse {
    let Some(head_end) = received
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
    else {
        return PeerRequestParse::PartialHead;
    };
    let head = &received[..head_end];
    let mut lengths = head
        .split(|byte| *byte == b'\n')
        .skip(1)
        .filter_map(|line| {
            let colon = line.iter().position(|byte| *byte == b':')?;
            Some((&line[..colon], &line[colon + 1..]))
        })
        .filter(|(name, _)| {
            name.trim_ascii_end()
                .eq_ignore_ascii_case(b"content-length")
        })
        .map(|(_, value)| value);
    // The adapter's fixed POST always carries exactly one Content-Length.
    let Some(value) = lengths.next() else {
        return PeerRequestParse::Malformed;
    };
    if lengths.next().is_some() {
        // Duplicated even with equal values: the smuggling-shaped header set
        // a real server rejects instead of guessing.
        return PeerRequestParse::Malformed;
    }
    let value = value.trim_ascii();
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return PeerRequestParse::Malformed;
    }
    let Ok(digits) = std::str::from_utf8(value) else {
        return PeerRequestParse::Malformed;
    };
    let Ok(body_len) = digits.parse::<usize>() else {
        return PeerRequestParse::Malformed;
    };
    let Some(body_end) = head_end.checked_add(body_len) else {
        return PeerRequestParse::Malformed;
    };
    if body_end > PEER_REQUEST_MAX {
        return PeerRequestParse::Malformed;
    }
    if received.len() < body_end {
        PeerRequestParse::PartialBody { body_end }
    } else {
        PeerRequestParse::Complete
    }
}

/// Focused controls for the fixture parser above: the fixed POST completes
/// only once head AND declared body are buffered; a short read stays
/// incomplete; missing, duplicated, unparsable or over-bound Content-Length
/// is Malformed (never silently a zero-length body).
#[test]
fn peer_request_parse_rejects_incomplete_and_malformed_fixed_post() {
    let head =
        b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\ncontent-length: 10\r\n\r\n";
    let body = b"{\"ping\":1}";
    let expected_end = head.len() + body.len();
    let mut whole = head.to_vec();
    whole.extend_from_slice(body);
    assert_eq!(peer_request_parse(&whole), PeerRequestParse::Complete);
    assert_eq!(
        peer_request_parse(head),
        PeerRequestParse::PartialBody {
            body_end: expected_end
        }
    );
    // Head terminator incomplete and body one byte short: never complete.
    assert_eq!(
        peer_request_parse(&head[..head.len() - 1]),
        PeerRequestParse::PartialHead
    );
    assert_eq!(
        peer_request_parse(&whole[..expected_end - 1]),
        PeerRequestParse::PartialBody {
            body_end: expected_end
        }
    );
    // Missing Content-Length.
    let missing = b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    assert_eq!(peer_request_parse(missing), PeerRequestParse::Malformed);
    // Duplicated Content-Length: identical and conflicting values.
    for duplicated in [
        b"POST /mcp HTTP/1.1\r\ncontent-length: 9\r\ncontent-length: 9\r\n\r\n".as_slice(),
        b"POST /mcp HTTP/1.1\r\ncontent-length: 3\r\ncontent-length: 9\r\n\r\n".as_slice(),
    ] {
        assert_eq!(peer_request_parse(duplicated), PeerRequestParse::Malformed);
    }
    // Unparsable values: empty, signed, alphabetic, and beyond usize.
    for unparsable in [
        b"POST /mcp HTTP/1.1\r\ncontent-length:\r\n\r\n".as_slice(),
        b"POST /mcp HTTP/1.1\r\ncontent-length: -9\r\n\r\n".as_slice(),
        b"POST /mcp HTTP/1.1\r\ncontent-length: nine\r\n\r\n".as_slice(),
        b"POST /mcp HTTP/1.1\r\ncontent-length: 99999999999999999999999\r\n\r\n".as_slice(),
    ] {
        assert_eq!(peer_request_parse(unparsable), PeerRequestParse::Malformed);
    }
    // Well-formed digits beyond the fixture bound.
    let over_bound = format!(
        "POST /mcp HTTP/1.1\r\ncontent-length: {}\r\n\r\n",
        PEER_REQUEST_MAX + 1
    );
    assert_eq!(
        peer_request_parse(over_bound.as_bytes()),
        PeerRequestParse::Malformed
    );
}

/// Drains the adapter's fixed POST (head plus declared body) BEFORE the
/// fixture response is written: bytes sent before the request exists on the
/// wire are unsolicited on an idle client connection and can surface as an
/// early error that races the deadline. Malformed or incomplete input is a
/// fixture failure (see [`PeerRequestParse`]), never a client-closure signal.
async fn peer_read_request(stream: &mut tokio::net::TcpStream) -> std::io::Result<()> {
    use tokio::io::AsyncRead;

    let mut chunk = [0u8; 512];
    let mut received = Vec::new();
    loop {
        match peer_request_parse(&received) {
            PeerRequestParse::Complete => return Ok(()),
            PeerRequestParse::Malformed => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "fixture request malformed: Content-Length missing, duplicated, invalid or over-bound",
                ))
            }
            PeerRequestParse::PartialHead | PeerRequestParse::PartialBody { .. } => {}
        }
        if received.len() >= PEER_REQUEST_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fixture request exceeded its bounded buffer",
            ));
        }
        let mut buf = tokio::io::ReadBuf::new(&mut chunk);
        std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_read(cx, &mut buf)).await?;
        if buf.filled().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer saw EOF before the fixture request completed",
            ));
        }
        received.extend_from_slice(buf.filled());
    }
}

/// Contract: a stalled announced-length response (Content-Length: 64, five
/// body bytes sent, socket held open) must surface as Err(Transport) naming
/// the timeout, AND the failed socket must be genuinely released — proven by
/// the peer observing a true EOF after the adapter's fixed POST was fully
/// drained. The peer answers only after the complete request (rationale on
/// `peer_read_request`).
///
/// Outcome discipline: ClientClosed is the success signal; ClientKeptSocket
/// is the retained-socket failure signal; PeerWriteFailed/PeerReadFailed are
/// fixture failures NEVER counted as closure; NoConnection means the client
/// never connected. The peer handle is retained across the bounded join
/// (abort+await fallback), and the client-side error assertions run only
/// after the peer outcome is collected.
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
        /// after its complete request was drained — the success signal: the
        /// failure path released the connection.
        ClientClosed,
        /// The peer's own absolute 10 s guard expired — the client KEPT
        /// the failed socket open (the retained-socket failure signal,
        /// asserted against).
        ClientKeptSocket,
        /// The fixture write errored or the write bound expired — a peer/
        /// fixture problem, NEVER evidence of client closure.
        PeerWriteFailed,
        /// The fixture read errored or the read bound expired before the
        /// client's request completed — a peer/fixture problem, NEVER
        /// evidence of client closure.
        PeerReadFailed,
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

    // ONE owned peer task: accept once, read the client's COMPLETE request,
    // write the fixture, then wait until the client closes (true EOF/error)
    // or the absolute 10 s guard fires.
    let mut peer = tokio::spawn(async move {
        let (mut stream, _) =
            match tokio::time::timeout(Duration::from_secs(10), listener.accept()).await {
                Ok(Ok(accepted)) => accepted,
                _ => return PeerOutcome::NoConnection,
            };
        // The request is fully drained BEFORE any response byte is written
        // (rationale on `peer_read_request`).
        match tokio::time::timeout(Duration::from_secs(10), peer_read_request(&mut stream)).await {
            Ok(Ok(())) => {}
            // Read error or bound expiry: NOT evidence of client closure.
            Ok(Err(_)) => return PeerOutcome::PeerReadFailed,
            Err(_) => return PeerOutcome::PeerReadFailed,
        }
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
        // per read: with the request fully drained before the fixture went
        // out, the client sends nothing further, so every read result is
        // closure (or a protocol violation, still NOT closure evidence).
        let drain = async {
            loop {
                match peer_read_one(&mut stream).await {
                    // Stray bytes are DATA, not closure evidence.
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
         PeerReadFailed = the fixture request read errored or its bound expired (a real, \
         distinguishable outcome — never counted as client closure), \
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
