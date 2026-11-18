use super::*;

const PEER_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_PEER_BODY_BYTES: usize = 1 << 20;
const PEER_ACCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const CONTROL_ACCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

fn serve_one_401(stream: std::net::TcpStream) -> Result<(), String> {
    let mut stream = stream;
    // Bound every peer I/O operation: a stalled or lying peer must never
    // wedge the smoke job.
    stream
        .set_read_timeout(Some(PEER_IO_TIMEOUT))
        .map_err(|e| format!("peer read timeout setup failed: {e}"))?;
    stream
        .set_write_timeout(Some(PEER_IO_TIMEOUT))
        .map_err(|e| format!("peer write timeout setup failed: {e}"))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    // Bounded read: headers end at the first empty CRLF line. Any premature
    // close, stall or oversize request FAILS the peer verdict instead of
    // masquerading as the expected-401 success.
    let header_end;
    loop {
        let read = read_bounded(&mut stream, &mut chunk)?;
        if read == 0 {
            return Err("peer closed before complete request headers".to_string());
        }
        buf.extend_from_slice(&chunk[..read]);
        if buf.len() > 64 * 1024 {
            return Err("peer headers exceed the peer header cap".to_string());
        }
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
    }
    let headers = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
    let content_length: usize = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    // Refuse a lying content-length so our own buffer stays finite.
    if content_length > MAX_PEER_BODY_BYTES {
        return Err("peer content-length exceeds the peer body cap".to_string());
    }
    while buf.len() < header_end + content_length {
        let read = read_bounded(&mut stream, &mut chunk)?;
        if read == 0 {
            return Err("peer closed or stalled before complete request body".to_string());
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    // Only a COMPLETE request earns the response: one unsigned 401, then
    // close. The client must map this to Unauthenticated without parsing
    // anything; a truncated peer never reaches this point.
    stream
        .write_all(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
        .map_err(|e| format!("peer 401 write failed: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("peer flush failed: {e}"))
}

fn read_bounded(stream: &mut std::net::TcpStream, chunk: &mut [u8]) -> Result<usize, String> {
    match stream.read(chunk) {
        Ok(read) => Ok(read),
        // A timeout/WouldBlock means the peer stalled; fail the verdict.
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            Err("peer stalled: read timeout".to_string())
        }
        Err(e) => Err(format!("peer read failed: {e}")),
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Deadline-bounded accept: blocks on an OS-timer readiness wait (tokio's
/// timer + mio's net backend), never a sleep/poll loop. The current-thread
/// runtime matches the SDK transport's own worker idiom
/// (rust/src/client/http_transport.rs:318-330).
fn accept_within(
    listener: std::net::TcpListener,
    timeout: std::time::Duration,
) -> Result<std::net::TcpStream, String> {
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("peer listener nonblocking setup failed: {e}"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("peer accept runtime failed: {e}"))?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::from_std(listener)
            .map_err(|e| format!("peer listener conversion failed: {e}"))?;
        let (stream, _peer) = tokio::time::timeout(timeout, listener.accept())
            .await
            .map_err(|_| {
                "peer accept exceeded its independent bound; no connection arrived within the accept wait"
                    .to_string()
            })?
            .map_err(|e| format!("peer accept failed: {e}"))?;
        let mut stream = stream
            .into_std()
            .map_err(|e| format!("peer stream conversion failed: {e}"))?;
        stream
            .set_nonblocking(false)
            .map_err(|e| format!("peer stream blocking-mode reset failed: {e}"))?;
        Ok(stream)
    })
}

/// The peer's whole lifecycle: a deadline-bounded accept followed by the
/// bounded serve, entirely inside one finite function.
fn peer_lifecycle_401(
    listener: std::net::TcpListener,
    accept_timeout: std::time::Duration,
) -> Result<(), String> {
    let stream = accept_within(listener, accept_timeout)?;
    serve_one_401(stream)
}

pub(super) fn section_d(signer_arc: Arc<dyn Signer>, server_key: [u8; 32]) -> Result<(), String> {
    eprintln!("smoke: client-http over a real socket");
    let transport = mcp_jack::client::HttpTransport::builder()
        .build()
        .map_err(|e| format!("HttpTransport build failed: {e}"))?;
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("listener bind failed: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("listener addr failed: {e}"))?;
    check(
        addr.ip().is_loopback(),
        "listener must bind a loopback address",
    )?;
    // Accept lifecycle: the peer accept is deadline-bounded inside the peer
    // thread itself (tokio timeout, no release connect exists). A wedged SDK
    // call is the whole-job guard's concern (CI job timeout) and is
    // deliberately out of this fixture's scope.
    let (peer_tx, peer_rx) = std::sync::mpsc::channel();
    let peer = std::thread::spawn(move || {
        let _ = peer_tx.send(peer_lifecycle_401(listener, PEER_ACCEPT_TIMEOUT));
    });
    let (outcome_tx, outcome_rx) = std::sync::mpsc::channel();
    let client_thread = std::thread::spawn(move || {
        let outcome = (|| -> Result<(), String> {
            let cfg = rpc::Config {
                base_url: format!("http://{addr}/mcp"),
                aud: AUD.to_string(),
                signer: signer_arc,
                server_key,
                transport: Arc::new(transport),
                now: None,
                nonce: None,
                window_seconds: 0,
            };
            let client = rpc::Client::new(cfg).map_err(|e| format!("client build failed: {e}"))?;
            let err = expect_client_err(
                client.call_tool_raw_str(TOOL, Some("{}")),
                "unsigned 401 round trip must fail",
            )?;
            check(
                matches!(err, ClientErr::Unauthenticated(ref e) if e.status == 401),
                "unsigned 401 must surface as Unauthenticated with status 401",
            )
        })();
        let _ = outcome_tx.send(outcome);
    });
    let client_recv = outcome_rx
        .recv()
        .map_err(|_| "client phase dropped its channel".to_string());
    let peer_recv = peer_rx
        .recv()
        .map_err(|_| "peer lifecycle dropped its channel".to_string());
    let peer_join = peer
        .join()
        .map_err(|_| "peer lifecycle panicked".to_string());
    let client_join = client_thread
        .join()
        .map_err(|_| "client phase panicked".to_string());
    let client_outcome = client_recv?;
    let peer_verdict = peer_recv?;
    peer_join?;
    client_join?;
    // A failed peer verdict ALWAYS fails the section: a stalled or truncated
    // peer is never excused by an expected-401 client assertion. A wedged SDK
    // call (before its own transport deadline returns) is the whole-job
    // guard's concern: the client-thread join above is bounded by the SDK's
    // documented transport deadline, and a deadline regression degrades to
    // the CI job timeout.
    match peer_verdict {
        Err(e) => Err(format!("peer lifecycle failed: {e}")),
        Ok(()) => client_outcome,
    }
}

pub(super) fn section_f() -> Result<(), String> {
    eprintln!("smoke: CI-executed lifecycle controls");

    // Control A: the nonconnecting accept bound fires on its own, with no
    // SDK involvement at all. This calls the SAME production operation
    // section_d uses (`accept_within`); if that function were ever changed
    // to unbounded waiting, this control would block and the CI job would
    // fail — deliberately nonvacuous.
    let listener_a =
        TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("control A bind failed: {e}"))?;
    let verdict_a = accept_within(listener_a, CONTROL_ACCEPT_TIMEOUT);
    check(
        matches!(&verdict_a, Err(m) if m.contains("independent bound")),
        "nonconnecting accept must fail via the production deadline-bound accept",
    )?;

    // Control B: a raw lying peer sends complete headers but only part of the
    // declared body and shuts down; the peer verdict must fail instead of
    // yielding the expected-401 success.
    let listener_b =
        TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("control B bind failed: {e}"))?;
    let addr_b = listener_b
        .local_addr()
        .map_err(|e| format!("control B addr failed: {e}"))?;
    let mut lying = std::net::TcpStream::connect(addr_b)
        .map_err(|e| format!("control B lying peer connect failed: {e}"))?;
    lying
        .set_write_timeout(Some(PEER_IO_TIMEOUT))
        .map_err(|e| format!("control B write timeout setup failed: {e}"))?;
    lying
        .write_all(b"POST /mcp HTTP/1.1\r\ncontent-length: 4\r\n\r\nbo")
        .map_err(|e| format!("control B lying peer write failed: {e}"))?;
    lying
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| format!("control B lying peer shutdown failed: {e}"))?;
    drop(lying);
    // The connection is already pending and its FIN gives serve_one_401 the
    // EOF, so the accept returns promptly.
    let stream_b = accept_within(listener_b, PEER_ACCEPT_TIMEOUT)
        .map_err(|e| format!("control B accept failed: {e}"))?;
    let msg = match serve_one_401(stream_b) {
        Err(m) => m,
        Ok(()) => {
            return Err("incomplete-body control unexpectedly succeeded".to_string());
        }
    };
    check(
        msg.contains("request body"),
        "incomplete-body control must fail with a request-body verdict",
    )
}
