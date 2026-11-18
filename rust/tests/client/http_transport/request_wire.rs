use super::*;

/// Contract: the request line is byte-exact — the origin-form target on the
/// wire is identical to the signed target (percent escapes, query and dot
/// segments preserved, nothing normalized), and fragments are stripped
/// before sending (spec 01 section 3.1). The live server echoes back the
/// received method and raw request target; the client compares byte
/// equality against `mcp_jack::client::url::request_target` of the dialed
/// URL. Counterfactual caught: a backend that percent-decoded, removed dot
/// segments (`/../`), or appended the fragment would produce a different
/// echo than the signed target.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn origin_form_target_byte_exact_and_fragment_stripped() {
    let (listener, addr) = bind_loopback().await;
    let handler: Handler = Arc::new(|parts, _body| {
        Box::pin(async move {
            let echo = format!("{} {}", parts.method.as_str(), wire_target(&parts));
            full(200, &[("Content-Type", "text/plain")], echo.into_bytes())
        })
    });
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(15), None);

    // Dot segments + percent escapes + query preserved verbatim.
    let url = format!("http://{addr}/a%20b/../c?x=%2F&q=1");
    let req = HttpRequest {
        method: "POST".to_string(),
        url: url.clone(),
        headers: Vec::new(),
        body: Vec::new(),
    };
    let resp = transport
        .round_trip(req)
        .expect("direct adapter round trip must reach the server");
    let signed_target = request_target(&url).expect("policy-valid url has a target");
    let echo = String::from_utf8(resp.body).expect("echo is utf-8");
    assert_eq!(
        format!("POST {signed_target}"),
        echo,
        "the wire request line must be byte-identical to the signed target (dot segments, percent escapes, query preserved)"
    );

    // Fragment stripped before sending: the server must see /frag, never
    // /frag#nope.
    let url = format!("http://{addr}/frag#nope");
    let req = HttpRequest {
        method: "GET".to_string(),
        url: url.clone(),
        headers: Vec::new(),
        body: Vec::new(),
    };
    let resp = transport
        .round_trip(req)
        .expect("fragment request must reach the server");
    let echo = String::from_utf8(resp.body).expect("echo is utf-8");
    assert_eq!(
        format!("GET {}", request_target(&url).expect("target")),
        echo,
        "the fragment must be stripped from the wire request"
    );

    let _ = server.shutdown().await;
}

/// Contract: the destination policy is enforced LOCALLY by the adapter even
/// on direct use — `http://localhost:<port>/` is refused (plain http is
/// allowed only for a literal 127.x.y.z / [::1] host) BEFORE any I/O, even
/// though "localhost" resolves to the very counting listener bound on
/// 127.0.0.1. Counterfactual caught: an adapter that skipped the local
/// policy check would resolve localhost, connect, and increment the
/// counter.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_use_policy_http_localhost_refused_before_io() {
    let counting = CountingListener::bind().await;
    let transport = make_transport(Duration::from_secs(15), None);
    let err = transport
        .round_trip(HttpRequest {
            method: "GET".to_string(),
            url: format!("http://localhost:{}/", counting.addr.port()),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .expect_err("http://localhost must be refused");
    match &err {
        TransportError::Client(m) => assert!(
            m.contains("https required"),
            "policy refusal must carry the https-required message, got: {m}"
        ),
        other => panic!("policy refusal must be Err(Client), got: {other:?}"),
    }
    assert_eq!(
        0,
        counting.count(),
        "a policy-refused request must never touch the network"
    );
    drop(counting);
}

/// Contract: unrepresentable input is refused BEFORE any I/O — a header
/// value containing CR/LF (header injection), an invalid method (space), and
/// a CONNECT method (authority-form target can never match the signed
/// origin-form target) each produce a local Client error and never contact
/// the counting listener. Counterfactual caught: an adapter that passed such values to
/// its HTTP backend would either inject a second header onto the wire
/// (server-side request smuggling shape) or connect before failing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn header_injection_and_bad_method_refused_before_io() {
    let counting = CountingListener::bind().await;
    let base = format!("https://{}", counting.addr);
    let transport = make_transport(Duration::from_secs(15), None);

    let err = transport
        .round_trip(HttpRequest {
            method: "POST".to_string(),
            url: format!("{base}/mcp"),
            headers: vec![("X-Benign".to_string(), "ok\r\nX-Evil: 1".to_string())],
            body: Vec::new(),
        })
        .expect_err("CR/LF header value must be refused");
    assert!(
        matches!(&err, TransportError::Client(m) if m.contains("header value")),
        "injection refusal must be a Client header-value error, got: {err:?}"
    );

    let err = transport
        .round_trip(HttpRequest {
            method: "BAD METHOD".to_string(),
            url: format!("{base}/mcp"),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .expect_err("invalid method must be refused");
    assert!(
        matches!(&err, TransportError::Client(m) if m.contains("invalid method")),
        "bad-method refusal must be a Client error, got: {err:?}"
    );

    // CONNECT is refused before any I/O: its authority-form target could
    // never match the signed origin-form target, so the adapter refuses it
    // locally and the counting listener stays untouched.
    let err = transport
        .round_trip(HttpRequest {
            method: "CONNECT".to_string(),
            url: format!("{base}/mcp"),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .expect_err("CONNECT must be refused before any I/O");
    assert!(
        matches!(&err, TransportError::Client(m) if m.contains("CONNECT")),
        "CONNECT refusal must be a Client error naming CONNECT, got: {err:?}"
    );

    assert_eq!(
        0,
        counting.count(),
        "input-refused requests must never touch the network"
    );
    drop(counting);
}

/// Contract: a connection/read error mid-response leaves the transport
/// usable — after the server aborts the FIRST response mid-body (the head
/// promises more bytes than arrive), the SAME `HttpTransport` instance
/// completes a fresh signed round trip against the SAME server1 endpoint
/// (the handler is stateful: request 1 truncates, requests >= 2 answer a
/// signed 200, so both round trips hit one address).
///
/// What this PROVES: the failed request does not corrupt or poison the
/// agent/pool state — a subsequent signed request on the same instance to
/// the same endpoint succeeds.
///
/// What this does NOT prove (stated honestly): that the failed request's
/// socket was closed and its thread released. ureq's pool checkout probes
/// liveness (pool.rs `get` -> `is_open`) before handing out a pooled
/// connection, so even a leaked dead socket would be evicted rather than
/// reused, and this test could not distinguish eviction from correct
/// release. The hard peer-side evidence for socket release on the failure
/// path is `timeout_failure_socket_released_peer_observes_eof` above/below,
/// which observes EOF from the peer itself (ureq drops the BodyHandler
/// without pooling on read errors — reuse only happens for fulfilled bodies
/// via `ended()`).
///
/// Counterfactual caught: a backend that leaked per-request state into the
/// agent would fail the second request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_error_cleanup_and_transport_reusable() {
    let oracle = oracle();
    // ONE stateful server: request 1 truncates the response mid-body;
    // requests >= 2 are a healthy signed endpoint. The second round trip
    // goes to the SAME address on the SAME transport, proving reuse after a
    // failed request against the very endpoint that failed.
    let (listener, addr) = bind_loopback().await;
    let handler_oracle = Arc::clone(&oracle);
    let served = Arc::new(AtomicUsize::new(0));
    let handler_served = Arc::clone(&served);
    let handler: Handler = Arc::new(move |parts, body| {
        let oracle = Arc::clone(&handler_oracle);
        let served = Arc::clone(&handler_served);
        Box::pin(async move {
            let n = served.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                return full(200, &[("Content-Type", "application/json")], Vec::new()).with_body(
                    BodyKind::Truncated(vec![
                        b"this chunk arrives".to_vec(),
                        b" but the message never completes".to_vec(),
                    ]),
                );
            }
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
    });
    let server1 = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(15), None);
    let err = transport
        .round_trip(post(&format!("http://{addr}/mcp"), br#"{"ping":1}"#))
        .expect_err("a truncated response must be a transport error");
    assert!(
        matches!(err, TransportError::Transport(_)),
        "mid-body close must be Err(Transport), got: {err:?}"
    );

    // SAME transport, SAME server1 address: a fresh signed round trip must
    // succeed against the very endpoint that just failed.
    let st = signing_transport(transport, &oracle);
    let resp = st
        .round_trip(post(&format!("http://{addr}/mcp"), br#"{"ping":1}"#))
        .expect("the same transport must still work after a failed request");
    assert_eq!(200, resp.status);
    assert_eq!(rpc_result_body(&serde_json::json!({"ok": true})), resp.body);
    server1.shutdown().await;
}

/// Contract: the overall timeout is finite and enforced across every phase —
/// the server reads the request and then parks (never responds until
/// released); the client carries a 1 s `timeout(...)` deadline, so the call
/// RETURNS bounded with Err(Transport) whose Display names the timeout. An
/// INDEPENDENT 3 s guard (blocking thread + mpsc recv_timeout) fails the
/// test if the mechanism under test is broken, instead of hanging CI. No
/// wall-clock duration is asserted. Counterfactual caught: a backend without
/// a global deadline (or one applying it only to connect) would hang until
/// the independent guard fires.
///
/// Ownership: the client thread's termination is proven by a final join of the
/// ACTUAL `std::thread` (`join_client_thread_after_release`) AFTER the parked
/// peer has been released and the server shut down — the supported failure
/// boundary is documented on the helper; the
/// timeout-error and timeout-substring assertions run only after that
/// cleanup. A channel send or notification is NOT a join — only the real
/// `thread::join` proves the thread has fully terminated, so no thread,
/// server task, or parked peer is ever left detached.
///
/// NOTE: the drip/freeing sequence in the body below is unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeout_deadline_bounds_a_stalled_server() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let (listener, addr) = bind_loopback().await;
    let handler_gate = Arc::clone(&gate);
    let handler: Handler = Arc::new(move |_parts, _body| {
        let gate = Arc::clone(&handler_gate);
        Box::pin(async move {
            // Park before answering anything.
            gate.notified().await;
            full(200, &[], b"too late".to_vec())
        })
    });
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(1), None);
    // Run the blocking round trip on its own thread; the independent
    // recv_timeout guard below must fire BEFORE any hang becomes a CI kill.
    let (tx, rx) = std::sync::mpsc::channel();
    let url = format!("http://{addr}/mcp");
    let client = std::thread::spawn(move || {
        let result = transport.round_trip(post(&url, br#"{"ping":1}"#));
        let _ = tx.send(result);
    });
    match rx.recv_timeout(Duration::from_secs(3)) {
        Ok(result) => {
            // Deadline works: release the parked server FIRST so shutdown()
            // can join every task, join the ACTUAL client thread under a
            // bound, and ONLY THEN run the error-type and timeout-substring
            // assertions.
            gate.notify_one();
            let _ = server.shutdown().await;
            join_client_thread_after_release(client)
                .await
                .expect("client thread must terminate after peer release");
            let err = result.expect_err("a stalled server must hit the deadline");
            assert!(
                matches!(err, TransportError::Transport(_)),
                "the deadline must surface as Err(Transport), got: {err:?}"
            );
            assert!(
                err.to_string().to_lowercase().contains("timeout"),
                "the deadline error must name the timeout (ureq: \"timeout: ...\"), got: {err}"
            );
        }
        Err(_) => {
            // Guard fired: the deadline is broken. Clean up FIRST (bounded
            // peer release + server teardown), join the ACTUAL client thread,
            // and only then fail.
            gate.notify_one();
            let _ = server.shutdown().await;
            join_client_thread_after_release(client)
                .await
                .expect("client thread must terminate after peer release even though the deadline is broken");
            panic!("the deadline did not bound the call: independent 3 s guard fired");
        }
    }
}

/// Contract: the global timeout bounds the TLS HANDSHAKE itself — a server
/// that accepts the TCP connection and then never speaks (no TLS accept at
/// all) leaves the client stalled inside the handshake's first read, which
/// ureq bounds with the remaining global budget, surfacing
/// Err(Transport) naming the timeout. The independent 3 s guard (blocking
/// thread + mpsc recv_timeout) fails the test instead of hanging CI if the
/// deadline is not applied to the handshake phase. No wall-clock duration
/// is asserted. Counterfactual caught: a backend that applied its deadline
/// only to connect (or not at all during rustls complete_io) would hang
/// here until the independent guard fires.
///
/// Ownership: the client thread's termination is proven by a final join of the
/// ACTUAL `std::thread` (`join_client_thread_after_release`) AFTER the parked
/// accept task is released and joined (closing the socket,
/// unblocking the client's handshake read) — the supported failure
/// boundary is documented on the helper; the timeout assertions run only
/// after that cleanup. A channel send or notification is NOT a join — only
/// the real `thread::join` proves the thread has fully terminated, so no
/// thread or task is left detached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_handshake_stall_bounded_by_deadline() {
    let (ca_cert, _ca_key) = gen_ca("mcp-jack test ca");
    let ca_der = cert_der(&ca_cert);
    let gate = Arc::new(tokio::sync::Notify::new());
    // A PLAIN listener: accepts one connection and parks — no TLS accept,
    // no response, ever (until released).
    let (listener, addr) = bind_loopback().await;
    let listener_gate = Arc::clone(&gate);
    let mut parker = tokio::spawn(async move {
        if let Ok((_stream, _)) = listener.accept().await {
            listener_gate.notified().await;
            // _stream drops here, closing the socket.
        }
    });

    let transport = make_transport(Duration::from_secs(1), Some(ca_der));
    let (tx, rx) = std::sync::mpsc::channel();
    let url = format!("https://{addr}/mcp");
    let client = std::thread::spawn(move || {
        let result = transport.round_trip(post(&url, br#"{"ping":1}"#));
        let _ = tx.send(result);
    });
    match rx.recv_timeout(Duration::from_secs(3)) {
        Ok(result) => {
            // Release the parked accept task FIRST (closing the socket
            // unblocks the client's handshake read), join it under a bound,
            // then the FINAL join of the ACTUAL client thread AFTER the
            // owned, bounded peer release — and ONLY THEN the error-type and
            // timeout-substring assertions.
            gate.notify_one();
            let _ = join_owned_bounded(&mut parker).await;
            join_client_thread_after_release(client)
                .await
                .expect("client thread must terminate after peer release");
            let err = result.expect_err("a stalled TLS handshake must hit the deadline");
            assert!(
                matches!(err, TransportError::Transport(_)),
                "the handshake deadline must surface as Err(Transport), got: {err:?}"
            );
            assert!(
                err.to_string().to_lowercase().contains("timeout"),
                "the handshake deadline error must name the timeout, got: {err}"
            );
        }
        Err(_) => {
            // Guard fired: the deadline is broken. Clean up FIRST — release
            // the parked accept task (closing the socket unblocks the
            // client's handshake read) and join it, then the FINAL join of
            // the ACTUAL client thread AFTER the owned, bounded peer release
            // — and only then fail.
            gate.notify_one();
            let _ = join_owned_bounded(&mut parker).await;
            join_client_thread_after_release(client)
                .await
                .expect("client thread must terminate after peer release even though the deadline is broken");
            panic!("the deadline did not bound the TLS handshake: independent 3 s guard fired");
        }
    }
}

/// Contract: the adapter adds NOTHING to the wire beyond the caller's
/// headers (plus framing) — no User-Agent, no Accept, no Accept-Encoding
/// reach the server, and the caller's Jack-Auth appears exactly once. The
/// live server echoes every received header name into the body. Counterfactual
/// caught: a backend that auto-injected ureq/http defaults would show
/// user-agent/accept/accept-encoding in the echo.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_exactness_no_auto_headers_and_single_jack_auth() {
    let (listener, addr) = bind_loopback().await;
    let handler: Handler = Arc::new(|parts, _body| {
        Box::pin(async move {
            // `keys()` DEDUPLICATES, so the jack-auth count is echoed
            // separately via get_all: otherwise a duplicated header would be
            // unobservable (the exactly-once assertion could never fail).
            let jack_auth_count = parts.headers.get_all("jack-auth").iter().count();
            let names: Vec<&str> = parts.headers.keys().map(|k| k.as_str()).collect();
            full(
                200,
                &[("Content-Type", "text/plain")],
                format!("{};jack-auth={}", names.join(","), jack_auth_count).into_bytes(),
            )
        })
    });
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(15), None);
    let req = HttpRequest {
        method: "POST".to_string(),
        url: format!("http://{addr}/mcp"),
        headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            (
                "Jack-Auth".to_string(),
                "v1 kid=x,ts=1,nonce=y,sig=z".to_string(),
            ),
        ],
        body: br#"{"ping":1}"#.to_vec(),
    };
    let resp = transport
        .round_trip(req)
        .expect("direct adapter round trip must reach the server");
    let names = String::from_utf8(resp.body).expect("echo is utf-8");
    let (names, jack_auth) = names
        .split_once(";jack-auth=")
        .expect("the echo carries the jack-auth count");
    for banned in ["user-agent", "accept", "accept-encoding"] {
        assert!(
            !names.split(',').any(|n| n.eq_ignore_ascii_case(banned)),
            "no auto {banned} header may reach the wire, got: {names}"
        );
    }
    assert_eq!(
        1,
        jack_auth.parse::<usize>().expect("jack-auth count echoes"),
        "the caller's Jack-Auth must appear exactly once on the wire (counted via get_all, not the deduplicated keys), got: {names}"
    );

    let _ = server.shutdown().await;
}

/// Contract: the adapter's LOCAL pre-I/O refusals fire before ANY network
/// contact — caller framing headers (`Content-Length` / `Transfer-Encoding`),
/// a nonempty body on a non-POST/PUT/PATCH method, a duplicate `Host`, and
/// non-UTF-8 `Host` / `Authorization` values each yield an immediate
/// `TransportError::Client` naming the guard, and the counting listener's
/// connection count stays 0 across ALL sub-cases.
/// Counterfactual caught: a backend that deferred these checks to ureq-proto's
/// `analyze()` (which rejects duplicate/non-UTF-8 Host/Authorization only
/// AFTER connect) would connect and increment the counter; one that sent a
/// disagreeing framing header would also reach the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn framing_and_shape_refusals_never_touch_network() {
    let counting = CountingListener::bind().await;
    let base = format!("https://{}", counting.addr);
    let transport = make_transport(Duration::from_secs(15), None);

    // a) A caller Content-Length disagreeing with a nonempty body would
    //    silently drop the body (request-smuggling surface).
    let err = transport
        .round_trip(HttpRequest {
            method: "POST".to_string(),
            url: format!("{base}/mcp"),
            headers: vec![("Content-Length".to_string(), "0".to_string())],
            body: b"real bytes".to_vec(),
        })
        .expect_err("caller Content-Length must be refused");
    assert!(
        matches!(&err, TransportError::Client(m) if m.contains("framing header")),
        "Content-Length refusal must name the framing header guard, got: {err:?}"
    );

    // b) Same for Transfer-Encoding: framing is derived from the raw body.
    let err = transport
        .round_trip(HttpRequest {
            method: "POST".to_string(),
            url: format!("{base}/mcp"),
            headers: vec![("Transfer-Encoding".to_string(), "chunked".to_string())],
            body: b"real bytes".to_vec(),
        })
        .expect_err("caller Transfer-Encoding must be refused");
    assert!(
        matches!(&err, TransportError::Client(m) if m.contains("framing header")),
        "Transfer-Encoding refusal must name the framing header guard, got: {err:?}"
    );

    // c) More than one Host header: ureq-proto rejects it only AFTER connect.
    let err = transport
        .round_trip(HttpRequest {
            method: "POST".to_string(),
            url: format!("{base}/mcp"),
            headers: vec![
                (
                    "Host".to_string(),
                    format!("127.0.0.1:{}", counting.addr.port()),
                ),
                ("Host".to_string(), "127.0.0.1:9".to_string()),
            ],
            body: Vec::new(),
        })
        .expect_err("duplicate Host must be refused");
    assert!(
        matches!(&err, TransportError::Client(m) if m.contains("duplicate Host header")),
        "duplicate Host refusal must name the duplicate Host guard, got: {err:?}"
    );

    // d) A non-UTF-8 Host value: the obs-text byte 0x80 IS a valid
    //    HeaderValue, so only the adapter's explicit UTF-8 guard catches it
    //    before any I/O (the backend rejects it after connecting).
    let err = transport
        .round_trip(HttpRequest {
            method: "POST".to_string(),
            url: format!("{base}/mcp"),
            headers: vec![("Host".to_string(), "127.0.0.1:1\u{80}".to_string())],
            body: Vec::new(),
        })
        .expect_err("non-UTF-8 Host must be refused");
    assert!(
        matches!(&err, TransportError::Client(m) if m.contains("must be UTF-8")),
        "non-UTF-8 Host refusal must name the UTF-8 guard, got: {err:?}"
    );

    // e) Same guard for a non-UTF-8 Authorization value.
    let err = transport
        .round_trip(HttpRequest {
            method: "POST".to_string(),
            url: format!("{base}/mcp"),
            headers: vec![("Authorization".to_string(), "Basic\u{80}x".to_string())],
            body: Vec::new(),
        })
        .expect_err("non-UTF-8 Authorization must be refused");
    assert!(
        matches!(&err, TransportError::Client(m) if m.contains("must be UTF-8")),
        "non-UTF-8 Authorization refusal must name the UTF-8 guard, got: {err:?}"
    );

    // f) A nonempty body on GET: the backend would silently omit it.
    let err = transport
        .round_trip(HttpRequest {
            method: "GET".to_string(),
            url: format!("{base}/mcp"),
            headers: Vec::new(),
            body: b"silent victim".to_vec(),
        })
        .expect_err("GET with a body must be refused");
    assert!(
        matches!(&err, TransportError::Client(m) if m.contains("request body")),
        "GET-with-body refusal must name the request body guard, got: {err:?}"
    );

    assert_eq!(
        0,
        counting.count(),
        "every locally refused request must be rejected before ANY network contact"
    );
    drop(counting);
}

/// Contract: extension methods are transmitted EXACTLY — the adapter enables
/// ureq's `allow_non_standard_methods(true)`, so a WebDAV-style PROPFIND is
/// sent verbatim on the request line and the live server echoes
/// "PROPFIND /mcp" byte-exactly. Counterfactual caught: a backend that
/// rejected extension methods (ureq's default method/version check, which
/// fires only AFTER DNS/TCP connect — making the earlier version waste I/O
/// and refuse late) fails this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn extension_method_propfind_transmitted_exactly() {
    let (listener, addr) = bind_loopback().await;
    let handler: Handler = Arc::new(|parts, _body| {
        Box::pin(async move {
            let echo = format!("{} {}", parts.method.as_str(), wire_target(&parts));
            full(200, &[("Content-Type", "text/plain")], echo.into_bytes())
        })
    });
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(15), None);
    let resp = transport
        .round_trip(HttpRequest {
            method: "PROPFIND".to_string(),
            url: format!("http://{addr}/mcp"),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .expect("a PROPFIND extension method must be transmitted, not refused");
    let echo = String::from_utf8(resp.body).expect("echo is utf-8");
    assert_eq!(
        "PROPFIND /mcp", echo,
        "the extension method must reach the wire exactly as written"
    );

    let _ = server.shutdown().await;
}

/// Trusted TLS positive control: a finite paced body reaches autonomous EOF
/// and returns all four exact frames. Cleanup (including the real std-thread
/// join) completes before any behavioral assertion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_trickling_body_completes_with_sufficient_deadline() {
    let (ca, ca_key) = gen_ca("paced TLS CA");
    let (leaf, leaf_key) = gen_leaf("127.0.0.1", &ca, &ca_key);
    let (chain, key) = server_tls_parts(&leaf, &leaf_key, &ca);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let (listener, addr) = bind_loopback().await;
    let handler_gate = Arc::clone(&gate);
    let handler: Handler = Arc::new(move |_parts, _body| {
        let gate = Arc::clone(&handler_gate);
        Box::pin(async move {
            full(200, &[], Vec::new()).with_body(BodyKind::Trickle {
                gate,
                frames: (0..4).map(|_| vec![b'.'; 64]).collect(),
            })
        })
    });
    let server = spawn_tls(listener, tls_server_config(chain, key), handler);
    let transport = make_transport(Duration::from_secs(10), Some(cert_der(&ca)));
    let drip_gate = Arc::clone(&gate);
    let mut drip = tokio::spawn(async move {
        for _ in 0..4 {
            drip_gate.add_permits(1);
            tokio::time::sleep(TRICKLE_INTERVAL).await;
        }
        drip_gate.add_permits(1); // autonomous clean EOF
    });
    let (tx, rx) = std::sync::mpsc::channel();
    let client = std::thread::spawn(move || {
        let result = transport.round_trip(post(&format!("https://{addr}/mcp"), b"request"));
        let _ = tx.send(result);
    });
    let received =
        tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(6))).await;
    let shutdown = server.shutdown().await;
    let (drip_result, drip_aborted) = join_owned_bounded(&mut drip).await;
    let client_join = join_client_thread_after_release(client).await;
    let received = received
        .expect("receiver task")
        .expect("client result before 6 s guard");
    assert!(
        matches!(drip_result, Ok(())) && !drip_aborted,
        "drip did not finish: {drip_result:?}, aborted={drip_aborted}"
    );
    assert!(shutdown.cooperative(), "server shutdown: {shutdown:?}");
    assert_eq!(client_join, Ok(()));
    let response = received.expect("trusted TLS paced response succeeds");
    assert_eq!(response.body, vec![b'.'; 256]);
}

/// A paced TLS body keeps making progress past the one-second cumulative
/// budget. Its autonomous EOF means a broken deadline still finishes; the
/// independent receive guard only bounds a regression hang.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_overall_deadline_bounds_trickling_chunked_body() {
    let (ca, ca_key) = gen_ca("paced TLS CA");
    let (leaf, leaf_key) = gen_leaf("127.0.0.1", &ca, &ca_key);
    let (chain, key) = server_tls_parts(&leaf, &leaf_key, &ca);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let (listener, addr) = bind_loopback().await;
    let handler_gate = Arc::clone(&gate);
    let handler: Handler = Arc::new(move |_parts, _body| {
        let gate = Arc::clone(&handler_gate);
        Box::pin(async move {
            full(200, &[], Vec::new()).with_body(BodyKind::Trickle {
                gate,
                frames: (0..TRICKLE_FRAMES).map(|_| vec![b'.'; 64]).collect(),
            })
        })
    });
    let server = spawn_tls(listener, tls_server_config(chain, key), handler);
    let transport = make_transport(Duration::from_secs(1), Some(cert_der(&ca)));
    let drip_gate = Arc::clone(&gate);
    let mut drip = tokio::spawn(async move {
        for _ in 0..TRICKLE_FRAMES {
            drip_gate.add_permits(1);
            tokio::time::sleep(TRICKLE_INTERVAL).await;
        }
        drip_gate.add_permits(1); // autonomous clean EOF
    });
    let (tx, rx) = std::sync::mpsc::channel();
    let client = std::thread::spawn(move || {
        let result = transport.round_trip(post(&format!("https://{addr}/mcp"), b"request"));
        let _ = tx.send(result);
    });
    let received =
        tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(6))).await;
    let shutdown = server.shutdown().await;
    let (drip_result, drip_aborted) = join_owned_bounded(&mut drip).await;
    let client_join = join_client_thread_after_release(client).await;
    let received = received
        .expect("receiver task")
        .expect("result before independent 6 s guard");
    let result = received;
    assert!(
        matches!(drip_result, Ok(())) && !drip_aborted,
        "drip did not finish: {drip_result:?}, aborted={drip_aborted}"
    );
    assert_eq!(client_join, Ok(()));
    assert!(shutdown.cooperative(), "server shutdown: {shutdown:?}");
    let err = result.expect_err("cumulative TLS body deadline must fire");
    assert!(
        matches!(&err, TransportError::Transport(m) if m.to_lowercase().contains("timeout")),
        "expected actual timeout, got {err:?}"
    );
}
