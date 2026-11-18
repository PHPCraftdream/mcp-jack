use super::*;

/// Contract: TLS certificate validation is always on and the trusted-CA
/// path works — `trusted_certificates_der` REPLACES the root store with the
/// given test CA, so a full SigningTransport round trip over the live TLS
/// server signs (alice) and verifies (pinned oracle public key — the key
/// whose harness `sign_response` signed the answer) end to end.
/// Counterfactual caught: a backend that skips TLS validation or breaks the
/// trusted-root replacement would fail the handshake or fail verification.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_positive_path_signed_round_trip() {
    let oracle = oracle();
    let (ca_cert, ca_key) = gen_ca("mcp-jack test ca");
    let (leaf, leaf_key) = gen_leaf("127.0.0.1", &ca_cert, &ca_key);
    let (chain, key_der) = server_tls_parts(&leaf, &leaf_key, &ca_cert);
    let (listener, addr) = bind_loopback().await;
    let server = spawn_tls(
        listener,
        tls_server_config(chain, key_der),
        signed_ok_handler(Arc::clone(&oracle)),
    );

    let transport = make_transport(Duration::from_secs(15), Some(cert_der(&ca_cert)));
    let st = signing_transport(transport, &oracle);
    let resp = st
        .round_trip(post(&format!("https://{addr}/mcp"), br#"{"ping":1}"#))
        .expect("signed round trip over trusted TLS must verify");
    assert_eq!(200, resp.status);
    assert_eq!(rpc_result_body(&serde_json::json!({"ok": true})), resp.body);

    let _ = server.shutdown().await;
}

/// Contract: plain HTTP is allowed only for a literal loopback host, and the
/// same signed round trip works there (http://127.0.0.1 is accepted by the
/// URL policy). Counterfactual caught: a backend that rewrote the scheme,
/// refused loopback http, or mangled the signed target would fail
/// verification on the server or the pinned-oracle-key response check on the
/// client.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_http_loopback_signed_round_trip() {
    let oracle = oracle();
    let (listener, addr) = bind_loopback().await;
    let server = spawn_plain(listener, signed_ok_handler(Arc::clone(&oracle)));

    let transport = make_transport(Duration::from_secs(15), None);
    let st = signing_transport(transport, &oracle);
    let resp = st
        .round_trip(post(&format!("http://{addr}/mcp"), br#"{"ping":1}"#))
        .expect("signed round trip over loopback http must verify");
    assert_eq!(200, resp.status);
    assert_eq!(rpc_result_body(&serde_json::json!({"ok": true})), resp.body);

    let _ = server.shutdown().await;
}

/// Contract: TLS validation cannot be bypassed — a server whose certificate
/// was signed by an UNRELATED CA is refused even though the SANs match,
/// because the client trusts only its own CA. The error must be a
/// Transport-level error (connection/TLS failure), not a Client/Protocol
/// error (nothing about the request was wrong).
/// Counterfactual caught: a backend that fell back to the default webpki
/// roots, ignored `trusted_certificates_der`, or disabled validation would
/// let the handshake succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_ca_refused_as_transport_error() {
    let oracle = oracle();
    // The client's trusted CA...
    let (client_ca, _client_ca_key) = gen_ca("client ca");
    // ...and an independent CA that actually signs the server cert.
    let (other_ca, other_ca_key) = gen_ca("unrelated ca");
    let (leaf, leaf_key) = gen_leaf("127.0.0.1", &other_ca, &other_ca_key);
    let (chain, key_der) = server_tls_parts(&leaf, &leaf_key, &other_ca);
    let (listener, addr) = bind_loopback().await;
    let server = spawn_tls(
        listener,
        tls_server_config(chain, key_der),
        signed_ok_handler(Arc::clone(&oracle)),
    );

    let transport = make_transport(Duration::from_secs(15), Some(cert_der(&client_ca)));
    let st = signing_transport(transport, &oracle);
    let err = st
        .round_trip(post(&format!("https://{addr}/mcp"), br#"{"ping":1}"#))
        .expect_err("unknown CA must be refused");
    assert!(
        matches!(err, TransportError::Transport(ref m) if !m.is_empty()),
        "unknown CA must be a Transport error, got: {err:?}"
    );

    let _ = server.shutdown().await;
}

/// Contract: hostname/IP-SAN validation is always on — a certificate from
/// the TRUSTED CA whose SANs do not include the dialed IP (127.0.0.1) is
/// still refused. Counterfactual caught: a backend that checked only the
/// chain (or skipped name verification) would accept this connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostname_san_mismatch_refused_as_transport_error() {
    let oracle = oracle();
    let (ca_cert, ca_key) = gen_ca("mcp-jack test ca");
    // Trusted CA, but the SAN names a DNS host, never 127.0.0.1.
    let (leaf, leaf_key) = gen_leaf("mcp.example.test", &ca_cert, &ca_key);
    let (chain, key_der) = server_tls_parts(&leaf, &leaf_key, &ca_cert);
    let (listener, addr) = bind_loopback().await;
    let server = spawn_tls(
        listener,
        tls_server_config(chain, key_der),
        signed_ok_handler(Arc::clone(&oracle)),
    );

    let transport = make_transport(Duration::from_secs(15), Some(cert_der(&ca_cert)));
    let st = signing_transport(transport, &oracle);
    let err = st
        .round_trip(post(&format!("https://{addr}/mcp"), br#"{"ping":1}"#))
        .expect_err("IP-SAN mismatch must be refused");
    assert!(
        matches!(err, TransportError::Transport(_)),
        "SAN mismatch must be a Transport error, got: {err:?}"
    );

    let _ = server.shutdown().await;
}

/// Contract: redirects are NEVER followed. The live server answers a signed
/// request with an unsigned 302 and then a 307 whose Location points at a
/// counting listener; SigningTransport refuses the redirect (Err(Client),
/// message names redirects) BEFORE any second request, so the counting
/// listener's connection count stays 0. The 3xx answer is deliberately
/// unsigned: `SigningTransport` refuses redirects before verification.
/// Counterfactual caught: a backend with auto-follow enabled would connect
/// to the Location and increment the counter.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_follow_302_and_307_destination_not_contacted() {
    let oracle = oracle();
    let counting = CountingListener::bind().await;
    let (listener, addr) = bind_loopback().await;
    let location = format!("http://{}/next", counting.addr);
    let handler: Handler = Arc::new(move |parts, _body| {
        let location = location.clone();
        Box::pin(async move {
            let status = match parts.uri.path() {
                "/r307" => 307,
                _ => 302,
            };
            full(status, &[("Location", &location)], Vec::new())
        })
    });
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(15), None);
    let st = signing_transport(transport, &oracle);
    for path in ["/r302", "/r307"] {
        let err = st
            .round_trip(post(&format!("http://{addr}{path}"), br#"{"ping":1}"#))
            .expect_err("redirect must be refused");
        match &err {
            TransportError::Client(m) => assert!(
                m.contains("redirect"),
                "redirect refusal must mention redirects, got: {m}"
            ),
            other => panic!("redirect must be Err(Client), got: {other:?}"),
        }
    }
    assert_eq!(
        0,
        counting.count(),
        "the redirect Location target must never be contacted"
    );

    let _ = server.shutdown().await;
    drop(counting);
}

/// Contract: 304 is NOT in the redirect set — a signed empty-body 304 goes
/// through the normal verification and is returned to the caller as Ok
/// (interop.md 9.2). Counterfactual caught: a backend (or guard) treating
/// 304 as a redirect/refusal would break conditional requests.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_304_verifies_as_ok() {
    let oracle = oracle();
    let (listener, addr) = bind_loopback().await;
    let handler: Handler = {
        let oracle = Arc::clone(&oracle);
        Arc::new(move |parts, body| {
            let oracle = Arc::clone(&oracle);
            Box::pin(async move {
                let target = wire_target(&parts);
                match verify_request(
                    &oracle,
                    parts.method.as_ref(),
                    &target,
                    &parts.headers,
                    &body,
                ) {
                    Some(auth) => {
                        let headers = signed_json_headers(&oracle, &auth, 304, &[]);
                        full(304, &[], Vec::new()).override_headers(headers)
                    }
                    None => full(401, &[], Vec::new()),
                }
            })
        })
    };
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(15), None);
    let st = signing_transport(transport, &oracle);
    let resp = st
        .round_trip(post(&format!("http://{addr}/mcp"), br#"{"ping":1}"#))
        .expect("signed 304 must verify");
    assert_eq!(304, resp.status);
    assert!(resp.body.is_empty(), "304 body must stay empty");

    let _ = server.shutdown().await;
}

/// Contract: a signed non-2xx (404 with a body) verifies normally and passes
/// through as Ok with its status preserved, while an UNSIGNED 401 is mapped
/// to Err(Unauthenticated) with the body never parsed (spec 01 section 5).
/// Counterfactual caught: a backend with http_status_as_error-style
/// behaviour (or a verification path that rejects every non-2xx) would turn
/// the signed 404 into an error instead of a verified response.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_2xx_signed_passes_and_unsigned_401_maps() {
    let oracle = oracle();
    let (listener, addr) = bind_loopback().await;
    let handler: Handler = {
        let oracle = Arc::clone(&oracle);
        Arc::new(move |parts, body| {
            let oracle = Arc::clone(&oracle);
            Box::pin(async move {
                let target = wire_target(&parts);
                let want = br#"{"error":{"code":"not_found","message":"gone"}}"#.to_vec();
                match parts.uri.path() {
                    "/signed404" => match verify_request(
                        &oracle,
                        parts.method.as_ref(),
                        &target,
                        &parts.headers,
                        &body,
                    ) {
                        Some(auth) => {
                            let headers = signed_json_headers(&oracle, &auth, 404, &want);
                            full(404, &[], want).override_headers(headers)
                        }
                        None => full(401, &[], Vec::new()),
                    },
                    // Unsigned on purpose: exercises the 401 mapping.
                    _ => full(
                        401,
                        &[("Content-Type", "application/json")],
                        br#"{"error":{"code":"unknown_key","message":"verification failed"}}"#
                            .to_vec(),
                    ),
                }
            })
        })
    };
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(15), None);
    let st = signing_transport(transport, &oracle);
    let resp = st
        .round_trip(post(&format!("http://{addr}/signed404"), br#"{"ping":1}"#))
        .expect("signed 404 must verify and pass through");
    assert_eq!(404, resp.status);
    assert_eq!(
        br#"{"error":{"code":"not_found","message":"gone"}}"#.to_vec(),
        resp.body
    );

    let err = st
        .round_trip(post(
            &format!("http://{addr}/unsigned401"),
            br#"{"ping":1}"#,
        ))
        .expect_err("unsigned 401 must map to Unauthenticated");
    assert!(
        matches!(err, TransportError::Unauthenticated(_)),
        "unsigned 401 must be Unauthenticated, got: {err:?}"
    );

    let _ = server.shutdown().await;
}

/// Contract: a `text/event-stream` response is refused (exactly
/// `TransportError::Streaming`) on the response HEADERS, before any body
/// byte is buffered. The server writes the SSE head and then parks its body
/// on a release channel; the client carries a 1 s deadline as the bounded
/// failure guard. Counterfactual caught: an adapter that buffered the body
/// before refusing would stall on the pending body until the 1 s deadline
/// and surface Err(Transport) instead of the immediate Streaming error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_refused_on_headers_before_body_buffering() {
    let oracle = oracle();
    let gate = Arc::new(tokio::sync::Notify::new());
    let (listener, addr) = bind_loopback().await;
    let handler_gate = Arc::clone(&gate);
    let handler: Handler = Arc::new(move |_parts, _body| {
        let gate = Arc::clone(&handler_gate);
        Box::pin(async move {
            // Head goes out immediately; body never arrives until released.
            full(200, &[("Content-Type", "text/event-stream")], Vec::new())
                .with_body(BodyKind::Stalled(gate))
        })
    });
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(1), None);
    let st = signing_transport(transport, &oracle);
    let err = st
        .round_trip(post(&format!("http://{addr}/mcp"), br#"{"ping":1}"#))
        .expect_err("SSE must be refused");
    assert_eq!(
        TransportError::Streaming,
        err,
        "the SSE refusal must be the exact Streaming error (got {err:?}); a body-buffering adapter would instead hit the 1 s deadline as Transport"
    );

    // Release the server so the test ends with every task finite.
    gate.notify_one();
    let _ = server.shutdown().await;
}

/// MAX-1 and MAX bodies verify normally (Ok); a MAX+1 body is truncated by
/// the adapter's `take`-limited reader and then refused by SigningTransport
/// with the documented "response body exceeds" Client error. The oversized
/// answers are deliberately unsigned: the cap refusal happens before
/// verification. Counterfactual caught: an adapter that buffered without a
/// cap (unbounded memory) or truncated BELOW the cap (breaking MAX-sized
/// bodies) would fail one of these cases.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn body_cap_boundary_trio() {
    let oracle = oracle();
    let (listener, addr) = bind_loopback().await;
    let handler: Handler = {
        let oracle = Arc::clone(&oracle);
        Arc::new(move |parts, body| {
            let oracle = Arc::clone(&oracle);
            Box::pin(async move {
                let target = wire_target(&parts);
                let Some(auth) = verify_request(
                    &oracle,
                    parts.method.as_ref(),
                    &target,
                    &parts.headers,
                    &body,
                ) else {
                    return full(401, &[], Vec::new());
                };
                let len: usize = match parts.uri.path() {
                    "/max1" => MAX_BODY_BYTES - 1,
                    "/max" => MAX_BODY_BYTES,
                    // Deliberately unsigned: the cap check precedes
                    // verification, so an unsigned oversized answer still
                    // deterministically yields the cap Client error.
                    _ => return full(200, &[], vec![b'x'; MAX_BODY_BYTES + 1]),
                };
                let want = vec![b'x'; len];
                full(200, &[], want.clone())
                    .override_headers(signed_json_headers(&oracle, &auth, 200, &want))
            })
        })
    };
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(15), None);
    let st = signing_transport(transport, &oracle);

    let resp = st
        .round_trip(post(&format!("http://{addr}/max1"), br#"{"ping":1}"#))
        .expect("MAX-1 body must verify");
    assert_eq!(MAX_BODY_BYTES - 1, resp.body.len());

    let resp = st
        .round_trip(post(&format!("http://{addr}/max"), br#"{"ping":1}"#))
        .expect("MAX body must verify");
    assert_eq!(MAX_BODY_BYTES, resp.body.len());

    let err = st
        .round_trip(post(&format!("http://{addr}/over"), br#"{"ping":1}"#))
        .expect_err("MAX+1 body must be refused");
    match &err {
        TransportError::Client(m) => assert!(
            m.contains("response body exceeds"),
            "cap refusal must mention the cap, got: {m}"
        ),
        other => panic!("oversize body must be Err(Client), got: {other:?}"),
    }

    let _ = server.shutdown().await;
}

/// Contract: the cap applies while READING, independent of framing — a
/// chunked (unknown-length) MAX+1 body split across two chunks is still
/// capped to MAX+1 bytes by the `take`-limited reader, and SigningTransport
/// refuses it with the same Client error. Counterfactual caught: an adapter
/// that only honoured content-length (or concatenated chunk boundaries
/// incorrectly) would either accept the oversized chunked body or error at
/// the transport level instead of yielding the cap error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chunked_oversize_body_capped_while_reading() {
    let oracle = oracle();
    let (listener, addr) = bind_loopback().await;
    let handler: Handler = Arc::new(move |_parts, _body| {
        Box::pin(async move {
            // MAX+1 bytes across two chunks, no Content-Length: hyper uses
            // Transfer-Encoding: chunked. Unsigned (cap precedes verify).
            full(200, &[], Vec::new()).with_body(BodyKind::Chunks(vec![
                vec![b'x'; MAX_BODY_BYTES / 2],
                vec![b'x'; MAX_BODY_BYTES - MAX_BODY_BYTES / 2 + 1],
            ]))
        })
    });
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(15), None);
    let st = signing_transport(transport, &oracle);
    let err = st
        .round_trip(post(&format!("http://{addr}/mcp"), br#"{"ping":1}"#))
        .expect_err("chunked MAX+1 body must be refused");
    match &err {
        TransportError::Client(m) => assert!(
            m.contains("response body exceeds"),
            "chunked cap refusal must mention the cap, got: {m}"
        ),
        other => panic!("chunked oversize must be Err(Client), got: {other:?}"),
    }

    let _ = server.shutdown().await;
}

/// Contract: the cap bounds READING against a producer that NEVER finishes.
/// The server sends `Content-Length: MAX_BODY_BYTES + 2` but only MAX+1
/// body bytes, then parks forever (the announced message never completes).
/// The adapter must stop reading at the `take(MAX_BODY_BYTES + 1)` cap and
/// refuse with the "response body exceeds" Client error WITHOUT waiting for
/// the announced-but-never-sent remainder.
/// Counterfactual: without the adapter's `take(MAX+1)`, the adapter would
/// block reading the missing final two bytes of the announced length and
/// eventually surface `Err(Transport)` from the 5 s deadline — so this test
/// fails for an adapter that buffers past the cap against a producer that
/// never finishes its message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn body_cap_stops_reading_held_open_producer() {
    let oracle = oracle();
    let gate = Arc::new(tokio::sync::Notify::new());
    let (listener, addr) = bind_loopback().await;
    let handler_gate = Arc::clone(&gate);
    let handler_oracle = Arc::clone(&oracle);
    let handler: Handler = Arc::new(move |parts, body| {
        let gate = Arc::clone(&handler_gate);
        let oracle = Arc::clone(&handler_oracle);
        Box::pin(async move {
            // Signed-ok handshake proves the failure is the CAP, not a
            // verification problem.
            let target = wire_target(&parts);
            let Some(auth) = verify_request(
                &oracle,
                parts.method.as_ref(),
                &target,
                &parts.headers,
                &body,
            ) else {
                return full(401, &[], Vec::new());
            };
            full(200, &[], Vec::new())
                .with_body(BodyKind::ExactThenPark {
                    announced: MAX_BODY_BYTES as u64 + 2,
                    chunks: vec![vec![b'x'; MAX_BODY_BYTES + 1]],
                    gate,
                })
                .override_headers(signed_json_headers(&oracle, &auth, 200, &[]))
        })
    });
    let server = spawn_plain(listener, handler);

    let transport = make_transport(Duration::from_secs(5), None);
    let st = signing_transport(transport, &oracle);
    let err = st
        .round_trip(post(&format!("http://{addr}/mcp"), br#"{"ping":1}"#))
        .expect_err("an over-cap body from a never-finishing producer must be refused");
    match &err {
        TransportError::Client(m) => assert!(
            m.contains("response body exceeds"),
            "the cap refusal must fire without waiting for the announced remainder, got: {m}"
        ),
        other => panic!(
            "held-open over-cap producer must yield Err(Client), got: {other:?} (a cap-less adapter would block until the deadline as Err(Transport))"
        ),
    }

    // Release the parked producer so the guard's shutdown() can join it.
    gate.notify_one();
    let _ = server.shutdown().await;
}

/// Contract: status and ALL response headers are preserved untouched,
/// including REPEATED Jack-Auth values in wire order — nothing is merged,
/// reordered or dropped. Two observations:
///
/// a) DIRECT adapter use (`HttpTransport::round_trip`, no signing wrapper):
///    the server sends two Jack-Auth values (first signed-valid, second
///    junk) and the adapter returns Ok with BOTH values in wire order.
/// b) `SigningTransport` over the same server: verification sees two values
///    and fails with Err(Protocol) whose message names the header being
///    present more than once.
///
/// Counterfactual (why (b) is the preservation proof): if the adapter
/// DROPPED duplicate Jack-Auth values, verification would silently pass
/// with the single surviving value — the Protocol error itself proves both
/// values reached verification.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_jack_auth_response_headers_preserved() {
    let oracle = oracle();
    let (listener, addr) = bind_loopback().await;
    let handler: Handler = {
        let oracle = Arc::clone(&oracle);
        Arc::new(move |parts, body| {
            let oracle = Arc::clone(&oracle);
            Box::pin(async move {
                let target = wire_target(&parts);
                let want = rpc_result_body(&serde_json::json!({"ok": true}));
                match verify_request(
                    &oracle,
                    parts.method.as_ref(),
                    &target,
                    &parts.headers,
                    &body,
                ) {
                    Some(auth) => {
                        let valid = signed_response_header(&oracle, &auth.sig, 200, &want);
                        full(200, &[("Content-Type", "application/json")], want.clone())
                            .with_headers(vec![
                                ("Jack-Auth".to_string(), valid),
                                ("Jack-Auth".to_string(), "v1 kid=xx,ts=1,sig=yy".to_string()),
                            ])
                    }
                    None => full(401, &[], Vec::new()),
                }
            })
        })
    };
    let server = spawn_plain(listener, handler);

    // Hand-sign the request exactly like SigningTransport does (same signer,
    // aud, nonce and clock pins), so the handler takes the duplicate-header
    // branch and the first response value is signed-valid.
    let url = format!("http://{addr}/mcp");
    let target = request_target(&url).expect("policy-valid url has a target");
    let req_body = br#"{"ping":1}"#.to_vec();
    let signed = mcp_jack::client::auth::sign_request(
        &signer_by_name("alice"),
        FIXTURE_AUD,
        "POST",
        &target,
        &req_body,
        &[7u8; 16],
        FIXTURE_NOW,
    )
    .expect("hand-signed request");
    let mut request = post(&url, &req_body);
    request
        .headers
        .push(("Jack-Auth".to_string(), signed.header_value));

    // (a) DIRECT adapter use: duplicates survive in wire order, Ok response.
    let transport = make_transport(Duration::from_secs(15), None);
    let resp = transport
        .round_trip(request)
        .expect("the direct adapter must return the duplicated headers untouched");
    assert_eq!(200, resp.status);
    let values = resp.header_values("Jack-Auth");
    assert_eq!(2, values.len(), "both Jack-Auth values must survive");
    assert_eq!(
        "v1 kid=xx,ts=1,sig=yy", values[1],
        "second junk value preserved verbatim"
    );
    // The first value must be the signed-valid one for THIS request.
    let want_first = signed_response_header(
        &oracle,
        &signed.auth.sig,
        200,
        &rpc_result_body(&serde_json::json!({"ok": true})),
    );
    assert_eq!(
        want_first, values[0],
        "first value is the signed-valid one, in wire order"
    );

    // (b) SigningTransport over the same server: verification sees TWO
    // values and fails with Protocol — the proof of preservation (see the
    // counterfactual in the doc comment above).
    let st = signing_transport(make_transport(Duration::from_secs(15), None), &oracle);
    let err = st
        .round_trip(post(&url, &req_body))
        .expect_err("duplicated Jack-Auth must fail verification");
    match &err {
        TransportError::Protocol(e) => assert!(
            e.message.contains("more than once"),
            "the Protocol error must name the duplicate Jack-Auth header, got: {e:?}"
        ),
        other => panic!("duplicates must be Err(Protocol), got: {other:?}"),
    }

    let _ = server.shutdown().await;
}

/// Read TLS records until rustls has consumed the whole ClientHello and has
/// queued a real server flight. TCP reads may split that one handshake message.
async fn collect_rustls_server_flight(
    stream: &mut tokio::net::TcpStream,
    conn: &mut tokio_rustls::rustls::ServerConnection,
) -> Result<Vec<u8>, String> {
    use std::io::Cursor;
    use tokio::io::AsyncReadExt;
    let mut input = [0u8; 4096];
    while !conn.wants_write() {
        let n = stream.read(&mut input).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("client closed before complete ClientHello".to_string());
        }
        let mut cursor = Cursor::new(&input[..n]);
        let mut consumed = 0usize;
        while consumed < n {
            let read = conn.read_tls(&mut cursor).map_err(|e| e.to_string())?;
            if read == 0 {
                return Err("rustls consumed no ClientHello bytes".to_string());
            }
            consumed += read;
            conn.process_new_packets().map_err(|e| e.to_string())?;
        }
    }
    let mut flight = Vec::new();
    conn.write_tls(&mut flight).map_err(|e| e.to_string())?;
    if flight.is_empty() {
        return Err("rustls generated an empty server flight".to_string());
    }
    Ok(flight)
}

enum HandshakePeerOutcome {
    Closed,
    GuardExpired,
}

/// A real rustls flight is sent in finite paced writes. After the flight, a
/// short bounded drain distinguishes client closure from peer-guard expiry;
/// an idle-only client that waits for HTTP cannot pass merely by timing out.
/// Accept, TLS input, flight generation, fragmentation, and drain share one
/// absolute peer lifetime bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_handshake_fragment_deadline_is_absolute() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const PEER_BOUND: Duration = Duration::from_secs(10);
    const RECEIVE_GUARD: Duration = Duration::from_secs(6);
    const JOIN_GUARD: Duration = Duration::from_secs(12);
    const FRAGMENTS: usize = 40;
    const GAP: Duration = Duration::from_millis(80);

    let (ca, ca_key) = gen_ca("fragment deadline CA");
    let (leaf, leaf_key) = gen_leaf("127.0.0.1", &ca, &ca_key);
    let (chain, key) = server_tls_parts(&leaf, &leaf_key, &ca);
    let config = std::sync::Arc::new(tls_server_config(chain, key));
    let (listener, addr) = bind_loopback().await;
    let mut peer = tokio::spawn(async move {
        let bounded = tokio::time::timeout(PEER_BOUND, async move {
            let (mut stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
            let mut conn =
                tokio_rustls::rustls::ServerConnection::new(config).map_err(|e| e.to_string())?;
            let flight = collect_rustls_server_flight(&mut stream, &mut conn).await?;
            let flight_len = flight.len();
            let chunk_size = flight.len().div_ceil(FRAGMENTS).max(1);
            // A write failure ends transmission but is not closure evidence;
            // proceed to drain queued bytes until the client truly closes.
            for part in flight.chunks(chunk_size).take(FRAGMENTS) {
                if stream.write_all(part).await.is_err() {
                    break;
                }
                tokio::time::sleep(GAP).await;
            }
            // The short absolute drain guard is NOT closure evidence: a client
            // still waiting for HTTP after completing TLS must fail the oracle.
            let mut buf = [0u8; 1024];
            let drained = tokio::time::timeout(Duration::from_millis(200), async {
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => return HandshakePeerOutcome::Closed,
                        Ok(_) => continue,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => return HandshakePeerOutcome::Closed,
                    }
                }
            })
            .await
            .unwrap_or(HandshakePeerOutcome::GuardExpired);
            Ok::<(usize, HandshakePeerOutcome), String>((flight_len, drained))
        })
        .await;
        match bounded {
            Ok(Ok(outcome)) => Ok(outcome),
            Ok(Err(e)) => Err(e),
            Err(_) => Ok((0, HandshakePeerOutcome::GuardExpired)),
        }
    });

    let transport = make_transport(Duration::from_secs(1), Some(cert_der(&ca)));
    let (client_tx, client_rx) = std::sync::mpsc::channel();
    let client = std::thread::spawn(move || {
        let result = transport.round_trip(post(&format!("https://{addr}/mcp"), b"request"));
        let _ = client_tx.send(result);
    });

    // Collect the independent client result before joining the still-running
    // peer. Retain the JoinHandle through bounded wait and abort+await fallback.
    let received = tokio::task::spawn_blocking(move || client_rx.recv_timeout(RECEIVE_GUARD)).await;
    let peer_result = match tokio::time::timeout(JOIN_GUARD, &mut peer).await {
        Ok(joined) => joined,
        Err(_) => {
            peer.abort();
            peer.await
        }
    };
    let client_join = join_client_thread_after_release(client).await;

    let received = received.ok().and_then(Result::ok);
    let peer_result = match peer_result {
        Ok(Ok(result)) => Some(result),
        Ok(Err(e)) => {
            assert_eq!(client_join, Ok(()), "client thread did not join");
            panic!("peer fixture failed: {e}");
        }
        Err(e) => {
            assert_eq!(client_join, Ok(()), "client thread did not join");
            panic!("peer task failed or was aborted: {e}");
        }
    };
    assert_eq!(client_join, Ok(()), "client thread did not join");
    let (flight_len, peer_outcome) = peer_result.expect("peer result collected");
    assert!(flight_len > 0, "rustls generated no server flight");
    let err = received
        .expect("client result before independent receive guard")
        .expect_err("incomplete handshake must fail");
    assert!(
        matches!(&err, TransportError::Transport(m) if m.to_lowercase().contains("timeout")),
        "expected handshake timeout, got {err:?}"
    );
    assert!(
        matches!(peer_outcome, HandshakePeerOutcome::Closed),
        "peer did not observe client closure"
    );
}

/// Contract: the streaming-refusal decision is byte-based across every
/// Content-Type field line (spec/fixtures/client-streaming-refusal.json):
/// a line whose media type is `text/event-stream` refuses the response as
/// `TransportError::Streaming` EVEN when the header value is not valid
/// UTF-8 (raw 0xFF bytes alongside the media type). Go and TypeScript refuse
/// such a response; the adapter must lossily decode each line rather than
/// skipping it. Counterfactual caught: a check that filters lines through
/// `HeaderValue::to_str().ok()` drops this line entirely, so the response is
/// buffered and then fails as Err(Transport) ("non-UTF-8 response header")
/// instead of the exact Streaming refusal.
///
/// The hyper test harness cannot express non-UTF-8 header values, so this
/// test answers over a raw TCP socket with hand-written response bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_utf8_content_type_with_sse_media_type_refused_as_streaming() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let oracle = oracle();
    let (listener, addr) = bind_loopback().await;
    let responder = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("raw peer accept");
        let mut buf = vec![0u8; 8192];
        let mut seen = 0usize;
        loop {
            let n = sock
                .read(&mut buf[seen..])
                .await
                .expect("raw peer read request");
            assert!(n > 0, "client closed before sending a full request");
            seen += n;
            if buf[..seen].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            assert!(seen < buf.len(), "request larger than the read buffer");
        }
        // Hand-written head: the Content-Type value carries a raw 0xFF byte
        // (obs-text, legal in a header value) next to the SSE media type, so
        // `to_str()` fails on that line.
        let mut head = Vec::new();
        head.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; x=");
        head.push(0xFF);
        head.extend_from_slice(b"\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
        sock.write_all(&head).await.expect("raw peer write");
        let _ = sock.shutdown().await;
    });

    let transport = make_transport(Duration::from_secs(1), None);
    let st = signing_transport(transport, &oracle);
    let err = st
        .round_trip(post(&format!("http://{addr}/mcp"), br#"{"ping":1}"#))
        .expect_err("a non-UTF-8 SSE Content-Type must still be refused");
    assert_eq!(
        TransportError::Streaming,
        err,
        "the refusal must be the exact Streaming error (got {err:?}); \
         skipping the non-UTF-8 Content-Type line buffers the body and \
         surfaces Err(Transport) instead"
    );

    responder.abort();
    let _ = responder.await;
}
