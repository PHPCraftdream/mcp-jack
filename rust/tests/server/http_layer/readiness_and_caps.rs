use super::*;

// ---------------------------------------------------------------------------
// Readiness contract: a clone drops readiness state, so tower requires the
// instance readied by poll_ready to be the one `call` invokes.
// ---------------------------------------------------------------------------

/// Inner service that panics if `call` runs on an instance whose poll_ready
/// was not the last readiness method invoked on it (catches
/// clone-after-ready).
struct NeedsReady {
    calls: Arc<AtomicUsize>,
    ready: bool,
}

impl Clone for NeedsReady {
    fn clone(&self) -> Self {
        // tower: a clone may have dropped readiness state, so it starts NOT
        // ready.
        Self {
            calls: Arc::clone(&self.calls),
            ready: false,
        }
    }
}

impl tower::Service<http::Request<Full<Bytes>>> for NeedsReady {
    type Response = http::Response<Full<Bytes>>;
    type Error = String;
    type Future = std::future::Ready<Result<http::Response<Full<Bytes>>, String>>;
    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), String>> {
        self.ready = true;
        std::task::Poll::Ready(Ok(()))
    }
    fn call(&mut self, _req: http::Request<Full<Bytes>>) -> Self::Future {
        if !std::mem::replace(&mut self.ready, false) {
            panic!("inner.call() without poll_ready() on this instance (clone-after-ready)");
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(http::Response::builder()
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from_static(b"{}")))
            .expect("static response")))
    }
}

/// The readied inner instance must be the one that serves the request.
///
/// Pipeline: verification passes and the GET forwards. oneshot polls poll_ready on the JackService, which forwards to the inner
/// instance's poll_ready (ready=true on THAT instance); call must move THAT
/// instance into the future. The second request exercises the fresh-clone
/// cycle left behind by the first call's replace. Old code cloned the service
/// inside call, so the inner clone started ready=false -> panic -> test
/// failure.
#[tokio::test]
async fn readiness_ready_instance_is_called() {
    let state = MemoryState::new();
    seed_registry(&state);
    let layer = JackLayer::new(HandlerConfig {
        verifier: build_verifier(state, None),
        server_key: server_signing_key(),
        max_body_bytes: 0,
        max_response_bytes: 0,
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let svc = layer.layer(NeedsReady {
        calls: Arc::clone(&calls),
        ready: false,
    });
    let alice = harness::signer_by_name("alice");
    for _ in 0..2 {
        let signed = signed_request(&alice, "GET", "/mcp", b"");
        let res = svc
            .clone()
            .oneshot(build_request(&signed, "GET", "/mcp", b""))
            .await
            .expect("no inner error");
        assert_eq!(res.status(), 200);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

/// An inner Jack-Auth header must be REPLACED, not appended (Go header.Set).
///
/// Pipeline: verification passes and the GET forwards; the signed
/// answer must carry exactly one Jack-Auth (ours) and no inner Content-Length.
/// Old code appended, yielding two Jack-Auth headers -> the len==1 assert
/// fails.
#[tokio::test]
async fn inner_jack_auth_is_replaced_not_appended() {
    let h = new_harness(
        0,
        InnerResponse {
            status: 200,
            content_type: "application/json",
            body: INNER_OK_BODY.to_vec(),
            extra_headers: vec![
                ("Jack-Auth", "v1 kid=bogus,ts=1,sig=bogus"),
                ("Content-Length", "999"),
            ],
        },
    );
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "GET", "/mcp", b"");
    let got = inspect(
        send(&h.service, build_request(&signed, "GET", "/mcp", b""))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(
        got.jack_auth.len(),
        1,
        "exactly one Jack-Auth — Go header.Set parity"
    );
    assert_signed(&got, &signed.request_sig, &h.server_pub);
    assert_eq!(got.content_length, None, "inner Content-Length is dropped");
}

/// The SSE refusal must not buffer (or even poll) the inner body.
///
/// Pipeline: verification passes and the GET forwards; the inner 200
/// text/event-stream is refused by the stream guard BEFORE the body is read,
/// so an endless (always-pending Channel) body cannot hang the response and
/// is dropped unread. Old code buffered first -> the timeout fires -> test
/// failure.
#[tokio::test]
async fn refuses_endless_stream_without_buffering() {
    let state = MemoryState::new();
    seed_registry(&state);
    let layer = JackLayer::new(HandlerConfig {
        verifier: build_verifier(state, None),
        server_key: server_signing_key(),
        max_body_bytes: 0,
        max_response_bytes: 0,
    });
    let (mut sender, body) = http_body_util::Channel::<Bytes>::new(1);
    let cell = Arc::new(Mutex::new(Some(body)));
    let svc = layer.layer(tower::service_fn(
        move |_req: http::Request<Full<Bytes>>| {
            // Channel is not Clone; hand the single body out of a shared cell.
            let body = cell
                .lock()
                .expect("body cell")
                .take()
                .expect("one inner request");
            async move {
                Ok::<_, String>(
                    http::Response::builder()
                        .header("Content-Type", "text/event-stream")
                        .body(body)
                        .expect("static response"),
                )
            }
        },
    ));
    let server_pub = *server_signing_key().verifying_key().as_bytes();
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "GET", "/mcp", b"");
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        svc.oneshot(build_request(&signed, "GET", "/mcp", b"")),
    )
    .await
    .expect("SSE refusal must not wait on the endless body")
    .expect("request accepted");
    let got = inspect(res).await;
    assert_eq!(got.status, 501);
    assert_eq!(error_code(&got.body), "streaming_unsupported");
    assert_signed(&got, &signed.request_sig, &server_pub);
    // The body was dropped unread: the producer can no longer enqueue frames.
    let send_error: http_body_util::channel::SendError = sender
        .send_data(Bytes::from_static(b"data: never\n\n"))
        .await
        .expect_err("the endless body must be dropped without polling");
    assert_eq!(send_error.to_string(), "failed to send frame");
}

// ---------------------------------------------------------------------------
// Response cap (HandlerConfig::max_response_bytes). Probes are channels,
// counters and drop flags, never sleeps. Every overflow test is red on the
// pre-cap code (limit usize::MAX): it answered the upstream status and full
// body instead of the signed 502.
// ---------------------------------------------------------------------------

const OVERFLOW_BODY: &str = concat!(
    r#"{"error":{"code":"response_too_large","#,
    r#""message":"upstream response exceeds the configured limit"}}"#
);

/// A response seen from the layer: headers are captured before the body is
/// consumed, plus the request signature it must be bound to.
struct Observed {
    got: GotResponse,
    headers: http::HeaderMap,
    sent: SentRequest,
}

impl Observed {
    fn header_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.headers.keys().map(|k| k.as_str().to_owned()).collect();
        names.sort();
        names
    }
}

async fn observe(res: http::Response<Full<Bytes>>, sent: SentRequest) -> Observed {
    let headers = res.headers().clone();
    Observed {
        got: inspect(res).await,
        headers,
        sent,
    }
}

/// One signed GET /mcp through the harness service.
async fn get_via(h: &TestHarness) -> Observed {
    let alice = harness::signer_by_name("alice");
    let sent = signed_request(&alice, "GET", "/mcp", b"");
    let res = send(&h.service, build_request(&sent, "GET", "/mcp", b""))
        .await
        .expect("no inner error");
    observe(res, sent).await
}

/// Upstream answer carrying headers that must NOT survive an overflow.
fn upstream_of(len: usize) -> InnerResponse {
    InnerResponse {
        status: 201,
        content_type: "text/plain",
        body: vec![b'x'; len],
        extra_headers: vec![("X-Upstream", "1"), ("Set-Cookie", "sid=1")],
    }
}

/// The overflow answer: signed 502 bound to the ORIGINAL request signature,
/// a fresh Content-Type-only header set and no upstream byte.
fn assert_overflow_answer(o: &Observed, server_pub: &[u8; 32]) {
    assert_eq!(o.got.status, 502);
    assert_eq!(error_code(&o.got.body), "response_too_large");
    assert_eq!(o.got.body.as_ref(), OVERFLOW_BODY.as_bytes());
    assert_eq!(o.header_names(), vec!["content-type", "jack-auth"]);
    assert_eq!(o.got.content_type.as_deref(), Some("application/json"));
    assert_signed(&o.got, &o.sent.request_sig, server_pub);
    // A different (never-sent) request has a different signature; the answer
    // must not verify against it.
    let other = signed_request(&harness::signer_by_name("alice"), "GET", "/mcp", b"");
    assert_ne!(other.request_sig, o.sent.request_sig);
    let values: Vec<&str> = o.got.jack_auth.iter().map(String::as_str).collect();
    let error = mcp_jack::signing::verify_response(
        server_pub,
        502,
        &values,
        &other.request_sig,
        &o.got.body,
        FIXTURE_NOW,
        30,
    )
    .expect_err("overflow answer must be bound to its own request only");
    assert_eq!(error.http_status, 0);
    assert_eq!(error.code, mcp_jack::error::codes::BAD_SIGNATURE);
}

/// An ordinary upstream answer passes untouched and is signed.
fn assert_passed_through(o: &Observed, expected_body: &[u8], server_pub: &[u8; 32]) {
    assert_eq!(o.got.status, 201);
    assert_eq!(o.got.body.as_ref(), expected_body);
    assert_eq!(o.got.content_type.as_deref(), Some("text/plain"));
    assert_eq!(
        o.headers.get("x-upstream").map(|v| v.as_bytes()),
        Some(&b"1"[..])
    );
    assert_eq!(
        o.headers.get("set-cookie").map(|v| v.as_bytes()),
        Some(&b"sid=1"[..])
    );
    assert_eq!(o.got.content_length, None);
    assert_signed(&o.got, &o.sent.request_sig, server_pub);
}

/// Cap 8: cap-1 and exactly cap bytes in a single frame pass byte for byte.
///
/// Red-before: n/a (passes before too); it pins the exact-boundary side so
/// the overflow tests below cannot be satisfied by rejecting everything.
#[tokio::test]
async fn response_cap_minus_one_and_exact_pass() {
    for len in [7usize, 8] {
        let h = new_harness_with(0, 8, upstream_of(len));
        let o = get_via(&h).await;
        assert_passed_through(&o, &vec![b'x'; len], &h.server_pub);
    }
}

/// Cap 8: cap+1 bytes in a single frame overflow into the signed 502.
///
/// Red-before: old code returned 201 with the 9 upstream bytes.
#[tokio::test]
async fn response_cap_plus_one_overflows() {
    let h = new_harness_with(0, 8, upstream_of(9));
    let o = get_via(&h).await;
    assert_overflow_answer(&o, &h.server_pub);
    assert_eq!(h.inner.calls(), 1);
    assert!(o.headers.get("x-upstream").is_none());
    assert!(o.headers.get("set-cookie").is_none());
}

/// max_response_bytes 0 means 1 MiB: 1<<20 passes, one more byte overflows.
///
/// Red-before (overflow half): old code had no response limit and answered 201.
#[tokio::test]
async fn default_response_limit_is_one_mib() {
    let h = new_harness_with(0, 0, upstream_of(1 << 20));
    let o = get_via(&h).await;
    assert_passed_through(&o, &vec![b'x'; 1 << 20], &h.server_pub);

    let h = new_harness_with(0, 0, upstream_of((1 << 20) + 1));
    let o = get_via(&h).await;
    assert_overflow_answer(&o, &h.server_pub);
}

/// A configured limit replaces the default in both directions.
///
/// Red-before: the configured-small half (see response_cap_plus_one_overflows)
/// answered 201; the configured-large half guards against ignoring the field.
#[tokio::test]
async fn configured_limit_replaces_default() {
    let h = new_harness_with(0, (1 << 20) + 1, upstream_of((1 << 20) + 1));
    let o = get_via(&h).await;
    assert_passed_through(&o, &vec![b'x'; (1 << 20) + 1], &h.server_pub);

    let h = new_harness_with(0, 8, upstream_of(9));
    let o = get_via(&h).await;
    assert_eq!(o.got.status, 502);
}

/// The request cap does not limit the response.
#[tokio::test]
async fn small_request_cap_does_not_limit_response() {
    let h = new_harness_with(64, 0, upstream_of(2000));
    let o = get_via(&h).await;
    assert_passed_through(&o, &vec![b'x'; 2000], &h.server_pub);
}

/// The response cap does not limit the request.
#[tokio::test]
async fn small_response_cap_does_not_limit_request() {
    let h = new_harness_with(
        0,
        8,
        InnerResponse {
            status: 200,
            content_type: "application/json",
            body: b"{}".to_vec(),
            extra_headers: Vec::new(),
        },
    );
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":{{"pad":"{}"}}}}"#,
        "x".repeat(200)
    )
    .into_bytes();
    let alice = harness::signer_by_name("alice");
    let sent = signed_request(&alice, "POST", "/mcp", &body);
    let res = send(&h.service, build_request(&sent, "POST", "/mcp", &body))
        .await
        .expect("no inner error");
    let o = observe(res, sent).await;
    assert_eq!(o.got.status, 200);
    assert_eq!(o.got.body.as_ref(), b"{}");
    assert_eq!(h.inner.seen_bodies(), vec![body]);
}

/// What the end of a probed upstream body looks like.
#[derive(Clone, Copy)]
enum Tail {
    /// The producer finished normally.
    End,
    /// The producer failed after its frames.
    Fail,
    /// The producer stays open and idle (an unfinished body).
    KeepOpen,
}

/// Counts consumed frames and records when the body (which owns it through
/// its map_frame closure) is dropped.
struct Probe {
    polled: Arc<AtomicUsize>,
    dropped: Arc<std::sync::atomic::AtomicBool>,
}

impl Probe {
    fn record(&self) {
        self.polled.fetch_add(1, Ordering::SeqCst);
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

struct Streamed {
    observed: Observed,
    /// Frames the adapter pulled out of the upstream body.
    polled: usize,
    /// The upstream body was dropped by the time the answer was produced.
    dropped: bool,
    /// For Tail::KeepOpen: the producer's send failed (receiver gone).
    source_closed: Option<bool>,
    server_pub: [u8; 32],
}

/// Runs one GET through a layer whose inner service answers 201 with a
/// channel body holding `frames`. http_body_util is the only body source
/// available (http_body is not a direct dependency, so no hand-written Body):
/// Channel gives per-frame control, BodyExt::map_frame adds the counter and
/// the drop observer. Frames are queued before the call so the run needs no
/// scheduling luck. The timeout is only a hang guard for code that waits on
/// an unfinished body forever; nothing synchronizes on it.
async fn send_streamed(
    max_response_bytes: usize,
    content_type: &'static str,
    frames: &[&[u8]],
    tail: Tail,
) -> Streamed {
    let state = MemoryState::new();
    seed_registry(&state);
    let layer = JackLayer::new(HandlerConfig {
        verifier: build_verifier(state, None),
        server_key: server_signing_key(),
        max_body_bytes: 0,
        max_response_bytes,
    });
    let (mut sender, channel) =
        http_body_util::Channel::<Bytes, std::io::Error>::new(frames.len() + 1);
    for frame in frames {
        sender
            .send_data(Bytes::copy_from_slice(frame))
            .await
            .expect("frame fits the channel buffer");
    }
    let polled = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let probe = Probe {
        polled: Arc::clone(&polled),
        dropped: Arc::clone(&dropped),
    };
    let body = http_body_util::BodyExt::map_frame(channel, move |frame| {
        probe.record();
        frame
    });
    let mut open_sender = None;
    match tail {
        Tail::End => drop(sender),
        Tail::Fail => sender.abort(std::io::Error::other("upstream reset")),
        Tail::KeepOpen => open_sender = Some(sender),
    }
    // Channel is not Clone; hand the single body out of a shared cell.
    let cell = Arc::new(Mutex::new(Some(body)));
    let svc = layer.layer(tower::service_fn(
        move |_req: http::Request<Full<Bytes>>| {
            let body = cell
                .lock()
                .expect("body cell")
                .take()
                .expect("one inner request");
            async move {
                Ok::<_, String>(
                    http::Response::builder()
                        .status(201)
                        .header("Content-Type", content_type)
                        .header("X-Upstream", "1")
                        .header("Set-Cookie", "sid=1")
                        .body(body)
                        .expect("static response"),
                )
            }
        },
    ));
    let alice = harness::signer_by_name("alice");
    let sent = signed_request(&alice, "GET", "/mcp", b"");
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        svc.oneshot(build_request(&sent, "GET", "/mcp", b"")),
    )
    .await
    .expect("the adapter must not wait on an upstream body it should have dropped")
    .expect("no inner error");
    let observed = observe(res, sent).await;
    let source_closed = match open_sender.as_mut() {
        Some(s) => Some(s.send_data(Bytes::from_static(b"late")).await.is_err()),
        None => None,
    };
    Streamed {
        observed,
        polled: polled.load(Ordering::SeqCst),
        dropped: dropped.load(Ordering::SeqCst),
        source_closed,
        server_pub: *server_signing_key().verifying_key().as_bytes(),
    }
}

/// Several frames summing to exactly the cap pass with exact bytes.
///
/// Red-before: n/a (passes before too); the exact-boundary control.
#[tokio::test]
async fn multi_frame_exact_cap_passes() {
    let r = send_streamed(8, "text/plain", &[b"aaaa", b"bbbb"], Tail::End).await;
    assert_passed_through(&r.observed, b"aaaabbbb", &r.server_pub);
    assert_eq!(r.polled, 2);
}

/// The total crosses the cap on the last frame (4+4+1).
///
/// Red-before: old code answered 201 with the 9 bytes.
#[tokio::test]
async fn multi_frame_total_cap_plus_one_overflows() {
    let r = send_streamed(8, "text/plain", &[b"aaaa", b"bbbb", b"c"], Tail::End).await;
    assert_overflow_answer(&r.observed, &r.server_pub);
    assert_eq!(r.polled, 3);
    assert!(r.dropped);
}

/// A later frame crosses the cap and the frames after it are never consumed.
///
/// Red-before: old code consumed all 3 frames (polled == 3, status 201).
#[tokio::test]
async fn multi_frame_later_frame_crosses_cap_and_stops_polling() {
    let r = send_streamed(8, "text/plain", &[b"aaaa", b"bbbbb", b"c"], Tail::End).await;
    assert_overflow_answer(&r.observed, &r.server_pub);
    assert_eq!(r.polled, 2, "the frame after the overflow must stay unread");
    assert!(r.dropped, "the upstream body must be dropped on overflow");
}

/// An unfinished producer is released on overflow: its sender sees the
/// receiver gone, and the queued tail frames were never consumed.
///
/// Red-before: old code consumed every queued frame and then awaited the idle
/// producer forever (the hang guard in send_streamed fails the test).
#[tokio::test]
async fn overflow_drops_unfinished_source() {
    let r = send_streamed(
        8,
        "text/plain",
        &[b"aaaaaa", b"bbbbbb", b"cccccc", b"dddddd"],
        Tail::KeepOpen,
    )
    .await;
    assert_overflow_answer(&r.observed, &r.server_pub);
    assert_eq!(r.polled, 2);
    assert!(r.dropped);
    assert_eq!(
        r.source_closed,
        Some(true),
        "the producer must see a closed receiver"
    );
}

/// SSE precedence: an event-stream larger than the cap is still the signed
/// 501 and its body is dropped without being read.
///
/// Red-before: n/a (SSE precedence already held); guards the ordering of the
/// stream check and the cap.
#[tokio::test]
async fn sse_precedence_over_response_cap() {
    let big = [b'd'; 100];
    let r = send_streamed(
        8,
        "text/event-stream; charset=utf-8",
        &[&big, &big, &big],
        Tail::KeepOpen,
    )
    .await;
    assert_eq!(r.observed.got.status, 501);
    assert_eq!(error_code(&r.observed.got.body), "streaming_unsupported");
    assert_signed(&r.observed.got, &r.observed.sent.request_sig, &r.server_pub);
    assert_eq!(r.polled, 0, "the SSE body must not be read at all");
    assert!(r.dropped);
    assert_eq!(r.source_closed, Some(true));
}

/// A read error before the cap is reached stays the signed 500, not a 502.
///
/// Red-before: n/a (500 already held); distinguishes the two failure kinds.
#[tokio::test]
async fn read_error_before_overflow_is_500() {
    let r = send_streamed(8, "text/plain", &[b"aaaa"], Tail::Fail).await;
    let got = &r.observed.got;
    assert_eq!(got.status, 500);
    assert_eq!(error_code(&got.body), "internal_error");
    assert_signed(got, &r.observed.sent.request_sig, &r.server_pub);
    assert_eq!(r.observed.header_names(), vec!["content-type", "jack-auth"]);
    assert!(r.dropped);
}
