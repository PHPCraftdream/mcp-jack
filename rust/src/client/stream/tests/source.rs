//! Fakes for the transport-facing stream surface and the `open_stream` tests:
//! the opt-in header of spec 05 section 1.1, the no-follow guard of 1.4 and
//! the end-to-end delivery of a stream built with the fixture key.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::auth_header::parse_request_auth;
use crate::client::signer::{InMemorySigner, Signer};
use crate::client::stream::{ChunkRead, StreamBody, StreamResponse, StreamSource};
use crate::client::transport::{
    Clock, HttpRequest, HttpResponse, NonceSource, SigningTransport, Transport, TransportError,
};
use crate::stream::StreamBuilder;

use super::{
    frame_bytes, hex_seed, svc_signer, ALICE_SEED_HEX, AUD, MSG_A, MSG_B, OPEN_TS, ROOT_SEED_HEX,
    SID, SVC_KID,
};

/// One scripted `next_chunk` outcome.
pub(super) enum Script {
    Data(Vec<u8>),
    Timeout,
    End,
    Error(String),
}

/// One fresh drop flag and log, shared by a fake body and the test.
pub(super) fn state() -> (Arc<AtomicBool>, Arc<Mutex<Vec<String>>>) {
    (
        Arc::new(AtomicBool::new(false)),
        Arc::new(Mutex::new(Vec::new())),
    )
}

/// A body that replays `script` (an exhausted script answers `End`), records every outcome in
/// `log` and sets `dropped` when it is dropped — which is the client's stream cancellation
/// (spec 05 section 3.7).
pub(super) struct FakeBody {
    script: VecDeque<Script>,
    log: Arc<Mutex<Vec<String>>>,
    dropped: Arc<AtomicBool>,
}

impl FakeBody {
    pub(super) fn new(
        script: Vec<Script>,
        log: Arc<Mutex<Vec<String>>>,
        dropped: Arc<AtomicBool>,
    ) -> Self {
        FakeBody {
            script: script.into(),
            log,
            dropped,
        }
    }
}

impl StreamBody for FakeBody {
    fn next_chunk(&mut self, _deadline: Instant) -> Result<ChunkRead, TransportError> {
        let (entry, result) = match self.script.pop_front().unwrap_or(Script::End) {
            Script::Data(bytes) => (format!("data {}", bytes.len()), Ok(ChunkRead::Data(bytes))),
            Script::Timeout => ("timeout".to_string(), Ok(ChunkRead::Timeout)),
            Script::End => ("end".to_string(), Ok(ChunkRead::End)),
            Script::Error(message) => {
                ("error".to_string(), Err(TransportError::Transport(message)))
            }
        };
        self.log.lock().expect("log lock").push(entry);
        result
    }
}

impl Drop for FakeBody {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
        self.log.lock().expect("log lock").push("drop".to_string());
    }
}

/// The response headers of a stream response (1.4) carrying `jack_auth`.
pub(super) fn stream_headers(jack_auth: String) -> Vec<(String, String)> {
    vec![
        ("Content-Type".to_string(), "text/event-stream".to_string()),
        ("Jack-Auth".to_string(), jack_auth),
    ]
}

/// One stream response whose body replays `script`.
pub(super) fn stream_response(
    status: u16,
    headers: Vec<(String, String)>,
    script: Vec<Script>,
    log: Arc<Mutex<Vec<String>>>,
    dropped: Arc<AtomicBool>,
) -> StreamResponse {
    StreamResponse {
        status,
        headers,
        body: Box::new(FakeBody::new(script, log, dropped)),
    }
}

/// Builds the response of one `open_stream` call from the request it received.
pub(super) type Responder = Box<dyn Fn(&HttpRequest) -> StreamResponse + Send + Sync>;

/// A fake that is both a `Transport` and a `StreamSource`. The buffered v1 path must never run
/// for a stream; the requests it saw stay readable after the call.
pub(super) struct FakeTransport {
    responder: Responder,
    requests: Mutex<Vec<HttpRequest>>,
    round_trips: AtomicUsize,
}

impl FakeTransport {
    pub(super) fn new(responder: Responder) -> Self {
        FakeTransport {
            responder,
            requests: Mutex::new(Vec::new()),
            round_trips: AtomicUsize::new(0),
        }
    }

    pub(super) fn requests(&self) -> Vec<HttpRequest> {
        self.requests.lock().expect("requests lock").clone()
    }
}

impl Transport for FakeTransport {
    fn round_trip(&self, _req: HttpRequest) -> Result<HttpResponse, TransportError> {
        self.round_trips.fetch_add(1, Ordering::SeqCst);
        Err(TransportError::Transport(
            "jack client: the v1 path must not run for a stream".to_string(),
        ))
    }
}

impl StreamSource for FakeTransport {
    fn open_stream(&self, req: HttpRequest) -> Result<StreamResponse, TransportError> {
        self.requests
            .lock()
            .expect("requests lock")
            .push(req.clone());
        Ok((self.responder)(&req))
    }
}

/// A client signer from a `keys.json` seed (TEST ONLY).
fn client_signer(seed_hex: &str) -> Arc<dyn Signer> {
    Arc::new(InMemorySigner::from_seed(&hex_seed(seed_hex)).expect("32-byte seed"))
}

/// A `SigningTransport` over the fake, with the fixed clock, nonce and window.
fn signing(fake: FakeTransport, signer: Arc<dyn Signer>) -> SigningTransport<FakeTransport> {
    let now: Clock = Arc::new(|| OPEN_TS);
    let nonce: NonceSource = Arc::new(|| Ok(vec![7u8; 16]));
    let mut transport = SigningTransport::new(fake, AUD, signer, svc_signer().verifying_key());
    transport.now = now;
    transport.nonce = nonce;
    transport.window_seconds = 30;
    transport
}

fn request() -> HttpRequest {
    HttpRequest {
        method: "POST".to_string(),
        url: AUD.to_string(),
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#.to_vec(),
    }
}

/// Answers with a clean stream (two messages, then the end frame) bound to the arriving
/// request's own signature.
fn clean_responder(dropped: Arc<AtomicBool>, log: Arc<Mutex<Vec<String>>>) -> Responder {
    Box::new(move |req: &HttpRequest| {
        let raw = req.header("Jack-Auth").expect("the request must be signed");
        let auth = parse_request_auth(&[raw]).expect("canonical request header");
        let (mut builder, open) =
            StreamBuilder::open(200, &auth.sig, SVC_KID, OPEN_TS, SID, &svc_signer())
                .expect("open header signed");
        let mut bytes = frame_bytes(&mut builder, OPEN_TS, MSG_A);
        bytes.extend_from_slice(&frame_bytes(&mut builder, OPEN_TS + 1, MSG_B));
        bytes.extend_from_slice(&frame_bytes(&mut builder, OPEN_TS + 2, ""));
        stream_response(
            200,
            stream_headers(open.jack_auth),
            vec![Script::Data(bytes), Script::End],
            Arc::clone(&log),
            Arc::clone(&dropped),
        )
    })
}

#[test]
fn open_stream_carries_one_auth_header_and_the_sdk_opt_in() {
    let (dropped, log) = state();
    let transport = signing(
        FakeTransport::new(clean_responder(Arc::clone(&dropped), Arc::clone(&log))),
        client_signer(ALICE_SEED_HEX),
    );
    // The caller supplies its own stale auth and a different opt-in: both are replaced.
    let mut req = request();
    req.headers
        .push(("jack-auth".to_string(), "v1 stale".to_string()));
    req.headers
        .push(("Jack-Accept".to_string(), "s1, s2".to_string()));
    let stream = transport.open_stream(req).expect("a clean stream opens");

    let requests = transport.transport.requests();
    let sent = requests.first().expect("exactly one open_stream call");
    let auth = sent.header_values("Jack-Auth");
    assert_eq!(auth.len(), 1, "exactly one Jack-Auth header must be sent");
    assert!(
        auth[0].starts_with("v1 "),
        "the request must carry the freshly signed header"
    );
    assert_eq!(
        parse_request_auth(&auth)
            .expect("canonical request header")
            .ts,
        OPEN_TS
    );
    assert_eq!(
        sent.header_values("Jack-Accept"),
        vec!["s1"],
        "the SDK owns the opt-in header and sends exactly s1"
    );
    assert_eq!(
        transport.transport.round_trips.load(Ordering::SeqCst),
        0,
        "the buffered v1 path must not run for a stream"
    );
    drop(stream);
}

#[test]
fn open_stream_as_signs_with_the_explicit_signer() {
    let (dropped, log) = state();
    let transport = signing(
        FakeTransport::new(clean_responder(Arc::clone(&dropped), Arc::clone(&log))),
        client_signer(ALICE_SEED_HEX),
    );
    let root = client_signer(ROOT_SEED_HEX);
    let stream = transport
        .open_stream_as(root.as_ref(), request())
        .expect("a clean stream opens");
    let requests = transport.transport.requests();
    let raw = requests
        .first()
        .expect("exactly one open_stream call")
        .header("Jack-Auth")
        .expect("a signed request");
    assert_eq!(
        parse_request_auth(&[raw])
            .expect("canonical request header")
            .kid,
        root.kid(),
        "the explicit signer must sign the request"
    );
    drop(stream);
}

#[test]
fn open_stream_refuses_a_redirect() {
    for status in [301u16, 302, 303, 307, 308] {
        let (dropped, log) = state();
        let inner_dropped = Arc::clone(&dropped);
        let inner_log = Arc::clone(&log);
        let responder: Responder = Box::new(move |_req: &HttpRequest| {
            stream_response(
                status,
                stream_headers("s1 kid=x".to_string()),
                vec![Script::Data(b"leak".to_vec())],
                Arc::clone(&inner_log),
                Arc::clone(&inner_dropped),
            )
        });
        let transport = signing(FakeTransport::new(responder), client_signer(ALICE_SEED_HEX));
        let error = match transport.open_stream(request()) {
            Ok(_) => panic!("a redirect must be refused, not opened (status {status})"),
            Err(error) => error,
        };
        match error {
            TransportError::Client(message) => {
                assert!(
                    message.contains(&format!("redirect (status {status}) refused")),
                    "{message}"
                );
                assert!(message.contains("never follows redirects"), "{message}");
            }
            other => panic!("expected Client, got {other:?}"),
        }
        assert!(
            dropped.load(Ordering::SeqCst),
            "the refused body must be dropped"
        );
        assert!(
            log.lock().expect("log lock").is_empty(),
            "no byte may be read from a refused response"
        );
    }
}

#[test]
fn open_stream_refuses_a_non_stream_response() {
    let (dropped, log) = state();
    let inner_dropped = Arc::clone(&dropped);
    let inner_log = Arc::clone(&log);
    let responder: Responder = Box::new(move |_req: &HttpRequest| {
        stream_response(
            200,
            vec![("Content-Type".to_string(), "application/json".to_string())],
            vec![Script::Data(br#"{"ok":true}"#.to_vec())],
            Arc::clone(&inner_log),
            Arc::clone(&inner_dropped),
        )
    });
    let transport = signing(FakeTransport::new(responder), client_signer(ALICE_SEED_HEX));
    let error = match transport.open_stream(request()) {
        Ok(_) => panic!("a non-stream response belongs to the v1 path"),
        Err(error) => error,
    };
    match error {
        TransportError::Client(message) => {
            assert!(message.contains("spec 05 section 1.4"), "{message}");
        }
        other => panic!("expected Client, got {other:?}"),
    }
    assert!(
        dropped.load(Ordering::SeqCst),
        "the refused body must be dropped"
    );
    assert!(
        log.lock().expect("log lock").is_empty(),
        "no byte may be read from a refused response"
    );
}

#[test]
fn open_stream_delivers_the_verified_messages() {
    let (dropped, log) = state();
    let transport = signing(
        FakeTransport::new(clean_responder(Arc::clone(&dropped), Arc::clone(&log))),
        client_signer(ALICE_SEED_HEX),
    );
    let mut stream = transport
        .open_stream(request())
        .expect("a clean stream opens");
    assert_eq!(stream.sid(), SID);
    assert_eq!(stream.open_auth().kid, SVC_KID);
    let outcomes: Vec<_> = stream.by_ref().collect();
    assert_eq!(outcomes, vec![Ok(MSG_A.to_string()), Ok(MSG_B.to_string())]);
    assert_eq!(
        stream.frames_verified(),
        3,
        "two messages and the end frame"
    );
    assert!(
        !dropped.load(Ordering::SeqCst),
        "the body stays alive while the stream does"
    );
    drop(stream);
    assert!(
        dropped.load(Ordering::SeqCst),
        "dropping the stream closes the body (spec 05 section 3.7)"
    );
}
