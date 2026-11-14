//! CI-only integration tests for the candidate rotation HTTP refresh client
//! (`mcp_jack::client::rotation_http::RotationHttpClient`): one explicit
//! signed `jack.server.key` page POST per call against REAL local HTTP/1.1
//! servers on 127.0.0.1 ephemeral ports. Linux-only (the rotation store) and
//! gated on `client-http` (the real transport).
#![cfg(all(target_os = "linux", feature = "client-http"))]

use std::net::SocketAddr;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mcp_jack::auth_header::{format_response_auth, parse_request_auth, RequestAuth, ResponseAuth};
use mcp_jack::client::rotation_http::RotationHttpClient;
use mcp_jack::client::{InMemorySigner, Signer};
use mcp_jack::encoding::{decode_b64url_fixed, encode_b64url, key_id};
use mcp_jack::rotation::create_record;
use mcp_jack::rotation::{
    Binding, Checkpoint, OwnedBinding, Record, ResultCursor, RotationStoreOptions,
    RotationTrustStore, MAX_RESULT_BODY_BYTES,
};
use mcp_jack::signing::{request_signing_string, response_signing_string};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const TS: i64 = 1200;
const TS_U: u64 = 1200;
const WINDOW: u64 = 30;
const AUD: &str = "rotation-http-test";
const TIMEOUT: Duration = Duration::from_secs(2);
const PATH: &str = "/mcp";
const PATH_QUERY: &str = "/mcp?raw=%2f&x=1";
/// The fake server's own request-read bounds (head cap, then body cap).
const HEAD_CAP_BYTES: usize = 64 * 1024;
const BODY_CAP_BYTES: usize = 1024 * 1024 + 1;

fn anchor_signer() -> InMemorySigner {
    InMemorySigner::from_seed(&[31; 32]).expect("32-byte seed")
}

fn next_signer() -> InMemorySigner {
    InMemorySigner::from_seed(&[32; 32]).expect("32-byte seed")
}

fn client_signer() -> InMemorySigner {
    // Публичный fixture seed, mirrors Go fixtureSigner(61).
    InMemorySigner::from_seed(&[61; 32]).expect("32-byte seed")
}

fn anchor_checkpoint() -> Checkpoint {
    let anchor = anchor_signer();
    Checkpoint {
        ordinal: 0,
        hash: "-".to_owned(),
        kid: anchor.kid().to_owned(),
        public_key: anchor.public_key(),
        published_at: 0,
    }
}

fn http_url(path: &str, addr: SocketAddr) -> String {
    format!("http://{addr}{path}")
}

fn single_record(endpoint: &str) -> Vec<Record> {
    vec![create_record(
        Binding { endpoint, aud: AUD },
        &anchor_checkpoint(),
        &anchor_signer(),
        &next_signer(),
        TS_U,
    )
    .expect("one signed candidate record")]
}

fn record_cursor(record: &Record) -> ResultCursor {
    ResultCursor {
        ordinal: record.ordinal,
        hash: record.hash.clone(),
    }
}

fn anchor_cursor() -> ResultCursor {
    ResultCursor {
        ordinal: 0,
        hash: "-".to_owned(),
    }
}

fn store_options(endpoint: &str) -> RotationStoreOptions {
    RotationStoreOptions {
        binding: OwnedBinding {
            endpoint: endpoint.to_owned(),
            aud: AUD.to_owned(),
        },
        window: WINDOW,
        checkpoint: anchor_checkpoint(),
    }
}

fn http_client(endpoint: &str) -> RotationHttpClient {
    RotationHttpClient::new(
        OwnedBinding {
            endpoint: endpoint.to_owned(),
            aud: AUD.to_owned(),
        },
        WINDOW,
        anchor_checkpoint(),
        Arc::new(client_signer()),
        TIMEOUT,
    )
    .expect("rotation http client")
}

struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "jack-rust-rotation-http-{}",
            encode_b64url(&random)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("private sandbox");
        Self(path)
    }

    fn file(&self) -> PathBuf {
        self.0.join("trust")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

/// Strict `jack.server.key` result the controller decoder accepts; id = 1.
fn page_payload(records: &[Record], head: &ResultCursor, complete: bool) -> Vec<u8> {
    let anchor = anchor_signer();
    let payload = serde_json::json!({
        "current": {
            "kid": anchor.kid(),
            "public_key": encode_b64url(&anchor.public_key()),
        },
        "records": records.iter().map(|record| record.wire.clone()).collect::<Vec<_>>(),
        "head": { "ordinal": head.ordinal, "hash": head.hash },
        "complete": complete,
    });
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [{ "type": "text", "text": payload.to_string() }],
            "structuredContent": payload,
            "isError": false,
        },
    })
    .to_string()
    .into_bytes()
}

/// One deterministic server behaviour per test connection.
#[derive(Clone)]
enum ServerAction {
    /// Signed 200 page with the prebuilt body.
    Page { body: Vec<u8> },
    /// Signed 200 with an empty body.
    EmptyBody,
    /// Signed 200 whose body exceeds the refresh limit by one byte.
    Oversize,
    /// Signed response with a non-200 status.
    Status(u16),
    /// Valid signed response sent with TWO Jack-Auth header lines.
    DuplicateAuth,
    /// Bare 307 redirect to a second local listener; that listener counts
    /// every connection so the test proves no redirect is followed.
    Redirect,
    /// Announced Content-Length, a few body bytes, connection dropped.
    Truncate,
    /// Response head only, then the server parks; the client deadline is
    /// the bounded failure guard.
    Stall,
}

/// The parsed inbound request the fake server keeps for test assertions.
#[derive(Clone)]
struct CapturedRequest {
    target: String,
    method: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    nonce: String,
}

/// Real HTTP/1.1 server on 127.0.0.1:0 plus a redirect sink listener.
struct LiveServer {
    addr: SocketAddr,
    handle: JoinHandle<()>,
    requests: Arc<AtomicUsize>,
    followed: Arc<AtomicUsize>,
    captures: Arc<Mutex<Vec<CapturedRequest>>>,
    violations: Arc<Mutex<Vec<String>>>,
    action: Arc<Mutex<ServerAction>>,
}

impl LiveServer {
    async fn start(action: ServerAction) -> Self {
        let main_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("main listener");
        let target_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("target listener");
        let addr = main_listener.local_addr().expect("main address");
        let target = target_listener.local_addr().expect("target address");
        let action = Arc::new(Mutex::new(action));
        let requests = Arc::new(AtomicUsize::new(0));
        let followed = Arc::new(AtomicUsize::new(0));
        let captures = Arc::new(Mutex::new(Vec::new()));
        let violations = Arc::new(Mutex::new(Vec::new()));

        // Redirect sink: counts every accepted connection, closes the socket.
        let sink = Arc::clone(&followed);
        tokio::spawn(async move {
            loop {
                let Ok((_socket, _)) = target_listener.accept().await else {
                    break;
                };
                sink.fetch_add(1, Ordering::SeqCst);
            }
        });

        let task_action = Arc::clone(&action);
        let task_requests = Arc::clone(&requests);
        let task_captures = Arc::clone(&captures);
        let task_violations = Arc::clone(&violations);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = main_listener.accept().await else {
                    break;
                };
                task_requests.fetch_add(1, Ordering::SeqCst);
                let connection_action = Arc::clone(&task_action);
                let connection_captures = Arc::clone(&task_captures);
                let connection_violations = Arc::clone(&task_violations);
                tokio::spawn(handle_connection(
                    stream,
                    connection_action,
                    connection_captures,
                    connection_violations,
                    target,
                ));
            }
        });

        Self {
            addr,
            handle,
            requests,
            followed,
            captures,
            violations,
            action,
        }
    }

    fn one(&self) -> CapturedRequest {
        let captures = self.captures.lock().expect("captures");
        captures.first().expect("one captured request").clone()
    }
}

impl Drop for LiveServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n".as_slice())
}

fn content_length_of(head: &str) -> Option<usize> {
    let lower = head.to_ascii_lowercase();
    for line in lower.lines() {
        if let Some(value) = line.strip_prefix("content-length:") {
            return value.trim().parse::<usize>().ok();
        }
    }
    None
}

/// Reads one full request (head plus exactly Content-Length body bytes)
/// under a bounded deadline; any breach is a violation message.
async fn read_request(stream: &mut TcpStream) -> Result<(String, Vec<u8>), &'static str> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 512];
    let (head, mut body) = loop {
        if let Some(end) = find_head_end(&buffer) {
            let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
            break (head, buffer[end + 4..].to_vec());
        }
        if buffer.len() > HEAD_CAP_BYTES {
            return Err("request head exceeded the head cap");
        }
        let read = match stream.read(&mut chunk).await {
            Ok(read) => read,
            Err(_) => return Err("request read failed"),
        };
        if read == 0 {
            return Err("request head never completed");
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let Some(content_length) = content_length_of(&head) else {
        return Err("request head has no content-length");
    };
    if content_length > BODY_CAP_BYTES {
        return Err("request content-length exceeds the body cap");
    }
    while body.len() < content_length {
        let read = match stream.read(&mut chunk).await {
            Ok(read) => read,
            Err(_) => return Err("request body read failed"),
        };
        if read == 0 {
            return Err("request body never completed");
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);
    Ok((head, body))
}

fn verify_client_request(
    method: &str,
    target: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<RequestAuth, String> {
    if method != "POST" {
        return Err("request method is not POST".to_owned());
    }
    let auth_values: Vec<&str> = headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("Jack-Auth"))
        .map(|(_, value)| value.as_str())
        .collect();
    let [auth_value] = auth_values.as_slice() else {
        return Err("request carries not exactly one Jack-Auth header".to_owned());
    };
    let auth = parse_request_auth(&[auth_value])
        .map_err(|_| "request auth header is malformed".to_owned())?;
    if auth.kid != client_signer().kid() {
        return Err("request signed by an unexpected kid".to_owned());
    }
    if auth.ts != TS {
        return Err("request timestamp is not the pinned value".to_owned());
    }
    let proto = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("MCP-Protocol-Version"));
    if proto.map(|(_, value)| value.as_str()) != Some("2025-11-25") {
        return Err("request MCP-Protocol-Version is not 2025-11-25".to_owned());
    }
    let content_type = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("Content-Type"));
    if content_type.map(|(_, value)| value.as_str()) != Some("application/json") {
        return Err("request content type is not application/json".to_owned());
    }
    let signing =
        request_signing_string(method, target, AUD, &auth.kid, auth.ts, &auth.nonce, body);
    let Ok(sig) = decode_b64url_fixed(&auth.sig, 64) else {
        return Err("request signature is not canonical base64url".to_owned());
    };
    if !mcp_jack::ed25519::verify(&client_signer().public_key(), signing.as_bytes(), &sig) {
        return Err("request signature does not verify".to_owned());
    }
    Ok(auth)
}

/// The Jack-Auth header value of one signed response (anchor server key).
fn signed_response_auth(status: u16, request_sig: &str, body: &[u8]) -> String {
    let anchor = anchor_signer();
    let kid = key_id(&anchor.public_key());
    let signing = response_signing_string(i64::from(status), request_sig, &kid, TS, body);
    let signature = anchor.sign(signing.as_bytes()).expect("anchor sign");
    format_response_auth(&ResponseAuth {
        kid,
        ts: TS,
        sig: encode_b64url(&signature),
    })
}

fn signed_head(status: u16, request_sig: &str, body: &[u8]) -> String {
    let auth_header = signed_response_auth(status, request_sig, body);
    format!(
        "HTTP/1.1 {status} Test\r\nJack-Auth: {auth_header}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
}

async fn write_response(stream: &mut TcpStream, head: &str, body: &[u8]) {
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body).await;
    let _ = stream.flush().await;
}

async fn write_bad_request(stream: &mut TcpStream) {
    let _ = stream
        .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        .await;
    let _ = stream.flush().await;
}

async fn handle_connection(
    mut stream: TcpStream,
    action: Arc<Mutex<ServerAction>>,
    captures: Arc<Mutex<Vec<CapturedRequest>>>,
    violations: Arc<Mutex<Vec<String>>>,
    target_addr: SocketAddr,
) {
    let outcome = tokio::time::timeout(Duration::from_secs(5), read_request(&mut stream)).await;
    let (head, body) = match outcome {
        Ok(Ok(pair)) => pair,
        Ok(Err(violation)) => {
            violations
                .lock()
                .expect("violations")
                .push(violation.to_owned());
            write_bad_request(&mut stream).await;
            return;
        }
        Err(_) => {
            violations
                .lock()
                .expect("violations")
                .push("request never completed in time".to_owned());
            write_bad_request(&mut stream).await;
            return;
        }
    };
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default().to_owned();
    let target = request_parts.next().unwrap_or_default().to_owned();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    let auth = match verify_client_request(&method, &target, &headers, &body) {
        Ok(auth) => auth,
        Err(violation) => {
            violations.lock().expect("violations").push(violation);
            write_bad_request(&mut stream).await;
            return;
        }
    };
    let request_sig = auth.sig.clone();
    let nonce = auth.nonce.clone();
    let captured = CapturedRequest {
        target,
        method,
        headers,
        body,
        nonce,
    };
    captures.lock().expect("captures").push(captured);

    let action = action.lock().expect("action").clone();
    match action {
        ServerAction::Page { body } => {
            let head = signed_head(200, &request_sig, &body);
            write_response(&mut stream, &head, &body).await;
        }
        ServerAction::EmptyBody => {
            let body: Vec<u8> = Vec::new();
            let head = signed_head(200, &request_sig, &body);
            write_response(&mut stream, &head, &body).await;
        }
        ServerAction::Oversize => {
            let body = vec![b'A'; MAX_RESULT_BODY_BYTES + 1];
            let head = signed_head(200, &request_sig, &body);
            write_response(&mut stream, &head, &body).await;
        }
        ServerAction::Status(status) => {
            let body = b"no".to_vec();
            let head = signed_head(status, &request_sig, &body);
            write_response(&mut stream, &head, &body).await;
        }
        ServerAction::DuplicateAuth => {
            let body = page_payload(&[], &anchor_cursor(), true);
            let auth_header = signed_response_auth(200, &request_sig, &body);
            let head = format!(
                "HTTP/1.1 200 OK\r\nJack-Auth: {auth_header}\r\nJack-Auth: {auth_header}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            write_response(&mut stream, &head, &body).await;
        }
        ServerAction::Redirect => {
            let _ = stream
                .write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: ")
                .await;
            let head = format!("http://{target_addr}/x\r\nContent-Length: 0\r\n\r\n");
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.flush().await;
        }
        ServerAction::Truncate => {
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\npartial")
                .await;
            let _ = stream.flush().await;
        }
        ServerAction::Stall => {
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n")
                .await;
            let _ = stream.flush().await;
            std::future::pending::<()>().await;
        }
    }
}

/// One explicit refresh against a fresh server and store: asserts the
/// sanitized code and that the server saw exactly ONE request (no retry).
async fn assert_refresh_fails(action: ServerAction, want_code: &str) {
    let server = LiveServer::start(action).await;
    let endpoint = http_url(PATH, server.addr);
    let opts = store_options(&endpoint);
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    RotationTrustStore::initialize_unused(&path, opts.clone(), || Ok(TS_U)).expect("initialize");
    let mut store = RotationTrustStore::open(&path, opts, || Ok(TS_U)).expect("open");
    let client = http_client(&endpoint);
    let error = client.refresh(&mut store).expect_err("refresh must fail");
    assert_eq!(error.code, want_code);
    assert_eq!(error.http_status, 0);
    let requests = server.requests.load(Ordering::SeqCst);
    assert_eq!(requests, 1, "exactly one request");
    let violations = server.violations.lock().expect("violations");
    assert!(
        violations.is_empty(),
        "server observed invalid requests: {violations:?}",
    );
    let _ = store.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_refresh_commits_one_signed_page_per_call_and_never_repeats() {
    let server = LiveServer::start(ServerAction::EmptyBody).await;
    let endpoint = http_url(PATH_QUERY, server.addr);
    let opts = store_options(&endpoint);
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    RotationTrustStore::initialize_unused(&path, opts.clone(), || Ok(TS_U)).expect("initialize");
    let mut store = RotationTrustStore::open(&path, opts, || Ok(TS_U)).expect("open");
    let client = http_client(&endpoint);
    let records = single_record(&endpoint);
    let first_cursor = record_cursor(&records[0]);
    *server.action.lock().expect("action") = ServerAction::Page {
        body: page_payload(&records, &first_cursor, true),
    };
    let result = client
        .refresh(&mut store)
        .expect("explicit refresh commits");
    assert!(result.committed);
    assert!(result.complete);
    assert_eq!(result.revision, 2);
    assert_eq!(result.head, first_cursor);
    assert_eq!(result.terminal, first_cursor);

    let captured = server.one();
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.target, PATH_QUERY);
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    let protocol = captured
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("MCP-Protocol-Version"))
        .map(|(_, value)| value.as_str());
    assert_eq!(protocol, Some("2025-11-25"));
    let content_type = captured
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("Content-Type"))
        .map(|(_, value)| value.as_str());
    assert_eq!(content_type, Some("application/json"));
    let request_body: serde_json::Value =
        serde_json::from_slice(&captured.body).expect("request body json");
    assert_eq!(request_body["jsonrpc"], "2.0");
    assert_eq!(request_body["id"], 1);
    assert_eq!(request_body["method"], "tools/call");
    assert_eq!(request_body["params"]["name"], "jack.server.key");
    assert_eq!(request_body["params"]["arguments"]["after_ordinal"], 0);
    assert_eq!(request_body["params"]["arguments"]["after_hash"], "-");
    let auth_values: Vec<&str> = captured
        .headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("Jack-Auth"))
        .map(|(_, value)| value.as_str())
        .collect();
    let auth = parse_request_auth(&auth_values).expect("request auth parses");
    let signing = request_signing_string(
        "POST",
        PATH_QUERY,
        AUD,
        &auth.kid,
        auth.ts,
        &auth.nonce,
        &captured.body,
    );
    let signature = decode_b64url_fixed(&auth.sig, 64).expect("canonical request signature");
    assert!(mcp_jack::ed25519::verify(
        &client_signer().public_key(),
        signing.as_bytes(),
        &signature
    ));
    assert_eq!(auth.kid, client_signer().kid());
    assert_eq!(auth.ts, TS);
    let violations = server.violations.lock().expect("violations");
    assert!(
        violations.is_empty(),
        "server observed invalid requests: {violations:?}",
    );

    *server.action.lock().expect("action") = ServerAction::Page {
        body: page_payload(&records, &first_cursor, true),
    };
    let repeat = client
        .refresh(&mut store)
        .expect("duplicate refresh is a noop");
    assert!(!repeat.committed);
    assert_eq!(repeat.revision, 2);
    assert_eq!(server.requests.load(Ordering::SeqCst), 2);
    let captures = server.captures.lock().expect("captures");
    assert_ne!(captures[0].nonce, captures[1].nonce);

    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision, 2);
    assert_eq!(snapshot.head, first_cursor);
    store.close().expect("clean close");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_page_body_is_refused_without_a_second_request() {
    assert_refresh_fails(ServerAction::EmptyBody, "rotation_result_invalid").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversize_page_body_is_refused_without_a_second_request() {
    assert_refresh_fails(ServerAction::Oversize, "rotation_result_invalid").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_is_refused_and_never_followed() {
    let server = LiveServer::start(ServerAction::Redirect).await;
    let endpoint = http_url(PATH, server.addr);
    let opts = store_options(&endpoint);
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    RotationTrustStore::initialize_unused(&path, opts.clone(), || Ok(TS_U)).expect("initialize");
    let mut store = RotationTrustStore::open(&path, opts, || Ok(TS_U)).expect("open");
    let client = http_client(&endpoint);
    let error = client.refresh(&mut store).expect_err("redirect refused");
    assert_eq!(error.code, "rotation_redirect_refused");
    assert_eq!(error.http_status, 0);
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    let followed = server.followed.load(Ordering::SeqCst);
    assert_eq!(followed, 0, "redirect never followed");
    let violations = server.violations.lock().expect("violations");
    assert!(
        violations.is_empty(),
        "server observed invalid requests: {violations:?}",
    );
    let _ = store.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_non_200_page_is_refused_without_a_second_request() {
    assert_refresh_fails(ServerAction::Status(500), "rotation_result_invalid").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_response_auth_headers_are_refused_without_a_second_request() {
    assert_refresh_fails(ServerAction::DuplicateAuth, "malformed_auth").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn truncated_response_body_is_request_unavailable_without_retry() {
    assert_refresh_fails(ServerAction::Truncate, "rotation_request_unavailable").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_response_head_hits_the_absolute_deadline_without_retry() {
    let server = LiveServer::start(ServerAction::Stall).await;
    let endpoint = http_url(PATH, server.addr);
    let opts = store_options(&endpoint);
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    RotationTrustStore::initialize_unused(&path, opts.clone(), || Ok(TS_U)).expect("initialize");
    let mut store = RotationTrustStore::open(&path, opts, || Ok(TS_U)).expect("open");
    let client = RotationHttpClient::new(
        OwnedBinding {
            endpoint: endpoint.to_owned(),
            aud: AUD.to_owned(),
        },
        WINDOW,
        anchor_checkpoint(),
        Arc::new(client_signer()),
        Duration::from_secs(1),
    )
    .expect("bounded rotation http client");
    let error = client
        .refresh(&mut store)
        .expect_err("stall must hit the absolute deadline");
    assert_eq!(error.code, "rotation_request_unavailable");
    assert_eq!(error.http_status, 0);
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    let violations = server.violations.lock().expect("violations");
    assert!(
        violations.is_empty(),
        "server observed invalid requests: {violations:?}",
    );
    let _ = store.close();
}

#[test]
fn constructor_bounds_refuse_bad_profiles_without_side_effects() {
    // Zero deadline is refused.
    let error = RotationHttpClient::new(
        OwnedBinding {
            endpoint: "https://svc.example.test/mcp".to_owned(),
            aud: AUD.to_owned(),
        },
        WINDOW,
        anchor_checkpoint(),
        Arc::new(client_signer()),
        Duration::from_secs(0),
    )
    .err()
    .expect("zero timeout is refused");
    assert_eq!(error.code, "rotation_state_unknown");
    // Deadlines above 30 seconds are refused.
    let error = RotationHttpClient::new(
        OwnedBinding {
            endpoint: "https://svc.example.test/mcp".to_owned(),
            aud: AUD.to_owned(),
        },
        WINDOW,
        anchor_checkpoint(),
        Arc::new(client_signer()),
        Duration::from_secs(31),
    )
    .err()
    .expect("31 second timeout is refused");
    assert_eq!(error.code, "rotation_state_unknown");
    // Window 0 is refused.
    let error = RotationHttpClient::new(
        OwnedBinding {
            endpoint: "https://svc.example.test/mcp".to_owned(),
            aud: AUD.to_owned(),
        },
        0,
        anchor_checkpoint(),
        Arc::new(client_signer()),
        TIMEOUT,
    )
    .err()
    .expect("zero window is refused");
    assert_eq!(error.code, "rotation_state_unknown");
    // Window above 120 is refused.
    let error = RotationHttpClient::new(
        OwnedBinding {
            endpoint: "https://svc.example.test/mcp".to_owned(),
            aud: AUD.to_owned(),
        },
        121,
        anchor_checkpoint(),
        Arc::new(client_signer()),
        TIMEOUT,
    )
    .err()
    .expect("121 window is refused");
    assert_eq!(error.code, "rotation_state_unknown");
    // Plain http is refused for a non-loopback-literal host.
    let error = RotationHttpClient::new(
        OwnedBinding {
            endpoint: "http://localhost/mcp".to_owned(),
            aud: AUD.to_owned(),
        },
        WINDOW,
        anchor_checkpoint(),
        Arc::new(client_signer()),
        TIMEOUT,
    )
    .err()
    .expect("non-loopback plain http is refused");
    assert_eq!(error.code, "rotation_state_unknown");
    // Positive control: a well-formed https profile constructs.
    let ok = RotationHttpClient::new(
        OwnedBinding {
            endpoint: "https://svc.example.test/mcp".to_owned(),
            aud: AUD.to_owned(),
        },
        WINDOW,
        anchor_checkpoint(),
        Arc::new(client_signer()),
        TIMEOUT,
    )
    .is_ok();
    assert!(ok);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_refresh_leaves_the_acked_state_unchanged() {
    let server = LiveServer::start(ServerAction::Status(500)).await;
    let endpoint = http_url(PATH, server.addr);
    let opts = store_options(&endpoint);
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    RotationTrustStore::initialize_unused(&path, opts.clone(), || Ok(TS_U)).expect("initialize");
    let mut store = RotationTrustStore::open(&path, opts, || Ok(TS_U)).expect("open");
    let client = http_client(&endpoint);
    // Proof a page was AVAILABLE; the signed non-200 must still be refused.
    let _records = single_record(&endpoint);
    let error = client
        .refresh(&mut store)
        .expect_err("signed non-200 refused");
    assert_eq!(error.code, "rotation_result_invalid");
    assert_eq!(error.http_status, 0);
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    let (snapshot, _) = store.snapshot().expect("snapshot after failure");
    assert_eq!(snapshot.revision, 1);
    assert_eq!(snapshot.head.ordinal, 0);
    assert!(snapshot.records.is_empty());
    store
        .close()
        .expect("failure before any CAS keeps clean close possible");
}
