//! Client URL policy (spec 01 section 1; docs/design/interop.md section 9):
//! every case of spec/fixtures/client-url-policy.json is run against every
//! entry point. A refused URL must produce no signature and no inner
//! transport call; an allowed URL must reach the inner transport (a spy that
//! returns a canned error, no network). Redirects (exactly 301, 302, 303,
//! 307, 308) are refused without a second call; other statuses, including a
//! signed 304, are verified as usual.
//!
//! Entry paths exercised by EVERY row of the fixture, with no skip and no
//! row-dependent exception (there is no URL parser here; `parse_reject` rows
//! concern only other SDKs' parsers and are still accepted/refused by `allow`):
//!
//! 1. `validate_base_url`            (fixture_validate_base_url_and_request_target)
//! 2. `request_target`               (same test)
//! 3. `Client::new`                  (fixture_client_new)
//! 4. `load_profile`                 (fixture_load_profile_and_from_profile)
//! 5. `Client::from_profile`         (same test)
//! 6. `SigningTransport::round_trip`    (fixture_signing_transport_round_trip)
//! 7. `SigningTransport::round_trip_as` (fixture_signing_transport_round_trip_as)
//!
//! allow=true rows must be accepted by all seven (paths 6 and 7 reach the
//! inner spy exactly once with the unchanged URL); allow=false rows must be
//! refused by all seven with the policy error, zero signer calls and zero
//! inner calls. Each test tallies the rows it checked per path and asserts
//! the tally equals the number of rows (`cases.len()`).

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use common::fixtures::*;
use common::harness::*;

use mcp_jack::auth_header::parse_request_auth;
use mcp_jack::client::error::ClientError;
use mcp_jack::client::profile::{load_profile, Profile};
use mcp_jack::client::rpc::{Client, Config};
use mcp_jack::client::signer::{InMemorySigner, Signer};
use mcp_jack::client::transport::{
    HttpRequest, HttpResponse, SigningTransport, Transport, TransportError,
};
use mcp_jack::client::url::{request_target, validate_base_url};
use mcp_jack::encoding::encode_b64url;
use serde_json::json;

type Reply = Box<dyn Fn(&HttpRequest) -> Result<HttpResponse, TransportError> + Send + Sync>;

/// Inner transport spy: counts calls and records the wire URL; the reply is
/// canned, nothing touches the network.
struct SpyTransport {
    calls: Arc<AtomicUsize>,
    urls: Arc<Mutex<Vec<String>>>,
    reply: Reply,
}

impl Transport for SpyTransport {
    fn round_trip(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.urls.lock().expect("urls mutex").push(req.url.clone());
        (self.reply)(&req)
    }
}

/// Signer spy: counts sign calls, delegates to a fixture key.
struct SpySigner {
    inner: InMemorySigner,
    signs: Arc<AtomicUsize>,
}

impl Signer for SpySigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ClientError> {
        self.signs.fetch_add(1, Ordering::SeqCst);
        self.inner.sign(message)
    }
    fn public_key(&self) -> [u8; 32] {
        self.inner.public_key()
    }
    fn kid(&self) -> &str {
        self.inner.kid()
    }
}

const CANNED: &str = "spy: canned transport error";

/// Everything a test needs to observe about one spied stack.
struct Spy {
    calls: Arc<AtomicUsize>,
    signs: Arc<AtomicUsize>,
    urls: Arc<Mutex<Vec<String>>>,
    transport: SpyTransport,
    signer: Arc<SpySigner>,
}

fn spy_with(reply: Reply) -> Spy {
    let calls = Arc::new(AtomicUsize::new(0));
    let signs = Arc::new(AtomicUsize::new(0));
    let urls = Arc::new(Mutex::new(Vec::new()));
    Spy {
        transport: SpyTransport {
            calls: Arc::clone(&calls),
            urls: Arc::clone(&urls),
            reply,
        },
        signer: Arc::new(SpySigner {
            inner: signer_by_name("alice"),
            signs: Arc::clone(&signs),
        }),
        calls,
        signs,
        urls,
    }
}

fn spy() -> Spy {
    spy_with(Box::new(|_| {
        Err(TransportError::Transport(CANNED.to_string()))
    }))
}

fn spy_status(status: u16) -> Spy {
    spy_with(Box::new(move |_| {
        Ok(HttpResponse {
            status,
            headers: vec![("Location".to_string(), "http://evil.example/".to_string())],
            body: Vec::new(),
        })
    }))
}

fn signing(
    spy: Spy,
) -> (
    SigningTransport<SpyTransport>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let calls = Arc::clone(&spy.calls);
    let signs = Arc::clone(&spy.signs);
    let t = SigningTransport {
        transport: spy.transport,
        aud: FIXTURE_AUD.to_string(),
        signer: spy.signer,
        server_key: TestServer::new().pub_key,
        now: fixed_clock(FIXTURE_NOW),
        nonce: Arc::new(|| Ok(vec![7u8; 16])),
        window_seconds: 30,
    };
    (t, calls, signs)
}

fn request(url: &str) -> HttpRequest {
    HttpRequest {
        method: "POST".to_string(),
        url: url.to_string(),
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: br#"{"ping":1}"#.to_vec(),
    }
}

fn cases() -> Vec<UrlPolicyCase> {
    let f = load_client_url_policy().expect("load client-url-policy.json");
    assert!(f.cases.len() >= 207, "fixture shrank: {}", f.cases.len());
    assert!(f.cases.iter().any(|c| c.allow) && f.cases.iter().any(|c| !c.allow));
    // parse_reject is informational for other SDKs; it only ever annotates an
    // allow=true row, and Rust accepts such a row like any other.
    for c in &f.cases {
        assert!(
            c.parse_reject.is_empty() || c.allow,
            "{}: parse_reject on a refused row",
            c.name
        );
    }
    f.cases
}

fn config(url: &str, spy: Spy) -> (Config, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let calls = Arc::clone(&spy.calls);
    let signs = Arc::clone(&spy.signs);
    let cfg = Config {
        base_url: url.to_string(),
        aud: FIXTURE_AUD.to_string(),
        signer: spy.signer,
        server_key: TestServer::new().pub_key,
        transport: Arc::new(spy.transport),
        now: Some(fixed_clock(FIXTURE_NOW)),
        nonce: None,
        window_seconds: 0,
    };
    (cfg, calls, signs)
}

fn profile_for(url: &str) -> Profile {
    Profile {
        url: url.to_string(),
        aud: FIXTURE_AUD.to_string(),
        server_public_key: encode_b64url(&TestServer::new().pub_key),
        kid: String::new(),
        name: String::new(),
    }
}

/// Fails the test listing every case that deviated.
fn finish(entry: &str, failures: Vec<String>, tallies: &[(&str, usize)], rows: usize) {
    for (path, n) in tallies {
        assert_eq!(
            *n, rows,
            "{entry}: entry path {path} checked {n} of {rows} rows"
        );
    }
    assert!(
        failures.is_empty(),
        "{entry}: {} case(s) deviate from client-url-policy.json:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn fixture_validate_base_url_and_request_target() {
    let mut failures = Vec::new();
    let all = cases();
    let (mut n_validate, mut n_target) = (0usize, 0usize);
    for c in &all {
        if validate_base_url(&c.url).is_ok() != c.allow {
            failures.push(format!(
                "{}: validate_base_url({:?}) allow={}",
                c.name, c.url, c.allow
            ));
        }
        n_validate += 1;
        if request_target(&c.url).is_ok() != c.allow {
            failures.push(format!(
                "{}: request_target({:?}) allow={}",
                c.name, c.url, c.allow
            ));
        }
        n_target += 1;
    }
    finish(
        "validate_base_url/request_target",
        failures,
        &[
            ("validate_base_url", n_validate),
            ("request_target", n_target),
        ],
        all.len(),
    );
}

#[test]
fn fixture_client_new() {
    let mut failures = Vec::new();
    let all = cases();
    let mut n_new = 0usize;
    for c in &all {
        n_new += 1;
        let s = spy();
        let (cfg, calls, signs) = config(&c.url, s);
        let ok = Client::new(cfg).is_ok();
        if ok != c.allow {
            failures.push(format!(
                "{}: Client::new({:?}) ok={ok} allow={}",
                c.name, c.url, c.allow
            ));
        }
        if calls.load(Ordering::SeqCst) != 0 || signs.load(Ordering::SeqCst) != 0 {
            failures.push(format!("{}: Client::new made a call or signature", c.name));
        }
    }
    finish(
        "Client::new",
        failures,
        &[("Client::new", n_new)],
        all.len(),
    );
}

#[test]
fn fixture_load_profile_and_from_profile() {
    let mut failures = Vec::new();
    let all = cases();
    let (mut n_load, mut n_from) = (0usize, 0usize);
    for c in &all {
        let p = profile_for(&c.url);
        let text = serde_json::to_string(&p).expect("profile serializes");
        n_load += 1;
        let ok = load_profile(&text).is_ok();
        if ok != c.allow {
            failures.push(format!(
                "{}: load_profile({:?}) ok={ok} allow={}",
                c.name, c.url, c.allow
            ));
        }

        let s = spy();
        let calls = Arc::clone(&s.calls);
        let signs = Arc::clone(&s.signs);
        n_from += 1;
        let ok = Client::from_profile(&p, s.signer, Arc::new(s.transport)).is_ok();
        if ok != c.allow {
            failures.push(format!(
                "{}: from_profile({:?}) ok={ok} allow={}",
                c.name, c.url, c.allow
            ));
        }
        if calls.load(Ordering::SeqCst) != 0 || signs.load(Ordering::SeqCst) != 0 {
            failures.push(format!("{}: from_profile made a call or signature", c.name));
        }
    }
    finish(
        "load_profile/from_profile",
        failures,
        &[("load_profile", n_load), ("from_profile", n_from)],
        all.len(),
    );
}

fn check_signing_case(c: &UrlPolicyCase, explicit_signer: bool, failures: &mut Vec<String>) {
    let s = spy();
    let urls = Arc::clone(&s.urls);
    let (t, calls, signs) = signing(s);
    let req = request(&c.url);
    let res = if explicit_signer {
        let other = signer_by_name("alice");
        t.round_trip_as(&other, Some(FIXTURE_NOW), req)
    } else {
        t.round_trip(req)
    };
    let how = if explicit_signer {
        "round_trip_as"
    } else {
        "round_trip"
    };
    let (n_calls, n_signs) = (calls.load(Ordering::SeqCst), signs.load(Ordering::SeqCst));
    if c.allow {
        // Allowed: reaches the inner transport exactly once, with the very URL
        // that was signed (never rewritten); the spy's canned error passes through.
        match res {
            Err(TransportError::Transport(m)) if m == CANNED => {}
            other => failures.push(format!("{}: {how} allowed but got {other:?}", c.name)),
        }
        let seen = urls.lock().expect("urls mutex").clone();
        if seen != [c.url.clone()] {
            failures.push(format!("{}: {how} wire urls {seen:?}", c.name));
        }
        if n_calls != 1 {
            failures.push(format!("{}: {how} inner calls {n_calls}, want 1", c.name));
        }
        // Explicit signer: the default (spied) signer is not used.
        let want_signs = usize::from(!explicit_signer);
        if n_signs != want_signs {
            failures.push(format!(
                "{}: {how} signs {n_signs}, want {want_signs}",
                c.name
            ));
        }
    } else {
        if !matches!(res, Err(TransportError::Client(_))) {
            failures.push(format!("{}: {how} refused URL gave {res:?}", c.name));
        }
        if n_calls != 0 || n_signs != 0 {
            failures.push(format!(
                "{}: {how} refused but calls={n_calls} signs={n_signs}",
                c.name
            ));
        }
    }
}

#[test]
fn fixture_signing_transport_round_trip() {
    let mut failures = Vec::new();
    let all = cases();
    let mut n = 0usize;
    for c in &all {
        check_signing_case(c, false, &mut failures);
        n += 1;
    }
    finish(
        "SigningTransport::round_trip",
        failures,
        &[("round_trip", n)],
        all.len(),
    );
}

#[test]
fn fixture_signing_transport_round_trip_as() {
    let mut failures = Vec::new();
    let all = cases();
    let mut n = 0usize;
    for c in &all {
        check_signing_case(c, true, &mut failures);
        n += 1;
    }
    finish(
        "SigningTransport::round_trip_as",
        failures,
        &[("round_trip_as", n)],
        all.len(),
    );
}

/// Bypass regression: a remote plain-http URL handed straight to the
/// SigningTransport (not through Client) never reaches nonce, signer or inner
/// transport, and the error is the distinct https-required message.
#[test]
fn signing_transport_direct_bypass_is_refused() {
    let nonce_calls = Arc::new(AtomicUsize::new(0));
    let s = spy();
    let (mut t, calls, signs) = signing(s);
    let n = Arc::clone(&nonce_calls);
    t.nonce = Arc::new(move || {
        n.fetch_add(1, Ordering::SeqCst);
        Ok(vec![7u8; 16])
    });
    let err = t
        .round_trip(request("http://svc.example.test/mcp"))
        .expect_err("remote http must be refused");
    match err {
        TransportError::Client(m) => assert!(m.contains("https required"), "message: {m}"),
        other => panic!("expected Client error, got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(signs.load(Ordering::SeqCst), 0);
    assert_eq!(
        nonce_calls.load(Ordering::SeqCst),
        0,
        "nonce source untouched"
    );

    // Malformed forms keep the original base-url message.
    let (t, calls, _) = signing(spy());
    match t.round_trip(request("https://user@svc.example.test/")) {
        Err(TransportError::Client(m)) => {
            assert!(m.contains("absolute http/https URL"), "message: {m}")
        }
        other => panic!("expected Client error, got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn client_new_and_profile_messages_are_distinct() {
    let (cfg, _, _) = config("http://svc.example.test/mcp", spy());
    match Client::new(cfg) {
        Err(ClientError::Client(m)) => assert!(m.contains("https required"), "message: {m}"),
        other => panic!("expected Client error, got {:?}", other.map(|_| ())),
    }
    let text = serde_json::to_string(&profile_for("http://svc.example.test/mcp")).expect("json");
    match load_profile(&text) {
        Err(ClientError::Client(m)) => assert!(m.contains("https required"), "message: {m}"),
        other => panic!("expected Client error, got {other:?}"),
    }
    let text = serde_json::to_string(&profile_for("https://svc.example.test@/mcp")).expect("json");
    match load_profile(&text) {
        Err(ClientError::Client(m)) => assert!(m.contains("absolute http/https URL"), "{m}"),
        other => panic!("expected Client error, got {other:?}"),
    }
}

/// Signed round trip against the fake server for the given URL; returns the
/// target the server observed.
fn signed_round_trip(url: &str) -> String {
    let srv = TestServer::new();
    let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let seen_clone = Arc::clone(&seen);
    srv.set_handler(Box::new(move |srv, _method, target, auth, _body| {
        *seen_clone.lock().expect("mutex") = Some(target.to_string());
        srv.write_signed_json(auth, 200, &rpc_result_body(&json!({"ok": true})))
    }));
    let tr = SigningTransport {
        transport: Arc::clone(&srv),
        aud: FIXTURE_AUD.to_string(),
        signer: Arc::new(signer_by_name("alice")),
        server_key: srv.pub_key,
        now: fixed_clock(FIXTURE_NOW),
        nonce: Arc::new(|| Ok(vec![7u8; 16])),
        window_seconds: 30,
    };
    let resp = tr
        .round_trip(request(url))
        .unwrap_or_else(|e| panic!("{url}: signed round trip must verify: {e}"));
    assert_eq!(resp.status, 200, "{url}");
    let target = seen.lock().expect("mutex").clone();
    target.unwrap_or_else(|| panic!("{url}: server saw no request"))
}

#[test]
fn percent_encoded_path_and_query_are_accepted_verbatim() {
    // Percent escapes are refused in the authority only.
    let url = "https://svc.example.test/a%20b?x=%2F";
    validate_base_url(url).expect("percent-encoded path/query is accepted");
    assert_eq!(request_target(url).expect("target"), "/a%20b?x=%2F");
    assert_eq!(signed_round_trip(url), "/a%20b?x=%2F");
    assert!(validate_base_url("https://svc.example.test%2e/a").is_err());
}

#[test]
fn signed_round_trips_for_allowed_destinations() {
    // Loopback http (IPv4 and IPv6) and a remote https control; the signed
    // target stays byte-for-byte, fragment cut.
    assert_eq!(signed_round_trip("http://127.0.0.1:8080/mcp"), "/mcp");
    assert_eq!(
        signed_round_trip("http://[::1]:8080/mcp?x=1#frag"),
        "/mcp?x=1"
    );
    assert_eq!(signed_round_trip("http://127.0.0.1"), "/");
    assert_eq!(
        signed_round_trip("https://svc.example.test/a%20b?q=a@b"),
        "/a%20b?q=a@b"
    );
    assert_eq!(signed_round_trip("https://203.0.113.7:8443/mcp"), "/mcp");
}

#[test]
fn redirects_are_refused_without_a_second_call() {
    for status in [301u16, 302, 303, 307, 308] {
        let (t, calls, signs) = signing(spy_status(status));
        // Unsigned redirect: verification would yield Protocol(missing_auth);
        // the redirect refusal must come first.
        let err = t
            .round_trip(request("https://svc.example.test/mcp"))
            .expect_err("redirect must be refused");
        match err {
            TransportError::Client(m) => {
                assert!(m.contains("redirect"), "status {status}: message {m}");
                assert!(
                    m.contains(&status.to_string()),
                    "status {status}: message {m}"
                );
            }
            other => panic!("status {status}: expected Client error, got {other:?}"),
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "status {status}: exactly one call"
        );
        assert_eq!(
            signs.load(Ordering::SeqCst),
            1,
            "status {status}: signed once"
        );
    }
}

/// Reply that signs `sign_status`/`sign_body` for the request it receives
/// (real server key and request signature) but delivers `status`/`body`.
fn signed_reply(
    sign_status: u16,
    sign_body: &'static [u8],
    status: u16,
    body: &'static [u8],
) -> Reply {
    let srv = TestServer::new();
    Box::new(move |req| {
        let raw = req.header("Jack-Auth").expect("signed request header");
        let auth = parse_request_auth(&[raw]).expect("canonical request header");
        Ok(HttpResponse {
            status,
            headers: vec![(
                "Jack-Auth".to_string(),
                srv.sign_response(&auth.sig, sign_status, sign_body),
            )],
            body: body.to_vec(),
        })
    })
}

/// Runs one round trip through a spied SigningTransport; returns the result
/// and the inner call count.
fn run_status(reply: Reply) -> (Result<HttpResponse, TransportError>, usize) {
    let (t, calls, _) = signing(spy_with(reply));
    let res = t.round_trip(request("https://svc.example.test/mcp"));
    (res, calls.load(Ordering::SeqCst))
}

/// A verification failure (Protocol), never the local redirect refusal.
fn assert_verification_error(label: &str, res: Result<HttpResponse, TransportError>, code: &str) {
    match res {
        Err(TransportError::Protocol(j)) => {
            assert_eq!(j.code, code, "{label}: code");
            assert!(
                !j.message.contains("redirect"),
                "{label}: message {}",
                j.message
            );
        }
        other => panic!("{label}: expected verification error, got {other:?}"),
    }
}

#[test]
fn signed_304_not_modified_is_verified_and_returned() {
    let (res, calls) = run_status(signed_reply(304, b"", 304, b""));
    let resp = res.expect("a correctly signed 304 must verify and be returned");
    assert_eq!(resp.status, 304);
    assert!(resp.body.is_empty());
    assert_eq!(calls, 1, "inner called exactly once");
}

#[test]
fn unsigned_non_redirect_3xx_is_a_verification_error() {
    // 300 and 304 are not in the redirect set: they reach verification and,
    // unsigned, fail with missing_auth (not the redirect error).
    for status in [300u16, 304, 305, 306, 399] {
        let (res, calls) = run_status(spy_status(status).transport.reply);
        assert_verification_error(
            &format!("unsigned {status}"),
            res,
            mcp_jack::error::codes::MISSING_AUTH,
        );
        assert_eq!(calls, 1, "status {status}: inner called exactly once");
    }
}

#[test]
fn tampered_304_is_a_verification_error() {
    // Signed as 200, delivered as 304: the status is part of the signing
    // string, so verification fails.
    let (res, calls) = run_status(signed_reply(200, b"", 304, b""));
    assert_verification_error(
        "200 signed, 304 delivered",
        res,
        mcp_jack::error::codes::BAD_SIGNATURE,
    );
    assert_eq!(calls, 1);

    // Signed 304 with an empty body, delivered with a different body.
    let (res, calls) = run_status(signed_reply(304, b"", 304, b"x"));
    assert_verification_error(
        "tampered 304 body",
        res,
        mcp_jack::error::codes::BAD_SIGNATURE,
    );
    assert_eq!(calls, 1);

    // Signed 304 delivered as 300.
    let (res, calls) = run_status(signed_reply(304, b"", 300, b""));
    assert_verification_error(
        "304 signed, 300 delivered",
        res,
        mcp_jack::error::codes::BAD_SIGNATURE,
    );
    assert_eq!(calls, 1);
}

#[test]
fn redirect_through_client_is_refused() {
    let s = spy_status(302);
    let urls = Arc::clone(&s.urls);
    let (cfg, calls, _) = config("https://svc.example.test/mcp", s);
    let client = Client::new(cfg).expect("valid config");
    let err = client
        .call_tool_raw("jack.whoami", None)
        .expect_err("302 must be refused");
    match err {
        ClientError::Client(m) => assert!(m.contains("redirect"), "message: {m}"),
        other => panic!("expected Client error, got {other:?}"),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "no second request after a redirect"
    );
    let seen = urls.lock().expect("urls mutex").clone();
    assert_eq!(seen, ["https://svc.example.test/mcp".to_string()]);
}
