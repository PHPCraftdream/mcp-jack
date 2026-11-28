//! Wire-level runner for `spec/fixtures/modern/modern-request-vectors.json`:
//! the same 98 request cases `request.rs` drives through `classify_request`,
//! now carried through the real HTTP layer of this crate.
//!
//! Every request is signed with `signer_by_name("alice")`, a never-repeating
//! nonce and the fixture document's own `aud`/`clock.now`, so the verifier
//! accepts it exactly as it accepts any other authenticated traffic (spec 01
//! section 4). A fresh `JackLayer`/`NonceStore` per case keeps the nonce cache
//! per case, which lets a refusal be replayed to prove that it consumed the
//! nonce (spec 01 section 4 step 8). Two assertions run for every case: the
//! engine classification (`classify_request`, the corpus-facing contract
//! `request.rs` checks) and — when the case is representable as an
//! `http::Request` — the wire behaviour.
//!
//! # Representability split
//!
//! Some fixture header values carry bytes no HTTP field-value can hold: the
//! control characters LF, CR, NUL and DEL are rejected by
//! `http::HeaderValue::from_bytes` (RFC 9110 field-value syntax), so the
//! request cannot be built at all (`req-name-header-lf` and its siblings, plus
//! the `Both`-profile legacy forward that carries an LF and a NUL). Those
//! cases are never sent: the runner asserts that `HeaderValue::from_bytes`
//! rejects the offending pair — the HTTP representation cannot carry that byte
//! — and asserts the classification outcome against the vector exactly as
//! `request.rs` does. They are reported as `excluded`; every other case is
//! reported as `pass`.
//!
//! # Forwarding is compared per name
//!
//! The forwarded header list is rebuilt from an `http::HeaderMap`, which groups
//! values by name and lowercases names, so the cross-name interleaving of the
//! fixture is not observable (see `rust/src/server/http/forward.rs`). The
//! runner therefore compares the values of every expected name in fixture
//! order, and only asserts that any other forwarded name is one of the
//! transport headers the layer itself supplies.
//!
//! # `HEAD` (rule `S2`)
//!
//! An HTTP `HEAD` response carries no body, so `req-modern-head` is asserted on
//! two levels: the wire answer is `405` with `Content-Type: application/json`,
//! an EMPTY body, and that empty body verifies with the real client verifier at
//! status `405`; the engine classification is asserted separately and must be
//! `ModernOutcome::Refuse` with `-32600`, `HTTP method not allowed` and a null
//! id — the JSON-RPC envelope the vector records for a body-carrying method.
#![cfg(feature = "http")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method};
use http_body_util::{BodyExt, Full};
use mcp_jack::user_key::ServerSigningKey;
use serde_json::Value;
use tower::{Layer, ServiceExt};

use mcp_jack::client::auth::sign_request;
use mcp_jack::client::signer::InMemorySigner;
use mcp_jack::server::http::{HandlerBuilder, JackService};
use mcp_jack::server::modern::{
    classify_request, HeaderField, ModernOutcome, ModernRequest, Profile,
};
use mcp_jack::server::native::{Native, NativeOptions};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::state::{MemoryState, RegistryEntry, StateStore};
use mcp_jack::server::verify::{Clock, VerifierBuilder};
use mcp_jack::signing::verify_response;

use super::fixtures::*;
use crate::server::common::fixtures::{load_keys, load_registry};
use crate::server::common::harness;

/// Returns a checker failure; the runner prefixes the case id when reporting.
macro_rules! fail {
    ($($arg:tt)*) => {
        return Err(format!($($arg)*))
    };
}

/// The case count stated in `spec/tests/modern/CASES.md`.
const EXPECTED_CASES: usize = 98;

/// The cases whose header bytes have no HTTP representation (control
/// characters inside a field-value), in corpus order. Pinned so a case can
/// never be silently dropped from the wire assertion.
const EXPECTED_EXCLUDED: [&str; 7] = [
    "req-both-legacy-malformed-name-forwarded",
    "req-name-header-lf",
    "req-name-header-cr",
    "req-name-header-nul",
    "req-name-header-del",
    "req-param-value-nul",
    "req-param-value-del",
];

/// Headers the layer or the transport contributes beyond the fixture list
/// (`jack-auth` is the verified request header itself).
const TRANSPORT_HEADERS: [&str; 4] = ["jack-auth", "host", "content-length", "transfer-encoding"];

/// The boxed inner service behind the harness (S::Error = String).
type InnerBox =
    tower::util::BoxCloneService<http::Request<Full<Bytes>>, http::Response<Full<Bytes>>, String>;

/// Process-wide nonce source: the first 8 bytes are zero, the last 8 encode a
/// never-repeating counter (the same idiom as the other HTTP harnesses).
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The canned inner answer signed back to the client on a forward.
const INNER_OK_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;

/// The deployment settings of the corpus: audience, clock and server key, all
/// taken from the fixture document and `keys.json`.
struct Deployment {
    aud: String,
    now: i64,
    window_seconds: i64,
    /// The original `keys.json` "svc" seed used to reconstruct this test key.
    server_seed: [u8; 32],
    /// The matching 32-byte public key the client verifier pins.
    server_pub: [u8; 32],
}

impl Deployment {
    fn from_document(document: &Value) -> Self {
        let aud = text(document, &["aud"]).to_owned();
        let now = at(document, &["clock", "now"])
            .as_i64()
            .expect("modern-request-vectors.json: clock.now is not an integer");
        let window_seconds = at(document, &["clock", "window_seconds"])
            .as_i64()
            .expect("modern-request-vectors.json: clock.window_seconds is not an integer");
        assert_eq!(
            window_seconds, 30,
            "modern-request-vectors.json: the corpus clock and the verifier window agree"
        );
        let server_seed = server_seed();
        let server_key = ServerSigningKey::from_bytes(&server_seed);
        let server_pub = server_key.public_key();
        Self {
            aud,
            now,
            window_seconds,
            server_seed,
            server_pub,
        }
    }
}

/// The deployment profile of one case.
fn profile_of(case: &Value) -> Profile {
    match text(case, &["profile"]) {
        "legacy" => Profile::Legacy,
        "modern" => Profile::Modern,
        "both" => Profile::Both,
        other => panic!("case {}: unknown profile `{}`", case_id(case), other),
    }
}

/// The request body of one case: `body_text`, or empty when absent.
fn body_of(case: &Value) -> &str {
    opt_text(case, &["request", "body_text"]).unwrap_or("")
}

/// The `[[name, value], ...]` list at `path` as owned header fields.
fn headers_of(case: &Value, path: &[&str]) -> Vec<HeaderField> {
    header_pairs(case, at(case, path))
        .into_iter()
        .map(|(name, value)| HeaderField::new(name, value))
        .collect()
}

/// Classifies the request of one case through the SDK rules, exactly as
/// `request.rs` does (fixture strings in fixture order).
fn classify_case(case: &Value) -> ModernOutcome {
    let headers = headers_of(case, &["request", "headers"]);
    let request = ModernRequest {
        method: text(case, &["request", "method"]),
        target: text(case, &["request", "target"]),
        headers: &headers,
        body: body_of(case).as_bytes(),
    };
    classify_request(profile_of(case), &request)
}

/// The keys.json "svc" signing key (the layer's response key).
fn server_seed() -> [u8; 32] {
    let keys = load_keys().expect("load keys.json");
    let svc = keys
        .keys
        .iter()
        .find(|key| key.name == "svc")
        .expect("keys.json has no key named svc");
    let seed: [u8; 32] = harness::hex_bytes(&svc.seed_hex)
        .try_into()
        .expect("svc seed is 32 bytes");
    seed
}

/// Seeds the fixture registry into a fresh in-memory state.
fn seed_registry(state: &MemoryState) {
    let registry = load_registry().expect("load registry.json");
    state
        .update(&mut |edit| {
            for entry in &registry.keys {
                edit.put_key(RegistryEntry {
                    kid: entry.kid.clone(),
                    public_key: entry.public_key.clone(),
                    name: entry.name.clone(),
                    admin: entry.admin,
                    not_before: entry.not_before,
                    not_after: entry.not_after,
                });
            }
            Ok(())
        })
        .expect("seed registry");
}

/// One forwarded request as the wrapped service observed it.
#[derive(Debug, Clone)]
struct Forwarded {
    method: String,
    target: String,
    /// `(lowercase name, raw value bytes)` in the map's iteration order.
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

/// What the wrapped service saw, across every call of one case.
#[derive(Default)]
struct Seen {
    requests: Mutex<Vec<Forwarded>>,
}

impl Seen {
    fn forwarded(&self) -> Vec<Forwarded> {
        self.requests.lock().expect("request mutex").clone()
    }
}

/// Records the forwarded request and answers a fixed JSON body.
async fn inner_handle(
    seen: Arc<Seen>,
    req: http::Request<Full<Bytes>>,
) -> Result<http::Response<Full<Bytes>>, String> {
    let (parts, body) = req.into_parts();
    let body = BodyExt::collect(body)
        .await
        .expect("Full body always collects")
        .to_bytes();
    let headers = parts
        .headers
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
        .collect();
    seen.requests
        .lock()
        .expect("request mutex")
        .push(Forwarded {
            method: parts.method.as_str().to_owned(),
            target: parts.uri.to_string(),
            headers,
            body: body.to_vec(),
        });
    Ok(http::Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from_static(INNER_OK_BODY)))
        .expect("static response parts"))
}

/// Fixture verifier, the `svc` server key, `profile`, and a recording inner
/// service. The `NonceStore` is fresh, so nonces are per case.
fn new_service(profile: Profile, deploy: &Deployment, seen: Arc<Seen>) -> JackService<InnerBox> {
    let state = MemoryState::new();
    seed_registry(&state);
    let now = deploy.now;
    let now_clock: Clock = Arc::new(move || now);
    let verifier = Arc::new(
        VerifierBuilder::new(deploy.aud.clone(), Arc::new(state))
            .nonces(Arc::new(NonceStore::new()))
            .native_tools(Some(Arc::new(Native::new(NativeOptions::default()))))
            .window_seconds(deploy.window_seconds)
            .now(now_clock)
            .try_build()
            .expect("verifier"),
    );
    let layer = HandlerBuilder::new(verifier, ServerSigningKey::from_bytes(&deploy.server_seed))
        .with_profile(profile)
        .build();
    layer.layer(tower::util::BoxCloneService::new(tower::service_fn(
        move |req: http::Request<Full<Bytes>>| {
            let seen = Arc::clone(&seen);
            async move { inner_handle(seen, req).await }
        },
    )))
}

/// One signed request under test.
struct Sent {
    /// The `Jack-Auth` header value carried on the wire.
    header_value: String,
    /// The request signature the server signs its answer against (spec 01
    /// section 5).
    request_sig: String,
}

/// Signs with a never-repeating nonce, the corpus timestamp and the exact
/// method, target and body bytes that are sent.
fn sign(
    deploy: &Deployment,
    signer: &InMemorySigner,
    method: &str,
    target: &str,
    body: &[u8],
) -> Sent {
    let n = NONCE_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    let mut nonce = [0u8; 16];
    nonce[8..].copy_from_slice(&n.to_be_bytes());
    let signed = sign_request(
        signer,
        &deploy.aud,
        method,
        target,
        body,
        &nonce,
        deploy.now,
    )
    .unwrap_or_else(|e| panic!("sign_request: {e}"));
    Sent {
        header_value: signed.header_value,
        request_sig: signed.auth.sig,
    }
}

/// Builds `method target` with `Jack-Auth` first, the case's headers in
/// fixture order, and the exact body bytes.
fn build(
    method: &Method,
    target: &str,
    headers: &[(HeaderName, HeaderValue)],
    signed: &Sent,
    body: &[u8],
) -> http::Request<Full<Bytes>> {
    let mut builder = http::Request::builder()
        .method(method.clone())
        .uri(target)
        .header("Jack-Auth", signed.header_value.as_str());
    for (name, value) in headers {
        builder = builder.header(name.clone(), value.clone());
    }
    builder
        .body(Full::new(Bytes::copy_from_slice(body)))
        .expect("fixture-derived request parts")
}

/// A response as the client sees it: status, `Content-Type`, every `Jack-Auth`
/// value in order, and the exact body bytes.
struct GotResponse {
    status: u16,
    content_type: Option<String>,
    jack_auth: Vec<String>,
    body: Bytes,
}

/// Sends one request through the layered service.
async fn send(service: &JackService<InnerBox>, request: http::Request<Full<Bytes>>) -> GotResponse {
    let response = service
        .clone()
        .oneshot(request)
        .await
        .expect("the inner service never errors");
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("Content-Type")
        .map(|value| value.to_str().expect("UTF-8 content type").to_owned());
    let jack_auth = response
        .headers()
        .get_all("Jack-Auth")
        .iter()
        .map(|value| value.to_str().expect("ASCII Jack-Auth").to_owned())
        .collect();
    let body = BodyExt::collect(response.into_body())
        .await
        .expect("Full body always collects")
        .to_bytes();
    GotResponse {
        status,
        content_type,
        jack_auth,
        body,
    }
}

/// The HTTP form of one case: either the parsed request parts, or the fact
/// that no representation exists.
enum WireParts {
    Send {
        method: Method,
        headers: Vec<(HeaderName, HeaderValue)>,
    },
    Excluded,
}

/// Parses the method, the origin-form target and every header pair of one
/// case. A header value the HTTP representation cannot carry (a control
/// character such as LF, CR, NUL or DEL) makes the whole case unrepresentable.
fn wire_parts(case: &Value) -> Result<WireParts, String> {
    let method_text = text(case, &["request", "method"]);
    let target = text(case, &["request", "target"]);
    let mut excluded = false;

    // No `http::Method` can hold these bytes, so no wire form exists either.
    let method = Method::from_bytes(method_text.as_bytes()).ok();
    excluded |= method.is_none();

    // Only an origin-form target is signable (spec 01 section 3.1).
    match target.parse::<http::Uri>() {
        Ok(uri)
            if uri.scheme().is_none()
                && uri.authority().is_none()
                && uri.path().starts_with('/') => {}
        _ => excluded = true,
    }

    let mut headers = Vec::new();
    for (name, value) in header_pairs(case, at(case, &["request", "headers"])) {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            // A name outside the token grammar has no HTTP representation.
            excluded = true;
            continue;
        };
        match HeaderValue::from_bytes(value.as_bytes()) {
            Ok(value) => headers.push((name, value)),
            Err(_) => {
                // The pair is unrepresentable: no `HeaderValue` carries this
                // byte, so the case is asserted through classification only.
                assert!(
                    HeaderValue::from_bytes(value.as_bytes()).is_err(),
                    "header value `{value}` was expected to be rejected"
                );
                excluded = true;
            }
        }
    }

    if excluded {
        return Ok(WireParts::Excluded);
    }
    let method = method.expect("an unparsable method is excluded above");
    Ok(WireParts::Send { method, headers })
}

/// Values of every header named `name` (HeaderName lowercased them), in order.
fn forwarded_values<'a>(headers: &'a [(String, Vec<u8>)], name: &str) -> Vec<&'a [u8]> {
    headers
        .iter()
        .filter(|(entry, _)| entry == name)
        .map(|(_, value)| value.as_slice())
        .collect()
}

/// Renders raw header values for failure messages.
fn render(values: &[&[u8]]) -> Vec<String> {
    values
        .iter()
        .map(|value| String::from_utf8_lossy(value).into_owned())
        .collect()
}

/// Compares the forwarded header list with `expect.forward.headers`, per name
/// only: an `http::HeaderMap` groups values by name and lowercases names, so
/// cross-name interleaving and casing are not observable (see
/// `rust/src/server/http/forward.rs`).
fn check_forwarded_headers(case: &Value, forwarded: &[(String, Vec<u8>)]) -> Result<(), String> {
    let expected = header_pairs(case, at(case, &["expect", "forward", "headers"]));
    let mut names: Vec<String> = Vec::new();
    for (name, _) in &expected {
        let lower = name.to_ascii_lowercase();
        if !names.contains(&lower) {
            names.push(lower);
        }
    }
    for name in &names {
        let want: Vec<&[u8]> = expected
            .iter()
            .filter(|(entry, _)| entry.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_bytes())
            .collect();
        let got = forwarded_values(forwarded, name);
        if want != got {
            fail!(
                "forwarded values of `{}` are {:?}, expected {:?}",
                name,
                render(&got),
                render(&want)
            );
        }
    }
    for (name, _) in forwarded {
        if names.contains(name) || TRANSPORT_HEADERS.contains(&name.as_str()) {
            continue;
        }
        fail!(
            "unexpected forwarded header `{}` outside the fixture list and the transport headers",
            name
        );
    }
    Ok(())
}

/// Verifies a response with the REAL client verifier (spec 01 section 5).
fn verify_wire_response(
    case: &Value,
    got: &GotResponse,
    signed: &Sent,
    deploy: &Deployment,
    status: u16,
) -> Result<(), String> {
    let values: Vec<&str> = got.jack_auth.iter().map(String::as_str).collect();
    verify_response(
        &deploy.server_pub,
        i64::from(status),
        &values,
        &signed.request_sig,
        &got.body,
        deploy.now,
        deploy.window_seconds,
    )
    .map_err(|e| {
        format!(
            "case {}: the response does not verify: {e:?}",
            case_id(case)
        )
    })
}

/// `expect.outcome == "forward"`: `200`, a verifiable signed answer, and the
/// request the wrapped service actually received.
fn check_forward(
    case: &Value,
    got: &GotResponse,
    signed: &Sent,
    seen: &[Forwarded],
    deploy: &Deployment,
) -> Result<(), String> {
    if got.status != 200 {
        fail!("forward status {} != 200", got.status);
    }
    if seen.len() != 1 {
        fail!(
            "the wrapped service saw {} requests, expected 1",
            seen.len()
        );
    }
    let forwarded = &seen[0];
    let want_method = text(case, &["expect", "forward", "method"]);
    if forwarded.method != want_method {
        fail!("forwarded method `{}` != `{want_method}`", forwarded.method);
    }
    let want_target = text(case, &["expect", "forward", "target"]);
    if forwarded.target != want_target {
        fail!("forwarded target `{}` != `{want_target}`", forwarded.target);
    }
    if forwarded.body != body_of(case).as_bytes() {
        fail!(
            "forwarded body `{}` != the request body",
            String::from_utf8_lossy(&forwarded.body)
        );
    }
    check_forwarded_headers(case, &forwarded.headers)?;
    verify_wire_response(case, got, signed, deploy, 200)
}

/// `expect.outcome == "refuse"`: the signed JSON-RPC refusal (spec 04 S10),
/// its status and `Content-Type`, and a verifiable signature over the exact
/// bytes.
fn check_refuse(
    case: &Value,
    got: &GotResponse,
    signed: &Sent,
    seen: &[Forwarded],
    deploy: &Deployment,
) -> Result<(), String> {
    if !seen.is_empty() {
        fail!("a refusal must never forward, but the wrapped service ran");
    }
    let Some(want_status) = at(case, &["expect", "http_status"]).as_u64() else {
        fail!("`expect.http_status` is not an integer");
    };
    if u64::from(got.status) != want_status {
        fail!("refusal status {} != {want_status}", got.status);
    }
    let want_content_type = text(case, &["expect", "content_type"]);
    if got.content_type.as_deref() != Some(want_content_type) {
        fail!(
            "Content-Type {:?} != `{want_content_type}`",
            got.content_type
        );
    }
    let body: Value = serde_json::from_slice(&got.body)
        .map_err(|e| format!("case {}: refusal body is not JSON: {e}", case_id(case)))?;
    let want = serde_json::json!({
        "jsonrpc": at(case, &["expect", "jsonrpc"]).clone(),
        "id": at(case, &["expect", "id"]).clone(),
        "error": at(case, &["expect", "error"]).clone(),
    });
    if body != want {
        fail!("refusal body {body} != expected {want}");
    }
    if at(case, &["expect", "consumes_nonce"]).as_bool() != Some(true) {
        fail!(
            "a Refuse outcome is produced after authentication, so the vector must carry consumes_nonce == true"
        );
    }
    verify_wire_response(case, got, signed, deploy, got.status)
}

/// `expect.outcome == "refuse_invalid_request"`: the era-neutral `400
/// invalid_request` envelope of spec 02 section 2 item 4.
fn check_invalid_request(
    case: &Value,
    got: &GotResponse,
    signed: &Sent,
    seen: &[Forwarded],
    deploy: &Deployment,
) -> Result<(), String> {
    if !seen.is_empty() {
        fail!("a classification refusal must never forward");
    }
    if got.status != 400 {
        fail!("invalid_request status {} != 400", got.status);
    }
    let want_content_type = text(case, &["expect", "content_type"]);
    if got.content_type.as_deref() != Some(want_content_type) {
        fail!(
            "Content-Type {:?} != `{want_content_type}`",
            got.content_type
        );
    }
    let body: Value = serde_json::from_slice(&got.body).map_err(|e| {
        format!(
            "case {}: invalid_request body is not JSON: {e}",
            case_id(case)
        )
    })?;
    let want = serde_json::json!({
        "error": {
            "code": "invalid_request",
            "message": text(case, &["expect", "error", "message"]),
        },
    });
    if body != want {
        fail!("invalid_request body {body} != expected {want}");
    }
    // The vector decides whether the answer is signed; never invent it.
    if at(case, &["expect"]).get("signed").and_then(Value::as_bool) == Some(true) {
        return verify_wire_response(case, got, signed, deploy, 400);
    }
    if !got.jack_auth.is_empty() {
        fail!("the vector does not mark the response signed, but it carries Jack-Auth");
    }
    Ok(())
}

/// `req-modern-head` (rule `S2`): an HTTP `HEAD` answer carries no body, so
/// the wire representation and the classification envelope are asserted
/// separately.
fn check_head(
    case: &Value,
    got: &GotResponse,
    signed: &Sent,
    seen: &[Forwarded],
    deploy: &Deployment,
    outcome: &ModernOutcome,
) -> Result<(), String> {
    if !seen.is_empty() {
        fail!("a refusal must never forward");
    }
    if got.status != 405 {
        fail!("HEAD refusal status {} != 405", got.status);
    }
    let want_content_type = text(case, &["expect", "content_type"]);
    if got.content_type.as_deref() != Some(want_content_type) {
        fail!(
            "Content-Type {:?} != `{want_content_type}`",
            got.content_type
        );
    }
    if !got.body.is_empty() {
        fail!(
            "an HTTP HEAD answer carries no body, got {} bytes",
            got.body.len()
        );
    }
    verify_wire_response(case, got, signed, deploy, 405)?;

    // The engine classification is the body-carrying method's envelope the
    // vector records; on the wire that body is absent by RFC 9110.
    let ModernOutcome::Refuse(refusal) = outcome else {
        fail!("expected Refuse, got {outcome:?}");
    };
    if refusal.reason.code() != -32600 {
        fail!("refusal code {} != -32600", refusal.reason.code());
    }
    if refusal.reason.message() != "HTTP method not allowed" {
        fail!(
            "refusal message `{}` != `HTTP method not allowed`",
            refusal.reason.message()
        );
    }
    if refusal.id.is_some() {
        fail!("a method-not-allowed refusal carries a null id");
    }
    Ok(())
}

/// Replaying the same signed request must be refused as a nonce replay, which
/// proves the first refusal consumed the nonce (spec 01 section 4 step 8).
fn check_replay(case: &Value, got: &GotResponse) -> Result<(), String> {
    if got.status != 401 {
        fail!("replay status {} != 401", got.status);
    }
    let body: Value = serde_json::from_slice(&got.body)
        .map_err(|e| format!("case {}: replay body is not JSON: {e}", case_id(case)))?;
    if body
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Value::as_str)
        != Some("replayed_nonce")
    {
        fail!("replay body {body} is not a replayed_nonce refusal");
    }
    Ok(())
}

/// The engine classification must match the vector exactly, as `request.rs`
/// asserts it: this is the whole check for a non-representable case, and the
/// corpus-facing half of the check for a representable one.
fn check_classification(case: &Value, outcome: &ModernOutcome) -> Result<(), String> {
    match text(case, &["expect", "outcome"]) {
        "forward" => {
            let ModernOutcome::Forward { era, headers } = outcome else {
                fail!("expected Forward, got {outcome:?}");
            };
            let want_era = text(case, &["expect", "era"]);
            if era.as_str() != want_era {
                fail!("era `{}` != expected `{want_era}`", era.as_str());
            }
            let want = headers_of(case, &["expect", "forward", "headers"]);
            if *headers != want {
                fail!("classification headers {headers:?} != expected {want:?}");
            }
            Ok(())
        }
        "refuse" => {
            let ModernOutcome::Refuse(refusal) = outcome else {
                fail!("expected Refuse, got {outcome:?}");
            };
            let got_id = match refusal.id.as_deref() {
                None => Value::Null,
                Some(raw) => serde_json::from_str(raw).map_err(|e| {
                    format!(
                        "case {}: refusal id `{raw}` is not JSON: {e}",
                        case_id(case)
                    )
                })?,
            };
            let got = serde_json::json!({
                "http_status": refusal.reason.http_status(),
                "id": got_id,
                "error": {"code": refusal.reason.code(), "message": refusal.reason.message()},
            });
            let want = serde_json::json!({
                "http_status": at(case, &["expect", "http_status"]),
                "id": at(case, &["expect", "id"]),
                "error": at(case, &["expect", "error"]),
            });
            if got != want {
                fail!("classification {got} != expected {want}");
            }
            Ok(())
        }
        "refuse_invalid_request" => {
            let ModernOutcome::ClassificationRefusal { message } = outcome else {
                fail!("expected ClassificationRefusal, got {outcome:?}");
            };
            let want_message = text(case, &["expect", "error", "message"]);
            if *message != want_message {
                fail!("classification message `{message}` != expected `{want_message}`");
            }
            if text(case, &["expect", "error", "code"]) != "invalid_request" {
                fail!("error code is not `invalid_request`");
            }
            Ok(())
        }
        other => Err(format!("unknown `expect.outcome` `{other}`")),
    }
}

/// How one case was asserted.
enum Run {
    /// Classification and the wire behaviour passed.
    Wire,
    /// Non-representable: classification and header rejection passed.
    Excluded,
}

/// Runs every assertion of one case through the real HTTP layer.
async fn run_case(
    case: &Value,
    deploy: &Deployment,
    signer: &InMemorySigner,
) -> Result<Run, String> {
    let outcome = classify_case(case);
    check_classification(case, &outcome)?;

    let method_text = text(case, &["request", "method"]);
    let target = text(case, &["request", "target"]);
    let body = body_of(case).as_bytes().to_vec();
    let (method, headers) = match wire_parts(case)? {
        WireParts::Excluded => return Ok(Run::Excluded),
        WireParts::Send { method, headers } => (method, headers),
    };

    let signed = sign(deploy, signer, method_text, target, &body);
    let seen = Arc::new(Seen::default());
    let service = new_service(profile_of(case), deploy, Arc::clone(&seen));
    let got = send(&service, build(&method, target, &headers, &signed, &body)).await;

    match text(case, &["expect", "outcome"]) {
        "forward" => check_forward(case, &got, &signed, &seen.forwarded(), deploy)?,
        "refuse" if method_text == "HEAD" => {
            check_head(case, &got, &signed, &seen.forwarded(), deploy, &outcome)?
        }
        "refuse" => {
            check_refuse(case, &got, &signed, &seen.forwarded(), deploy)?;
            // The same signed request again: the per-case nonce store answers
            // `401 replayed_nonce`, proving the refusal consumed the nonce.
            let replayed = send(&service, build(&method, target, &headers, &signed, &body)).await;
            check_replay(case, &replayed)?;
        }
        "refuse_invalid_request" => {
            check_invalid_request(case, &got, &signed, &seen.forwarded(), deploy)?
        }
        other => fail!("unknown `expect.outcome` `{other}`"),
    }
    Ok(Run::Wire)
}

#[tokio::test]
async fn modern_request_wire_vectors() {
    assert!(
        modern_dir().join("modern-request-vectors.json").is_file(),
        "the request corpus is missing from {}",
        modern_dir().display()
    );
    let document = load_modern_request_vectors();
    let listed = cases(&document);
    assert_eq!(
        listed.len(),
        EXPECTED_CASES,
        "Request wire vectors (`fixtures/modern/modern-request-vectors.json`, 98 cases)"
    );
    let deploy = Deployment::from_document(&document);
    let signer = harness::signer_by_name("alice");

    let mut failures: Vec<(String, String)> = Vec::new();
    let mut pass = 0usize;
    let mut excluded = 0usize;
    let mut excluded_ids: Vec<String> = Vec::new();

    for case in listed {
        match run_case(case, &deploy, &signer).await {
            Ok(Run::Wire) => pass += 1,
            Ok(Run::Excluded) => {
                excluded += 1;
                excluded_ids.push(case_id(case).to_owned());
            }
            Err(message) => failures.push((case_id(case).to_owned(), message)),
        }
    }

    if !failures.is_empty() {
        let listing: Vec<String> = failures
            .iter()
            .map(|(id, message)| format!("  {id}: {message}"))
            .collect();
        panic!(
            "modern request wire vectors: {pass} passed, {excluded} excluded; failures:\n{}",
            listing.join("\n")
        );
    }
    assert_eq!(
        excluded_ids, EXPECTED_EXCLUDED,
        "the non-representable cases are fixed by the fixture header bytes"
    );
    assert_eq!(
        pass + excluded,
        EXPECTED_CASES,
        "every corpus case is either asserted on the wire or excluded for its bytes"
    );
    println!(
        "VECTOR-SUMMARY corpus=modern-request-wire sdk=rust pass={pass} excluded={excluded} deviation=0"
    );
}
