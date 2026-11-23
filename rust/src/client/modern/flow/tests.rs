//! Unit tests of the era flow (spec 04 section 6, `C9`): era detection over a
//! stub [`Transport`] that verifies inbound signatures and signs its replies,
//! exactly like the server would.

use super::*;
use crate::auth_header::{format_response_auth, parse_request_auth, RequestAuth, ResponseAuth};
use crate::client::signer::InMemorySigner;
use crate::client::transport::{Clock, NonceSource, Transport, TransportError};
use crate::encoding::{decode_b64url_fixed, encode_b64url, key_id};
use crate::signing::{request_signing_string, response_signing_string};
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use std::sync::{Arc, Mutex};

// keys.json seeds, the conformance fixture is the oracle.
const ALICE_SEED_HEX: &str = "15949421ee8241acde219c4cff93cc346a0488e049deff61da312798b758d28f";
const SVC_SEED_HEX: &str = "cc9e39e830a43e09c6372b14852ef80a2bb8e7b1aa4c04bf076f33e0aad2c901";

const AUD: &str = "https://svc.example.test";
const BASE_URL: &str = "https://svc.example.test/mcp";
const FIXED_TS: i64 = 1767225600;
const SESSION: &str = "sess-1";

fn hex_bytes(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        out[i] =
            u8::from_str_radix(std::str::from_utf8(pair).expect("valid"), 16).expect("hex digit");
    }
    out
}

fn alice() -> Arc<dyn Signer> {
    Arc::new(InMemorySigner::from_seed(&hex_bytes(ALICE_SEED_HEX)).expect("32-byte seed"))
}

fn alice_pub() -> [u8; 32] {
    *SigningKey::from_bytes(&hex_bytes(ALICE_SEED_HEX))
        .verifying_key()
        .as_bytes()
}

fn svc_signing_key() -> SigningKey {
    SigningKey::from_bytes(&hex_bytes(SVC_SEED_HEX))
}

fn svc_key() -> [u8; 32] {
    *svc_signing_key().verifying_key().as_bytes()
}

/// One request as the stub saw it.
#[derive(Debug, Clone)]
struct Recorded {
    headers: Vec<(String, String)>,
    body: String,
}

impl Recorded {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).expect("request body is JSON")
    }

    fn method(&self) -> String {
        self.json()["method"].as_str().unwrap_or("").to_owned()
    }

    fn id(&self) -> Option<i64> {
        self.json().get("id").and_then(Value::as_i64)
    }

    fn params(&self) -> Value {
        self.json().get("params").cloned().unwrap_or(Value::Null)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

type Handler =
    Box<dyn Fn(&Recorded, &RequestAuth) -> (u16, String, Vec<(String, String)>) + Send + Sync>;

/// A stub transport that verifies every inbound request signature, records
/// the request and answers with a response signed over that request's
/// signature (spec 01 section 5), exactly like the server would.
struct StubTransport {
    handler: Handler,
    seen: Mutex<Vec<Recorded>>,
}

impl StubTransport {
    fn new(handler: Handler) -> Arc<Self> {
        Arc::new(StubTransport {
            handler,
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<Recorded> {
        self.seen.lock().expect("seen mutex").clone()
    }

    fn methods(&self) -> Vec<String> {
        self.seen().iter().map(|r| r.method()).collect()
    }
}

/// Verifies the inbound Jack-Auth header exactly as the server does.
fn verify_inbound(req: &HttpRequest) -> RequestAuth {
    let raw = req.header("Jack-Auth").expect("signed request header");
    let auth = parse_request_auth(&[raw]).expect("canonical request header");
    let sig = decode_b64url_fixed(&auth.sig, 64).expect("canonical sig");
    let target = crate::client::url::request_target(&req.url).expect("absolute url");
    let msg = request_signing_string(
        &req.method,
        &target,
        AUD,
        &auth.kid,
        auth.ts,
        &auth.nonce,
        &req.body,
    );
    assert_eq!(auth.kid, key_id(&alice_pub()));
    assert!(
        crate::ed25519::verify(&alice_pub(), msg.as_bytes(), &sig),
        "request signature must verify"
    );
    auth
}

impl Transport for StubTransport {
    fn round_trip(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        let auth = verify_inbound(&req);
        let recorded = Recorded {
            headers: req.headers.clone(),
            body: String::from_utf8(req.body.clone()).expect("utf-8 body"),
        };
        self.seen.lock().expect("seen mutex").push(recorded.clone());
        let (status, body, extra_headers) = (self.handler)(&recorded, &auth);
        let server = svc_signing_key();
        let kid = key_id(server.verifying_key().as_bytes());
        let msg =
            response_signing_string(status as i64, &auth.sig, &kid, FIXED_TS, body.as_bytes());
        let sig = server.sign(msg.as_bytes());
        let mut headers = vec![
            (
                "Jack-Auth".to_owned(),
                format_response_auth(&ResponseAuth {
                    kid,
                    ts: FIXED_TS,
                    sig: encode_b64url(&sig.to_bytes()),
                }),
            ),
            ("Content-Type".to_owned(), "application/json".to_owned()),
        ];
        headers.extend(extra_headers);
        Ok(HttpResponse {
            status,
            headers,
            body: body.into_bytes(),
        })
    }
}

fn mk_client(transport: Arc<StubTransport>, era: ClientEra) -> Client {
    let now: Clock = Arc::new(|| FIXED_TS);
    let nonce: NonceSource = Arc::new(|| Ok(vec![7u8; 16]));
    Client::new(crate::client::Config {
        base_url: BASE_URL.to_string(),
        aud: AUD.to_string(),
        signer: alice(),
        server_key: svc_key(),
        transport,
        now: Some(now),
        nonce: Some(nonce),
        window_seconds: 30,
    })
    .expect("valid config")
    .with_era(era)
}

/// A successful `tools/call` result.
fn call_result(id: i64) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"result":{{"content":[{{"type":"text","text":"ok"}}],"isError":false,"structuredContent":{{"ok":true}}}}}}"#
    )
}

/// A successful `server/discover` result.
fn discover_result(id: i64) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"result":{{"protocolVersion":"2026-07-28","capabilities":{{}}}}}}"#
    )
}

/// A successful `initialize` result with the given version.
fn initialize_result(id: i64, version: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"result":{{"protocolVersion":"{version}","capabilities":{{}},"serverInfo":{{"name":"jack","version":"1"}}}}}}"#
    )
}

/// A recognised JSON-RPC error body.
fn rpc_error(id: i64, code: i64, message: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":{code},"message":"{message}"}}}}"#)
}

/// A `-32022` with the given supported list.
fn version_mismatch(id: i64, supported: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":-32022,"message":"unsupported version","data":{{"supported":{supported}}}}}}}"#
    )
}

/// The session header of the successful `initialize` reply.
fn session_header() -> Vec<(String, String)> {
    vec![("Mcp-Session-Id".to_owned(), SESSION.to_owned())]
}

/// The method names of the recorded requests.
fn methods(stub: &StubTransport) -> Vec<String> {
    stub.methods()
}

#[test]
fn auto_probe_stays_modern_then_sends_the_operation() {
    let stub = StubTransport::new(Box::new(|req, _auth| {
        let id = req.id().unwrap_or(0);
        match req.method().as_str() {
            "server/discover" => (200, discover_result(id), vec![]),
            "tools/call" => (200, call_result(id), vec![]),
            other => panic!("unexpected method {other}"),
        }
    }));
    let client = mk_client(Arc::clone(&stub), ClientEra::Auto);

    let result = client.call_tool_raw("jack.whoami", None).expect("call");
    assert_eq!(result, serde_json::json!({"ok": true}));

    let seen = stub.seen();
    assert_eq!(
        methods(&stub),
        ["server/discover", "tools/call"],
        "the probe, never the caller's operation, goes first"
    );
    // The probe is modern-built: mirrors plus `_meta`.
    let probe = &seen[0];
    assert_eq!(
        probe.header("MCP-Protocol-Version"),
        Some(MODERN_MIN),
        "probe mirrors the version"
    );
    assert_eq!(probe.header("Mcp-Method"), Some("server/discover"));
    assert_eq!(
        probe.params()["_meta"]["io.modelcontextprotocol/protocolVersion"],
        MODERN_MIN
    );
    // The operation is modern too and carries the mirrors.
    assert_eq!(seen[1].header("Mcp-Method"), Some("tools/call"));
    assert_eq!(seen[1].header("Mcp-Name"), Some("jack.whoami"));
    assert_eq!(seen[1].params()["name"], "jack.whoami");

    // The decision is cached: a second call does not probe again.
    client
        .call_tool_raw("jack.whoami", None)
        .expect("second call");
    assert_eq!(
        methods(&stub),
        ["server/discover", "tools/call", "tools/call"]
    );
}

#[test]
fn auto_fallback_runs_the_legacy_handshake_once() {
    let stub = StubTransport::new(Box::new(|req, _auth| {
        let id = req.id().unwrap_or(0);
        match req.method().as_str() {
            "server/discover" => (
                405,
                r#"{"error":{"code":"invalid_request","message":"method not allowed"}}"#.to_owned(),
                vec![],
            ),
            "initialize" => (200, initialize_result(id, LEGACY_VERSION), session_header()),
            "notifications/initialized" => (202, String::new(), vec![]),
            "tools/call" => (200, call_result(id), vec![]),
            other => panic!("unexpected method {other}"),
        }
    }));
    let client = mk_client(Arc::clone(&stub), ClientEra::Auto);

    client
        .call_tool_raw("jack.whoami", None)
        .expect("fallback call");
    assert_eq!(
        methods(&stub),
        [
            "server/discover",
            "initialize",
            "notifications/initialized",
            "tools/call"
        ]
    );

    let seen = stub.seen();
    // The probe is modern, the initialize is not: no version header.
    assert_eq!(seen[0].header("MCP-Protocol-Version"), Some(MODERN_MIN));
    assert_eq!(seen[1].header("MCP-Protocol-Version"), None);
    assert_eq!(seen[1].header("Mcp-Method"), None);
    // `initialize` carries the 2025-11-25 lifecycle params, no `_meta`.
    assert_eq!(
        seen[1].params(),
        serde_json::json!({
            "protocolVersion": LEGACY_VERSION,
            "capabilities": {},
            "clientInfo": {
                "name": IMPLEMENTATION_NAME,
                "version": IMPLEMENTATION_VERSION,
            },
        })
    );
    assert!(seen[1].params().get("_meta").is_none());

    // `notifications/initialized` has no id and carries the negotiated
    // version and the session.
    assert_eq!(seen[2].id(), None, "a notification has no id");
    assert_eq!(seen[2].header("MCP-Protocol-Version"), Some(LEGACY_VERSION));
    assert_eq!(seen[2].header("Mcp-Session-Id"), Some(SESSION));

    // The legacy operation carries both headers and the 0.1.x bytes.
    assert_eq!(seen[3].header("MCP-Protocol-Version"), Some(LEGACY_VERSION));
    assert_eq!(seen[3].header("Mcp-Session-Id"), Some(SESSION));
    assert_eq!(
        seen[3].body,
        format!(
            r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{"name":"jack.whoami","arguments":{{}}}}}}"#,
            seen[3].id().expect("id")
        )
    );

    // Later calls reuse the session and never handshake again.
    client
        .call_tool_raw("jack.whoami", None)
        .expect("second call");
    let seen = stub.seen();
    assert_eq!(
        methods(&stub),
        [
            "server/discover",
            "initialize",
            "notifications/initialized",
            "tools/call",
            "tools/call"
        ]
    );
    assert_eq!(seen[4].header("Mcp-Session-Id"), Some(SESSION));
    assert_eq!(seen[4].header("MCP-Protocol-Version"), Some(LEGACY_VERSION));
}

/// A stub answering `server/discover` with a legacy verdict and every other
/// request with `initialize_reply`.
fn fallback_stub(initialize_reply: String) -> Arc<StubTransport> {
    StubTransport::new(Box::new(move |req, _auth| {
        let id = req.id().unwrap_or(0);
        match req.method().as_str() {
            "server/discover" => (405, String::new(), vec![]),
            "initialize" => (200, initialize_reply.clone(), session_header()),
            "notifications/initialized" => (202, String::new(), vec![]),
            "tools/call" => (200, call_result(id), vec![]),
            other => panic!("unexpected method {other}"),
        }
    }))
}

#[test]
fn initialize_rejections_leave_no_cached_state() {
    let cases = [
        (
            "error reply",
            r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"nope"}}"#.to_owned(),
        ),
        (
            "wrong id",
            r#"{"jsonrpc":"2.0","id":9,"result":{"protocolVersion":"2025-11-25"}}"#.to_owned(),
        ),
        (
            "wrong jsonrpc",
            r#"{"jsonrpc":"1.0","id":2,"result":{"protocolVersion":"2025-11-25"}}"#.to_owned(),
        ),
        (
            "unsupported version",
            r#"{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2020-01-01"}}"#.to_owned(),
        ),
        (
            "non-string version",
            r#"{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":7}}"#.to_owned(),
        ),
        (
            "result not an object",
            r#"{"jsonrpc":"2.0","id":2,"result":"ok"}"#.to_owned(),
        ),
        (
            "both result and error",
            r#"{"jsonrpc":"2.0","id":2,"result":{},"error":{"code":-1,"message":"m"}}"#.to_owned(),
        ),
        (
            "neither result nor error",
            r#"{"jsonrpc":"2.0","id":2}"#.to_owned(),
        ),
        ("not an object", r#"[1,2,3]"#.to_owned()),
    ];
    for (label, reply) in cases {
        let stub = fallback_stub(reply);
        let client = mk_client(Arc::clone(&stub), ClientEra::Auto);
        let err = client
            .call_tool_raw("jack.whoami", None)
            .expect_err("the handshake must fail");
        assert!(
            err.to_string()
                .starts_with("jack client: initialize handshake failed:"),
            "{label}: {err}"
        );
        // Nothing was sent after the rejected initialize.
        assert_eq!(methods(&stub), ["server/discover", "initialize"], "{label}");
        // No era, version or session is cached: the next call probes again.
        let _ = client.call_tool_raw("jack.whoami", None);
        let methods = methods(&stub);
        // The next call probes again (discover), then falls back to initialize once more.
        assert_eq!(methods[2], "server/discover", "{label}");
    }
}

#[test]
fn not_found_rehandshakes_once_and_never_replays_the_call() {
    let calls = Arc::new(Mutex::new(0usize));
    let counter = Arc::clone(&calls);
    let stub = StubTransport::new(Box::new(move |req, _auth| {
        let id = req.id().unwrap_or(0);
        match req.method().as_str() {
            "server/discover" => (405, String::new(), vec![]),
            "initialize" => {
                let mut n = counter.lock().expect("counter");
                *n += 1;
                let session = format!("sess-{n}");
                (
                    200,
                    initialize_result(id, LEGACY_VERSION),
                    vec![("Mcp-Session-Id".to_owned(), session)],
                )
            }
            "notifications/initialized" => (202, String::new(), vec![]),
            "tools/call" => (
                404,
                r#"{"error":{"code":"not_found","message":"session expired"}}"#.to_owned(),
                vec![],
            ),
            other => panic!("unexpected method {other}"),
        }
    }));
    // Only an `Auto` client has a session to recover: it probed its way into
    // the legacy era.
    let client = mk_client(Arc::clone(&stub), ClientEra::Auto);

    let err = client
        .call_tool_raw("jack.whoami", None)
        .expect_err("a tools/call is never replayed");
    assert!(
        matches!(err, ClientError::Http(_)),
        "the original 404 error is returned: {err}"
    );
    assert_eq!(
        methods(&stub),
        [
            "server/discover",
            "initialize",
            "notifications/initialized",
            "tools/call",
            "initialize",
            "notifications/initialized"
        ],
        "the session was rebuilt once and the call was not replayed"
    );

    // The next call carries the new session and does not handshake again.
    let _ = client.call_tool_raw("jack.whoami", None);
    let seen = stub.seen();
    let last_call = seen
        .iter()
        .rev()
        .find(|recorded| recorded.method() == "tools/call")
        .expect("a tools/call");
    assert_eq!(last_call.header("Mcp-Session-Id"), Some("sess-2"));
}

#[test]
fn a_failed_recovery_clears_the_state_so_the_next_call_probes() {
    let init_calls = Arc::new(Mutex::new(0usize));
    let counter = Arc::clone(&init_calls);
    let stub = StubTransport::new(Box::new(move |req, _auth| {
        let id = req.id().unwrap_or(0);
        match req.method().as_str() {
            "server/discover" => (405, String::new(), vec![]),
            "initialize" => {
                let mut n = counter.lock().expect("counter");
                *n += 1;
                if *n == 1 {
                    (200, initialize_result(id, LEGACY_VERSION), session_header())
                } else {
                    (
                        401,
                        r#"{"error":{"code":"unknown_key","message":"no"}}"#.to_owned(),
                        vec![],
                    )
                }
            }
            "notifications/initialized" => (202, String::new(), vec![]),
            "tools/call" => (
                404,
                r#"{"error":{"code":"not_found","message":"expired"}}"#.to_owned(),
                vec![],
            ),
            other => panic!("unexpected method {other}"),
        }
    }));
    let client = mk_client(Arc::clone(&stub), ClientEra::Auto);

    let err = client
        .call_tool_raw("jack.whoami", None)
        .expect_err("the re-handshake fails");
    assert!(
        err.to_string()
            .starts_with("jack client: initialize handshake failed:"),
        "the handshake error is returned: {err}"
    );

    // The state is gone: the next call probes server/discover again.
    let _ = client.call_tool_raw("jack.whoami", None);
    let methods = methods(&stub);
    assert_eq!(methods[0], "server/discover");
    assert_eq!(
        methods,
        [
            "server/discover",
            "initialize",
            "notifications/initialized",
            "tools/call",
            "initialize",
            "server/discover",
            "initialize"
        ]
    );
}

#[test]
fn a_stale_404_never_touches_a_newer_session() {
    let stub = StubTransport::new(Box::new(|_req, _auth| {
        panic!("a stale 404 must not send anything")
    }));
    let client = mk_client(Arc::clone(&stub), ClientEra::Auto);
    {
        let mut flow = client.flow.lock().expect("flow mutex");
        flow.era = Some(Era::Legacy);
        flow.version = Some(LEGACY_VERSION.to_owned());
        flow.session = Some("sess-new".to_owned());
    }

    recover_session(&client, None, None, "sess-old").expect("a stale 404 is ignored");
    assert!(stub.seen().is_empty(), "nothing was sent");
    assert_eq!(cached_session(&client).as_deref(), Some("sess-new"));
    assert_eq!(
        legacy_state(&client),
        Some((LEGACY_VERSION.to_owned(), Some("sess-new".to_owned())))
    );
}

#[test]
fn version_retry_takes_the_first_differing_implemented_entry() {
    let stub = StubTransport::new(Box::new(|req, _auth| {
        let id = req.id().unwrap_or(0);
        match req.method().as_str() {
            "server/discover" => {
                let version = req.header("MCP-Protocol-Version").unwrap_or("").to_owned();
                if version == MODERN_MIN {
                    (
                        400,
                        version_mismatch(id, r#"["2027-01-01","2025-11-25"]"#),
                        vec![],
                    )
                } else {
                    (200, discover_result(id), vec![])
                }
            }
            "tools/call" => (200, call_result(id), vec![]),
            other => panic!("unexpected method {other}"),
        }
    }));
    let client = mk_client(Arc::clone(&stub), ClientEra::Auto);

    client
        .call_tool_raw("jack.whoami", None)
        .expect("retried call");
    let seen = stub.seen();
    assert_eq!(
        methods(&stub),
        ["server/discover", "server/discover", "tools/call"]
    );
    assert_eq!(seen[1].header("MCP-Protocol-Version"), Some("2025-11-25"));
    assert_eq!(
        seen[1].params()["_meta"]["io.modelcontextprotocol/protocolVersion"],
        "2025-11-25"
    );
    // The adopted version is cached for the modern operation.
    assert_eq!(seen[2].header("MCP-Protocol-Version"), Some("2025-11-25"));
}

#[test]
fn first_entry_equals_attempted_aborts_without_a_retry() {
    let stub = StubTransport::new(Box::new(|req, _auth| {
        let id = req.id().unwrap_or(0);
        (400, version_mismatch(id, r#"["2026-07-28"]"#), vec![])
    }));
    let client = mk_client(Arc::clone(&stub), ClientEra::Auto);

    let err = client
        .call_tool_raw("jack.whoami", None)
        .expect_err("no other version to try");
    assert!(
        err.to_string().contains("unsupported_version_no_overlap"),
        "{err}"
    );
    assert_eq!(methods(&stub), ["server/discover"], "no retry was sent");
}

#[test]
fn a_second_retry_verdict_aborts_and_adopts_nothing() {
    let stub = StubTransport::new(Box::new(|req, _auth| {
        let id = req.id().unwrap_or(0);
        (400, version_mismatch(id, r#"["2025-11-25"]"#), vec![])
    }));
    let client = mk_client(Arc::clone(&stub), ClientEra::Auto);

    let err = client
        .call_tool_raw("jack.whoami", None)
        .expect_err("the budget is one");
    assert!(
        err.to_string().contains("already spent"),
        "the second verdict aborts: {err}"
    );
    assert_eq!(
        methods(&stub),
        ["server/discover", "server/discover"],
        "exactly one retry was sent"
    );
    // No era was adopted: the next call probes again (and the second
    // verdict's version was never adopted either).
    assert_eq!(cached_era(&client), None, "no era was adopted");
    let _ = client.call_tool_raw("jack.whoami", None);
    let seen = stub.seen();
    assert_eq!(seen.len(), 3, "the next call probes and never operates");
    assert_eq!(seen[2].method(), "server/discover");
}

#[test]
fn no_overlap_aborts() {
    let stub = StubTransport::new(Box::new(|req, _auth| {
        let id = req.id().unwrap_or(0);
        (400, version_mismatch(id, r#"["2027-01-01"]"#), vec![])
    }));
    let client = mk_client(Arc::clone(&stub), ClientEra::Auto);

    let err = client
        .call_tool_raw("jack.whoami", None)
        .expect_err("no mutual version");
    assert!(
        err.to_string().contains("unsupported_version_no_overlap"),
        "{err}"
    );
    assert_eq!(methods(&stub), ["server/discover"]);
}

#[test]
fn a_numeric_32020_is_surfaced_as_an_rpc_error_with_a_numeric_code() {
    let stub = StubTransport::new(Box::new(|req, _auth| {
        let id = req.id().unwrap_or(0);
        (
            400,
            rpc_error(
                id,
                -32020,
                "Header mismatch: Mcp-Name does not match the body value",
            ),
            vec![],
        )
    }));
    let client = mk_client(Arc::clone(&stub), ClientEra::Modern);

    match client.call_tool_raw("jack.whoami", None) {
        Err(ref err @ ClientError::Rpc(ref rpc)) => {
            assert_eq!(rpc.code, -32020);
            assert_eq!(
                rpc.message,
                "Header mismatch: Mcp-Name does not match the body value"
            );
            assert!(rpc.data.is_none());
            let reply = err.reply_error().expect("typed classification");
            assert_eq!(reply.status, 0, "RpcError carries no HTTP status");
            assert_eq!(reply.code, -32020);
            assert_eq!(reply.era, crate::client::error::ReplyEra::Modern);
            assert!(reply.data.is_none());
        }
        other => panic!("expected an rpc error, got {other:?}"),
    }
}

#[test]
fn reset_era_forgets_the_resolved_state() {
    let stub = StubTransport::new(Box::new(|req, _auth| {
        let id = req.id().unwrap_or(0);
        match req.method().as_str() {
            "server/discover" => (200, discover_result(id), vec![]),
            "tools/call" => (200, call_result(id), vec![]),
            other => panic!("unexpected method {other}"),
        }
    }));
    let client = mk_client(Arc::clone(&stub), ClientEra::Auto);
    client.call_tool_raw("jack.whoami", None).expect("probe");
    assert_eq!(cached_era(&client), Some(Era::Modern));

    client.reset_era();
    assert_eq!(cached_era(&client), None);
    assert_eq!(legacy_state(&client), None);
    assert_eq!(current_modern_version(&client), MODERN_MIN);

    client.call_tool_raw("jack.whoami", None).expect("re-probe");
    assert_eq!(
        methods(&stub),
        [
            "server/discover",
            "tools/call",
            "server/discover",
            "tools/call"
        ]
    );
}

#[test]
fn a_modern_error_for_a_legacy_request_forces_a_new_handshake() {
    let stub = StubTransport::new(Box::new(|req, _auth| {
        let id = req.id().unwrap_or(0);
        match req.method().as_str() {
            "server/discover" => (405, String::new(), vec![]),
            "initialize" => (200, initialize_result(id, LEGACY_VERSION), session_header()),
            "notifications/initialized" => (202, String::new(), vec![]),
            "tools/call" => (
                400,
                rpc_error(id, -32020, "Header mismatch: refused"),
                vec![],
            ),
            other => panic!("unexpected method {other}"),
        }
    }));
    let client = mk_client(Arc::clone(&stub), ClientEra::Auto);

    let err = client
        .call_tool_raw("jack.whoami", None)
        .expect_err("the modern error is surfaced");
    assert!(
        matches!(&err, ClientError::Rpc(rpc) if rpc.code == -32020),
        "got {err:?}"
    );
    assert_eq!(
        err.reply_error().map(|reply| reply.era),
        Some(crate::client::error::ReplyEra::Modern)
    );

    // The modern error clears the cached decision: the next call probes and
    // then handshakes again instead of reusing the negotiated session.
    let _ = client.call_tool_raw("jack.whoami", None);
    assert_eq!(
        methods(&stub),
        [
            "server/discover",
            "initialize",
            "notifications/initialized",
            "tools/call",
            "server/discover",
            "initialize",
            "notifications/initialized",
            "tools/call"
        ]
    );
}

#[test]
fn a_legacy_verdict_for_a_modern_request_forces_a_reprobe() {
    let stub = StubTransport::new(Box::new(|req, _auth| {
        let id = req.id().unwrap_or(0);
        match req.method().as_str() {
            "server/discover" => (200, discover_result(id), vec![]),
            "tools/call" => (
                404,
                r#"{"error":{"code":"not_found","message":"no such tool"}}"#.to_owned(),
                vec![],
            ),
            other => panic!("unexpected method {other}"),
        }
    }));
    let client = mk_client(Arc::clone(&stub), ClientEra::Auto);

    let err = client
        .call_tool_raw("jack.whoami", None)
        .expect_err("the legacy verdict is surfaced");
    assert!(matches!(err, ClientError::Http(_)), "got {err:?}");

    // The legacy verdict clears the modern decision: the next call probes.
    let _ = client.call_tool_raw("jack.whoami", None);
    assert_eq!(
        methods(&stub),
        [
            "server/discover",
            "tools/call",
            "server/discover",
            "tools/call"
        ]
    );
}

#[test]
fn a_signer_override_skips_the_flow_and_keeps_the_01x_bytes() {
    let stub = StubTransport::new(Box::new(|req, _auth| {
        let id = req.id().unwrap_or(0);
        match req.method().as_str() {
            "tools/call" => (200, call_result(id), vec![]),
            other => panic!("a signer override must not send {other}"),
        }
    }));
    let client = mk_client(Arc::clone(&stub), ClientEra::Auto);
    let override_signer = alice();

    let value = client
        .call_raw(Some(override_signer.as_ref()), None, "jack.enroll", None)
        .expect("the one-off call");
    assert_eq!(value, serde_json::json!({"ok": true}));
    assert_eq!(methods(&stub), ["tools/call"], "no probe and no handshake");

    let seen = stub.seen();
    assert_eq!(seen[0].header("MCP-Protocol-Version"), None);
    assert_eq!(seen[0].header("Mcp-Session-Id"), None);
    assert_eq!(
        seen[0].body,
        format!(
            r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{"name":"jack.enroll","arguments":{{}}}}}}"#,
            seen[0].id().expect("id")
        )
    );
    assert_eq!(cached_era(&client), None, "nothing was probed or cached");
}
#[test]
fn the_default_legacy_era_issues_exactly_one_request() {
    let stub = StubTransport::new(Box::new(|req, _auth| {
        let id = req.id().unwrap_or(0);
        match req.method().as_str() {
            "tools/call" => (200, call_result(id), vec![]),
            other => panic!("the default era must not send {other}"),
        }
    }));
    let client = mk_client(Arc::clone(&stub), ClientEra::Legacy);
    assert_eq!(client.era(), ClientEra::Legacy, "legacy is the default");

    let value = client
        .call_tool_raw("jack.whoami", None)
        .expect("the one-shot call");
    assert_eq!(value, serde_json::json!({"ok": true}));
    assert_eq!(
        methods(&stub),
        ["tools/call"],
        "no probe, no initialize, no notifications/initialized"
    );

    let seen = stub.seen();
    let unsigned: Vec<(String, String)> = seen[0]
        .headers
        .iter()
        .filter(|(name, _)| name != "Jack-Auth")
        .cloned()
        .collect();
    assert_eq!(
        unsigned,
        [("Content-Type".to_owned(), "application/json".to_owned())],
        "the 0.1.x headers: Content-Type only (besides the signature header)"
    );
    assert_eq!(seen[0].id(), Some(1), "the id counter still starts at 1");
    assert_eq!(
        seen[0].body,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.whoami","arguments":{}}}"#,
        "the 0.1.x bytes"
    );
    assert_eq!(cached_era(&client), None, "nothing was probed or cached");

    // A second call is a second single request, still no lifecycle traffic.
    client
        .call_tool_raw("jack.whoami", None)
        .expect("second one-shot call");
    assert_eq!(methods(&stub), ["tools/call", "tools/call"]);
}

#[test]
fn the_modern_era_issues_exactly_one_request() {
    let stub = StubTransport::new(Box::new(|req, _auth| {
        let id = req.id().unwrap_or(0);
        match req.method().as_str() {
            "tools/call" => (200, call_result(id), vec![]),
            other => panic!("the modern era must not send {other}"),
        }
    }));
    let client = mk_client(Arc::clone(&stub), ClientEra::Modern);

    client
        .call_tool_raw("jack.whoami", None)
        .expect("the modern call");
    assert_eq!(methods(&stub), ["tools/call"], "no probe and no handshake");

    let seen = stub.seen();
    assert_eq!(seen[0].header("MCP-Protocol-Version"), Some(MODERN_MIN));
    assert_eq!(seen[0].header("Mcp-Method"), Some("tools/call"));
    assert_eq!(seen[0].header("Mcp-Name"), Some("jack.whoami"));
    assert_eq!(seen[0].id(), Some(1), "the id counter still starts at 1");
    assert_eq!(cached_era(&client), None, "nothing was probed or cached");
}

/// `C9` + `C8`: `reset_era` drops the modern state wholesale, so a cached
/// result and both catalogs of the old era never survive the re-probe.
#[test]
fn reset_era_drops_the_modern_catalogs_and_the_result_cache() {
    let stub = StubTransport::new(Box::new(|req, _auth| {
        let id = req.id().unwrap_or(0);
        match req.method().as_str() {
            "server/discover" => (200, discover_result(id), vec![]),
            "tools/call" => (200, call_result(id), vec![]),
            other => panic!("unexpected method {other}"),
        }
    }));
    let client = mk_client(Arc::clone(&stub), ClientEra::Auto);
    client.call_tool_raw("jack.whoami", None).expect("probe");

    // Fill the state the way a resync plus an opt-in cache lookup would.
    {
        let mut state = lock_modern(&client);
        state.tools = crate::client::modern::ToolCatalog::from_tools_list(&json!({"tools": [{
            "name": "jack.whoami",
            "inputSchema": {"properties": {"region": {"type": "string", "x-mcp-header": "Region"}}},
        }]}));
        state.events =
            crate::client::modern::EventCatalog::from_events_list(&json!({"events": []}));
        state.results.insert(
            crate::client::modern::CacheKey::new(
                "tools/call",
                "{\"name\":\"jack.whoami\"}",
                Era::Modern,
            ),
            json!({"ok": true}),
            1_000,
            FIXED_TS as u64,
        );
    }
    assert_eq!(lock_modern(&client).results.len(), 1);
    assert_eq!(lock_modern(&client).tools.entries().len(), 1);

    client.reset_era();

    let state = lock_modern(&client);
    assert!(
        state.results.is_empty(),
        "a cached result belongs to the era that produced it"
    );
    assert_eq!(
        state.tools,
        crate::client::modern::ToolCatalog::default(),
        "the tool catalog belongs to the era that produced it"
    );
    assert_eq!(
        state.events,
        crate::client::modern::EventCatalog::default(),
        "the event catalog belongs to the era that produced it"
    );
}
