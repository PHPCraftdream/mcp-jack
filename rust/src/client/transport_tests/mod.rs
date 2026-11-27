use super::*;
use crate::auth_header::{format_response_auth, parse_request_auth, RequestAuth, ResponseAuth};
use crate::encoding::{encode_b64url, key_id};
use crate::signing::response_signing_string;
use crate::user_key::ServerSigningKey;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

// keys.json seeds, the conformance fixture is the oracle.
const ALICE_SEED_HEX: &str = "15949421ee8241acde219c4cff93cc346a0488e049deff61da312798b758d28f";
const SVC_SEED_HEX: &str = "cc9e39e830a43e09c6372b14852ef80a2bb8e7b1aa4c04bf076f33e0aad2c901";
const ROOT_SEED_HEX: &str = "b25e7cd6e4b7528df098bd668a1c765f37f8c28f407d13f18dbb84aea6dcaff1";

const AUD: &str = "https://svc.example.test";
const FIXED_TS: i64 = 1767225600;

fn hex_bytes(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        out[i] =
            u8::from_str_radix(std::str::from_utf8(pair).expect("valid"), 16).expect("hex digit");
    }
    out
}

fn signer_from_hex(seed_hex: &str) -> Arc<dyn Signer> {
    Arc::new(
        crate::client::signer::InMemorySigner::from_seed(&hex_bytes(seed_hex))
            .expect("32-byte seed"),
    )
}

/// Test-only request handler closure type.
type Handler = Box<dyn Fn(&HttpRequest) -> Result<HttpResponse, TransportError> + Send + Sync>;

struct FakeTransport {
    handler: Handler,
}

impl Transport for FakeTransport {
    fn round_trip(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        (self.handler)(&req)
    }
}

/// A SigningTransport over a fake with the fixed test clock and nonce.
fn server(signer: Arc<dyn Signer>, server_key: [u8; 32]) -> SigningTransport<FakeTransport> {
    let now: Clock = Arc::new(|| FIXED_TS);
    let nonce: NonceSource = Arc::new(|| Ok(vec![7u8; 16]));
    SigningTransport {
        transport: FakeTransport {
            handler: Box::new(|_| panic!("handler must be installed by the test")),
        },
        aud: AUD.to_string(),
        signer,
        server_key,
        now,
        nonce,
        window_seconds: 30,
    }
}

fn with_handler(
    mut t: SigningTransport<FakeTransport>,
    handler: Handler,
) -> SigningTransport<FakeTransport> {
    t.transport = FakeTransport { handler };
    t
}

/// Builds a response signed by `server` over the request signature's
/// exact bytes (the request sig binds the response signing string).
fn signed_response(
    server: &ServerSigningKey,
    request_sig_b64: &str,
    status: u16,
    body: &[u8],
    ts: i64,
) -> HttpResponse {
    let kid = key_id(server.verifying_key().as_bytes());
    let msg = response_signing_string(status as i64, request_sig_b64, &kid, ts, body);
    let sig = server.sign(msg.as_bytes());
    let header = format_response_auth(&ResponseAuth {
        kid,
        ts,
        sig: encode_b64url(&sig),
    });
    HttpResponse {
        status,
        headers: vec![
            ("Jack-Auth".to_string(), header),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body: body.to_vec(),
    }
}

fn svc_signing_key() -> ServerSigningKey {
    ServerSigningKey::from_bytes(&hex_bytes(SVC_SEED_HEX))
}

#[test]
fn round_trip_signs_and_verifies() {
    let alice = signer_from_hex(ALICE_SEED_HEX);
    let svc = svc_signing_key();
    let captured: Arc<Mutex<Option<RequestAuth>>> = Arc::new(Mutex::new(None));
    let captured_clone = Arc::clone(&captured);

    let t = server(Arc::clone(&alice), *svc.verifying_key().as_bytes());
    let t = with_handler(
        t,
        Box::new(move |req| {
            let raw = req.header("Jack-Auth").expect("signed request header");
            let auth = parse_request_auth(&[raw]).expect("canonical request header");
            let resp = signed_response(&svc, &auth.sig, 200, br#"{"pong":2}"#, FIXED_TS);
            *captured_clone.lock().expect("mutex") = Some(auth);
            Ok(resp)
        }),
    );

    let req = HttpRequest {
        method: "POST".to_string(),
        url: AUD.to_string(),
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: br#"{"ping":1}"#.to_vec(),
    };
    let resp = t.round_trip(req).expect("signed round trip must verify");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, br#"{"pong":2}"#.to_vec());

    let auth = captured.lock().expect("mutex").clone().expect("captured");
    assert_eq!(auth.kid, alice.kid());
    assert_eq!(auth.kid, key_id(&alice.public_key()));
    assert_eq!(auth.ts, FIXED_TS);
    assert_eq!(auth.nonce, encode_b64url(&[7u8; 16]));
}

#[test]
fn unsigned_401_maps_to_unauthenticated() {
    let alice = signer_from_hex(ALICE_SEED_HEX);
    let svc = svc_signing_key();
    let t = server(alice, *svc.verifying_key().as_bytes());
    let t = with_handler(
        t,
        Box::new(|_| {
            Ok(HttpResponse {
                status: 401,
                headers: vec![],
                body: br#"{"error":{"code":"unknown_key","message":"nope"}}"#.to_vec(),
            })
        }),
    );
    let req = HttpRequest {
        method: "POST".to_string(),
        url: AUD.to_string(),
        headers: vec![],
        body: Vec::new(),
    };
    let err = t.round_trip(req).expect_err("401 without auth");
    match err {
        TransportError::Unauthenticated(u) => {
            // Only the status is trusted: the unsigned body is never
            // parsed (spec 01 section 5).
            assert_eq!(u.status, 401);
        }
        other => panic!("expected Unauthenticated, got {other:?}"),
    }
}

#[test]
fn unsigned_non_401_is_protocol_with_status_zero() {
    let alice = signer_from_hex(ALICE_SEED_HEX);
    let svc = svc_signing_key();
    for status in [200u16, 403, 500] {
        let t = server(alice.clone(), *svc.verifying_key().as_bytes());
        let t = with_handler(
            t,
            Box::new(move |_| {
                Ok(HttpResponse {
                    status,
                    headers: vec![],
                    body: b"{}".to_vec(),
                })
            }),
        );
        let req = HttpRequest {
            method: "POST".to_string(),
            url: AUD.to_string(),
            headers: vec![],
            body: Vec::new(),
        };
        let err = t.round_trip(req).expect_err("unsigned answer");
        match err {
            TransportError::Protocol(j) => {
                assert_eq!(j.code, crate::error::codes::MISSING_AUTH);
                // Spec 01 section 5: client-side failures carry no HTTP
                // status. Go keeps the parser's 401 (reported divergence).
                assert_eq!(j.http_status, 0);
            }
            other => panic!("expected Protocol, got {other:?}"),
        }
    }
}

#[test]
fn tampered_body_is_bad_signature() {
    let alice = signer_from_hex(ALICE_SEED_HEX);
    let svc = svc_signing_key();
    let t = server(alice, *svc.verifying_key().as_bytes());
    let t = with_handler(
        t,
        Box::new(move |req| {
            let raw = req.header("Jack-Auth").expect("signed request header");
            let auth = parse_request_auth(&[raw]).expect("canonical request header");
            // Sign body_a, deliver body_b (same length, one flipped byte):
            // the signature no longer matches the sent bytes.
            let body_a = br#"{"ok":true}"#.to_vec();
            let mut body_b = body_a.clone();
            let len = body_b.len();
            body_b[len - 2] = b'X';
            let kid = key_id(svc.verifying_key().as_bytes());
            let msg = response_signing_string(200, &auth.sig, &kid, FIXED_TS, &body_a);
            let sig = svc.sign(msg.as_bytes());
            let header = format_response_auth(&ResponseAuth {
                kid,
                ts: FIXED_TS,
                sig: encode_b64url(&sig),
            });
            Ok(HttpResponse {
                status: 200,
                headers: vec![
                    ("Jack-Auth".to_string(), header),
                    ("Content-Type".to_string(), "application/json".to_string()),
                ],
                body: body_b,
            })
        }),
    );
    let req = HttpRequest {
        method: "POST".to_string(),
        url: AUD.to_string(),
        headers: vec![],
        body: Vec::new(),
    };
    let err = t.round_trip(req).expect_err("tampered body");
    match err {
        TransportError::Protocol(j) => assert_eq!(j.code, crate::error::codes::BAD_SIGNATURE),
        other => panic!("expected Protocol, got {other:?}"),
    }
}

#[test]
fn unpinned_server_key_rejected() {
    let alice = signer_from_hex(ALICE_SEED_HEX);
    let svc = svc_signing_key();
    let root = ServerSigningKey::from_bytes(&hex_bytes(ROOT_SEED_HEX));
    // Pinned to ROOT, signed by SVC.
    let t = server(alice, *root.verifying_key().as_bytes());
    let t = with_handler(
        t,
        Box::new(move |req| {
            let raw = req.header("Jack-Auth").expect("signed request header");
            let auth = parse_request_auth(&[raw]).expect("canonical request header");
            Ok(signed_response(&svc, &auth.sig, 200, b"{}", FIXED_TS))
        }),
    );
    let req = HttpRequest {
        method: "POST".to_string(),
        url: AUD.to_string(),
        headers: vec![],
        body: Vec::new(),
    };
    let err = t.round_trip(req).expect_err("unpinned signer key");
    match err {
        TransportError::Protocol(j) => {
            assert_eq!(j.code, crate::error::codes::UNKNOWN_SERVER_KEY)
        }
        other => panic!("expected Protocol, got {other:?}"),
    }
}

#[test]
fn stale_timestamp_rejected() {
    let alice = signer_from_hex(ALICE_SEED_HEX);
    let svc = svc_signing_key();
    let mut t = server(alice, *svc.verifying_key().as_bytes());
    // Transport clock one hour past the response's ts.
    t.now = Arc::new(|| FIXED_TS + 3600);
    let t = with_handler(
        t,
        Box::new(move |req| {
            let raw = req.header("Jack-Auth").expect("signed request header");
            let auth = parse_request_auth(&[raw]).expect("canonical request header");
            Ok(signed_response(&svc, &auth.sig, 200, b"{}", FIXED_TS))
        }),
    );
    let req = HttpRequest {
        method: "POST".to_string(),
        url: AUD.to_string(),
        headers: vec![],
        body: Vec::new(),
    };
    let err = t.round_trip(req).expect_err("stale response ts");
    match err {
        TransportError::Protocol(j) => {
            assert_eq!(j.code, crate::error::codes::TIMESTAMP_OUT_OF_WINDOW)
        }
        other => panic!("expected Protocol, got {other:?}"),
    }
}

#[test]
fn streaming_refused() {
    let alice = signer_from_hex(ALICE_SEED_HEX);
    let svc = svc_signing_key();
    // content types (the third has a MALFORMED parameter list — Go's mime
    // parser would error and not refuse; this port refuses on the type
    // alone, a deliberate safer divergence).
    for ct in [
        "text/event-stream",
        "text/event-stream; charset=utf-8",
        "TEXT/EVENT-STREAM ; x",
    ] {
        let t = server(Arc::clone(&alice), *svc.verifying_key().as_bytes());
        let content_type = ct.to_string();
        let t = with_handler(
            t,
            Box::new(move |_| {
                Ok(HttpResponse {
                    status: 200,
                    headers: vec![("Content-Type".to_string(), content_type.clone())],
                    body: b"event: x".to_vec(),
                })
            }),
        );
        let req = HttpRequest {
            method: "POST".to_string(),
            url: AUD.to_string(),
            headers: vec![],
            body: Vec::new(),
        };
        assert_eq!(
            t.round_trip(req).expect_err("streaming must be refused"),
            TransportError::Streaming,
            "content type {ct}"
        );
    }

    // The guard does not fire for a non-streaming content type: an
    // unsigned application/json 200 is a Protocol rejection instead.
    let t = server(alice, *svc.verifying_key().as_bytes());
    let t = with_handler(
        t,
        Box::new(|_| {
            Ok(HttpResponse {
                status: 200,
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: b"{}".to_vec(),
            })
        }),
    );
    let req = HttpRequest {
        method: "POST".to_string(),
        url: AUD.to_string(),
        headers: vec![],
        body: Vec::new(),
    };
    match t.round_trip(req).expect_err("unsigned 200") {
        TransportError::Protocol(j) => {
            assert_eq!(j.code, crate::error::codes::MISSING_AUTH)
        }
        other => panic!("expected Protocol, got {other:?}"),
    }
}

/// A clock that advances one hour per call: sample 1 returns FIXED_TS
/// (request ts), sample 2 returns FIXED_TS + 3600 (verification time).
fn advancing_clock() -> Clock {
    let step = Arc::new(AtomicI64::new(0));
    Arc::new(move || FIXED_TS + 3600 * step.fetch_add(1, Ordering::Relaxed))
}

#[test]
fn fresh_response_accepted_after_clock_advance() {
    // Request ts = sample 1 (FIXED_TS); the fake signs its response at the
    // verification-time value (FIXED_TS + 3600). Verification must accept
    // ONLY because the clock is re-sampled after the round trip.
    let alice = signer_from_hex(ALICE_SEED_HEX);
    let svc = svc_signing_key();
    let mut t = server(alice, *svc.verifying_key().as_bytes());
    t.now = advancing_clock();
    let t = with_handler(
        t,
        Box::new(move |req| {
            let raw = req.header("Jack-Auth").expect("signed request header");
            let auth = parse_request_auth(&[raw]).expect("canonical request header");
            Ok(signed_response(
                &svc,
                &auth.sig,
                200,
                b"{}",
                FIXED_TS + 3600,
            ))
        }),
    );
    let req = HttpRequest {
        method: "POST".to_string(),
        url: AUD.to_string(),
        headers: vec![],
        body: Vec::new(),
    };
    t.round_trip(req)
        .expect("a response signed at the fresh sample must verify");
}

#[test]
fn stale_response_rejected_after_clock_advance() {
    // Same advancing clock, but the fake signs at T0: against the fresh
    // verification sample (+3600) the response is out of window.
    let alice = signer_from_hex(ALICE_SEED_HEX);
    let svc = svc_signing_key();
    let mut t = server(alice, *svc.verifying_key().as_bytes());
    t.now = advancing_clock();
    let t = with_handler(
        t,
        Box::new(move |req| {
            let raw = req.header("Jack-Auth").expect("signed request header");
            let auth = parse_request_auth(&[raw]).expect("canonical request header");
            Ok(signed_response(&svc, &auth.sig, 200, b"{}", FIXED_TS))
        }),
    );
    let req = HttpRequest {
        method: "POST".to_string(),
        url: AUD.to_string(),
        headers: vec![],
        body: Vec::new(),
    };
    match t
        .round_trip(req)
        .expect_err("stale response must be rejected")
    {
        TransportError::Protocol(j) => {
            assert_eq!(j.code, crate::error::codes::TIMESTAMP_OUT_OF_WINDOW)
        }
        other => panic!("expected Protocol(timestamp_out_of_window), got {other:?}"),
    }
}

#[test]
fn replaces_existing_auth_header_case_insensitively() {
    // Spec 01 section 3: exactly one Jack-Auth header. A caller-provided
    // header (any case) must be replaced, not appended (Go: Header.Set).
    let alice = signer_from_hex(ALICE_SEED_HEX);
    let svc = svc_signing_key();
    let captured: Arc<Mutex<Option<Vec<String>>>> = Arc::new(Mutex::new(None));
    let captured_clone = Arc::clone(&captured);
    let t = server(alice, *svc.verifying_key().as_bytes());
    let t = with_handler(
        t,
        Box::new(move |req| {
            *captured_clone.lock().expect("mutex") = Some(
                req.header_values("Jack-Auth")
                    .into_iter()
                    .map(String::from)
                    .collect(),
            );
            let raw = req.header("Jack-Auth").expect("signed request header");
            let auth = parse_request_auth(&[raw]).expect("canonical request header");
            Ok(signed_response(&svc, &auth.sig, 200, b"{}", FIXED_TS))
        }),
    );
    let req = HttpRequest {
        method: "POST".to_string(),
        url: AUD.to_string(),
        headers: vec![("jack-auth".to_string(), "v1 stale".to_string())],
        body: Vec::new(),
    };
    t.round_trip(req).expect("round trip must succeed");
    let values = captured.lock().expect("mutex").clone().expect("captured");
    assert_eq!(values.len(), 1, "exactly one Jack-Auth header must be sent");
    assert_ne!(values[0], "v1 stale", "the stale header must be replaced");
    parse_request_auth(&[values[0].as_str()])
        .expect("the sent header must be the freshly signed one");
}

#[test]
fn oversized_body_rejected() {
    let alice = signer_from_hex(ALICE_SEED_HEX);
    let svc = svc_signing_key();
    let t = server(alice, *svc.verifying_key().as_bytes());
    let t = with_handler(
        t,
        Box::new(|_| {
            Ok(HttpResponse {
                status: 200,
                headers: vec![],
                body: vec![0u8; MAX_BODY_BYTES + 1],
            })
        }),
    );
    let req = HttpRequest {
        method: "POST".to_string(),
        url: AUD.to_string(),
        headers: vec![],
        body: Vec::new(),
    };
    assert_eq!(MAX_BODY_BYTES, 1048576);
    let err = t.round_trip(req).expect_err("oversized body");
    assert_eq!(
        err.to_string(),
        "jack client: response body exceeds 1048576 bytes"
    );
}

#[test]
fn inner_error_passthrough() {
    let alice = signer_from_hex(ALICE_SEED_HEX);
    let svc = svc_signing_key();
    let t = server(alice, *svc.verifying_key().as_bytes());
    let t = with_handler(
        t,
        Box::new(|_| Err(TransportError::Transport("jack client: boom".to_string()))),
    );
    let req = HttpRequest {
        method: "POST".to_string(),
        url: AUD.to_string(),
        headers: vec![],
        body: Vec::new(),
    };
    assert_eq!(
        t.round_trip(req)
            .expect_err("inner error must pass through"),
        TransportError::Transport("jack client: boom".to_string())
    );
}

#[test]
fn header_helpers() {
    let req = HttpRequest {
        method: "POST".to_string(),
        url: "https://h".to_string(),
        headers: vec![
            ("content-type".to_string(), "a".to_string()),
            ("X-Thing".to_string(), "1".to_string()),
            ("x-thing".to_string(), "2".to_string()),
        ],
        body: Vec::new(),
    };
    assert_eq!(req.header("X-THING"), Some("1"));
    assert_eq!(req.header("content-TYPE"), Some("a"));
    assert_eq!(req.header("missing"), None);

    let resp = HttpResponse {
        status: 200,
        headers: vec![
            ("JACK-AUTH".to_string(), "first".to_string()),
            ("jack-auth".to_string(), "second".to_string()),
            ("Other".to_string(), "x".to_string()),
        ],
        body: Vec::new(),
    };
    assert_eq!(resp.header("jack-auth"), Some("first"));
    assert_eq!(resp.header_values("Jack-Auth"), vec!["first", "second"]);
    assert!(resp.header_values("Missing").is_empty());
}
