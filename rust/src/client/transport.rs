//! The Transport trait abstracts one HTTP round trip over plain structs; an
//! optional blocking HTTP/HTTPS implementation ships behind the `client-http`
//! feature (see [`crate::client::http_transport`]).
//! SigningTransport wraps any Transport to sign requests and verify responses
//! (spec 01 sections 4 and 5).

use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::client::auth::{random_nonce, sign_request};
use crate::client::error::{ClientError, UnauthenticatedResponseError};
use crate::client::signer::Signer;
use crate::client::url::request_target;
use crate::error::JackError;

/// The exact redirect statuses `SigningTransport` refuses. 300 (Multiple
/// Choices) and 304 (Not Modified) are not redirects to follow and go through
/// the normal guard and verification.
const REDIRECT_STATUSES: [u16; 5] = [301, 302, 303, 307, 308];

fn is_redirect_status(status: u16) -> bool {
    REDIRECT_STATUSES.contains(&status)
}

/// Caps response buffering so a hostile body cannot exhaust memory (Go:
/// maxBodyBytes = 1<<20).
pub const MAX_BODY_BYTES: usize = 1 << 20;

/// Injected signing clock returning Unix seconds (Go: t.Now func() time.Time).
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// Injected per-request nonce source returning the 16 nonce bytes (Go:
/// NonceSource).
pub type NonceSource = Arc<dyn Fn() -> Result<Vec<u8>, ClientError> + Send + Sync>;

/// One outgoing HTTP request as plain data (no HTTP crate in the core
/// library).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    /// The absolute destination URL, already accepted by the client URL policy
    /// (https for any host; http only for a literal `127.x.y.z` or `[::1]`).
    /// The `Transport` MUST connect to exactly this URL: the wire URL must be
    /// the one whose origin-form target was signed. It MUST use TLS with
    /// certificate validation for `https`, MUST NOT rewrite or downgrade the
    /// URL, and MUST NOT follow redirects (301, 302, 303, 307, 308): return
    /// the response as is.
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// One buffered HTTP response as plain data. The body is always fully read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// First value of the named header, case-insensitive (Go: Header.Get).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// All values of the named header, case-insensitive, in order (Go:
    /// Header.Values).
    pub fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

impl HttpResponse {
    /// First value of the named header, case-insensitive (Go: Header.Get).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// All values of the named header, case-insensitive, in order (Go:
    /// Header.Values).
    pub fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

/// Errors of one round trip. The full response-to-outcome mapping:
///
/// | response | outcome |
/// |---|---|
/// | Content-Type media type is `text/event-stream` (case-insensitive, up to the first `;`) | `Streaming` — refused before verification |
/// | body larger than MAX_BODY_BYTES | `Client("...response body exceeds...")` — refused before verification |
/// | the inner transport errors | passed through unchanged |
/// | verification fails with `missing_auth` AND status 401 (unsigned answer) | `Unauthenticated` — HTTP status only; the body is never parsed (spec 01 section 5) |
/// | any other verification failure (unpinned kid, window, signature; missing/malformed header on a non-401) | `Protocol(JackError)` — client-side code, http_status 0 |
/// | verification succeeds | `Ok(HttpResponse)` (a signed non-2xx passes through; rpc.rs parses that VERIFIED body) |
#[derive(Debug, Clone, PartialEq)]
pub enum TransportError {
    /// The server answered with a text/event-stream body: a stream cannot be
    /// read in full and therefore cannot be signature-verified, so it is
    /// refused before verification (Go: ErrStreamingUnsupported; spec 01
    /// section 5, open question Q1).
    Streaming,
    /// The underlying transport failed (connection-level). Never
    /// server-derived.
    Transport(String),
    /// A client-side step failed (nonce, signing, target, body cap).
    Client(String),
    /// A 401 answered WITHOUT a verified Jack-Auth header (Go:
    /// *UnauthenticatedResponseError).
    Unauthenticated(UnauthenticatedResponseError),
    /// The response was signed but verification failed, or the header was
    /// malformed on a non-401 answer (Go: *jack.Error with http_status 0).
    Protocol(JackError),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Streaming => write!(
                f,
                "jack client: streaming responses cannot be verified and are refused (spec 01 section 5, open question Q1)"
            ),
            // The stored strings are complete Go-style messages.
            TransportError::Transport(s) | TransportError::Client(s) => write!(f, "{s}"),
            TransportError::Unauthenticated(e) => write!(f, "{e}"),
            TransportError::Protocol(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TransportError::Protocol(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TransportError> for ClientError {
    // Mirror of Go client.call: transport errors pass through unchanged for
    // errors.Is / errors.As (client/rpc.go).
    fn from(e: TransportError) -> Self {
        match e {
            TransportError::Streaming => ClientError::Streaming,
            TransportError::Transport(s) | TransportError::Client(s) => ClientError::Client(s),
            TransportError::Unauthenticated(u) => ClientError::Unauthenticated(u),
            TransportError::Protocol(j) => ClientError::Protocol(j),
        }
    }
}

/// One raw HTTP round trip (Go: http.RoundTripper). Implementations must
/// fully buffer the response body before returning it; object-safe, Send+Sync.
///
/// Obligations of every implementation (the SDK cannot police arbitrary
/// custom transport behaviour; it only refuses locally what it can see):
///
/// - use TLS with certificate validation for `https` URLs; offer no
///   insecure or skip-verify mode;
/// - connect to exactly the URL in [`HttpRequest::url`]; never rewrite it,
///   downgrade https to http, or resolve it through an alias;
/// - never follow redirects: return the 301/302/303/307/308 response as is.
///   `SigningTransport` refuses exactly those statuses with an error, without
///   following them and without verifying them against the signed target.
///   This is a no-follow guard (a signed request must not be verified against
///   another target), NOT TLS enforcement. Other statuses (300, 304, ...) are
///   verified as usual.
///
/// The client URL policy (see `docs/design/interop.md` section 9) is applied
/// by `SigningTransport` and `Client` before this method is reached; the
/// SDK never calls a transport for a refused URL.
pub trait Transport: Send + Sync {
    fn round_trip(&self, req: HttpRequest) -> Result<HttpResponse, TransportError>;
}

/// Lets an owned trait object (Arc<dyn Transport>, as held by Config) act as
/// the inner transport of SigningTransport.
impl<T: Transport + ?Sized> Transport for Arc<T> {
    fn round_trip(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        (**self).round_trip(req)
    }
}

/// Signs every request and verifies every response before the caller sees the
/// body (Go: client.Transport). Generic over the inner transport; `server_key`
/// is the pinned 32-byte raw server public key (a wrong length is
/// unrepresentable — Go checks it at runtime).
pub struct SigningTransport<T> {
    pub transport: T,
    /// Audience bound into the signing string.
    pub aud: String,
    /// Default signer for outgoing requests.
    pub signer: Arc<dyn Signer>,
    /// Pinned server public key responses are verified against.
    pub server_key: [u8; 32],
    /// Signing clock; defaults to the system clock.
    pub now: Clock,
    /// Per-request nonce source; defaults to OS randomness.
    pub nonce: NonceSource,
    /// Response timestamp tolerance in seconds; <= 0 means the default window.
    pub window_seconds: i64,
}

impl<T: Transport> SigningTransport<T> {
    /// Builds a signing transport with the default clock, nonce source and
    /// window (Go: NewTransport).
    pub fn new(
        transport: T,
        aud: impl Into<String>,
        signer: Arc<dyn Signer>,
        server_key: [u8; 32],
    ) -> Self {
        Self {
            transport,
            aud: aud.into(),
            signer,
            server_key,
            now: system_clock(),
            nonce: random_nonce_source(),
            window_seconds: 0,
        }
    }

    /// Performs one signed, verified round trip with an explicit signer and
    /// an optional pinned timestamp (Go: the per-request context overrides
    /// WithRequestSigner / withFixedNow, used by enroll and rotate flows).
    pub fn round_trip_as(
        &self,
        signer: &dyn Signer,
        pinned_ts: Option<i64>,
        req: HttpRequest,
    ) -> Result<HttpResponse, TransportError> {
        // Client URL policy FIRST: a refused URL produces no nonce, no
        // signature and no inner transport call.
        crate::client::url::validate_base_url(&req.url)
            .map_err(|e| TransportError::Client(e.to_string()))?;

        let ts = pinned_ts.unwrap_or_else(|| (self.now)());
        // The pin applies to the REQUEST ts only (rotate proof binding, spec
        // 03 section 3.1); response freshness is checked against a fresh
        // sample below.

        let nonce = (self.nonce)()
            .map_err(|e| TransportError::Client(format!("jack client: nonce: {e}")))?;

        // The origin-form target exactly as it is sent on the wire.
        let target = request_target(&req.url).map_err(|e| TransportError::Client(e.to_string()))?;

        let signed = sign_request(
            signer,
            &self.aud,
            &req.method,
            &target,
            &req.body,
            &nonce,
            ts,
        )
        .map_err(|e| TransportError::Client(e.to_string()))?;

        let mut wire_req = req;
        // Spec 01 section 3: exactly one Jack-Auth header. Replace any
        // caller-provided header of that name case-insensitively (Go:
        // Header.Set) instead of appending a second one.
        wire_req
            .headers
            .retain(|(n, _)| !n.eq_ignore_ascii_case("Jack-Auth"));
        wire_req
            .headers
            .push(("Jack-Auth".to_string(), signed.header_value.clone()));
        // The inner transport already returns TransportError and its value may
        // itself be Streaming/Protocol/etc: pass it through unchanged.
        let resp = self.transport.round_trip(wire_req)?;

        // Redirects are never followed and never verified against the old
        // target: a 301/302/303/307/308 answer is refused locally (the
        // Location is ignored). No-follow guard only, not TLS enforcement.
        // 300 and 304 are not in the set and are verified like any status.
        if is_redirect_status(resp.status) {
            return Err(TransportError::Client(format!(
                "jack client: redirect (status {}) refused: the client never follows redirects (301, 302, 303, 307, 308)",
                resp.status
            )));
        }

        // Streaming guard BEFORE verification: a stream cannot be verified
        // (spec 01 section 5, open question Q1).
        if let Some(ct) = resp.header("Content-Type") {
            if media_type(ct) == "text/event-stream" {
                return Err(TransportError::Streaming);
            }
        }

        // Body cap BEFORE verification (Go reads with a LimitReader and
        // refuses larger bodies the same way).
        if resp.body.len() > MAX_BODY_BYTES {
            return Err(TransportError::Client(format!(
                "jack client: response body exceeds {MAX_BODY_BYTES} bytes"
            )));
        }

        // Response freshness against a FRESH clock sample taken after the
        // round trip (Go samples now() again for VerifyResponse); a pinned
        // request ts must not freeze this check.
        let now = (self.now)();

        // Go: VerifyResponse (the spec-wins remap of parser 401 -> 0 is
        // inside crate::signing::verify_response).
        let header_values = resp.header_values("Jack-Auth");
        if let Err(err) = crate::signing::verify_response(
            &self.server_key,
            resp.status as i64,
            &header_values,
            &signed.auth.sig,
            &resp.body,
            now,
            self.window_seconds,
        ) {
            // Spec 01 section 5: an unsigned answer is acted on only up to its
            // status — the body is never parsed (Go also surfaces the
            // untrusted body code/message: reported Go/spec divergence).
            if err.code == crate::error::codes::MISSING_AUTH && resp.status == 401 {
                return Err(TransportError::Unauthenticated(
                    UnauthenticatedResponseError {
                        status: resp.status,
                    },
                ));
            }
            return Err(TransportError::Protocol(err));
        }
        Ok(resp)
    }
}

impl<T: Transport> Transport for SigningTransport<T> {
    fn round_trip(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        self.round_trip_as(self.signer.as_ref(), None, req)
    }
}

/// The media type of a Content-Type value: everything up to the first ';',
/// trimmed and lowercased. Deliberate difference from Go: mime.ParseMediaType
/// rejects malformed parameters (e.g. "text/event-stream; charset" without a
/// value) and Go then does NOT refuse the stream; this port refuses whenever
/// the type itself is text/event-stream — a stream cannot be verified (spec 01
/// section 5, open question Q1) regardless of its parameter list.
pub(crate) fn media_type(ct: &str) -> String {
    let base = match ct.find(';') {
        Some(i) => &ct[..i],
        None => ct,
    };
    base.trim().to_ascii_lowercase()
}

/// The default clock: Unix seconds, negative before the epoch (mirroring Go's
/// negative time.Time.Unix).
pub(crate) fn system_clock() -> Clock {
    Arc::new(unix_now)
}

fn unix_now() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

/// The default nonce source: 16 OS-random bytes.
pub(crate) fn random_nonce_source() -> NonceSource {
    Arc::new(|| random_nonce().map(|n| n.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_header::{format_response_auth, parse_request_auth, RequestAuth, ResponseAuth};
    use crate::encoding::{encode_b64url, key_id};
    use crate::signing::response_signing_string;
    use ed25519_dalek::{Signer as DalekSigner, SigningKey};
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
            out[i] = u8::from_str_radix(std::str::from_utf8(pair).expect("valid"), 16)
                .expect("hex digit");
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
        server: &SigningKey,
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
            sig: encode_b64url(&sig.to_bytes()),
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

    fn svc_signing_key() -> SigningKey {
        SigningKey::from_bytes(&hex_bytes(SVC_SEED_HEX))
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
                    sig: encode_b64url(&sig.to_bytes()),
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
        let root = SigningKey::from_bytes(&hex_bytes(ROOT_SEED_HEX));
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
}
