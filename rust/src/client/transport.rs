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
use crate::client::stream::VerifiedStream;
use crate::client::url::request_target;
use crate::error::JackError;

/// The exact redirect statuses `SigningTransport` refuses. 300 (Multiple
/// Choices) and 304 (Not Modified) are not redirects to follow and go through
/// the normal guard and verification.
const REDIRECT_STATUSES: [u16; 5] = [301, 302, 303, 307, 308];

pub(crate) fn is_redirect_status(status: u16) -> bool {
    REDIRECT_STATUSES.contains(&status)
}

/// The local no-follow refusal of a redirect status (Go: ErrRedirect).
fn redirect_refusal(status: u16) -> TransportError {
    TransportError::Client(format!(
        "jack client: redirect (status {status}) refused: the client never follows redirects (301, 302, 303, 307, 308)"
    ))
}

/// Replaces every header named `name` (case-insensitively) with exactly one `value`.
fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
    headers.push((name.to_string(), value.to_string()));
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
/// | Any comma-separated member of the Content-Type lines has media type `text/event-stream` (case-insensitive, up to the first `;`) | `Streaming` — refused before verification |
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

    /// The first half of every signed call: URL policy, timestamp, nonce, target, signature and
    /// the single `Jack-Auth` header (spec 01 section 3); shared with `open_stream_as`.
    fn sign_wire_request(
        &self,
        signer: &dyn Signer,
        pinned_ts: Option<i64>,
        req: HttpRequest,
    ) -> Result<(HttpRequest, crate::client::auth::SignedRequest), TransportError> {
        // Client URL policy FIRST: a refused URL produces no nonce, signature or transport call.
        crate::client::url::validate_base_url(&req.url)
            .map_err(|e| TransportError::Client(e.to_string()))?;

        let ts = pinned_ts.unwrap_or_else(|| (self.now)());
        // The pin binds the REQUEST ts only (spec 03 section 3.1); freshness is sampled later.
        let nonce = (self.nonce)()
            .map_err(|e| TransportError::Client(format!("jack client: nonce: {e}")))?;

        // The origin-form target exactly as it is sent on the wire.
        let target = request_target(&req.url).map_err(|e| TransportError::Client(e.to_string()))?;

        let result = sign_request(
            signer,
            &self.aud,
            &req.method,
            &target,
            &req.body,
            &nonce,
            ts,
        );
        let signed = result.map_err(|e| TransportError::Client(e.to_string()))?;

        let mut wire_req = req;
        // Spec 01 section 3: exactly one Jack-Auth header (Go: Header.Set).
        set_header(&mut wire_req.headers, "Jack-Auth", &signed.header_value);
        Ok((wire_req, signed))
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
        let (wire_req, signed) = self.sign_wire_request(signer, pinned_ts, req)?;
        // The inner transport already returns TransportError and its value may
        // itself be Streaming/Protocol/etc: pass it through unchanged.
        let resp = self.transport.round_trip(wire_req)?;

        // Redirects are never followed and never verified against the old
        // target: a 301/302/303/307/308 answer is refused locally (the
        // Location is ignored). No-follow guard only, not TLS enforcement.
        // 300 and 304 are not in the set and are verified like any status.
        if is_redirect_status(resp.status) {
            return Err(redirect_refusal(resp.status));
        }

        // Streaming guard BEFORE verification: a stream cannot be verified
        // (spec 01 section 5, open question Q1).
        if is_event_stream(resp.header_values("Content-Type")) {
            return Err(TransportError::Streaming);
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

impl<T: Transport + crate::client::stream::StreamSource> SigningTransport<T> {
    /// Sends the request with `Jack-Accept: s1` (spec 05 section 1.1) and returns the verified
    /// stream (section 4). Rotation-aware callers use `VerifiedStream::from_response` directly.
    pub fn open_stream(&self, req: HttpRequest) -> Result<VerifiedStream, TransportError> {
        self.open_stream_as(self.signer.as_ref(), req)
    }

    /// Same with an explicit signer (the enroll/rotate idiom of `round_trip_as`).
    /// Rotation-aware callers use `VerifiedStream::from_response` directly with their own key map.
    pub fn open_stream_as(
        &self,
        signer: &dyn Signer,
        req: HttpRequest,
    ) -> Result<VerifiedStream, TransportError> {
        let (mut wire_req, signed) = self.sign_wire_request(signer, None, req)?;
        // 1.1: the SDK owns the opt-in header on this call; every caller value is replaced.
        set_header(&mut wire_req.headers, "Jack-Accept", "s1");
        let response = self.transport.open_stream(wire_req)?;

        // The same no-follow guard as `round_trip_as` (spec 05 section 1.4).
        if is_redirect_status(response.status) {
            return Err(redirect_refusal(response.status));
        }

        // The pinned server key is the only trusted stream key; the transport clock is reused.
        let mut config = crate::stream::StreamVerifierConfig::pinned(
            crate::encoding::key_id(&self.server_key),
            self.server_key,
            signed.auth.sig,
        );
        config.window_seconds = self.window_seconds;
        config.now = self.now.clone();
        VerifiedStream::from_response(response, config)
    }
}

impl<T: Transport> Transport for SigningTransport<T> {
    fn round_trip(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        self.round_trip_as(self.signer.as_ref(), None, req)
    }
}

/// Reports whether the Content-Type field lines declare a stream. The lines
/// are joined with commas (the combined form a fetch client also sees) and any
/// comma-separated member whose media type is text/event-stream refuses the
/// response: the media type is the text before the first ';' with SP and HTAB
/// trimmed, compared ASCII case-insensitively. A stream cannot be verified
/// (spec 01 section 5, open question Q1) whatever its parameter list or a
/// malformed combined value looks like.
pub(crate) fn is_event_stream<'a>(values: impl IntoIterator<Item = &'a str>) -> bool {
    values
        .into_iter()
        .flat_map(|value| value.split(','))
        .any(|member| {
            let base = member.split(';').next().unwrap_or("");
            base.trim_matches(|c| c == ' ' || c == '\t')
                .eq_ignore_ascii_case("text/event-stream")
        })
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
#[path = "transport_tests/mod.rs"]
mod tests;
