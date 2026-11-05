//! Shared test harness porting Go client/harness_test.go: the httptest server
//! becomes a fake Transport that verifies incoming requests with the shared
//! primitives and signs its responses with its own key. Tests install
//! per-test handlers after construction (Go: s.Handle).

// Shared harness; not every helper is used by every test file (mirrors Go
// harness_test.go).
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer as DalekSigner, SigningKey};

use super::fixtures::load_keys;
use mcp_jack::auth_header::{format_response_auth, parse_request_auth};
use mcp_jack::auth_header::{RequestAuth, ResponseAuth};
use mcp_jack::client::error::ClientError;
use mcp_jack::client::signer::{InMemorySigner, Signer};
use mcp_jack::client::transport::{
    Clock, HttpRequest, HttpResponse, NonceSource, Transport, TransportError,
};
use mcp_jack::client::url::request_target;
use mcp_jack::encoding::{decode_b64url, decode_b64url_fixed, encode_b64url, key_id};
use mcp_jack::signing::{request_signing_string, response_signing_string};

/// The fixture clock (Go: fixtureNow; every request/response fixture case pins it).
pub const FIXTURE_NOW: i64 = 1767225600;
/// The fixture audience (Go: fixtureAud).
pub const FIXTURE_AUD: &str = "https://svc.example.test";
/// The fixed base URL the fakes accept; only its /mcp target is observable.
pub const TEST_URL: &str = "https://test.local/mcp";

/// The fake server's signing seed (hex). Go used ed25519.GenerateKey (OS
/// randomness); this port pins a fixed seed so tests are deterministic. The
/// value is deliberately NOT any keys.json seed, so the server key differs
/// from every client key.
const TEST_SERVER_SEED_HEX: &str =
    "3f0a1c5e9d2b7a84f6c3e15d09a8b4726c5f0e8a3d1b9c742a6e8f05d3c7b914";

/// A second fixed seed used by tests that need an unrelated key (Go:
/// TestTransportRejectsUnpinnedServerKey's ed25519.GenerateKey call).
const UNRELATED_SEED_HEX: &str = "7c1e9a4f2d8b5c06e3a7f1d84c9b2e5a0f6d3c817b4e2a9f5c0d8e3a6f1b4c72";

/// Chunked 2-char hex decode (mirrors the inline hex_bytes of the src tests).
pub fn hex_bytes(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .enumerate()
        .map(|(i, pair)| {
            u8::from_str_radix(
                std::str::from_utf8(pair).unwrap_or_else(|e| panic!("hex pair {i}: {e}")),
                16,
            )
            .unwrap_or_else(|e| panic!("hex pair {i}: {e}"))
        })
        .collect()
}

fn signing_key(seed_hex: &str) -> SigningKey {
    let seed: [u8; 32] = hex_bytes(seed_hex)
        .try_into()
        .unwrap_or_else(|_| panic!("seed hex {seed_hex} must be 32 bytes"));
    SigningKey::from_bytes(&seed)
}

/// InMemorySigner from a seed hex string (Go: seedSignerFromTestKey).
pub fn seed_signer(seed_hex: &str) -> InMemorySigner {
    InMemorySigner::from_seed(&hex_bytes(seed_hex))
        .unwrap_or_else(|e| panic!("seed {seed_hex}: from_seed: {e}"))
}

/// keys.json signer by name (Go: seedSignerByName); panics with a clear
/// message if absent.
pub fn signer_by_name(name: &str) -> InMemorySigner {
    let keys = load_keys_map();
    keys.get(name)
        .unwrap_or_else(|| panic!("keys.json has no key named {name:?}"))
        .clone()
}

/// keys.json signer by kid (Go: seedSignerByKid).
pub fn signer_by_kid(kid: &str) -> InMemorySigner {
    let keys = load_keys_map();
    keys.values()
        .find(|s| s.kid() == kid)
        .unwrap_or_else(|| panic!("keys.json has no key with kid {kid:?}"))
        .clone()
}

/// name -> signer map built once per call from keys.json (small fixture, so
/// re-reading keeps the helpers stateless).
fn load_keys_map() -> HashMap<String, InMemorySigner> {
    let kf = load_keys().expect("load keys.json");
    kf.keys
        .into_iter()
        .map(|k| (k.name.clone(), seed_signer(&k.seed_hex)))
        .collect()
}

/// kid -> 32-byte public key map built from the fixture keys (Go: fixtureKeys).
pub fn fixture_keys() -> HashMap<String, [u8; 32]> {
    let kf = load_keys().expect("load keys.json");
    kf.keys
        .into_iter()
        .map(|k| {
            let s = seed_signer(&k.seed_hex);
            (s.kid().to_string(), s.public_key())
        })
        .collect()
}

/// Clock fixed at `ts` Unix seconds (Go: fixedClock).
pub fn fixed_clock(ts: i64) -> Clock {
    Arc::new(move || ts)
}

/// Nonce source yielding the given base64url nonces in order; exhausted or
/// bad input -> Err (Go: queuedNonce + nonceQueueError).
pub fn queued_nonce(nonces_b64u: &[&str]) -> NonceSource {
    let queue: Vec<String> = nonces_b64u.iter().map(|n| (*n).to_string()).collect();
    let cursor = Arc::new(Mutex::new(0usize));
    Arc::new(move || {
        let mut i = cursor.lock().expect("nonce queue mutex");
        let n = queue
            .get(*i)
            .ok_or_else(|| ClientError::Client("jack client: nonce queue exhausted".to_string()))?;
        *i += 1;
        decode_b64url_fixed(n, 16)
            .map_err(|e| ClientError::Client(format!("jack client: bad nonce {n:?}: {e:?}")))
    })
}

/// Wraps a JSON-RPC 2.0 / MCP CallToolResult body around `structured`
/// (Go: rpcResultBody), byte-identical template.
pub fn rpc_result_body(structured: &serde_json::Value) -> Vec<u8> {
    let s = serde_json::to_string(structured).expect("structured serializes");
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":\"ok\"}}],\"isError\":false,\"structuredContent\":{s}}}}}"
    )
    .into_bytes()
}

/// Per-test response logic (Go: s.Handle). The fake passes the observed
/// request method and origin-form target so tests can assert on the real
/// bytes instead of restating them.
pub type Handler =
    Box<dyn Fn(&TestServer, &str, &str, &RequestAuth, &[u8]) -> HttpResponse + Send + Sync>;

/// The fake server: verifies requests per spec 01 section 4 and signs
/// responses with its own key (Go: testServer).
pub struct TestServer {
    key: SigningKey,
    /// 32-byte server public key (Go: s.Pub).
    pub pub_key: [u8; 32],
    /// key_id(&pub_key) (Go: s.Kid).
    pub kid: String,
    /// Client kid -> public key accepted for verification (Go: s.Keys).
    pub client_keys: HashMap<String, [u8; 32]>,
    /// Audience used in request signing strings (Go: s.Aud).
    pub aud: &'static str,
    /// Response timestamp; tests may adjust (Go: s.Now).
    pub now: i64,
    handle: Mutex<Option<Handler>>,
}

impl TestServer {
    /// Fresh server with a fixed-seed key (Go: ed25519.GenerateKey(nil);
    /// deterministic here — see TEST_SERVER_SEED_HEX).
    pub fn new() -> Arc<Self> {
        let key = signing_key(TEST_SERVER_SEED_HEX);
        let pub_key = *key.verifying_key().as_bytes();
        Arc::new(Self {
            kid: key_id(&pub_key),
            key,
            pub_key,
            client_keys: fixture_keys(),
            aud: FIXTURE_AUD,
            now: FIXTURE_NOW,
            handle: Mutex::new(None),
        })
    }

    /// Installs the per-test handler (Go: s.Handle = ...). Must be set before
    /// requests; requests before this serve the 500 "no handler" body.
    pub fn set_handler(&self, h: Handler) {
        *self.handle.lock().expect("server mutex") = Some(h);
    }

    /// Signs status+request-sig+kid+ts+body per spec 01 section 5 with the
    /// server key and returns the response with Jack-Auth + Content-Type
    /// application/json headers (Go: writeSignedJSON). ts = self.now.
    pub fn write_signed_json(&self, auth: &RequestAuth, status: u16, body: &[u8]) -> HttpResponse {
        let header = self.sign_response(&auth.sig, status, body);
        HttpResponse {
            status,
            headers: vec![
                ("Jack-Auth".to_string(), header),
                ("Content-Type".to_string(), "application/json".to_string()),
            ],
            body: body.to_vec(),
        }
    }

    /// Builds only the signed Jack-Auth response header value for
    /// `request_sig`/`status`/`body` (Go's writeSignedJSON signing step),
    /// letting tests send a DIFFERENT body than the signed one (tamper case).
    pub fn sign_response(&self, request_sig_b64: &str, status: u16, body: &[u8]) -> String {
        let msg =
            response_signing_string(status as i64, request_sig_b64, &self.kid, self.now, body);
        let sig = self.key.sign(msg.as_bytes());
        format_response_auth(&ResponseAuth {
            kid: self.kid.clone(),
            ts: self.now,
            sig: encode_b64url(&sig.to_bytes()),
        })
    }

    /// Writes status+body without a Jack-Auth header (Go: writeUnsignedJSON).
    pub fn write_unsigned_json(&self, status: u16, body: &[u8]) -> HttpResponse {
        HttpResponse {
            status,
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: body.to_vec(),
        }
    }
}

impl Transport for TestServer {
    fn round_trip(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        // Mirrors Go newTestServer's handler: verify per spec 01 section 4;
        // on any verification failure serve the unsigned 401 body.
        let unsigned_401 = || {
            Ok(self.write_unsigned_json(
                401,
                br#"{"error":{"code":"unknown_key","message":"verification failed"}}"#,
            ))
        };
        let values = req.header_values("Jack-Auth");
        if values.len() != 1 {
            // Spec 01 section 4 step 2: the header must appear exactly once.
            return unsigned_401();
        }
        let Ok(auth) = parse_request_auth(&values) else {
            return unsigned_401();
        };
        let Some(client_pub) = self.client_keys.get(&auth.kid) else {
            return unsigned_401();
        };
        let Ok(target) = request_target(&req.url) else {
            return unsigned_401();
        };
        let msg = request_signing_string(
            &req.method,
            &target,
            self.aud,
            &auth.kid,
            auth.ts,
            &auth.nonce,
            &req.body,
        );
        let Ok(sig) = decode_b64url_fixed(&auth.sig, 64) else {
            return unsigned_401();
        };
        if !mcp_jack::ed25519::verify(client_pub, msg.as_bytes(), &sig) {
            return unsigned_401();
        }
        // Go: 500 {"error":{"code":"internal","message":"no handler"}} when
        // Handle is nil.
        let guard = self.handle.lock().expect("server mutex");
        let Some(handler) = guard.as_ref() else {
            return Ok(self.write_unsigned_json(
                500,
                br#"{"error":{"code":"internal","message":"no handler"}}"#,
            ));
        };
        Ok(handler(self, &req.method, &target, &auth, &req.body))
    }
}

/// A 32-byte public key from an unrelated fixed seed (Go: the second
/// ed25519.GenerateKey in TestTransportRejectsUnpinnedServerKey).
pub fn fresh_key() -> [u8; 32] {
    *signing_key(UNRELATED_SEED_HEX).verifying_key().as_bytes()
}

/// decode_b64url with a fixture-context message (keeps test files terse).
pub fn decode_body(id: &str, b64: &str) -> Vec<u8> {
    decode_b64url(b64).unwrap_or_else(|e| panic!("{id}: bad body b64u: {e:?}"))
}

/// The runner-side rule of spec/tests/README.md: a string equal to
/// "<b64u43>" in an expectation matches any canonical base64url string of
/// 43 characters (invite codes and ids are random in real servers).
/// Objects must have the same key set; arrays the same length.
pub fn structured_matches(want: &serde_json::Value, got: &serde_json::Value) -> bool {
    match (want, got) {
        (serde_json::Value::String(w), serde_json::Value::String(g)) => {
            // The literal "<b64u43>" must never match itself: the placeholder
            // matches only a CANONICAL base64url string of exactly 43 chars
            // (`<`/`>` are outside the alphabet; re-encoding proves
            // canonicity) — the runner-side rule of spec/tests/README.md.
            if w == "<b64u43>" {
                g.len() == 43
                    && mcp_jack::encoding::decode_b64url(g)
                        .is_ok_and(|raw| &mcp_jack::encoding::encode_b64url(&raw) == g)
            } else {
                w == g
            }
        }
        (serde_json::Value::Array(w), serde_json::Value::Array(g)) => {
            w.len() == g.len() && w.iter().zip(g).all(|(a, b)| structured_matches(a, b))
        }
        (serde_json::Value::Object(w), serde_json::Value::Object(g)) => {
            w.len() == g.len()
                && w.iter()
                    .all(|(k, v)| g.get(k).is_some_and(|gv| structured_matches(v, gv)))
        }
        _ => want == got,
    }
}

/// Asserts the audit expectation of one step: the event on the result and the
/// sink's last record must match (or both be absent).
pub fn check_audit(
    label: &str,
    got: &Option<mcp_jack::server::audit::AuditEvent>,
    want: &Option<super::fixtures::AuditExpect>,
    sink: &mcp_jack::server::audit::MemoryAuditSink,
) {
    match (want, got) {
        (None, Some(a)) => panic!("case {}: unexpected audit event {:?}", label, a),
        (Some(w), None) => panic!("case {}: missing audit event, want {:?}", label, w),
        (Some(w), Some(a)) => {
            let want_code = w.code.clone().unwrap_or_default();
            assert_eq!(a.tool, w.tool, "case {}: audit tool", label);
            assert_eq!(a.outcome, w.outcome, "case {}: audit outcome", label);
            assert_eq!(a.code, want_code, "case {}: audit code", label);
            assert_eq!(a.actor_kid, w.actor_kid, "case {}: audit actor_kid", label);
            // The sink must have recorded exactly this event.
            let events = sink.events();
            let last = events
                .last()
                .unwrap_or_else(|| panic!("case {}: audit sink empty", label));
            assert_eq!(last, a, "case {}: audit sink last event", label);
        }
        (None, None) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_never_matches_literal() {
        let ph = serde_json::json!("<b64u43>");
        // The literal placeholder is not a canonical base64url string.
        assert!(!structured_matches(&ph, &ph));

        let real = encode_b64url(&[0xA5; 32]);
        assert_eq!(real.len(), 43);
        assert!(structured_matches(&ph, &serde_json::json!(real)));
        // 42 characters: too short.
        assert!(!structured_matches(&ph, &serde_json::json!(&real[..42])));
        // Non-canonical trailing bits: encode_b64url([0u8;32]) is 43 'A's;
        // replacing the last char breaks canonicity.
        let mut non_canonical = encode_b64url(&[0u8; 32]);
        non_canonical.replace_range(42..43, "B");
        assert!(!structured_matches(&ph, &serde_json::json!(non_canonical)));

        // Plain equality is untouched for non-placeholder strings.
        assert!(structured_matches(
            &serde_json::json!("alice"),
            &serde_json::json!("alice")
        ));
        assert!(!structured_matches(
            &serde_json::json!("alice"),
            &serde_json::json!("bob")
        ));

        // Nested object: matches a real code, not the literal.
        assert!(structured_matches(
            &serde_json::json!({"code": "<b64u43>"}),
            &serde_json::json!({"code": real})
        ));
        assert!(!structured_matches(
            &serde_json::json!({"code": "<b64u43>"}),
            &serde_json::json!({"code": "<b64u43>"})
        ));
    }
}
