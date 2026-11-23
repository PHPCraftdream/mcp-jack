//! Unit tests of the Server Card key source (spec 06 R7.1-R7.6).
//!
//! `source` drives the operational [`CardSource`] through a scripted
//! [`CardTransport`]: the wire is a queue of canned responses and `now` is an
//! argument, so no test opens a socket or reads a clock. `keys` pins the R7.3
//! rejection of a JWK the card still publishes and the R7.6 cross-check over
//! that raw published set.
//!
//! The card keys are derived the way the vector fixtures derive them: the seed
//! of a test key is `sha256("mcp-jack test key: <name>")` and its `kid` is
//! `base64url(SHA-256(x))` (spec 06 R7.3).

mod keys;
mod source;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};

use crate::encoding::{encode_b64url, key_id};
use crate::webhook::card::source::{CardResponse, CardSource, CardTransport};
use crate::webhook::encoding::sha256;
use crate::webhook::WebhookError;

/// The MCP streamable-HTTP endpoint every fixture card matches
/// (spec 06 R7.1, R7.2).
pub(crate) const MCP_URL: &str = "https://svc.example.test/mcp";

/// The fixed clock of every test, in unix seconds (spec 06 R7.2).
pub(crate) const NOW: i64 = 1_767_225_600;

/// The measured fetch time of every canned response, below the R7.2 cap
/// (spec 06 R7.2).
const ELAPSED_MS: i64 = 5;

/// One fixture card key: the public key `x` and the `kid` derived from it
/// (spec 06 R7.3).
pub(crate) struct CardKey {
    /// The R7.3 key id, `base64url(SHA-256(x))`.
    pub(crate) kid: String,
    /// The canonical unpadded base64url of the 32 raw public-key bytes.
    pub(crate) x: String,
}

/// Returns the deterministic card key of `name` (spec 06 R7.3).
pub(crate) fn card_key(name: &str) -> CardKey {
    let seed = sha256(format!("mcp-jack test key: {name}").as_bytes());
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    let public_key = verifying.as_bytes();
    CardKey {
        kid: key_id(public_key),
        x: encode_b64url(public_key),
    }
}

/// Renders one fixture key as the JWK the card publishes
/// (spec 06 R7.1, R7.3).
pub(crate) fn jwk(key: &CardKey) -> Value {
    json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": key.x,
        "kid": key.kid,
    })
}

/// Renders [`jwk`] plus an `alg` member the R7.3 validator has an opinion on
/// (spec 06 R7.3).
pub(crate) fn jwk_with_alg(key: &CardKey, alg: &str) -> Value {
    let mut value = jwk(key);
    if let Value::Object(members) = &mut value {
        members.insert("alg".to_owned(), Value::String(alg.to_owned()));
    }
    value
}

/// Builds one card body publishing `keys` on the remote that matches
/// [`MCP_URL`] (spec 06 R7.1).
pub(crate) fn card_body(keys: &[Value]) -> Vec<u8> {
    json!({
        "remotes": [{
            "url": MCP_URL,
            "extensionsInfo": {
                "io.modelcontextprotocol/events": {
                    "webhooks": {
                        "signingKeys": { "keys": keys },
                    },
                },
            },
        }],
    })
    .to_string()
    .into_bytes()
}

/// Returns a `200` card response carrying `body` and no cache directive
/// (spec 06 R7.2).
pub(crate) fn response(body: Vec<u8>) -> CardResponse {
    CardResponse {
        status: 200,
        body,
        declared_length: None,
        overflow: false,
        cache_control: None,
        elapsed_ms: ELAPSED_MS,
    }
}

/// Returns a `200` card response carrying `body` and the `Cache-Control` value
/// `cache_control` (spec 06 R7.2).
pub(crate) fn cached_response(body: Vec<u8>, cache_control: &str) -> CardResponse {
    let mut value = response(body);
    value.cache_control = Some(cache_control.to_owned());
    value
}

/// A [`CardTransport`] that replays canned responses (spec 06 R7.2).
///
/// Fetch `n` answers with response `n`, and every fetch past the end answers
/// with the last response, so a test states the sequence it expects and the
/// call count it asserts. No clock, no resolver and no socket are involved.
pub(crate) struct ScriptedTransport {
    /// The canned responses, in fetch order (spec 06 R7.2).
    responses: Vec<CardResponse>,
    /// The number of fetches performed so far (spec 06 R7.2).
    calls: AtomicUsize,
}

impl ScriptedTransport {
    /// Builds the transport over `responses` (spec 06 R7.2).
    pub(crate) fn new(responses: Vec<CardResponse>) -> Arc<Self> {
        assert!(!responses.is_empty(), "a script needs one response");
        Arc::new(Self {
            responses,
            calls: AtomicUsize::new(0),
        })
    }

    /// Returns the number of fetches performed so far (spec 06 R7.2).
    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl CardTransport for ScriptedTransport {
    /// Replays the next canned response (spec 06 R7.2).
    fn fetch_card(&self, _url: &str) -> Result<CardResponse, WebhookError> {
        let index = self.calls.fetch_add(1, Ordering::SeqCst);
        let last = self.responses.len() - 1;
        Ok(self.responses[index.min(last)].clone())
    }
}

/// Builds one source over `transport` and the default card url of R7.2.
pub(crate) fn source(transport: &Arc<ScriptedTransport>) -> CardSource {
    let transport: Arc<dyn CardTransport> = transport.clone();
    CardSource::new(MCP_URL, transport, None, None).expect("the fixture card url is the MCP origin")
}
