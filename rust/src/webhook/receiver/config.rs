//! The configuration of the framework-neutral receiver (spec 06 section 3,
//! R3.1-R3.18, plus R5.6, R7.6 and R4.5/R4.6).
//!
//! Every field is a plain value: an audience, a window in seconds, the
//! accepted card keys, the Jack signing keys, the delivery secrets and the
//! subscription ids the receiver was told to route. Nothing here performs I/O
//! and nothing here holds a clock, so the same configuration produces the same
//! answers on every call (spec 06 section 3).

use std::collections::BTreeMap;

use serde_json::Value;

use crate::webhook::card::WebhookKeyRecord;
use crate::webhook::encoding::WebhookSecret;

/// The freshness window used when the configuration names none, in seconds
/// (spec 06 R3.9).
const DEFAULT_WINDOW: i64 = 300;

/// The body limit used when the configuration names none, in bytes
/// (spec 06 R1.2, R3.6).
const DEFAULT_MAX_BODY: usize = super::errors::MAX_BODY_BYTES;

/// How long an accepted `webhook-id` is remembered when the configuration
/// names no retention, in seconds (spec 06 R3.16).
const DEFAULT_DEDUP_RETENTION: i64 = 1200;

/// The Jack window used when the configuration names none, in seconds
/// (spec 06 R4.4).
const DEFAULT_JACK_WINDOW: i64 = 30;

/// The Jack `w1` settings of a receiver (spec 06 R4.2-R4.6).
///
/// A configured [`JackConfig`] makes the `Jack-Webhook-Auth` header required
/// on every delivery (spec 06 R4.6); a receiver without one ignores the
/// header entirely, its grammar included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JackConfig {
    /// The Jack audience the signing string carries, never taken from the
    /// request (spec 06 R4.3).
    pub aud: String,
    /// The Jack freshness window in seconds, independent of the 300 s
    /// Standard Webhooks window (spec 06 R4.4). [`JackConfig::default`] uses
    /// the 30 s of R4.4.
    pub window: i64,
    /// The callback url of every known subscription, keyed by subscription
    /// id; `w1` binds that exact byte string (spec 06 R4.3, R4.5).
    ///
    /// The pending-secret path of section 5 does not read this map: it uses
    /// the callback url of the pending entry that verified (spec 06 R5.6).
    pub callback_urls: BTreeMap<String, String>,
}

impl Default for JackConfig {
    /// Returns the R4.4 defaults: an empty audience, the 30 s window and no
    /// known callback urls (spec 06 R4.4).
    fn default() -> Self {
        Self {
            aud: String::new(),
            window: DEFAULT_JACK_WINDOW,
            callback_urls: BTreeMap::new(),
        }
    }
}

/// One delivery secret of a receiver (spec 06 R3.7, R5.6).
///
/// A registered entry carries the `subscription_id` it belongs to; a pending
/// entry keeps `None` until a verification envelope binds it, and then keeps
/// the `callback_url` it was registered with (spec 06 R5.6).
#[derive(Debug, Clone)]
pub struct ReceiverSecret {
    /// The decoded `whsec_` secret, never rendered (spec 06 R2.1).
    pub secret: WebhookSecret,
    /// The subscription id this secret is registered for, or `None` for a
    /// pending entry of section 5 (spec 06 R3.7, R5.6).
    pub subscription_id: Option<String>,
    /// The callback url the pending entry expects its challenge under
    /// (spec 06 R5.6).
    pub callback_url: Option<String>,
}

/// The configuration of one [`super::Receiver`] (spec 06 section 3).
///
/// The defaults are the ones the reference receiver applies: a 300 s window,
/// the 262144-byte body limit, a 1200 s dedup retention, no enforced server
/// identity, no accepted keys, no Jack settings, no secrets and no routed ids
/// (spec 06 R1.2, R3.6, R3.9, R3.14, R3.16, R4.6, R5.6, R7.6).
#[derive(Debug, Clone)]
pub struct ReceiverConfig {
    /// The freshness window on the receiver clock, in seconds
    /// (spec 06 R3.9). Defaults to 300.
    pub window: i64,
    /// The largest accepted raw body, in bytes (spec 06 R1.2, R3.6).
    /// Defaults to 262144.
    pub max_body: usize,
    /// How long an accepted `webhook-id` stays remembered, in seconds
    /// (spec 06 R3.16). Defaults to 1200.
    pub dedup_retention: i64,
    /// `true` when server identity is enforced, so a `v1a` or `v2a` entry
    /// must verify with an accepted card key (spec 06 R3.14).
    pub enforce_server_identity: bool,
    /// The configured MCP server key id, never accepted as a `w1` `kid`
    /// (spec 06 R4.5).
    pub mcp_server_kid: Option<String>,
    /// The configured MCP server raw public key in unpadded base64url, which
    /// names its own `kid` and drops the matching card key (spec 06 R4.5).
    pub mcp_server_public_key: Option<String>,
    /// The accepted card keys `v1a`, `v2a` and `w1` verify with
    /// (spec 06 R2.7, R4.5, R7.3).
    pub keys: Vec<WebhookKeyRecord>,
    /// `true` when the optional `jack.server.webhook_key` cross-check of R7.6
    /// is required, so a missing or disagreeing result rejects the delivery.
    pub require_webhook_key_check: bool,
    /// The `jack.server.webhook_key` tool result the cross-check compares
    /// with the card (spec 06 R7.6).
    pub webhook_key_tool: Option<Value>,
    /// The Jack `w1` settings, or `None` when `w1` is not configured and the
    /// header is ignored (spec 06 R4.6).
    pub jack: Option<JackConfig>,
    /// The registered and pending delivery secrets, in configuration order
    /// (spec 06 R3.7, R5.6).
    pub secrets: Vec<ReceiverSecret>,
    /// The subscription ids the receiver was told to route (spec 06 R3.8).
    pub routed: Vec<String>,
}

impl Default for ReceiverConfig {
    /// Returns the reference defaults: window 300, max body 262144, dedup
    /// retention 1200, and everything else empty, `false` or `None`
    /// (spec 06 R1.2, R3.6, R3.9, R3.16).
    fn default() -> Self {
        Self {
            window: DEFAULT_WINDOW,
            max_body: DEFAULT_MAX_BODY,
            dedup_retention: DEFAULT_DEDUP_RETENTION,
            enforce_server_identity: false,
            mcp_server_kid: None,
            mcp_server_public_key: None,
            keys: Vec::new(),
            require_webhook_key_check: false,
            webhook_key_tool: None,
            jack: None,
            secrets: Vec::new(),
            routed: Vec::new(),
        }
    }
}
