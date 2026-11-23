//! The operational Server Card key source of spec 06 R7.1-R7.4: one
//! [`CardSource`] fetches the `server-card` document through an injected
//! [`CardTransport`], takes the R7.2 fetch decision of
//! [`fetch_decision`](crate::webhook::card::discovery::fetch_decision), caches
//! the resulting [`KeySnapshot`] for the R7.2 cache lifetime and reports it as
//! a [`KeySource`] of R7.1-R7.4.
//!
//! The source is pure in the sense that only the injected transport performs
//! I/O: `now` is an argument, the cache is process-local memory, and every
//! rejection is the fixed-literal code of R7.2. The cache lock is never held
//! across a fetch, so a slow card never blocks a delivery reading the
//! snapshot, and after the TTL the key set is no longer trusted: a failed
//! refresh answers an empty snapshot, so a retired key stops verifying
//! (R7.2, R7.3).

use std::sync::{Arc, Mutex, PoisonError};

use serde_json::Value;

use crate::webhook::card::discovery::{
    default_card_url, fetch_decision, published_jwks, same_origin, CardFetchInput,
};
use crate::webhook::card::keys::{KeySnapshot, KeySource};
use crate::webhook::ssrf::url::check_url;
use crate::webhook::{codes, WebhookError};

/// The whole-fetch deadline of one operational card fetch, in seconds
/// (spec 06 R7.2).
///
/// A card fetch MUST complete within 10 s of wall clock; the transport bounds
/// every phase — DNS, connect, TLS, the request write and the response read —
/// by this one budget (spec 06 R7.2).
pub const CARD_FETCH_SECONDS: u64 = 10;

/// The status of a card rejection: R7.2 discards the card before any key is
/// trusted and assigns the fetch refusals no HTTP answer, so no wire status
/// is reported (spec 06 R7.2).
const NO_HTTP_STATUS: u16 = 0;

/// One card response as the transport read it (spec 06 R7.2).
///
/// The transport reports the status, the body it buffered and whether the
/// body crossed the 65536-byte cap; [`crate::webhook::card::discovery::fetch_decision`]
/// judges them in the R7.2 order and never echoes a body byte (spec 06 R7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardResponse {
    /// The HTTP status the fetch was answered with (spec 06 R7.2).
    pub status: u16,
    /// The raw body bytes, truncated to the 65536-byte cap when `overflow`
    /// is set (spec 06 R7.2).
    pub body: Vec<u8>,
    /// The declared `Content-Length`, when the response carried one
    /// (spec 06 R7.2).
    pub declared_length: Option<u64>,
    /// True when the response carried, or declared, more body than the
    /// 65536-byte cap; the decision then answers `too_large` before the JSON
    /// step (spec 06 R7.2).
    pub overflow: bool,
    /// The `Cache-Control` header value of the response, when the transport
    /// can read it; it caps the per-origin cache at `max-age` (spec 06 R7.2).
    pub cache_control: Option<String>,
    /// The measured wall clock of the whole fetch in milliseconds
    /// (spec 06 R7.2).
    pub elapsed_ms: i64,
}

/// Fetches one card over the hardened path (spec 06 R7.2).
///
/// The implementation owns the wire, the DNS answers and the time budget; the
/// source only sees the resulting [`CardResponse`] or the R1.9 network code
/// of a failed fetch, so the caching and the decision stay pure and
/// replayable (spec 06 R7.2).
pub trait CardTransport: Send + Sync {
    /// Fetches `url` over the hardened path with a whole-fetch deadline of
    /// `CARD_FETCH_SECONDS` (R7.2).
    fn fetch_card(&self, url: &str) -> Result<CardResponse, WebhookError>;
}

/// One cached key set and the moment it stops being fresh (spec 06 R7.2).
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The accepted keys and raw published JWKs of the cached card
    /// (spec 06 R7.2-R7.4).
    snapshot: KeySnapshot,
    /// The unix second from which the entry is stale,
    /// `created_at + cache_ttl_seconds` (spec 06 R7.2).
    expires_at: i64,
}

/// The operational Server Card key source (spec 06 R7.1-R7.4).
///
/// The source holds the MCP endpoint, the card url of R7.2, the transport, the
/// configured MCP server key members applied at the R7.3 JWK step, and the
/// one cached [`KeySnapshot`]. Every call takes `&self`, so one source is
/// shared by every delivery of the origin and rotation of R7.4 reaches a
/// delivery without a re-delivery (spec 06 R7.1-R7.4).
pub struct CardSource {
    /// The MCP streamable-HTTP endpoint the card must match
    /// (spec 06 R7.2).
    mcp_url: String,
    /// The card url that is fetched; the reserved `server-card` path by
    /// default, else the configured one (spec 06 R7.2).
    card_url: String,
    /// The fetch of the hardened path (spec 06 R7.2).
    transport: Arc<dyn CardTransport>,
    /// The configured MCP server key id, rejected at the R7.3 JWK step
    /// (spec 06 R7.3, R4.5).
    mcp_server_kid: Option<String>,
    /// The configured raw MCP server public key, rejected at the R7.3 JWK
    /// step (spec 06 R7.3, R4.5).
    mcp_server_public_key: Option<String>,
    /// The cached key set and the moment it stops being fresh; an entry past
    /// `expires_at` is never trusted again unless a refresh succeeds
    /// (spec 06 R7.2, R7.3).
    cache: Mutex<Option<CacheEntry>>,
}

impl CardSource {
    /// Builds a source over the default card url of R7.2.
    ///
    /// The default url is the reserved `GET <streamable-http-url>/server-card`
    /// of [`default_card_url`], which is only built from an `https` MCP
    /// endpoint. An MCP endpoint that is not an `https` url is `not_https`,
    /// and a default url that is not the endpoint's origin is `cross_origin`
    /// (spec 06 R7.2).
    pub fn new(
        mcp_url: &str,
        transport: Arc<dyn CardTransport>,
        mcp_server_kid: Option<String>,
        mcp_server_public_key: Option<String>,
    ) -> Result<Self, WebhookError> {
        let Some(card_url) = default_card_url(mcp_url) else {
            return Err(not_https());
        };
        check_card_url(mcp_url, &card_url)?;
        Ok(Self {
            mcp_url: mcp_url.to_owned(),
            card_url,
            transport,
            mcp_server_kid,
            mcp_server_public_key,
            cache: Mutex::new(None),
        })
    }

    /// Replaces the default card url with a configured one (spec 06 R7.2).
    ///
    /// The configured url MUST be `https` (`not_https`) and MUST be the same
    /// origin as the MCP endpoint (`cross_origin`); a url of another origin
    /// is never fetched, so a catalog entry pointing at a foreign host cannot
    /// widen the key set (spec 06 R7.2).
    pub fn with_card_url(mut self, card_url: &str) -> Result<Self, WebhookError> {
        check_card_url(&self.mcp_url, card_url)?;
        self.card_url = card_url.to_owned();
        Ok(self)
    }

    /// Fetches the card, validates it and replaces the cached key set
    /// (spec 06 R7.2-R7.4).
    ///
    /// The fetch runs outside the cache lock, so a slow card never blocks a
    /// [`CardSource::current`] read. On success the R7.2
    /// decision accepts the card, the accepted keys and the rejected entries
    /// become the snapshot and the raw JWKs of the selected remote become its
    /// `published` members — invalid members included, so the R7.6 cross-check
    /// sees them (spec 06 R7.3, R7.6). The snapshot replaces the cache entry
    /// whole, so a key removed from the card disappears at the next refresh
    /// and both published keys are accepted while both are present
    /// (spec 06 R7.4). The cache lifetime is `card.cache_ttl_seconds` counted
    /// from `now` (spec 06 R7.2).
    pub fn refresh(&self, now: i64) -> Result<KeySnapshot, WebhookError> {
        let response = self.transport.fetch_card(&self.card_url)?;
        let input = CardFetchInput {
            mcp_url: &self.mcp_url,
            card_url: &self.card_url,
            status: Some(response.status),
            redirect: false,
            body: &response.body,
            elapsed_ms: Some(response.elapsed_ms),
            cache_control: response.cache_control.as_deref(),
            mcp_server_kid: self.mcp_server_kid.as_deref(),
            mcp_server_public_key: self.mcp_server_public_key.as_deref(),
            overflow: response.overflow,
        };
        let card = fetch_decision(&input)?;
        let parsed: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
        let published = published_jwks(&parsed, &self.mcp_url)?;
        let snapshot = KeySnapshot {
            accepted: card.keys,
            rejected: card.rejected_keys,
            published,
        };
        let entry = CacheEntry {
            snapshot: snapshot.clone(),
            expires_at: now.saturating_add(card.cache_ttl_seconds),
        };
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        *cache = Some(entry);
        Ok(snapshot)
    }

    /// Returns the cached snapshot, refreshed first when it is stale
    /// (spec 06 R7.2, R7.3).
    ///
    /// An entry whose `expires_at` is still ahead of `now` is returned
    /// without a fetch. A stale entry is refreshed from the card; a failed
    /// refresh — a network failure or any R7.2 rejection, including
    /// `too_large` of an overflowing body — no longer returns the stale
    /// snapshot. It answers [`KeySnapshot::empty`]: after the TTL the set is
    /// not trusted, so the receiver answers the fixed `no_server_keys`
    /// refusal (spec 06 R7.3) until a refresh succeeds (spec 06 R7.2, R7.3).
    pub fn current(&self, now: i64) -> KeySnapshot {
        if let Some(snapshot) = self.fresh(now) {
            return snapshot;
        }
        match self.refresh(now) {
            Ok(snapshot) => snapshot,
            Err(_) => KeySnapshot::empty(),
        }
    }

    /// Returns the cached snapshot while it is fresh at `now`
    /// (spec 06 R7.2).
    fn fresh(&self, now: i64) -> Option<KeySnapshot> {
        let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        cache
            .as_ref()
            .filter(|entry| now < entry.expires_at)
            .map(|entry| entry.snapshot.clone())
    }
}

impl KeySource for CardSource {
    /// Reports the cached snapshot at `now`, refreshed first when it is stale;
    /// a stale entry whose refresh fails reports no accepted key
    /// (spec 06 R7.2, R7.3).
    fn snapshot(&self, now: i64) -> KeySnapshot {
        self.current(now)
    }
}

/// Validates a card url against the MCP endpoint (spec 06 R7.2).
///
/// The url must parse as `https` (`not_https`) and must share the endpoint's
/// host and port (`cross_origin`); a card of another origin, or one reached
/// through a cross-origin redirect, is never fetched (spec 06 R7.2).
fn check_card_url(mcp_url: &str, card_url: &str) -> Result<(), WebhookError> {
    if check_url(card_url).is_err() {
        return Err(not_https());
    }
    if !same_origin(card_url, mcp_url) {
        return Err(cross_origin());
    }
    Ok(())
}

/// Builds the `not_https` rejection of a card url that is not `https`
/// (spec 06 R7.2).
fn not_https() -> WebhookError {
    WebhookError::with_reason(
        NO_HTTP_STATUS,
        codes::NOT_HTTPS,
        "url",
        "the card url is not an https url",
    )
}

/// Builds the `cross_origin` rejection of a card url of another origin
/// (spec 06 R7.2).
fn cross_origin() -> WebhookError {
    WebhookError::with_reason(
        NO_HTTP_STATUS,
        codes::CROSS_ORIGIN,
        "origin_mismatch",
        "the card url is not the MCP origin",
    )
}
