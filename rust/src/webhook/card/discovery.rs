//! Server Card discovery of spec 06 section 7 (R7.1, R7.2, R7.5): origin and
//! default-url rules, remote selection, the events webhooks object, the
//! advisory egress CIDR list, the card cache TTL and the one fetch decision
//! of R7.2 in the order https, same origin, redirect, status, time, size,
//! json, keys.
//!
//! Everything here is pure: the caller performs the fetch and supplies the
//! status, the redirect flag, the raw body bytes, the measured elapsed time
//! and the `Cache-Control` value. A decision carries the fixed-literal code
//! and reason of the R7.2 rule and never echoes a body byte.

use serde_json::Value;

use crate::webhook::card::jwk::{accept_jwk_set, KeyRejection, WebhookKeyRecord, EVENTS_EXTENSION};
use crate::webhook::ssrf::cidr::parse_cidr;
use crate::webhook::ssrf::url::check_url;
use crate::webhook::{codes, WebhookError};

/// The largest card body a fetch may deliver, in bytes (spec 06 R7.2).
pub const MAX_CARD_BYTES: usize = 65_536;

/// The longest a card may be cached, in seconds (spec 06 R7.2).
pub const MAX_CARD_TTL_SECONDS: i64 = 300;

/// The cache lifetime used when `Cache-Control` carries no usable `max-age`
/// (spec 06 R7.2).
const DEFAULT_CARD_TTL_SECONDS: i64 = 300;

/// The default `https` port, never rendered in a card url (spec 06 R7.2).
const DEFAULT_PORT: u16 = 443;

/// The reserved default card path appended to the MCP streamable-HTTP url
/// (spec 06 R7.2).
const CARD_SUFFIX: &str = "/server-card";

/// The wall-clock cap of one card fetch, in milliseconds (spec 06 R7.2).
const MAX_CARD_ELAPSED_MS: i64 = 10_000;

/// The fixed-literal reason of a malformed egress range (spec 06 R7.5).
const MALFORMED_CIDR: &str = "malformed_cidr";

/// The status of a card rejection: R7.2 discards the card before any key is
/// trusted and assigns the fetch refusals no HTTP answer, so no wire status
/// is reported (spec 06 R7.2).
const NO_HTTP_STATUS: u16 = 0;

/// Returns true when both urls are `https` with the same host and port
/// (spec 06 R7.2).
///
/// A url that does not parse is never the same origin, and the comparison
/// uses the R6.1-R6.3 normalized host and the R8.2 defaulted port, so
/// `https://a.test/mcp` and `https://a.test:443/x` are the same origin.
pub fn same_origin(a: &str, b: &str) -> bool {
    let (Ok(left), Ok(right)) = (check_url(a), check_url(b)) else {
        return false;
    };
    left.scheme == right.scheme && left.host == right.host && left.port == right.port
}

/// Returns the reserved default card url under the MCP streamable-HTTP url,
/// or `None` off `https` (spec 06 R7.2).
///
/// The host is the R6.3 normalized host, the port is omitted for 443, the
/// query is dropped and one trailing slash of the path is removed, then the
/// `server-card` path is appended: `GET <streamable-http-url>/server-card`.
pub fn default_card_url(mcp_url: &str) -> Option<String> {
    let checked = check_url(mcp_url).ok()?;
    let suffix = if checked.port == DEFAULT_PORT {
        String::new()
    } else {
        format!(":{}", checked.port)
    };
    let path = if checked.path.len() > 1 && checked.path.ends_with('/') {
        &checked.path[..checked.path.len() - 1]
    } else {
        checked.path.as_str()
    };
    let prefix = if path == "/" { "" } else { path };
    Some(format!(
        "https://{}{suffix}{prefix}{CARD_SUFFIX}",
        checked.host
    ))
}

/// Selects the remote entry whose substituted `url` is the MCP endpoint
/// (spec 06 R7.1).
///
/// Only a remote with a string `url` that is the same origin as `mcp_url` is
/// a candidate; a templated `url` containing `{` is never substituted here
/// and is skipped. Candidates are ranked by the exact path, then by the
/// longest path prefix of the endpoint, then by origin only; ties keep card
/// order. No candidate is `no_remote` (spec 06 R7.1, R7.2).
pub fn select_remote<'a>(card: &'a Value, mcp_url: &str) -> Result<&'a Value, WebhookError> {
    let Ok(target) = check_url(mcp_url) else {
        return Err(no_remote());
    };
    let mut best: Option<&'a Value> = None;
    let mut best_tier = 0u8;
    let mut best_length: i64 = -1;
    if let Some(remotes) = card.get("remotes").and_then(Value::as_array) {
        for remote in remotes {
            let Some(url) = remote.get("url").and_then(Value::as_str) else {
                continue;
            };
            if url.contains('{') {
                continue;
            }
            let Ok(checked) = check_url(url) else {
                continue;
            };
            if !same_origin(url, mcp_url) {
                continue;
            }
            let (tier, length) = if checked.path == target.path {
                (3, 0)
            } else if target.path.starts_with(&checked.path) {
                (2, i64::try_from(checked.path.len()).unwrap_or(i64::MAX))
            } else {
                (1, 0)
            };
            if tier > best_tier || (tier == best_tier && length > best_length) {
                best = Some(remote);
                best_tier = tier;
                best_length = length;
            }
        }
    }
    best.ok_or_else(no_remote)
}

/// The events webhooks object of the selected remote (spec 06 R7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookInfo {
    /// The `signingKeys` JWK set as published, or `None` when the member is
    /// absent; a remote without it yields no keys and is not an error
    /// (spec 06 R7.1).
    pub signing_keys: Option<Value>,
    /// The optional `egressIpRanges` string entries, unvalidated and in card
    /// order (spec 06 R7.1, R7.5).
    pub egress_ip_ranges: Vec<String>,
    /// The selected remote's substituted `url` (spec 06 R7.1).
    pub remote_url: String,
}

/// Reads the events webhooks object of the selected remote
/// (spec 06 R7.1).
///
/// The `webhooks` object is read from
/// `extensionsInfo["io.modelcontextprotocol/events"]` of the remote that
/// `select_remote` picks. Presence or absence of the entry states or denies
/// nothing about support for the Events extension, so an absent entry, an
/// absent `webhooks` object or an absent `signingKeys` member simply yields
/// no keys; only a card with no matching remote is `no_remote`
/// (spec 06 R7.1).
pub fn webhook_info(card: &Value, mcp_url: &str) -> Result<WebhookInfo, WebhookError> {
    let remote = select_remote(card, mcp_url)?;
    let info = remote
        .get("extensionsInfo")
        .and_then(|value| value.get(EVENTS_EXTENSION))
        .and_then(|value| value.get("webhooks"));
    let present = info.is_some_and(|value| value.is_object() || value.is_array());
    let signing_keys = if present {
        info.and_then(|value| value.get("signingKeys"))
            .filter(|value| value.is_object() || value.is_array())
            .cloned()
    } else {
        None
    };
    let egress_ip_ranges = if present {
        match info
            .and_then(|value| value.get("egressIpRanges"))
            .and_then(Value::as_array)
        {
            Some(values) => values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            None => Vec::new(),
        }
    } else {
        Vec::new()
    };
    let remote_url = remote
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Ok(WebhookInfo {
        signing_keys,
        egress_ip_ranges,
        remote_url,
    })
}

/// One accepted advisory egress range (spec 06 R7.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedCidr {
    /// The range exactly as published (spec 06 R7.5).
    pub cidr: String,
    /// The address family, `ipv4` or `ipv6` (spec 06 R6.11, R7.5).
    pub family: &'static str,
    /// The prefix length in bits (spec 06 R6.11, R7.5).
    pub prefix: u8,
}

/// One dropped advisory egress range (spec 06 R7.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedCidr {
    /// The entry exactly as published (spec 06 R7.5).
    pub value: String,
    /// The fixed-literal reason, always `malformed_cidr` (spec 06 R7.5).
    pub reason: &'static str,
}

/// The accepted and rejected advisory egress ranges (spec 06 R7.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrList {
    /// The entries that parse as an R6.11 CIDR, in card order
    /// (spec 06 R7.5).
    pub accepted: Vec<AcceptedCidr>,
    /// The entries that do not, with their fixed-literal reason
    /// (spec 06 R7.5).
    pub rejected: Vec<RejectedCidr>,
}

/// Validates `egressIpRanges` as CIDRs of the R6.11 shape
/// (spec 06 R7.5).
///
/// `egressIpRanges` is advisory egress allowlisting and never a substitute
/// for the signatures; a malformed entry is dropped and recorded as
/// `malformed_cidr` instead of invalidating the card (spec 06 R7.5).
pub fn parse_cidr_list(values: &[String]) -> CidrList {
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for value in values {
        match parse_cidr(value) {
            Some(cidr) => accepted.push(AcceptedCidr {
                cidr: value.clone(),
                family: cidr.family().as_str(),
                prefix: cidr.prefix(),
            }),
            None => rejected.push(RejectedCidr {
                value: value.clone(),
                reason: MALFORMED_CIDR,
            }),
        }
    }
    CidrList { accepted, rejected }
}

/// Returns the card cache lifetime in seconds (spec 06 R7.2).
///
/// The first usable `max-age=<digits>` token of the `Cache-Control` value
/// caps the lifetime at 300 s; an absent, unparsable or other value keeps the
/// full 300 s. A larger `max-age` is clamped to 300 s, so a card is cached
/// per origin for at most 300 s (spec 06 R7.2).
pub fn card_cache_ttl(cache_control: Option<&str>) -> i64 {
    let Some(value) = cache_control else {
        return DEFAULT_CARD_TTL_SECONDS;
    };
    for part in value.split(',') {
        let token = part.trim();
        let Some(digits) = token.strip_prefix("max-age=") else {
            continue;
        };
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        return match digits.parse::<u64>() {
            Ok(seconds) => i64::try_from(seconds.min(MAX_CARD_TTL_SECONDS as u64))
                .unwrap_or(MAX_CARD_TTL_SECONDS),
            Err(_) => MAX_CARD_TTL_SECONDS,
        };
    }
    DEFAULT_CARD_TTL_SECONDS
}

/// The inputs of one card fetch decision (spec 06 R7.2).
///
/// The caller performs the fetch; `status` and `redirect` describe the
/// response, `body` is the raw body exactly as received, `elapsed_ms` is the
/// measured wall clock and `cache_control` is the `Cache-Control` header
/// value. The configured MCP server key is applied at the JWK step, so a card
/// that publishes the server key yields no accepted key from that member
/// (spec 06 R7.2, R7.3).
#[derive(Debug, Clone, Copy)]
pub struct CardFetchInput<'a> {
    /// The MCP streamable-HTTP endpoint the card must match (spec 06 R7.2).
    pub mcp_url: &'a str,
    /// The card url that was fetched (spec 06 R7.2).
    pub card_url: &'a str,
    /// The HTTP status of the response, if one arrived (spec 06 R7.2).
    pub status: Option<u16>,
    /// True when the response was a redirect, whatever its status
    /// (spec 06 R7.2).
    pub redirect: bool,
    /// The raw body bytes (spec 06 R7.2).
    pub body: &'a [u8],
    /// The measured wall clock of the fetch in milliseconds (spec 06 R7.2).
    pub elapsed_ms: Option<i64>,
    /// The `Cache-Control` header value of the response (spec 06 R7.2).
    pub cache_control: Option<&'a str>,
    /// The configured MCP server key id (spec 06 R7.2, R7.3).
    pub mcp_server_kid: Option<&'a str>,
    /// The configured raw MCP server public key (spec 06 R7.2, R7.3).
    pub mcp_server_public_key: Option<&'a str>,
}

/// The accepted result of one card fetch decision (spec 06 R7.2, R7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedCard {
    /// The accepted card keys, with the configured server key and every
    /// duplicated `kid` moved out (spec 06 R7.2, R7.3).
    pub keys: Vec<WebhookKeyRecord>,
    /// The accepted advisory egress ranges, unvalidated input entries
    /// dropped (spec 06 R7.2, R7.5).
    pub egress_ip_ranges: Vec<String>,
    /// The rejected card keys with their fixed-literal reasons
    /// (spec 06 R7.2, R7.3).
    pub rejected_keys: Vec<KeyRejection>,
    /// The per-origin cache lifetime of the card (spec 06 R7.2).
    pub cache_ttl_seconds: i64,
}

/// Takes one card fetch decision (spec 06 R7.2, R7.3).
///
/// The checks run in the spec order and the first failure wins: the card url
/// must be `https` (`not_https`); it must be the same origin as the MCP
/// endpoint (`cross_origin`); a redirect is refused (`redirect_refused`);
/// the status must be `2xx` (`http_status`); `elapsed_ms > 10000` is
/// `timeout`; a body above 65536 bytes is `too_large`; a body that is not a
/// JSON object is `bad_json`; and a card with no remote matching the MCP
/// endpoint is `no_remote`. On success the JWK set of the selected remote is
/// validated, the configured MCP server key is applied at that step, and the
/// advisory egress ranges are parsed (spec 06 R7.2, R7.3, R7.5).
pub fn fetch_decision(input: &CardFetchInput<'_>) -> Result<FetchedCard, WebhookError> {
    if let Err(err) = check_url(input.card_url) {
        let reason = err.reason().unwrap_or(err.code).to_owned();
        return Err(fetch_error(
            codes::NOT_HTTPS,
            &reason,
            "the card url is not https",
        ));
    }
    if !same_origin(input.card_url, input.mcp_url) {
        return Err(fetch_error(
            codes::CROSS_ORIGIN,
            "origin_mismatch",
            "the card url is not the MCP origin",
        ));
    }
    let redirected =
        input.redirect || matches!(input.status, Some(status) if (300..=399).contains(&status));
    if redirected {
        return Err(fetch_error(
            codes::REDIRECT_REFUSED,
            "redirect",
            "the card response is a redirect",
        ));
    }
    if !matches!(input.status, Some(status) if (200..=299).contains(&status)) {
        return Err(fetch_error(
            codes::HTTP_STATUS,
            "status",
            "the card response is not a 2xx",
        ));
    }
    if input
        .elapsed_ms
        .is_some_and(|elapsed| elapsed > MAX_CARD_ELAPSED_MS)
    {
        return Err(fetch_error(
            codes::TIMEOUT,
            "elapsed",
            "the card fetch exceeded the time cap",
        ));
    }
    if input.body.len() > MAX_CARD_BYTES {
        return Err(fetch_error(
            codes::TOO_LARGE,
            "body",
            "the card body exceeds the size cap",
        ));
    }
    let parsed: Value = match serde_json::from_slice(input.body) {
        Ok(parsed) => parsed,
        Err(_) => {
            return Err(fetch_error(
                codes::BAD_JSON,
                "json",
                "the card body is not JSON",
            ))
        }
    };
    if !parsed.is_object() {
        return Err(fetch_error(
            codes::BAD_JSON,
            "shape",
            "the card body is not a JSON object",
        ));
    }
    let info = webhook_info(&parsed, input.mcp_url)?;
    let keys = accept_jwk_set(
        info.signing_keys.as_ref(),
        input.mcp_server_kid,
        input.mcp_server_public_key,
    );
    let egress = parse_cidr_list(&info.egress_ip_ranges);
    Ok(FetchedCard {
        keys: keys.accepted,
        egress_ip_ranges: egress
            .accepted
            .into_iter()
            .map(|range| range.cidr)
            .collect(),
        rejected_keys: keys.rejected,
        cache_ttl_seconds: card_cache_ttl(input.cache_control),
    })
}

/// Builds the `no_remote` rejection of R7.1 (spec 06 R7.1, R7.2).
fn no_remote() -> WebhookError {
    fetch_error(
        codes::NO_REMOTE,
        "no_remote",
        "the card has no remote matching the MCP endpoint",
    )
}

/// Builds a fixed-literal card rejection with its R7.2 code and reason
/// (spec 06 R7.2).
fn fetch_error(code: &'static str, reason: &str, message: &'static str) -> WebhookError {
    WebhookError::with_reason(NO_HTTP_STATUS, code, reason, message)
}
