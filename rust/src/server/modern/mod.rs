//! Server rules of the modern profile (spec 04 sections 3 and 5): the profile,
//! the per-request era, the refusal vocabulary and the classification outcome.
//!
//! The rules run strictly after authentication (spec 01 section 4 steps 1-8)
//! and after body classification (spec 02 section 2); `classify_request` in
//! the `rules` submodule mirrors the reference `classifyRequest` of
//! `spec/tools/modern/headers/reference/server.mjs` in the same order with the
//! same first-failure-wins behaviour.

use crate::modern::is_modern_version;

/// Deployment profile (spec 04 section 1): chosen once per server, unlike the
/// per-request era.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Profile {
    /// Every request is served as legacy-era (0.1.x behaviour).
    #[default]
    Legacy,
    /// Every request is served as modern-era.
    Modern,
    /// The era is decided per request by `S3`.
    Both,
}

impl Profile {
    /// Canonical lowercase name: `"legacy"`, `"modern"` or `"both"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Modern => "modern",
            Self::Both => "both",
        }
    }
}

/// Per-request classification (spec 04 section 1).
pub use crate::modern::Era;

/// One received header in received order, casing preserved. Header names are
/// compared case-insensitively, values case-sensitively (RFC 9110).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderField {
    /// Header name exactly as received.
    pub name: String,
    /// Header value after the HTTP layer removed OWS.
    pub value: String,
}

impl HeaderField {
    /// Builds a header field from any string-like name and value.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// The already authenticated request the rules inspect (spec 04 section 5).
#[derive(Debug)]
pub struct ModernRequest<'a> {
    /// HTTP method, exactly as received.
    pub method: &'a str,
    /// Request target, exactly as received.
    pub target: &'a str,
    /// Received headers in received order.
    pub headers: &'a [HeaderField],
    /// Verified body bytes.
    pub body: &'a [u8],
}

/// Why the modern-era rules refuse a request (spec 04 section 5.1). Each
/// variant carries the fixed token, rule id, HTTP status, JSON-RPC code and
/// message; the message never echoes a header or body value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// `S2`: the method is not `POST`.
    MethodNotAllowed,
    /// `S1`: a recognised header value is outside the field-value syntax.
    HeaderValueInvalid,
    /// `S1`: a mirror header appears more than once.
    HeaderRepeated,
    /// `S4`: `MCP-Protocol-Version` is absent on a request.
    VersionHeaderMissing,
    /// `S4`: `MCP-Protocol-Version` is not a well-formed version.
    VersionHeaderMalformed,
    /// `S4`: the header is present but `params._meta` carries no version.
    VersionMetaMissing,
    /// `S4`: the header and the `_meta` version differ byte-wise.
    VersionMismatch,
    /// `S5`: `Mcp-Method` is absent on a request.
    MethodHeaderMissing,
    /// `S5`: `Mcp-Method` is not byte-equal to the body method.
    MethodHeaderMismatch,
    /// `S6`: the method has no name source but `Mcp-Name` is present.
    NameHeaderNotApplicable,
    /// `S6`: the body has no string value for the name source field.
    NameSourceMissing,
    /// `S6`: the name source exists but `Mcp-Name` is absent on a request.
    NameHeaderMissing,
    /// `S6`: the `Mcp-Name` value is not a decodable base64 sentinel.
    NameHeaderBadEncoding,
    /// `S6`: the decoded `Mcp-Name` text differs from the body value.
    NameHeaderMismatch,
}

impl RefusalReason {
    /// The fixed reason token, for example `"name_header_bad_encoding"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MethodNotAllowed => "method_not_allowed",
            Self::HeaderValueInvalid => "header_value_invalid",
            Self::HeaderRepeated => "header_repeated",
            Self::VersionHeaderMissing => "version_header_missing",
            Self::VersionHeaderMalformed => "version_header_malformed",
            Self::VersionMetaMissing => "version_meta_missing",
            Self::VersionMismatch => "version_mismatch",
            Self::MethodHeaderMissing => "method_header_missing",
            Self::MethodHeaderMismatch => "method_header_mismatch",
            Self::NameHeaderNotApplicable => "name_header_not_applicable",
            Self::NameSourceMissing => "name_source_missing",
            Self::NameHeaderMissing => "name_header_missing",
            Self::NameHeaderBadEncoding => "name_header_bad_encoding",
            Self::NameHeaderMismatch => "name_header_mismatch",
        }
    }

    /// The rule that produces the refusal: `"S1"`, `"S2"`, `"S4"`, `"S5"` or
    /// `"S6"` (spec 04 section 5).
    pub fn rule(&self) -> &'static str {
        match self {
            Self::HeaderValueInvalid | Self::HeaderRepeated => "S1",
            Self::MethodNotAllowed => "S2",
            Self::VersionHeaderMissing
            | Self::VersionHeaderMalformed
            | Self::VersionMetaMissing
            | Self::VersionMismatch => "S4",
            Self::MethodHeaderMissing | Self::MethodHeaderMismatch => "S5",
            Self::NameHeaderNotApplicable
            | Self::NameSourceMissing
            | Self::NameHeaderMissing
            | Self::NameHeaderBadEncoding
            | Self::NameHeaderMismatch => "S6",
        }
    }

    /// The HTTP status: 405 for `method_not_allowed`, 400 for everything else.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::MethodNotAllowed => 405,
            _ => 400,
        }
    }

    /// The JSON-RPC error code: -32600 for `method_not_allowed`, -32020 for
    /// everything else.
    pub fn code(&self) -> i64 {
        match self {
            Self::MethodNotAllowed => -32600,
            _ => -32020,
        }
    }

    /// The fixed JSON-RPC error message, verbatim from spec 04 section 5.1: no
    /// trailing period and no echoed value.
    pub fn message(&self) -> &'static str {
        match self {
            Self::MethodNotAllowed => "HTTP method not allowed",
            Self::HeaderValueInvalid => {
                "Header mismatch: a request metadata header value contains a character outside the HTTP field-value syntax"
            }
            Self::HeaderRepeated => "Header mismatch: a request metadata header appears more than once",
            Self::VersionHeaderMissing => "Header mismatch: MCP-Protocol-Version is missing",
            Self::VersionHeaderMalformed => "Header mismatch: MCP-Protocol-Version is malformed",
            Self::VersionMetaMissing => "Header mismatch: params._meta protocolVersion is missing",
            Self::VersionMismatch => {
                "Header mismatch: MCP-Protocol-Version does not match params._meta protocolVersion"
            }
            Self::MethodHeaderMissing => "Header mismatch: Mcp-Method is missing",
            Self::MethodHeaderMismatch => "Header mismatch: Mcp-Method does not match the body method",
            Self::NameHeaderNotApplicable => {
                "Header mismatch: Mcp-Name is not defined for this method"
            }
            Self::NameSourceMissing => {
                "Header mismatch: the body has no string value for the Mcp-Name source field"
            }
            Self::NameHeaderMissing => "Header mismatch: Mcp-Name is missing",
            Self::NameHeaderBadEncoding => {
                "Header mismatch: Mcp-Name is not a valid base64 sentinel encoding"
            }
            Self::NameHeaderMismatch => "Header mismatch: Mcp-Name does not match the body value",
        }
    }
}

/// A refusal of one of the modern-era rules: the reason plus the JSON-RPC `id`
/// the signed error carries (`null` when there is none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Why the request was refused.
    pub reason: RefusalReason,
    /// Raw JSON text of the request id for a JSON-RPC Request body with a
    /// string or integer id; `None` (rendered as `null`) for a request with a
    /// `null` or fractional id (`S10`), for a notification, for a response
    /// object and for every non-`POST` request.
    pub id: Option<String>,
}

/// What the rules decide for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModernOutcome {
    /// Forward the request to the wrapped handler in `era` with `headers`.
    Forward {
        /// Era decided by `S3`.
        era: Era,
        /// Header list the handler receives: the received headers in received
        /// order, minus the `S8` removals in the modern era.
        headers: Vec<HeaderField>,
    },
    /// Refuse with a signed JSON-RPC error (`S10`).
    Refuse(Refusal),
    /// Refuse at body classification, before the era decision (spec 02
    /// section 2): the era-neutral `400 invalid_request` envelope.
    ClassificationRefusal {
        /// Fixed message text; never echoes a body value.
        message: &'static str,
    },
}

/// The `400 invalid_request` message for a `POST` whose body is not an
/// acceptable JSON-RPC object (spec 02 section 2). Unreachable after that
/// classification, which refuses the body first.
pub const INVALID_BODY_MESSAGE: &str = "the body is not an acceptable JSON-RPC object";

/// `S3` — the era decision (spec 04 section 3).
///
/// `Legacy` and `Modern` profiles decide unconditionally. Under `Both` the
/// request is modern-era iff some `MCP-Protocol-Version` header (name compared
/// ASCII case-insensitively) carries a well-formed modern version, or
/// `meta_version` — the string `params._meta` version of a request or
/// notification body — is a well-formed modern version.
///
/// A repeated header counts when any of its values is a modern version:
/// ambiguity must not buy the legacy path, because stripping one unsigned
/// header must never move a modern request onto legacy handling. Any
/// disagreement between the mirrors is then a signed `S4` refusal.
pub fn decide_era(profile: Profile, headers: &[HeaderField], meta_version: Option<&str>) -> Era {
    match profile {
        Profile::Legacy => Era::Legacy,
        Profile::Modern => Era::Modern,
        Profile::Both => {
            let modern_header = headers.iter().any(|h| {
                h.name.eq_ignore_ascii_case("MCP-Protocol-Version") && is_modern_version(&h.value)
            });
            if modern_header || meta_version.is_some_and(is_modern_version) {
                Era::Modern
            } else {
                Era::Legacy
            }
        }
    }
}

mod rules;

pub use rules::classify_request;
#[cfg(feature = "http")]
pub(crate) use rules::request_era;

#[cfg(test)]
mod tests;
