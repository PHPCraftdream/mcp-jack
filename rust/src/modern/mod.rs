//! Shared vocabulary of the modern profile (spec 04) for the server rules
//! (section 5) and the client rules (section 6).
//!
//! The constants name the protocol version boundary, the `_meta` keys and
//! fixed messages; the helpers answer the closed questions the rules ask
//! (which parameter carries the target name, which headers are version
//! scoped). Parsing helpers live in the `values` submodule.

/// First modern-era protocol version (spec 04 section 2).
pub const MODERN_MIN: &str = "2026-07-28";

/// `_meta` key carrying the negotiated protocol version.
pub const META_VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";

/// `_meta` key carrying the client capabilities.
pub const META_CLIENT_CAPABILITIES_KEY: &str = "io.modelcontextprotocol/clientCapabilities";

/// `_meta` key carrying the client implementation info.
pub const META_CLIENT_INFO_KEY: &str = "io.modelcontextprotocol/clientInfo";

/// `_meta` key carrying the server implementation info.
pub const META_SERVER_INFO_KEY: &str = "io.modelcontextprotocol/serverInfo";

/// Implementation name reported in `_meta` information.
pub const IMPLEMENTATION_NAME: &str = "mcp-jack";

/// Implementation version reported in `_meta` information.
pub const IMPLEMENTATION_VERSION: &str = env!("CARGO_PKG_VERSION");

/// 2^53-1, the largest integer an `_meta`-mirrored argument may carry.
pub const SAFE_INT_MAX: i64 = 9_007_199_254_740_991;

/// The fixed `400 invalid_request` message for a `tools/call` body whose
/// `params.name` is not a string (spec 04 section 5, `S6`).
pub const TOOLS_CALL_NAME_MESSAGE: &str = "tools/call requires a string params.name";

/// Per-request classification (spec 04 section 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Era {
    /// MCP revisions that use `initialize` (`2025-11-25`, `2025-06-18`).
    Legacy,
    /// `2026-07-28` and later.
    Modern,
}

impl Era {
    /// Canonical lowercase name: `"legacy"` or `"modern"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Modern => "modern",
        }
    }
}

/// Which request parameter carries the target name the rules check
/// (spec 04 section 5, `S6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameSource {
    /// `params.name` (tools/call, prompts/get, events/poll, events/stream,
    /// events/subscribe, events/unsubscribe).
    Name,
    /// `params.uri` (resources/read).
    Uri,
}

/// Returns the parameter that must carry the target name for `method`, or
/// `None` when the method has no name-bearing parameter (spec 04 section 5,
/// `S6`). The match is exact and case-sensitive.
pub fn name_source(method: &str) -> Option<NameSource> {
    match method {
        "tools/call" | "prompts/get" | "events/poll" | "events/stream" | "events/subscribe"
        | "events/unsubscribe" => Some(NameSource::Name),
        "resources/read" => Some(NameSource::Uri),
        _ => None,
    }
}

/// Reports whether `name` is one of the headers the modern era removes
/// (`Mcp-Session-Id`, `Last-Event-ID`), compared ASCII case-insensitively
/// (spec 04 section 8, `S8`).
pub fn is_session_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("Mcp-Session-Id") || name.eq_ignore_ascii_case("Last-Event-ID")
}

mod values;

pub use values::{
    compare_versions, decode_header_value, encode_header_value, is_field_value, is_modern_version,
    is_token, is_version, DecodeHeaderValueError,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_source_table() {
        for method in [
            "tools/call",
            "prompts/get",
            "events/poll",
            "events/stream",
            "events/subscribe",
            "events/unsubscribe",
        ] {
            assert_eq!(name_source(method), Some(NameSource::Name), "{method}");
        }
        assert_eq!(name_source("resources/read"), Some(NameSource::Uri));
        for method in [
            "events/list",
            "server/discover",
            "tools/list",
            "subscriptions/listen",
            "Tools/Call",
            "",
        ] {
            assert_eq!(name_source(method), None, "{method}");
        }
    }

    #[test]
    fn session_header_table() {
        for name in [
            "Mcp-Session-Id",
            "mcp-session-id",
            "MCP-SESSION-ID",
            "Last-Event-ID",
            "last-event-id",
        ] {
            assert!(is_session_header(name), "{name}");
        }
        for name in [
            "Mcp-Session-Id2",
            "X-Mcp-Session-Id",
            "Last-Event-Id2",
            "",
            "Id",
        ] {
            assert!(!is_session_header(name), "{name}");
        }
    }
}
