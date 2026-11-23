//! The client's era choice (spec 04 section 6): a client either speaks the
//! legacy era exactly as 0.1.x did, builds modern-era requests, or probes the
//! server once and follows the verdict (`C9`).

/// The era a [`crate::client::Client`] builds its requests in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientEra {
    /// 0.1.x request shapes: no `_meta`, no mirror headers.
    #[default]
    Legacy,
    /// MCP 2026-07-28 request shapes: `_meta` plus the `C2` mirror headers.
    Modern,
    /// Probe with `server/discover` on the first call and follow the verified
    /// verdict (`C9`): stay modern or fall back to `initialize`.
    Auto,
}

impl ClientEra {
    /// Canonical lowercase name: `"legacy"`, `"modern"` or `"auto"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Modern => "modern",
            Self::Auto => "auto",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_names_and_default() {
        assert_eq!(ClientEra::Legacy.as_str(), "legacy");
        assert_eq!(ClientEra::Modern.as_str(), "modern");
        assert_eq!(ClientEra::Auto.as_str(), "auto");
        assert_eq!(ClientEra::default(), ClientEra::Legacy);
    }
}
