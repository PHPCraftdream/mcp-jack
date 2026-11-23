//! The client's era choice (spec 04 section 6): a client either speaks the
//! legacy era exactly as 0.1.x did or builds modern-era requests.

/// The era a [`crate::client::Client`] builds its requests in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientEra {
    /// 0.1.x request shapes: no `_meta`, no mirror headers.
    #[default]
    Legacy,
    /// MCP 2026-07-28 request shapes: `_meta` plus the `C2` mirror headers.
    Modern,
}

impl ClientEra {
    /// Canonical lowercase name: `"legacy"` or `"modern"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Modern => "modern",
        }
    }
}
