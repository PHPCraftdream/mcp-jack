//! The operator allowlist route of spec 06 section 5 (R5.7): entry parsing
//! and first-match lookup. An entry is `https://`, then the host, then an
//! optional `:` plus port, then an optional path; the host may be `*.`
//! followed by a parent domain that matches one or more labels.
//!
//! Everything here is pure and mirrors
//! `spec/tools/modern/webhooks/ref/verification.mjs` exactly: no query, no
//! fragment and no userinfo in an entry, the port defaults to 443 and the
//! path is a byte prefix at a segment boundary.

use crate::webhook::ssrf::host::{parse_host, HostKind};
use crate::webhook::ssrf::url::check_url;
use crate::webhook::verification::document::covers_path;

/// The scheme prefix every entry must start with (spec 06 R5.7).
const HTTPS_PREFIX: &str = "https://";

/// The wildcard prefix of a parent-domain host pattern (spec 06 R5.7).
const WILDCARD: &str = "*.";

/// The entry form whose authority is a wildcard host pattern
/// (spec 06 R5.7).
const WILDCARD_PREFIX: &str = "https://*.";

/// The port an entry without an explicit port matches (spec 06 R5.7).
const DEFAULT_PORT: u16 = 443;

/// One parsed allowlist entry: a host pattern, a port and a path prefix
/// (spec 06 R5.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistEntry {
    /// The literal host or `*.` plus a parent domain, lowercased
    /// (spec 06 R5.7).
    pub host_pattern: String,
    /// The port, defaulted to 443 (spec 06 R5.7).
    pub port: u16,
    /// The path prefix, `/` when the entry has no path (spec 06 R5.7).
    pub path: String,
}

/// Parses one allowlist entry, or returns `None` when it is not an absolute
/// `https` url prefix (spec 06 R5.7).
///
/// The entry must be printable ASCII and start with `https://`. A literal
/// host is validated by the R6 url rules with no query; a `*.` entry is
/// parsed here, because the url rules reject a wildcard label, and its parent
/// must be a host name, never a literal (spec 06 R5.7).
pub fn parse_allowlist_entry(text: &str) -> Option<AllowlistEntry> {
    if !text.starts_with(HTTPS_PREFIX) || !is_printable_ascii(text) {
        return None;
    }
    if !text.starts_with(WILDCARD_PREFIX) {
        let checked = check_url(text).ok()?;
        if !checked.query.is_empty() {
            return None;
        }
        return Some(AllowlistEntry {
            host_pattern: checked.host,
            port: checked.port,
            path: checked.path,
        });
    }
    let rest = &text[HTTPS_PREFIX.len()..];
    let stop = first_path_mark(rest);
    let authority = match stop {
        Some(stop) => &rest[..stop],
        None => rest,
    };
    let path = match stop {
        Some(stop) => &rest[stop..],
        None => "/",
    };
    if has_control_or_mark(path) || authority.contains('@') {
        return None;
    }
    let colon = authority.find(':');
    let host_text = match colon {
        Some(colon) => &authority[..colon],
        None => authority,
    };
    let port_text = colon.map(|colon| &authority[colon + 1..]);
    let port = match port_text {
        Some(text) => read_port(text)?,
        None => DEFAULT_PORT,
    };
    let parent_text = host_text.strip_prefix(WILDCARD)?;
    let parent = parse_host(parent_text).ok()?;
    if parent.kind != HostKind::Name {
        return None;
    }
    Some(AllowlistEntry {
        host_pattern: format!("{WILDCARD}{}", parent.normalized),
        port,
        path: path.to_string(),
    })
}

/// Returns the first entry that matches the canonical url on port, host and
/// path prefix, or `None` when none does (spec 06 R5.7).
///
/// A url that does not parse matches nothing, and the first matching entry
/// wins, so a match short-circuits (spec 06 R5.7).
pub fn allowlist_matches(entries: &[String], canonical_url: &str) -> Option<AllowlistEntry> {
    let checked = check_url(canonical_url).ok()?;
    for value in entries {
        let Some(entry) = parse_allowlist_entry(value) else {
            continue;
        };
        if entry.port != checked.port {
            continue;
        }
        if !host_matches(&entry.host_pattern, &checked.host) {
            continue;
        }
        if !covers_path(&entry.path, &checked.path) {
            continue;
        }
        return Some(entry);
    }
    None
}

/// Returns true when every character is printable ASCII, the R5.7 entry
/// alphabet (spec 06 R5.7).
fn is_printable_ascii(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

/// Returns the index of the first `/`, `?` or `#` of an authority tail
/// (spec 06 R5.7).
fn first_path_mark(text: &str) -> Option<usize> {
    text.find(['/', '?', '#'])
}

/// Returns true for a control character or a `?` or `#` mark, neither of
/// which may appear in an entry path (spec 06 R5.7).
fn has_control_or_mark(text: &str) -> bool {
    text.chars()
        .any(|character| matches!(character, '?' | '#' | '\0'..='\u{1f}' | '\u{7f}'))
}

/// Reads an explicit entry port: `0` or `[1-9][0-9]{0,4}` in 1-65535
/// (spec 06 R5.7).
fn read_port(text: &str) -> Option<u16> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if text.len() > 1 && text.starts_with('0') {
        return None;
    }
    let value: u32 = text.parse().ok()?;
    if (1..=u32::from(u16::MAX)).contains(&value) {
        Some(value as u16)
    } else {
        None
    }
}

/// Matches a host pattern against a normalized host: a literal compares
/// equal, `*.` plus a parent matches one or more labels and never the parent
/// itself (spec 06 R5.7).
fn host_matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix(WILDCARD) {
        Some(parent) => host.ends_with(&format!(".{parent}")) && host.len() > parent.len() + 1,
        None => pattern == host,
    }
}
