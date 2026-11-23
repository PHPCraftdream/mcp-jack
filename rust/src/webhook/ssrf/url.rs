//! Callback-url validation of spec 06 section 6 (R6.1-R6.3), the R5.11
//! dot-segment rule and the R8.2 canonical form.
//!
//! The url is scanned by hand: `https://` then the authority up to the first
//! `/`, `?` or `#`, then the path and the query. No normalization is ever
//! applied beyond the R8.2 form, and the path is never rewritten (R5.11).

use crate::webhook::ssrf::host::{parse_host, HostKind};
use crate::webhook::WebhookError;

/// The invalid-input status the profile uses for a rejected client value; the
/// spec assigns these codes no separate HTTP status (spec 06 section 3).
const BAD_REQUEST: u16 = 400;

/// The R6.2 code of a rejected url part.
const INVALID_CALLBACK_URL: &str = "invalid_callback_url";

/// The R6.1 code of a scheme other than `https`.
const SCHEME_NOT_HTTPS: &str = "scheme_not_https";

/// The default `https` port, never rendered in the canonical form
/// (spec 06 R8.2).
const HTTPS_PORT: u16 = 443;

/// The validated parts of a callback url (spec 06 R6.2, R8.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlParts {
    /// The scheme, always `https` (spec 06 R6.1).
    pub scheme: &'static str,
    /// The normalized host, bracketed for an IPv6 literal (spec 06 R6.3).
    pub host: String,
    /// The port, defaulted to 443 (spec 06 R6.2, R8.2).
    pub port: u16,
    /// The path exactly as supplied, `/` when empty (spec 06 R6.2, R8.2).
    pub path: String,
    /// The query exactly as supplied, empty when absent (spec 06 R8.2).
    pub query: String,
    /// The R8.2 canonical form used in the subscription key.
    pub canonical: String,
    /// The form of the host (spec 06 R6.3).
    pub host_kind: HostKind,
    /// The unbracketed address of a literal, or the host name
    /// (spec 06 R6.3).
    pub host_value: String,
}

/// Returns an `invalid_callback_url` rejection with the given reason
/// (spec 06 R6.2).
fn url_bad(reason: &'static str) -> WebhookError {
    WebhookError::with_reason(
        BAD_REQUEST,
        INVALID_CALLBACK_URL,
        reason,
        "the callback url is not acceptable",
    )
}

/// Returns the `scheme_not_https` rejection of R6.1.
fn scheme_not_https() -> WebhookError {
    WebhookError::new(
        BAD_REQUEST,
        SCHEME_NOT_HTTPS,
        "the callback url is not https",
    )
}

/// Validates a callback url and renders its canonical form (spec 06 R6.1,
/// R6.2, R6.3, R5.11, R8.2).
pub fn check_url(url: &str) -> Result<UrlParts, WebhookError> {
    for character in url.chars() {
        let code = character as u32;
        if code < 0x21 || code == 0x7f || code > 0x7e {
            return Err(url_bad("character"));
        }
    }
    let Some(marker) = url.find("://") else {
        return Err(scheme_not_https());
    };
    if !url[..marker].eq_ignore_ascii_case("https") {
        return Err(scheme_not_https());
    }
    let rest = &url[marker + 3..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let tail = &rest[end..];
    if authority.contains('@') {
        return Err(url_bad("userinfo"));
    }
    if tail.contains('#') {
        return Err(url_bad("fragment"));
    }
    if authority.is_empty() {
        return Err(url_bad("empty_host"));
    }
    let Some((host_text, port_text)) = split_authority(authority) else {
        return Err(url_bad("host"));
    };
    let Some(port) = read_port(port_text) else {
        return Err(url_bad("port"));
    };
    let host = parse_host(host_text)?;
    let (path, query) = if tail.is_empty() {
        ("/".to_string(), String::new())
    } else if let Some(query) = tail.strip_prefix('?') {
        ("/".to_string(), query.to_string())
    } else if let Some(remainder) = tail.strip_prefix('/') {
        match remainder.find('?') {
            Some(mark) => (
                format!("/{}", &remainder[..mark]),
                remainder[mark + 1..].to_string(),
            ),
            None => (format!("/{remainder}"), String::new()),
        }
    } else {
        return Err(url_bad("path"));
    };
    for segment in path.split('/') {
        let decoded = decode_dot_segment(segment);
        if decoded == "." || decoded == ".." {
            return Err(url_bad("dot_segment"));
        }
    }
    let suffix = if port == HTTPS_PORT {
        String::new()
    } else {
        format!(":{port}")
    };
    let canonical = if query.is_empty() {
        format!("https://{}{suffix}{path}", host.normalized)
    } else {
        format!("https://{}{suffix}{path}?{query}", host.normalized)
    };
    Ok(UrlParts {
        scheme: "https",
        host: host.normalized,
        port,
        path,
        query,
        canonical,
        host_kind: host.kind,
        host_value: host.address_or_name,
    })
}

/// Splits an authority into its host text and its optional port text
/// (spec 06 R6.2).
fn split_authority(authority: &str) -> Option<(&str, Option<&str>)> {
    if authority.starts_with('[') {
        let close = authority.find(']')?;
        let after = &authority[close + 1..];
        if after.is_empty() {
            return Some((&authority[..=close], None));
        }
        let port = after.strip_prefix(':')?;
        return Some((&authority[..=close], Some(port)));
    }
    let Some(first) = authority.find(':') else {
        return Some((authority, None));
    };
    if authority[first + 1..].contains(':') {
        return None;
    }
    Some((&authority[..first], Some(&authority[first + 1..])))
}

/// Reads the explicit port, defaulting to 443: digits only without a leading
/// zero, in 1-65535 (spec 06 R6.2).
fn read_port(text: Option<&str>) -> Option<u16> {
    let Some(text) = text else {
        return Some(HTTPS_PORT);
    };
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

/// Replaces every case variant of `%2e` by `.` in one path segment
/// (spec 06 R5.11).
fn decode_dot_segment(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && bytes[index + 1].eq_ignore_ascii_case(&b'2')
            && bytes[index + 2].eq_ignore_ascii_case(&b'e')
        {
            out.push('.');
            index += 3;
        } else {
            out.push(char::from(bytes[index]));
            index += 1;
        }
    }
    out
}
