//! Host forms of spec 06 section 6 (R6.3, R6.4) and the RFC 5952 spelling of
//! R6.6: a canonical dotted quad, a bracketed IPv6 literal or an ASCII LDH
//! name, and nothing else.
//!
//! Every literal is hand-parsed: no `std::net`, no `url`, no IDNA. A spelling
//! that is not one of the three forms is never reinterpreted as an address
//! (R6.3), so `127.1`, `2130706433`, `0x7f.0.0.1`, `0177.0.0.1`, `1.2.3.4.5`
//! and `a..b` are all rejected as `not_a_hostname`.

use crate::webhook::WebhookError;

/// The invalid-input status the profile uses for a rejected client value; the
/// spec assigns these codes no separate HTTP status (spec 06 section 3).
const BAD_REQUEST: u16 = 400;

/// The R6.3 code for a spelling that is not a canonical literal or an LDH
/// name.
const NOT_A_HOSTNAME: &str = "not_a_hostname";

/// The R6.2 code for a malformed host part.
const INVALID_CALLBACK_URL: &str = "invalid_callback_url";

/// The R6.2 reason for a malformed host part.
const HOST_REASON: &str = "host";

/// The longest LDH name, in characters (spec 06 R6.3).
const NAME_MAX_LEN: usize = 253;

/// The longest LDH label, in characters (spec 06 R6.3).
const LABEL_MAX_LEN: usize = 63;

/// The form of a parsed host (spec 06 R6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKind {
    /// A canonical dotted quad (spec 06 R6.4).
    Ipv4,
    /// A bracketed IPv6 literal, parsed from its unbracketed inner text
    /// (spec 06 R6.3).
    Ipv6,
    /// An ASCII LDH name, lowercased with one trailing dot stripped
    /// (spec 06 R6.3).
    Name,
}

impl HostKind {
    /// Returns the discriminator of the kind: `ipv4`, `ipv6` or `name`
    /// (spec 06 R6.3).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Name => "name",
        }
    }
}

/// A host normalized to its canonical spelling (spec 06 R6.3, R8.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHost {
    /// The form that matched (spec 06 R6.3).
    pub kind: HostKind,
    /// The canonical spelling: the dotted quad, the bracketed IPv6 literal or
    /// the lowercased name (spec 06 R6.3, R8.2).
    pub normalized: String,
    /// The unbracketed address of a literal, or the name (spec 06 R6.3).
    pub address_or_name: String,
}

/// Returns the `not_a_hostname` rejection of R6.3: a spelling that is never
/// reinterpreted as an address.
fn not_a_hostname(message: &'static str) -> WebhookError {
    WebhookError::with_reason(BAD_REQUEST, NOT_A_HOSTNAME, NOT_A_HOSTNAME, message)
}

/// Returns the `invalid_callback_url` rejection with reason `host` of R6.2.
fn host_not_acceptable() -> WebhookError {
    WebhookError::with_reason(
        BAD_REQUEST,
        INVALID_CALLBACK_URL,
        HOST_REASON,
        "the host is not acceptable",
    )
}

/// Parses a host into its normalized form (spec 06 R6.3, R6.4).
///
/// A bracketed IPv6 literal is normalized to its RFC 5952 spelling and kept
/// bracketed; a canonical dotted quad is kept verbatim; anything else must be
/// an ASCII LDH name, lowercased with exactly one trailing dot stripped.
pub fn parse_host(host: &str) -> Result<ParsedHost, WebhookError> {
    if host.is_empty() {
        return Err(not_a_hostname("the host is empty"));
    }
    if host.starts_with('[') {
        if !host.ends_with(']') {
            return Err(host_not_acceptable());
        }
        let inner = &host[1..host.len() - 1];
        if inner.contains('[') || inner.contains(']') || inner.contains('%') {
            return Err(host_not_acceptable());
        }
        let Some(bytes) = parse_ipv6(inner) else {
            return Err(host_not_acceptable());
        };
        let address = format_ipv6(&bytes);
        return Ok(ParsedHost {
            kind: HostKind::Ipv6,
            normalized: format!("[{address}]"),
            address_or_name: address,
        });
    }
    if host.contains('[') || host.contains(']') {
        return Err(host_not_acceptable());
    }
    if let Some(bytes) = parse_ipv4(host) {
        let address = format_ipv4(&bytes);
        return Ok(ParsedHost {
            kind: HostKind::Ipv4,
            normalized: address.clone(),
            address_or_name: address,
        });
    }
    let stripped = host.strip_suffix('.').unwrap_or(host);
    let name = stripped.to_ascii_lowercase();
    if !is_ldh_name(&name) {
        return Err(not_a_hostname(
            "the host is not a dotted quad, a bracketed IPv6 literal or an LDH name",
        ));
    }
    Ok(ParsedHost {
        kind: HostKind::Name,
        normalized: name.clone(),
        address_or_name: name,
    })
}

/// Parses a canonical dotted quad (spec 06 R6.4): four decimal octets 0-255,
/// no leading zeros, no sign and no whitespace.
pub fn parse_ipv4(text: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut bytes = [0u8; 4];
    for (index, part) in parts.iter().enumerate() {
        bytes[index] = decimal_group(part)?;
    }
    Some(bytes)
}

/// Parses one dotted-quad octet: `0` or `[1-9][0-9]{0,2}`, at most 255
/// (spec 06 R6.4).
fn decimal_group(text: &str) -> Option<u8> {
    if text.is_empty() || text.len() > 3 {
        return None;
    }
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if text.len() > 1 && text.starts_with('0') {
        return None;
    }
    let value: u16 = text.parse().ok()?;
    if value > 255 {
        return None;
    }
    Some(value as u8)
}

/// Parses an IPv6 literal (spec 06 R6.7): 1-8 hex groups, one `::`
/// compression, at most one embedded IPv4 in the final group, no zone id and
/// no brackets.
pub fn parse_ipv6(text: &str) -> Option<[u8; 16]> {
    if text.contains('%') || text.contains('[') || text.contains(']') {
        return None;
    }
    let gap = text.find("::");
    if let Some(gap) = gap {
        if text[gap + 2..].contains("::") {
            return None;
        }
    }
    let compressed = gap.is_some();
    let (head, tail): (Vec<&str>, Vec<&str>) = match gap {
        Some(gap) => {
            let head: Vec<&str> = if gap == 0 {
                Vec::new()
            } else {
                text[..gap].split(':').collect()
            };
            let tail_text = &text[gap + 2..];
            let tail: Vec<&str> = if tail_text.is_empty() {
                Vec::new()
            } else {
                tail_text.split(':').collect()
            };
            (head, tail)
        }
        None => (text.split(':').collect(), Vec::new()),
    };
    let head_values = hex_groups(&head, !compressed)?;
    let tail_values = hex_groups(&tail, compressed)?;
    let total = head_values.len() + tail_values.len();
    if compressed {
        if total > 7 {
            return None;
        }
    } else if total != 8 {
        return None;
    }
    let mut values = Vec::with_capacity(8);
    values.extend_from_slice(&head_values);
    if compressed {
        values.extend(std::iter::repeat_n(0, 8 - total));
    }
    values.extend_from_slice(&tail_values);
    let mut bytes = [0u8; 16];
    for (index, value) in values.iter().enumerate() {
        bytes[index * 2] = (value >> 8) as u8;
        bytes[index * 2 + 1] = (value & 0xff) as u8;
    }
    Some(bytes)
}

/// Parses the groups on one side of a `::` compression; the final group of an
/// uncompressed literal may be an embedded dotted quad (spec 06 R6.7).
fn hex_groups(parts: &[&str], allow_dotted_last: bool) -> Option<Vec<u16>> {
    let mut out = Vec::with_capacity(parts.len());
    for (index, part) in parts.iter().enumerate() {
        if allow_dotted_last && index + 1 == parts.len() && part.contains('.') {
            let quad = parse_ipv4(part)?;
            out.push((u16::from(quad[0]) << 8) | u16::from(quad[1]));
            out.push((u16::from(quad[2]) << 8) | u16::from(quad[3]));
            continue;
        }
        out.push(hex_group(part)?);
    }
    Some(out)
}

/// Parses one `[0-9a-fA-F]{1,4}` group (spec 06 R6.7).
fn hex_group(text: &str) -> Option<u16> {
    if text.is_empty() || text.len() > 4 {
        return None;
    }
    if !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u16::from_str_radix(text, 16).ok()
}

/// Formats four bytes as a canonical dotted quad (spec 06 R6.4).
pub fn format_ipv4(bytes: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

/// Formats sixteen bytes as the RFC 5952 compressed lowercase form; the
/// IPv4-mapped shape keeps its dotted quad (spec 06 R6.6).
pub fn format_ipv6(bytes: &[u8; 16]) -> String {
    if is_ipv4_mapped(bytes) {
        return format!(
            "::ffff:{}",
            format_ipv4(&[bytes[12], bytes[13], bytes[14], bytes[15]])
        );
    }
    let mut groups = [0u16; 8];
    for (index, group) in groups.iter_mut().enumerate() {
        *group = (u16::from(bytes[index * 2]) << 8) | u16::from(bytes[index * 2 + 1]);
    }
    let mut best_start = 0usize;
    let mut best_len = 0usize;
    let mut index = 0usize;
    while index < 8 {
        if groups[index] != 0 {
            index += 1;
            continue;
        }
        let mut next = index;
        while next < 8 && groups[next] == 0 {
            next += 1;
        }
        if next - index > best_len {
            best_start = index;
            best_len = next - index;
        }
        index = next;
    }
    let hex: Vec<String> = groups.iter().map(|group| format!("{group:x}")).collect();
    if best_len < 2 {
        return hex.join(":");
    }
    format!(
        "{}::{}",
        hex[..best_start].join(":"),
        hex[best_start + best_len..].join(":")
    )
}

/// Returns true for the IPv4-mapped `::ffff:a.b.c.d` shape (spec 06 R6.7).
pub(crate) fn is_ipv4_mapped(bytes: &[u8; 16]) -> bool {
    bytes[..10].iter().all(|byte| *byte == 0) && bytes[10] == 0xff && bytes[11] == 0xff
}

/// Returns true for an ASCII LDH name (spec 06 R6.3): two or more labels of
/// 1-63 `[A-Za-z0-9-]` characters without an edge hyphen, at most 253
/// characters, and a last label that is not all-numeric.
pub fn is_ldh_name(name: &str) -> bool {
    if name.len() > NAME_MAX_LEN {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if !is_ldh_label(label) {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
    }
    !labels[labels.len() - 1]
        .bytes()
        .all(|byte| byte.is_ascii_digit())
}

/// Returns true for one `[A-Za-z0-9-]{1,63}` label (spec 06 R6.3).
fn is_ldh_label(label: &str) -> bool {
    if label.is_empty() || label.len() > LABEL_MAX_LEN {
        return false;
    }
    label
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}
