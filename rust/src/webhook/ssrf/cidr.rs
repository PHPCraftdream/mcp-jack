//! CIDR ranges of spec 06 R6.11: `<literal>/<decimal prefix>` with zero host
//! bits beyond the prefix, a containment test, and the address-literal parse
//! shared by the classification of R6.5-R6.7.
//!
//! A range is parsed once into bytes and a prefix; containment is exact bit
//! matching, never a text comparison.

use crate::webhook::ssrf::host::{format_ipv4, format_ipv6, parse_ipv4, parse_ipv6};

/// The address family of a range or a literal (spec 06 R6.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CidrFamily {
    /// An IPv4 `a.b.c.d/0-32` range (spec 06 R6.11).
    V4,
    /// An IPv6 `hex::/0-128` range (spec 06 R6.11).
    V6,
}

impl CidrFamily {
    /// Returns the discriminator of the family: `ipv4` or `ipv6`
    /// (spec 06 R6.11).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V4 => "ipv4",
            Self::V6 => "ipv6",
        }
    }
}

/// A parsed CIDR range with a canonical network literal and a decimal prefix
/// (spec 06 R6.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    family: CidrFamily,
    prefix: u8,
    bytes: Vec<u8>,
}

impl Cidr {
    /// Returns the family of the range (spec 06 R6.11).
    pub fn family(&self) -> CidrFamily {
        self.family
    }

    /// Returns the prefix length in bits (spec 06 R6.11).
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Returns true when an IPv4 address is inside this range; an IPv6 range
    /// never contains an IPv4 address (spec 06 R6.11).
    pub fn contains_ipv4(&self, address: &[u8; 4]) -> bool {
        self.family == CidrFamily::V4 && match_prefix(address, &self.bytes, self.prefix)
    }

    /// Returns true when an IPv6 address is inside this range; an IPv4 range
    /// never contains an IPv6 address (spec 06 R6.11).
    pub fn contains_ipv6(&self, address: &[u8; 16]) -> bool {
        self.family == CidrFamily::V6 && match_prefix(address, &self.bytes, self.prefix)
    }
}

/// Parses `<literal>/<prefix>` (spec 06 R6.11): exactly one `/`, a decimal
/// prefix of at most three digits without a leading zero, a canonical IPv4 or
/// IPv6 literal, and zero host bits beyond the prefix.
pub fn parse_cidr(text: &str) -> Option<Cidr> {
    let slash = text.find('/')?;
    let prefix_text = &text[slash + 1..];
    if prefix_text.contains('/') || !is_prefix_text(prefix_text) {
        return None;
    }
    let prefix: u8 = prefix_text.parse().ok()?;
    let literal = &text[..slash];
    let family = if literal.contains(':') {
        CidrFamily::V6
    } else {
        CidrFamily::V4
    };
    let limit: u8 = match family {
        CidrFamily::V4 => 32,
        CidrFamily::V6 => 128,
    };
    if prefix > limit {
        return None;
    }
    let bytes = match family {
        CidrFamily::V4 => parse_ipv4(literal)?.to_vec(),
        CidrFamily::V6 => parse_ipv6(literal)?.to_vec(),
    };
    if !host_bits_zero(&bytes, prefix) {
        return None;
    }
    Some(Cidr {
        family,
        prefix,
        bytes,
    })
}

/// Returns true when `address` is an address literal inside `cidr`
/// (spec 06 R6.11); a non-literal spelling and a family mismatch are false.
pub fn cidr_contains(cidr: &Cidr, address: &str) -> bool {
    let Some(parsed) = parse_address(address) else {
        return false;
    };
    if parsed.family != cidr.family() {
        return false;
    }
    match parsed.family {
        CidrFamily::V4 => {
            let mut quad = [0u8; 4];
            quad.copy_from_slice(&parsed.bytes[..4]);
            cidr.contains_ipv4(&quad)
        }
        CidrFamily::V6 => cidr.contains_ipv6(&parsed.bytes),
    }
}

/// An address literal in its canonical spelling (spec 06 R6.4, R6.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedAddress {
    /// The family of the literal (spec 06 R6.11).
    pub(crate) family: CidrFamily,
    /// The address bytes, zero-padded to sixteen for an IPv4 literal.
    pub(crate) bytes: [u8; 16],
    /// The canonical spelling (spec 06 R6.4, R6.6).
    pub(crate) address: String,
}

/// Parses one address literal, optionally bracketed (spec 06 R6.4, R6.6);
/// every other spelling is `None` and is never reinterpreted.
pub(crate) fn parse_address(text: &str) -> Option<ParsedAddress> {
    let mut input = text;
    if input.len() >= 2 && input.starts_with('[') && input.ends_with(']') {
        input = &input[1..input.len() - 1];
    }
    if let Some(quad) = parse_ipv4(input) {
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&quad);
        return Some(ParsedAddress {
            family: CidrFamily::V4,
            bytes,
            address: format_ipv4(&quad),
        });
    }
    if let Some(v6) = parse_ipv6(input) {
        return Some(ParsedAddress {
            family: CidrFamily::V6,
            bytes: v6,
            address: format_ipv6(&v6),
        });
    }
    None
}

/// Returns true for a decimal prefix of at most three digits without a
/// leading zero (spec 06 R6.11).
fn is_prefix_text(text: &str) -> bool {
    if text.is_empty() || text.len() > 3 {
        return false;
    }
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    !(text.len() > 1 && text.starts_with('0'))
}

/// Returns true when every bit after the prefix is zero (spec 06 R6.11).
fn host_bits_zero(bytes: &[u8], prefix: u8) -> bool {
    let whole = usize::from(prefix >> 3);
    let rest_bits = prefix & 7;
    if rest_bits == 0 {
        return bytes[whole..].iter().all(|byte| *byte == 0);
    }
    let mask = 0xffu8 << (8 - rest_bits);
    (bytes[whole] & !mask) == 0 && bytes[whole + 1..].iter().all(|byte| *byte == 0)
}

/// Returns true when `bytes` and `network` agree on the first `prefix` bits
/// (spec 06 R6.11).
fn match_prefix(bytes: &[u8], network: &[u8], prefix: u8) -> bool {
    if bytes.len() != network.len() {
        return false;
    }
    let whole = usize::from(prefix >> 3);
    if bytes[..whole] != network[..whole] {
        return false;
    }
    let rest_bits = prefix & 7;
    if rest_bits == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest_bits);
    (bytes[whole] & mask) == (network[whole] & mask)
}
