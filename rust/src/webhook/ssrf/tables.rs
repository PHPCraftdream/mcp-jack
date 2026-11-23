//! The IANA special-purpose registries of spec 06 R6.5 and R6.6, the
//! translation chains of R6.7 and the one decision rule over both families:
//! `allow` when the longest matching row is globally reachable and `reject`
//! otherwise; an address in no row is `allow` with reason `global`.
//!
//! Rows overlap on purpose (`0.0.0.0/8` contains the registry's own
//! `0.0.0.0/32` row, `192.0.0.0/24` contains the `/29` and `/32` rows, and
//! `2001::/23` contains the more specific `2001::/32` rows), so the longest
//! match decides.

use crate::webhook::ssrf::cidr::parse_cidr;
use crate::webhook::ssrf::host::is_ipv4_mapped;

/// IPv4 special-purpose blocks (spec 06 R6.5): `(cidr, reason, globally
/// reachable)`. The reason is always the row's registry name in snake_case.
pub const IPV4_BLOCKS: [(&str, &str, bool); 27] = [
    ("0.0.0.0/8", "this_network", false),
    ("0.0.0.0/32", "this_host_on_this_network", false),
    ("10.0.0.0/8", "private_use", false),
    ("100.64.0.0/10", "shared_address_space", false),
    ("127.0.0.0/8", "loopback", false),
    ("169.254.0.0/16", "link_local", false),
    ("172.16.0.0/12", "private_use", false),
    ("192.0.0.0/24", "ietf_protocol_assignments", false),
    ("192.0.0.0/29", "ipv4_service_continuity_prefix", false),
    ("192.0.0.8/32", "ipv4_dummy_address", false),
    ("192.0.0.9/32", "pcp_anycast", true),
    ("192.0.0.10/32", "turn_anycast", true),
    ("192.0.0.170/32", "nat64_dns64_discovery", false),
    ("192.0.0.171/32", "nat64_dns64_discovery", false),
    ("192.0.2.0/24", "documentation", false),
    ("192.31.196.0/24", "as112_v4", true),
    ("192.52.193.0/24", "amt", true),
    ("192.88.99.0/24", "deprecated_6to4_relay_anycast", false),
    ("192.88.99.2/32", "6a44_relay_anycast", false),
    ("192.168.0.0/16", "private_use", false),
    ("192.175.48.0/24", "as112_direct_delegation", true),
    ("198.18.0.0/15", "benchmarking", false),
    ("198.51.100.0/24", "documentation", false),
    ("203.0.113.0/24", "documentation", false),
    ("224.0.0.0/4", "multicast", false),
    ("240.0.0.0/4", "reserved", false),
    ("255.255.255.255/32", "limited_broadcast", false),
];

/// IPv6 special-purpose blocks (spec 06 R6.6): `(cidr, reason, globally
/// reachable)`, with the same decision rule as `IPV4_BLOCKS`.
pub const IPV6_BLOCKS: [(&str, &str, bool); 27] = [
    ("::/128", "unspecified", false),
    ("::1/128", "loopback", false),
    ("::/96", "ipv4_compatible_deprecated", false),
    ("::ffff:0:0/96", "ipv4_mapped", false),
    ("64:ff9b::/96", "nat64_well_known", true),
    ("64:ff9b:1::/48", "nat64_local_use", false),
    ("100::/64", "discard_only", false),
    ("100:0:0:1::/64", "dummy_ipv6_prefix", false),
    ("2001::/23", "ietf_protocol_assignments", false),
    ("2001::/32", "teredo", false),
    ("2001:1::1/128", "pcp_anycast", true),
    ("2001:1::2/128", "turn_anycast", true),
    ("2001:1::3/128", "dns_sd_srp_anycast", true),
    ("2001:2::/48", "benchmarking", false),
    ("2001:3::/32", "amt", true),
    ("2001:4:112::/48", "as112_v6", true),
    ("2001:10::/28", "orchid", false),
    ("2001:20::/28", "orchidv2", true),
    ("2001:30::/28", "drone_remote_id", true),
    ("2001:db8::/32", "documentation", false),
    ("2002::/16", "six_to_four", false),
    ("2620:4f:8000::/48", "as112_direct_delegation", true),
    ("3fff::/20", "documentation", false),
    ("5f00::/16", "srv6_sid", false),
    ("fc00::/7", "unique_local", false),
    ("fe80::/10", "link_local", false),
    ("ff00::/8", "multicast", false),
];

/// The reason of an address in no registry row (spec 06 R6.5).
const GLOBAL: &str = "global";

/// The number of leading bytes of the fixed NAT64 well-known embedding
/// (spec 06 R6.7).
const NAT64_WELL_KNOWN_LEN: usize = 12;

/// The first twelve bytes of `64:ff9b::/96` (spec 06 R6.7).
const NAT64_WELL_KNOWN: [u8; NAT64_WELL_KNOWN_LEN] =
    [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];

/// The allow/reject decision of one address (spec 06 R6.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The longest matching row is globally reachable, or no row matches.
    Allow,
    /// The longest matching row is not globally reachable.
    Reject,
}

impl Decision {
    /// Returns the discriminator of the decision: `allow` or `reject`
    /// (spec 06 R6.5).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Reject => "reject",
        }
    }
}

/// The decision and its reason for one address (spec 06 R6.5, R6.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressVerdict {
    /// The decision over both tables (spec 06 R6.5).
    pub decision: Decision,
    /// The row's registry name, the translation-chain composition, or
    /// `global` (spec 06 R6.5, R6.7).
    pub reason: String,
}

/// One best row while scanning a table: `(reason, globally reachable,
/// prefix)`.
type BestRow = (&'static str, bool, u8);

/// Classifies an IPv4 address by the longest matching `IPV4_BLOCKS` row
/// (spec 06 R6.5).
pub fn classify_ipv4(bytes: &[u8; 4]) -> AddressVerdict {
    let mut best: Option<BestRow> = None;
    for &(block, name, reachable) in &IPV4_BLOCKS {
        let Some(cidr) = parse_cidr(block) else {
            continue;
        };
        if best.is_some_and(|(_, _, prefix)| cidr.prefix() <= prefix) {
            continue;
        }
        if cidr.contains_ipv4(bytes) {
            best = Some((name, reachable, cidr.prefix()));
        }
    }
    best.map_or_else(global_verdict, row_verdict)
}

/// Classifies an IPv6 address: the translation chains of R6.7 first, then the
/// longest matching `IPV6_BLOCKS` row (spec 06 R6.6).
pub fn classify_ipv6(bytes: &[u8; 16]) -> AddressVerdict {
    if is_ipv4_mapped(bytes) {
        let embedded = classify_ipv4(&embedded_ipv4(bytes));
        return AddressVerdict {
            decision: embedded.decision,
            reason: chain_reason("ipv4_mapped", &embedded),
        };
    }
    if bytes[..NAT64_WELL_KNOWN_LEN] == NAT64_WELL_KNOWN {
        let embedded = classify_ipv4(&embedded_ipv4(bytes));
        return AddressVerdict {
            decision: embedded.decision,
            reason: chain_reason("nat64_well_known", &embedded),
        };
    }
    // R6.7: 2002::/16 and 2001::/32 block on their own; the embedded address
    // is no longer consulted and the row's name is the single reason string.
    if bytes[0] == 0x20 && bytes[1] == 0x02 {
        return reject_verdict("six_to_four");
    }
    if bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0 && bytes[3] == 0 {
        return reject_verdict("teredo");
    }
    let mut best: Option<BestRow> = None;
    for &(block, name, reachable) in &IPV6_BLOCKS {
        let Some(cidr) = parse_cidr(block) else {
            continue;
        };
        if best.is_some_and(|(_, _, prefix)| cidr.prefix() <= prefix) {
            continue;
        }
        if cidr.contains_ipv6(bytes) {
            best = Some((name, reachable, cidr.prefix()));
        }
    }
    best.map_or_else(global_verdict, row_verdict)
}

/// The address in no row: `allow` with reason `global` (spec 06 R6.5).
fn global_verdict() -> AddressVerdict {
    AddressVerdict {
        decision: Decision::Allow,
        reason: GLOBAL.to_string(),
    }
}

/// The verdict of the longest matching row: its reachability column picks the
/// decision and its name is the reason either way (spec 06 R6.5).
fn row_verdict(row: BestRow) -> AddressVerdict {
    let (name, reachable, _) = row;
    AddressVerdict {
        decision: if reachable {
            Decision::Allow
        } else {
            Decision::Reject
        },
        reason: name.to_string(),
    }
}

/// A `reject` verdict with the row's own name as the single reason
/// (spec 06 R6.7).
fn reject_verdict(reason: &'static str) -> AddressVerdict {
    AddressVerdict {
        decision: Decision::Reject,
        reason: reason.to_string(),
    }
}

/// Composes the reason of a translation chain: the chain name alone when the
/// embedded address is allowed, `chain/embedded reason` otherwise
/// (spec 06 R6.7).
fn chain_reason(chain: &str, embedded: &AddressVerdict) -> String {
    match embedded.decision {
        Decision::Allow => chain.to_string(),
        Decision::Reject => format!("{chain}/{}", embedded.reason),
    }
}

/// The embedded IPv4 address of a mapped or NAT64 IPv6 address
/// (spec 06 R6.7).
fn embedded_ipv4(bytes: &[u8; 16]) -> [u8; 4] {
    [bytes[12], bytes[13], bytes[14], bytes[15]]
}
