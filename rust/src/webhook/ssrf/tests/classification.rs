//! Classification unit tests (spec 06 R6.5-R6.7, R6.11).
//!
//! Every row of `IPV4_BLOCKS` and `IPV6_BLOCKS` is exercised at the first and
//! the last address of its own block, the edges are rebuilt from the CIDR text
//! rather than copied, and the R6.7 translation-chain examples are asserted
//! with their exact composed reason strings.

use crate::webhook::ssrf::delivery::{
    classify_address, classify_with_ranges, delivery_decision, AddressClass, DeliveryDecision,
    DeliveryInput,
};
use crate::webhook::ssrf::tables::{
    classify_ipv4, classify_ipv6, AddressVerdict, Decision, IPV4_BLOCKS, IPV6_BLOCKS,
};
use crate::webhook::ssrf::{parse_ipv4, parse_ipv6, CidrFamily};

/// One documented edge whose verdict belongs to a more specific row or to the
/// R6.7 chain rule rather than to the row that owns the block:
/// `(block, first edge, reason, globally reachable)`.
///
/// The block edges are the network address and the all-host-bits address, and
/// both can land inside a narrower row of the same table (R6.5, R6.6: the
/// longest match wins) or inside a translation chain (R6.7).
type EdgeOverride = (&'static str, bool, &'static str, bool);

/// IPv4 edges shadowed by the `0.0.0.0/32` row, the `192.0.0.0/29` row and
/// the `255.255.255.255/32` row (spec 06 R6.5).
const IPV4_EDGE_OVERRIDES: [EdgeOverride; 3] = [
    ("0.0.0.0/8", true, "this_host_on_this_network", false),
    (
        "192.0.0.0/24",
        true,
        "ipv4_service_continuity_prefix",
        false,
    ),
    ("240.0.0.0/4", false, "limited_broadcast", false),
];

/// IPv6 edges shadowed by `::/128`, by the `ipv4_mapped` and
/// `nat64_well_known` chains and by the `teredo` branch (spec 06 R6.6, R6.7).
const IPV6_EDGE_OVERRIDES: [EdgeOverride; 6] = [
    ("::/96", true, "unspecified", false),
    (
        "::ffff:0:0/96",
        true,
        "ipv4_mapped/this_host_on_this_network",
        false,
    ),
    (
        "::ffff:0:0/96",
        false,
        "ipv4_mapped/limited_broadcast",
        false,
    ),
    (
        "64:ff9b::/96",
        true,
        "nat64_well_known/this_host_on_this_network",
        false,
    ),
    (
        "64:ff9b::/96",
        false,
        "nat64_well_known/limited_broadcast",
        false,
    ),
    ("2001::/23", true, "teredo", false),
];

/// One R6.7 translation or tunneling vector: the literal, its decision and its
/// exact reason string (spec 06 R6.7).
struct ChainCase {
    address: &'static str,
    decision: Decision,
    reason: &'static str,
}

/// The R6.7 table plus the two allowed chain forms, whose reason is the bare
/// chain name because the embedded address is in no IPv4 row.
const R6_7_CHAINS: [ChainCase; 9] = [
    ChainCase {
        address: "::ffff:127.0.0.1",
        decision: Decision::Reject,
        reason: "ipv4_mapped/loopback",
    },
    ChainCase {
        address: "::ffff:8.8.8.8",
        decision: Decision::Allow,
        reason: "ipv4_mapped",
    },
    ChainCase {
        address: "64:ff9b::10.0.0.1",
        decision: Decision::Reject,
        reason: "nat64_well_known/private_use",
    },
    ChainCase {
        address: "64:ff9b::8.8.8.8",
        decision: Decision::Allow,
        reason: "nat64_well_known",
    },
    ChainCase {
        address: "2002:7f00:1::",
        decision: Decision::Reject,
        reason: "six_to_four",
    },
    ChainCase {
        address: "2001:0:4136:e378::",
        decision: Decision::Reject,
        reason: "teredo",
    },
    ChainCase {
        address: "2001::",
        decision: Decision::Reject,
        reason: "teredo",
    },
    ChainCase {
        address: "64:ff9b:1::1",
        decision: Decision::Reject,
        reason: "nat64_local_use",
    },
    ChainCase {
        address: "2002::1",
        decision: Decision::Reject,
        reason: "six_to_four",
    },
];

/// One `classify_address` vector: the spelling, its decision, its reason and
/// the family of the literal, `None` when the spelling is not a literal.
struct AddressCase {
    address: &'static str,
    decision: Decision,
    reason: &'static str,
    family: Option<CidrFamily>,
}

/// Global addresses, the two allowed registry rows and unparsable spellings
/// (spec 06 R6.5, R6.7).
const ADDRESS_CASES: [AddressCase; 7] = [
    AddressCase {
        address: "8.8.8.8",
        decision: Decision::Allow,
        reason: "global",
        family: Some(CidrFamily::V4),
    },
    AddressCase {
        address: "2606:4700::1111",
        decision: Decision::Allow,
        reason: "global",
        family: Some(CidrFamily::V6),
    },
    AddressCase {
        address: "192.0.0.9",
        decision: Decision::Allow,
        reason: "pcp_anycast",
        family: Some(CidrFamily::V4),
    },
    AddressCase {
        address: "2620:4f:8000::1",
        decision: Decision::Allow,
        reason: "as112_direct_delegation",
        family: Some(CidrFamily::V6),
    },
    AddressCase {
        address: "::ffff:127.0.0.1",
        decision: Decision::Reject,
        reason: "ipv4_mapped/loopback",
        family: Some(CidrFamily::V6),
    },
    AddressCase {
        address: "127.1",
        decision: Decision::Reject,
        reason: "not_a_hostname",
        family: None,
    },
    AddressCase {
        address: "hooks.example.test",
        decision: Decision::Reject,
        reason: "not_a_hostname",
        family: None,
    },
];

/// The expected verdict of one block edge.
struct Expectation {
    decision: Decision,
    reason: &'static str,
}

/// Splits `<literal>/<prefix>`, panicking on a table entry that does not
/// parse; the tables are constants, so this never fires at run time.
fn split_block(cidr: &str) -> (&str, u8) {
    let (literal, prefix) = match cidr.rsplit_once('/') {
        Some(parts) => parts,
        None => panic!("table entry {cidr} has no prefix"),
    };
    let prefix = match prefix.parse::<u8>() {
        Ok(prefix) => prefix,
        Err(_) => panic!("table entry {cidr} has no decimal prefix"),
    };
    (literal, prefix)
}

/// Rebuilds the two edges of one block: every host bit cleared for the first
/// address and every host bit set for the last (spec 06 R6.5, R6.6).
fn block_edges(cidr: &str) -> (Vec<u8>, Vec<u8>) {
    let (literal, prefix) = split_block(cidr);
    let bytes = if literal.contains(':') {
        match parse_ipv6(literal) {
            Some(bytes) => bytes.to_vec(),
            None => panic!("table entry {cidr} has no IPv6 literal"),
        }
    } else {
        match parse_ipv4(literal) {
            Some(bytes) => bytes.to_vec(),
            None => panic!("table entry {cidr} has no IPv4 literal"),
        }
    };
    let first = with_host_bits(&bytes, prefix, false);
    let last = with_host_bits(&bytes, prefix, true);
    (first, last)
}

/// Returns `bytes` with every bit beyond `prefix` cleared, or set to one.
fn with_host_bits(bytes: &[u8], prefix: u8, set: bool) -> Vec<u8> {
    let fill = if set { u8::MAX } else { 0 };
    bytes
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            let start = index * 8;
            if start >= usize::from(prefix) {
                return fill;
            }
            let covered = usize::from(prefix) - start;
            if covered >= 8 {
                return *byte;
            }
            let keep = u8::MAX << (8 - covered);
            (*byte & keep) | (fill & !keep)
        })
        .collect()
}

/// Returns the verdict an edge must carry: the override row when one is
/// documented for this edge, otherwise the row's own reason and decision.
fn edge_expectation(
    block: &str,
    first: bool,
    reason: &'static str,
    reachable: bool,
    overrides: &[EdgeOverride],
) -> Expectation {
    for &(override_block, override_first, override_reason, override_reachable) in overrides {
        if override_block == block && override_first == first {
            return Expectation {
                decision: if override_reachable {
                    Decision::Allow
                } else {
                    Decision::Reject
                },
                reason: override_reason,
            };
        }
    }
    Expectation {
        decision: if reachable {
            Decision::Allow
        } else {
            Decision::Reject
        },
        reason,
    }
}

/// Asserts one verdict against its expected decision and reason.
fn assert_verdict(verdict: &AddressVerdict, expected: &Expectation, block: &str, first: bool) {
    let edge = if first { "first" } else { "last" };
    assert_eq!(
        verdict.decision, expected.decision,
        "{edge} address of {block}"
    );
    assert_eq!(verdict.reason, expected.reason, "{edge} address of {block}");
}

/// Copies the first four bytes of a block edge into a dotted-quad word.
fn quad(bytes: &[u8]) -> [u8; 4] {
    let mut out = [0u8; 4];
    out.copy_from_slice(&bytes[..4]);
    out
}

/// Copies a block edge into a sixteen-byte word.
fn word(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[..16]);
    out
}

/// Returns the range overrides as owned entries, the shape the api takes.
fn ranges(entries: &[&str]) -> Vec<String> {
    entries.iter().map(|entry| (*entry).to_string()).collect()
}

/// Runs one `classify_with_ranges` call with owned range entries.
fn classify(text: &str, entries: &[&str]) -> AddressClass {
    classify_with_ranges(text, &ranges(entries))
}

#[test]
fn every_ipv4_row_covers_both_edges_of_its_block() {
    for &(block, reason, reachable) in &IPV4_BLOCKS {
        let (first, last) = block_edges(block);
        for (edge_first, bytes) in [(true, &first), (false, &last)] {
            let verdict = classify_ipv4(&quad(bytes));
            let expected =
                edge_expectation(block, edge_first, reason, reachable, &IPV4_EDGE_OVERRIDES);
            assert_verdict(&verdict, &expected, block, edge_first);
        }
    }
}

#[test]
fn every_ipv6_row_covers_both_edges_of_its_block() {
    for &(block, reason, reachable) in &IPV6_BLOCKS {
        let (first, last) = block_edges(block);
        for (edge_first, bytes) in [(true, &first), (false, &last)] {
            let verdict = classify_ipv6(&word(bytes));
            let expected =
                edge_expectation(block, edge_first, reason, reachable, &IPV6_EDGE_OVERRIDES);
            assert_verdict(&verdict, &expected, block, edge_first);
        }
    }
}

#[test]
fn r6_7_chains_compose_the_exact_reason() {
    for case in &R6_7_CHAINS {
        let bytes = match parse_ipv6(case.address) {
            Some(bytes) => bytes,
            None => panic!("{} is not an IPv6 literal", case.address),
        };
        let verdict = classify_ipv6(&bytes);
        assert_eq!(verdict.decision, case.decision, "{} decision", case.address);
        assert_eq!(verdict.reason, case.reason, "{} reason", case.address);
    }
}

#[test]
fn classify_address_covers_global_allowed_and_unparsable_spellings() {
    for case in &ADDRESS_CASES {
        let class = classify_address(case.address);
        assert_eq!(class.decision, case.decision, "{} decision", case.address);
        assert_eq!(class.reason, case.reason, "{} reason", case.address);
        assert_eq!(class.family, case.family, "{} family", case.address);
        match case.family {
            Some(_) => assert_eq!(
                class.address.as_deref(),
                Some(case.address),
                "{} canonical",
                case.address
            ),
            None => assert_eq!(class.address, None, "{} canonical", case.address),
        }
    }
}

#[test]
fn classify_address_global_is_the_bare_global_reason() {
    let class = classify_address("8.8.8.8");
    assert_eq!(class.decision, Decision::Allow);
    assert_eq!(class.reason, "global");
    assert_eq!(class.address.as_deref(), Some("8.8.8.8"));
}

#[test]
fn classify_with_ranges_overrides_a_rejected_ipv4_address() {
    let class = classify("10.0.0.5", &["10.0.0.0/8"]);
    assert_eq!(class.decision, Decision::Allow);
    assert_eq!(class.reason, "allowed_range");
    assert_eq!(class.family, Some(CidrFamily::V4));
    assert_eq!(class.address.as_deref(), Some("10.0.0.5"));
}

#[test]
fn classify_with_ranges_overrides_a_rejected_ipv6_address() {
    let class = classify("2001:db8::1", &["2001:db8::/32"]);
    assert_eq!(class.decision, Decision::Allow);
    assert_eq!(class.reason, "allowed_range");
    assert_eq!(class.family, Some(CidrFamily::V6));
    assert_eq!(class.address.as_deref(), Some("2001:db8::1"));
}

#[test]
fn classify_with_ranges_ignores_malformed_and_foreign_entries() {
    let class = classify("10.0.0.5", &["not a range", "10.0.0.0/8"]);
    assert_eq!(class.decision, Decision::Allow);
    assert_eq!(class.reason, "allowed_range");

    let class = classify("10.0.0.5", &["192.168.0.0/16"]);
    assert_eq!(class.decision, Decision::Reject);
    assert_eq!(class.reason, "private_use");

    let class = classify("2001:db8::1", &["10.0.0.0/8"]);
    assert_eq!(class.decision, Decision::Reject);
    assert_eq!(class.reason, "documentation");

    let class = classify("8.8.8.8", &["8.8.8.0/24"]);
    assert_eq!(class.decision, Decision::Allow);
    assert_eq!(class.reason, "global");
}

#[test]
fn classify_with_ranges_never_rescues_an_unparsable_spelling() {
    let class = classify("127.1", &["0.0.0.0/0"]);
    assert_eq!(class.decision, Decision::Reject);
    assert_eq!(class.reason, "not_a_hostname");
    assert_eq!(class.family, None);
    assert_eq!(class.address, None);
}

#[test]
fn allowed_ranges_never_rescue_a_non_https_scheme() {
    let answers = ["10.0.0.7".to_string()];
    let ranges = ["10.0.0.0/8".to_string()];
    let input = DeliveryInput {
        url: "http://hooks.example.test/hook",
        answers: &answers,
        recheck: &[],
        allowed_ranges: &ranges,
        redirect_status: None,
    };
    match delivery_decision(&input) {
        DeliveryDecision::Reject { code, reason } => {
            assert_eq!(code, "scheme_not_https");
            assert_eq!(reason, "");
        }
        other => panic!("{other:?}"),
    }
}
