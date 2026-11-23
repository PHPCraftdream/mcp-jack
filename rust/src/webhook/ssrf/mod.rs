//! Delivery-time network rules and SSRF protection of spec 06 section 6
//! (R6.1-R6.11) plus the R5.11 dot-segment rule: host forms and IPv4/IPv6
//! literal parsing, the two IANA special-purpose tables with their translation
//! chains, CIDR ranges for the operator override, callback-url validation with
//! the R8.2 canonical form, and the one delivery decision of `R6.8`.
//!
//! Everything here is pure: no resolver, no I/O, no clock. The caller supplies
//! the resolver answers and the re-resolution, and gets a `ConnectTarget` to
//! connect to or a fixed-literal rejection. A rejection never echoes a request
//! byte.

pub mod cidr;
pub mod delivery;
pub mod host;
pub mod tables;
pub mod url;

#[cfg(test)]
mod tests;

pub use cidr::{cidr_contains, parse_cidr, Cidr, CidrFamily};
pub use delivery::{
    classify_address, classify_with_ranges, delivery_decision, AddressClass, ConnectTarget,
    DeliveryDecision, DeliveryInput,
};
pub use host::{
    format_ipv4, format_ipv6, is_ldh_name, parse_host, parse_ipv4, parse_ipv6, HostKind, ParsedHost,
};
pub use tables::{
    classify_ipv4, classify_ipv6, AddressVerdict, Decision, IPV4_BLOCKS, IPV6_BLOCKS,
};
pub use url::{check_url, UrlParts};
