//! The delivery-time decision of spec 06 R6.8-R6.11: validate the url,
//! classify every resolver answer in order, refuse on the first reject, check
//! the re-resolution of R6.9 and return the connect target of R6.8.
//!
//! There is no resolver and no I/O here: the caller supplies the answers and
//! the recheck, exactly as the reference `checkDelivery` does.

use crate::webhook::ssrf::cidr::{parse_address, parse_cidr, CidrFamily, ParsedAddress};
use crate::webhook::ssrf::host::HostKind;
use crate::webhook::ssrf::tables::{classify_ipv4, classify_ipv6, AddressVerdict, Decision};
use crate::webhook::ssrf::url::check_url;

/// The R1.9 code of an answer whose decision is `reject` (spec 06 R6.8).
const BLOCKED_ADDRESS: &str = "blocked_address";

/// The R6.8 code of a hostname with no resolver answer.
const NO_ANSWER: &str = "no_answer";

/// The R6.9 code of a changed address between validation and connect.
const DNS_REBINDING: &str = "dns_rebinding";

/// The R6.10 code of a `3xx` response.
const REDIRECT_REFUSED: &str = "redirect_refused";

/// The R6.11 reason of an address rescued by the operator override.
const ALLOWED_RANGE: &str = "allowed_range";

/// The R6.5 reason of an address in no registry row.
const GLOBAL: &str = "global";

/// The reason of a spelling that is not an address literal (spec 06 R6.3).
const NOT_A_HOSTNAME: &str = "not_a_hostname";

/// The address to connect to and the names to present (spec 06 R6.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectTarget {
    /// The validated address; the connection must use exactly this one
    /// (spec 06 R6.8, R6.9).
    pub address: String,
    /// The `Host` header: the original host name plus `:port` when not 443,
    /// or the bracketed literal (spec 06 R6.8).
    pub host_header: String,
    /// The TLS SNI name: the host name, or `None` for an IP literal
    /// (spec 06 R6.8).
    pub sni: Option<String>,
}

/// The outcome of one delivery decision (spec 06 R6.8-R6.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryDecision {
    /// The attempt may connect to `connect` (spec 06 R6.8).
    Allow {
        /// The validated address and the names to present.
        connect: ConnectTarget,
        /// The reason of the first allowed answer, or `allowed_range`
        /// (spec 06 R6.8, R6.11).
        reason: String,
    },
    /// The attempt is refused before any request is sent (spec 06 R6.8-R6.10).
    Reject {
        /// The wire code of the refusal (spec 06 R6.8-R6.10).
        code: &'static str,
        /// The fixed-literal reason (spec 06 R6.8-R6.10).
        reason: String,
    },
}

/// The inputs of one delivery decision (spec 06 R6.8-R6.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryInput<'a> {
    /// The callback url exactly as supplied (spec 06 R6.1).
    pub url: &'a str,
    /// The resolver answers, in resolver order (spec 06 R6.8).
    pub answers: &'a [String],
    /// The answers of the re-resolution before connect (spec 06 R6.9).
    pub recheck: &'a [String],
    /// The operator override ranges of R6.11.
    pub allowed_ranges: &'a [String],
    /// The final status of the response, when one was already received: any
    /// value here is a `3xx` and is never followed (spec 06 R6.10).
    pub redirect_status: Option<u16>,
}

/// The classification of one address literal (spec 06 R6.4, R6.7, R6.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressClass {
    /// The decision (spec 06 R6.5).
    pub decision: Decision,
    /// The row's name, the chain composition, `global`, `allowed_range` or
    /// `not_a_hostname` (spec 06 R6.5, R6.11).
    pub reason: String,
    /// The family of the literal, `None` when it is not a literal
    /// (spec 06 R6.11).
    pub family: Option<CidrFamily>,
    /// The canonical spelling, `None` when it is not a literal
    /// (spec 06 R6.4, R6.6).
    pub address: Option<String>,
}

/// Classifies one address literal against both tables (spec 06 R6.4, R6.7).
pub fn classify_address(text: &str) -> AddressClass {
    let Some(parsed) = parse_address(text) else {
        return AddressClass {
            decision: Decision::Reject,
            reason: NOT_A_HOSTNAME.to_string(),
            family: None,
            address: None,
        };
    };
    let verdict = verdict_for(&parsed);
    AddressClass {
        decision: verdict.decision,
        reason: verdict.reason,
        family: Some(parsed.family),
        address: Some(parsed.address),
    }
}

/// Classifies one address literal, applying the operator override of R6.11
/// after the registry tables; an unparsable spelling is never rescued.
pub fn classify_with_ranges(text: &str, allowed_ranges: &[String]) -> AddressClass {
    let Some(parsed) = parse_address(text) else {
        return AddressClass {
            decision: Decision::Reject,
            reason: NOT_A_HOSTNAME.to_string(),
            family: None,
            address: None,
        };
    };
    let verdict = verdict_for(&parsed);
    if verdict.decision == Decision::Allow {
        return AddressClass {
            decision: Decision::Allow,
            reason: verdict.reason,
            family: Some(parsed.family),
            address: Some(parsed.address),
        };
    }
    let hit = allowed_ranges.iter().any(|entry| {
        parse_cidr(entry).is_some_and(|range| {
            range.family() == parsed.family
                && match parsed.family {
                    CidrFamily::V4 => {
                        let mut quad = [0u8; 4];
                        quad.copy_from_slice(&parsed.bytes[..4]);
                        range.contains_ipv4(&quad)
                    }
                    CidrFamily::V6 => range.contains_ipv6(&parsed.bytes),
                }
        })
    });
    if hit {
        return AddressClass {
            decision: Decision::Allow,
            reason: ALLOWED_RANGE.to_string(),
            family: Some(parsed.family),
            address: Some(parsed.address),
        };
    }
    AddressClass {
        decision: Decision::Reject,
        reason: verdict.reason,
        family: Some(parsed.family),
        address: Some(parsed.address),
    }
}

/// One delivery decision from the url, the resolver answers, the recheck and
/// the override ranges (spec 06 R6.8-R6.11).
pub fn delivery_decision(input: &DeliveryInput<'_>) -> DeliveryDecision {
    let checked = match check_url(input.url) {
        Ok(checked) => checked,
        Err(error) => {
            return DeliveryDecision::Reject {
                code: error.code,
                reason: error.reason.unwrap_or_default(),
            };
        }
    };
    if let Some(status) = input.redirect_status {
        return DeliveryDecision::Reject {
            code: REDIRECT_REFUSED,
            reason: format!("status_{status}"),
        };
    }
    let literal = checked.host_kind != HostKind::Name;
    let candidates: Vec<&str> = if literal {
        vec![checked.host_value.as_str()]
    } else {
        input.answers.iter().map(String::as_str).collect()
    };
    if candidates.is_empty() {
        return DeliveryDecision::Reject {
            code: NO_ANSWER,
            reason: "no_records".to_string(),
        };
    }
    let mut address: Option<String> = None;
    let mut reason: Option<String> = None;
    for candidate in candidates {
        let verdict = classify_with_ranges(candidate, input.allowed_ranges);
        if verdict.decision != Decision::Allow {
            return DeliveryDecision::Reject {
                code: BLOCKED_ADDRESS,
                reason: verdict.reason,
            };
        }
        if address.is_none() {
            address = verdict.address;
            reason = Some(verdict.reason);
        }
    }
    if let Some(first) = input.recheck.first() {
        let next = parse_address(first);
        let same = next
            .as_ref()
            .is_some_and(|next| Some(next.address.as_str()) == address.as_deref());
        if !same {
            return DeliveryDecision::Reject {
                code: DNS_REBINDING,
                reason: "address_changed".to_string(),
            };
        }
    }
    let suffix = if checked.port == 443 {
        String::new()
    } else {
        format!(":{}", checked.port)
    };
    let sni = if literal {
        None
    } else {
        Some(checked.host_value.clone())
    };
    DeliveryDecision::Allow {
        connect: ConnectTarget {
            address: address.unwrap_or_default(),
            host_header: format!("{}{suffix}", checked.host),
            sni,
        },
        reason: reason.unwrap_or_else(|| GLOBAL.to_string()),
    }
}

/// Classifies one parsed literal by its family (spec 06 R6.4, R6.7).
fn verdict_for(parsed: &ParsedAddress) -> AddressVerdict {
    match parsed.family {
        CidrFamily::V4 => {
            let mut quad = [0u8; 4];
            quad.copy_from_slice(&parsed.bytes[..4]);
            classify_ipv4(&quad)
        }
        CidrFamily::V6 => classify_ipv6(&parsed.bytes),
    }
}
