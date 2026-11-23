//! Callback-url and delivery-decision unit tests (spec 06 R5.11, R6.1-R6.3,
//! R6.8-R6.11, R8.2).
//!
//! Every vector is a pure literal: no name is resolved, no socket is opened and
//! no file is read. The R6.2/R6.3 tables are asserted through `check_url`, the
//! R6.11 range parsing through `parse_cidr`/`cidr_contains` and the single
//! R6.8-R6.10 decision through `delivery_decision`.

use crate::webhook::ssrf::delivery::{delivery_decision, DeliveryDecision, DeliveryInput};
use crate::webhook::ssrf::url::check_url;
use crate::webhook::ssrf::{cidr_contains, parse_cidr, CidrFamily, HostKind};
use crate::webhook::WebhookError;

/// One rejected callback url: the input, its wire code and its optional
/// fixed-literal reason (spec 06 R6.1, R6.2, R6.3).
struct UrlReject {
    url: &'static str,
    code: &'static str,
    reason: Option<&'static str>,
}

/// The rejected url parts of the R6.1/R6.2/R6.3 tables (spec 06 section 6).
const URL_REJECTS: [UrlReject; 16] = [
    UrlReject {
        url: "",
        code: "scheme_not_https",
        reason: None,
    },
    UrlReject {
        url: "//hooks.example.test/hook",
        code: "scheme_not_https",
        reason: None,
    },
    UrlReject {
        url: "http://hooks.example.test/hook",
        code: "scheme_not_https",
        reason: None,
    },
    UrlReject {
        url: "ftp://hooks.example.test/hook",
        code: "scheme_not_https",
        reason: None,
    },
    UrlReject {
        url: "https://user:pa@hooks.example.test/hook",
        code: "invalid_callback_url",
        reason: Some("userinfo"),
    },
    UrlReject {
        url: "https://hooks.example.test/hook#frag",
        code: "invalid_callback_url",
        reason: Some("fragment"),
    },
    UrlReject {
        url: "https:///hook",
        code: "invalid_callback_url",
        reason: Some("empty_host"),
    },
    UrlReject {
        url: "https://hooks.example.test:0/hook",
        code: "invalid_callback_url",
        reason: Some("port"),
    },
    UrlReject {
        url: "https://hooks.example.test:65536/hook",
        code: "invalid_callback_url",
        reason: Some("port"),
    },
    UrlReject {
        url: "https://hooks.example.test:/hook",
        code: "invalid_callback_url",
        reason: Some("port"),
    },
    UrlReject {
        url: "https://hooks.example.test/a b",
        code: "invalid_callback_url",
        reason: Some("character"),
    },
    UrlReject {
        url: "https://hooks.example.test/hôok",
        code: "invalid_callback_url",
        reason: Some("character"),
    },
    UrlReject {
        url: "https://hooks.example.test]/hook",
        code: "invalid_callback_url",
        reason: Some("host"),
    },
    UrlReject {
        url: "https://[::1/hook",
        code: "invalid_callback_url",
        reason: Some("host"),
    },
    UrlReject {
        url: "https://[fe80::1%25eth0]/hook",
        code: "invalid_callback_url",
        reason: Some("host"),
    },
    UrlReject {
        url: "https://[not-an-address]/hook",
        code: "invalid_callback_url",
        reason: Some("host"),
    },
];

/// Spellings that are never reinterpreted as an address (spec 06 R6.3).
const NOT_A_HOSTNAMES: [&str; 9] = [
    "https://127.1/hook",
    "https://2130706433/hook",
    "https://0x7f.0.0.1/hook",
    "https://0177.0.0.1/hook",
    "https://1.2.3.4.5/hook",
    "https://a..b/hook",
    "https://127.0.0.01/hook",
    "https://-bad.example/hook",
    "https://_dmarc.example/hook",
];

/// One accepted url with every validated part it must render (spec 06 R8.2).
struct UrlAccept {
    url: &'static str,
    host: &'static str,
    host_kind: HostKind,
    port: u16,
    path: &'static str,
    query: &'static str,
    canonical: &'static str,
}

/// The R8.2 canonical forms (spec 06 R8.2).
const URL_ACCEPTS: [UrlAccept; 9] = [
    UrlAccept {
        url: "https://hooks.example.test",
        host: "hooks.example.test",
        host_kind: HostKind::Name,
        port: 443,
        path: "/",
        query: "",
        canonical: "https://hooks.example.test/",
    },
    UrlAccept {
        url: "https://hooks.example.test/",
        host: "hooks.example.test",
        host_kind: HostKind::Name,
        port: 443,
        path: "/",
        query: "",
        canonical: "https://hooks.example.test/",
    },
    UrlAccept {
        url: "https://hooks.example.test:443/hook",
        host: "hooks.example.test",
        host_kind: HostKind::Name,
        port: 443,
        path: "/hook",
        query: "",
        canonical: "https://hooks.example.test/hook",
    },
    UrlAccept {
        url: "https://hooks.example.test:8443/hook",
        host: "hooks.example.test",
        host_kind: HostKind::Name,
        port: 8443,
        path: "/hook",
        query: "",
        canonical: "https://hooks.example.test:8443/hook",
    },
    UrlAccept {
        url: "https://Hooks.Example.TEST./hook",
        host: "hooks.example.test",
        host_kind: HostKind::Name,
        port: 443,
        path: "/hook",
        query: "",
        canonical: "https://hooks.example.test/hook",
    },
    UrlAccept {
        url: "https://hooks.example.test?b=2&a=1",
        host: "hooks.example.test",
        host_kind: HostKind::Name,
        port: 443,
        path: "/",
        query: "b=2&a=1",
        canonical: "https://hooks.example.test/?b=2&a=1",
    },
    UrlAccept {
        url: "https://hooks.example.test/a/b?x=1",
        host: "hooks.example.test",
        host_kind: HostKind::Name,
        port: 443,
        path: "/a/b",
        query: "x=1",
        canonical: "https://hooks.example.test/a/b?x=1",
    },
    UrlAccept {
        url: "https://[2606:4700::1111]:8443/hook",
        host: "[2606:4700::1111]",
        host_kind: HostKind::Ipv6,
        port: 8443,
        path: "/hook",
        query: "",
        canonical: "https://[2606:4700::1111]:8443/hook",
    },
    UrlAccept {
        url: "https://[2606:4700:0:0::1111]:443/hook",
        host: "[2606:4700::1111]",
        host_kind: HostKind::Ipv6,
        port: 443,
        path: "/hook",
        query: "",
        canonical: "https://[2606:4700::1111]/hook",
    },
];

/// The integer port of `https://hooks.example.test:8443/hook`, used to prove
/// the literal host spelling keeps its kind.
const IPV4_LITERAL_URL: &str = "https://93.184.216.34/hook";

/// Path segments that are a dot or a dot-dot after decoding (spec 06 R5.11).
const DOT_SEGMENT_URLS: [&str; 6] = [
    "https://hooks.example.test/a/./b",
    "https://hooks.example.test/a/../b",
    "https://hooks.example.test/a/%2E%2E/b",
    "https://hooks.example.test/a/%2e%2e/b",
    "https://hooks.example.test/a/%2E./b",
    "https://hooks.example.test/a/%2e%2E/b",
];

/// Path segments that only look like a dot segment and stay untouched
/// (spec 06 R5.11: no percent-decoding, no normalization).
const NON_DOT_SEGMENT_URLS: [&str; 3] = [
    "https://hooks.example.test/a.b/..c/d",
    "https://hooks.example.test/hooks%2Fa",
    "https://hooks.example.test/a/%2E%2Ebc",
];

/// One accepted CIDR range (spec 06 R6.11).
struct CidrAccept {
    text: &'static str,
    family: CidrFamily,
    prefix: u8,
}

/// Ranges with a canonical literal and zero host bits beyond the prefix.
const CIDR_ACCEPTS: [CidrAccept; 8] = [
    CidrAccept {
        text: "0.0.0.0/0",
        family: CidrFamily::V4,
        prefix: 0,
    },
    CidrAccept {
        text: "10.0.0.0/8",
        family: CidrFamily::V4,
        prefix: 8,
    },
    CidrAccept {
        text: "192.168.1.1/32",
        family: CidrFamily::V4,
        prefix: 32,
    },
    CidrAccept {
        text: "255.255.255.255/32",
        family: CidrFamily::V4,
        prefix: 32,
    },
    CidrAccept {
        text: "::/0",
        family: CidrFamily::V6,
        prefix: 0,
    },
    CidrAccept {
        text: "::1/128",
        family: CidrFamily::V6,
        prefix: 128,
    },
    CidrAccept {
        text: "2001:db8::/32",
        family: CidrFamily::V6,
        prefix: 32,
    },
    CidrAccept {
        text: "64:ff9b::/96",
        family: CidrFamily::V6,
        prefix: 96,
    },
];

/// Out-of-range prefixes, set host bits, a missing slash and malformed
/// prefixes (spec 06 R6.11).
const CIDR_REJECTS: [&str; 14] = [
    "10.0.0.0/33",
    "::/129",
    "10.1.0.0/8",
    "2001:db8::1/32",
    "10.0.0.0",
    "",
    "/",
    "10.0.0.0/",
    "10.0.0.0/08",
    "10.0.0.0/8/8",
    "10.0.0.0/+8",
    "10.0.0.0/ 8",
    "1.2.3.4.5/24",
    "0177.0.0.1/8",
];

/// One delivery-decision input, as named arguments rather than a long
/// positional call (spec 06 R6.8-R6.11).
struct DeliveryCase<'a> {
    url: &'a str,
    answers: &'a [&'a str],
    recheck: &'a [&'a str],
    ranges: &'a [&'a str],
    redirect: Option<u16>,
}

impl DeliveryCase<'_> {
    /// Runs the one decision with owned resolver answers, as the api takes
    /// them.
    fn decide(&self) -> DeliveryDecision {
        let answers = owned(self.answers);
        let recheck = owned(self.recheck);
        let ranges = owned(self.ranges);
        delivery_decision(&DeliveryInput {
            url: self.url,
            answers: &answers,
            recheck: &recheck,
            allowed_ranges: &ranges,
            redirect_status: self.redirect,
        })
    }
}

/// Returns borrowed strings as owned entries.
fn owned(entries: &[&str]) -> Vec<String> {
    entries.iter().map(|entry| (*entry).to_string()).collect()
}

/// Asserts one url is rejected with exactly `code` and `reason`.
fn assert_url_reject(case: &UrlReject) {
    let error: WebhookError = match check_url(case.url) {
        Ok(parts) => panic!("{} was accepted as {}", case.url, parts.canonical),
        Err(error) => error,
    };
    assert_eq!(error.http_status, 400, "{} status", case.url);
    assert_eq!(error.code, case.code, "{} code", case.url);
    assert_eq!(error.reason(), case.reason, "{} reason", case.url);
}

/// Asserts an allowed decision carries exactly the expected connect target
/// and reason.
fn assert_allow(
    case: &DeliveryCase<'_>,
    address: &str,
    host_header: &str,
    sni: Option<&str>,
    reason: &str,
) {
    match case.decide() {
        DeliveryDecision::Allow {
            connect,
            reason: actual_reason,
        } => {
            assert_eq!(connect.address, address, "{} address", case.url);
            assert_eq!(connect.host_header, host_header, "{} host header", case.url);
            assert_eq!(connect.sni.as_deref(), sni, "{} sni", case.url);
            assert_eq!(actual_reason, reason, "{} reason", case.url);
        }
        other => panic!("{} was refused: {other:?}", case.url),
    }
}

/// Asserts a refused decision carries exactly the expected code and reason.
fn assert_reject(case: &DeliveryCase<'_>, expected_code: &str, expected_reason: &str) {
    match case.decide() {
        DeliveryDecision::Reject { code, reason } => {
            assert_eq!(code, expected_code, "{} code", case.url);
            assert_eq!(reason, expected_reason, "{} reason", case.url);
        }
        other => panic!("{} was allowed: {other:?}", case.url),
    }
}

#[test]
fn r6_1_r6_2_r6_3_url_rejections() {
    for case in &URL_REJECTS {
        assert_url_reject(case);
    }
}

#[test]
fn r6_3_odd_host_spellings_are_not_a_hostname() {
    for url in NOT_A_HOSTNAMES {
        let error: WebhookError = match check_url(url) {
            Ok(parts) => panic!("{url} was accepted as {}", parts.canonical),
            Err(error) => error,
        };
        assert_eq!(error.http_status, 400, "{url} status");
        assert_eq!(error.code, "not_a_hostname", "{url} code");
        assert_eq!(error.reason(), Some("not_a_hostname"), "{url} reason");
    }
}

#[test]
fn r8_2_canonical_form_and_validated_parts() {
    for case in &URL_ACCEPTS {
        let parts = match check_url(case.url) {
            Ok(parts) => parts,
            Err(error) => panic!("{} was rejected: {error}", case.url),
        };
        assert_eq!(parts.scheme, "https", "{} scheme", case.url);
        assert_eq!(parts.host, case.host, "{} host", case.url);
        assert_eq!(parts.host_kind, case.host_kind, "{} host kind", case.url);
        assert_eq!(parts.port, case.port, "{} port", case.url);
        assert_eq!(parts.path, case.path, "{} path", case.url);
        assert_eq!(parts.query, case.query, "{} query", case.url);
        assert_eq!(parts.canonical, case.canonical, "{} canonical", case.url);
    }
}

#[test]
fn r6_3_ipv4_literal_is_its_own_host_value() {
    let parts = match check_url(IPV4_LITERAL_URL) {
        Ok(parts) => parts,
        Err(error) => panic!("{IPV4_LITERAL_URL} was rejected: {error}"),
    };
    assert_eq!(parts.host_kind, HostKind::Ipv4);
    assert_eq!(parts.host, "93.184.216.34");
    assert_eq!(parts.host_value, "93.184.216.34");
    assert_eq!(parts.canonical, IPV4_LITERAL_URL);
}

#[test]
fn r6_3_ipv6_literal_keeps_the_brackets_and_drops_them_for_the_value() {
    let parts = match check_url("https://[2606:4700::1111]/hook") {
        Ok(parts) => parts,
        Err(error) => panic!("the IPv6 literal was rejected: {error}"),
    };
    assert_eq!(parts.host_kind, HostKind::Ipv6);
    assert_eq!(parts.host, "[2606:4700::1111]");
    assert_eq!(parts.host_value, "2606:4700::1111");
}

#[test]
fn r5_11_rejects_every_dot_segment_spelling() {
    for url in DOT_SEGMENT_URLS {
        let error: WebhookError = match check_url(url) {
            Ok(parts) => panic!("{url} was accepted as {}", parts.canonical),
            Err(error) => error,
        };
        assert_eq!(error.code, "invalid_callback_url", "{url} code");
        assert_eq!(error.reason(), Some("dot_segment"), "{url} reason");
    }
}

#[test]
fn r5_11_never_rewrites_a_merely_dot_like_segment() {
    for url in NON_DOT_SEGMENT_URLS {
        if let Err(error) = check_url(url) {
            panic!("{url} was rejected: {error}");
        }
    }
    let parts = match check_url("https://hooks.example.test/a.b/..c/d") {
        Ok(parts) => parts,
        Err(error) => panic!("the path was rejected: {error}"),
    };
    assert_eq!(parts.path, "/a.b/..c/d");
}

#[test]
fn r6_11_parse_cidr_accepts_canonical_ranges() {
    for case in &CIDR_ACCEPTS {
        let range = match parse_cidr(case.text) {
            Some(range) => range,
            None => panic!("{} was rejected", case.text),
        };
        assert_eq!(range.family(), case.family, "{} family", case.text);
        assert_eq!(range.prefix(), case.prefix, "{} prefix", case.text);
    }
}

#[test]
fn r6_11_parse_cidr_rejects_malformed_ranges() {
    for text in CIDR_REJECTS {
        assert!(parse_cidr(text).is_none(), "{text} was accepted");
    }
}

#[test]
fn r6_11_cidr_contains_is_exact_bit_matching() {
    let v4 = match parse_cidr("192.0.2.0/24") {
        Some(range) => range,
        None => panic!("192.0.2.0/24 was rejected"),
    };
    assert!(cidr_contains(&v4, "192.0.2.0"));
    assert!(cidr_contains(&v4, "192.0.2.7"));
    assert!(cidr_contains(&v4, "192.0.2.255"));
    assert!(!cidr_contains(&v4, "192.0.3.0"));
    assert!(!cidr_contains(&v4, "2001:db8::1"));
    assert!(!cidr_contains(&v4, "hooks.example.test"));
    assert!(!cidr_contains(&v4, "127.1"));

    let wide = match parse_cidr("10.0.0.0/8") {
        Some(range) => range,
        None => panic!("10.0.0.0/8 was rejected"),
    };
    assert!(cidr_contains(&wide, "10.255.255.255"));
    assert!(!cidr_contains(&wide, "11.0.0.0"));

    let v6 = match parse_cidr("2001:db8::/32") {
        Some(range) => range,
        None => panic!("2001:db8::/32 was rejected"),
    };
    assert!(cidr_contains(&v6, "2001:db8::1"));
    assert!(cidr_contains(&v6, "2001:db8:ffff::"));
    assert!(cidr_contains(&v6, "[2001:db8::1]"));
    assert!(!cidr_contains(&v6, "2001:db9::1"));
    assert!(!cidr_contains(&v6, "192.0.2.7"));
}

#[test]
fn r6_8_allows_a_name_with_the_host_header_and_sni() {
    let case = DeliveryCase {
        url: "https://hooks.example.test/hook",
        answers: &["93.184.216.34"],
        recheck: &["93.184.216.34"],
        ranges: &[],
        redirect: None,
    };
    assert_allow(
        &case,
        "93.184.216.34",
        "hooks.example.test",
        Some("hooks.example.test"),
        "global",
    );
}

#[test]
fn r6_8_keeps_a_non_default_port_in_the_host_header() {
    let case = DeliveryCase {
        url: "https://hooks.example.test:8443/hook",
        answers: &["93.184.216.34"],
        recheck: &[],
        ranges: &[],
        redirect: None,
    };
    assert_allow(
        &case,
        "93.184.216.34",
        "hooks.example.test:8443",
        Some("hooks.example.test"),
        "global",
    );
}

#[test]
fn r6_8_allows_an_ipv6_literal_without_sni() {
    let case = DeliveryCase {
        url: "https://[2606:4700::1111]/hook",
        answers: &[],
        recheck: &[],
        ranges: &[],
        redirect: None,
    };
    assert_allow(
        &case,
        "2606:4700::1111",
        "[2606:4700::1111]",
        None,
        "global",
    );
}

#[test]
fn r6_8_allows_an_ipv4_literal_without_sni() {
    let case = DeliveryCase {
        url: "https://93.184.216.34/hook",
        answers: &[],
        recheck: &["93.184.216.34"],
        ranges: &[],
        redirect: None,
    };
    assert_allow(&case, "93.184.216.34", "93.184.216.34", None, "global");
}

#[test]
fn r6_8_refuses_a_name_with_no_answer() {
    let case = DeliveryCase {
        url: "https://hooks.example.test/hook",
        answers: &[],
        recheck: &[],
        ranges: &[],
        redirect: None,
    };
    assert_reject(&case, "no_answer", "no_records");
}

#[test]
fn r6_8_reports_the_first_failing_answer_in_resolver_order() {
    let case = DeliveryCase {
        url: "https://hooks.example.test/hook",
        answers: &["93.184.216.34", "127.0.0.1", "10.0.0.1"],
        recheck: &[],
        ranges: &[],
        redirect: None,
    };
    assert_reject(&case, "blocked_address", "loopback");

    let case = DeliveryCase {
        url: "https://hooks.example.test/hook",
        answers: &["93.184.216.34", "93.184.216.35", "10.0.0.1"],
        recheck: &[],
        ranges: &[],
        redirect: None,
    };
    assert_reject(&case, "blocked_address", "private_use");
}

#[test]
fn r6_10_refuses_every_redirect_status() {
    let case = DeliveryCase {
        url: "https://hooks.example.test/hook",
        answers: &["93.184.216.34"],
        recheck: &[],
        ranges: &[],
        redirect: Some(302),
    };
    assert_reject(&case, "redirect_refused", "status_302");

    let case = DeliveryCase {
        url: "https://hooks.example.test/hook",
        answers: &["93.184.216.34"],
        recheck: &[],
        ranges: &[],
        redirect: Some(301),
    };
    assert_reject(&case, "redirect_refused", "status_301");
}

#[test]
fn r6_9_refuses_a_changed_recheck_address() {
    let case = DeliveryCase {
        url: "https://hooks.example.test/hook",
        answers: &["93.184.216.34"],
        recheck: &["93.184.216.35"],
        ranges: &[],
        redirect: None,
    };
    assert_reject(&case, "dns_rebinding", "address_changed");
}

#[test]
fn r6_9_allows_a_recheck_equal_to_the_validated_address() {
    let case = DeliveryCase {
        url: "https://hooks.example.test/hook",
        answers: &["93.184.216.34"],
        recheck: &["93.184.216.34"],
        ranges: &[],
        redirect: None,
    };
    assert_allow(
        &case,
        "93.184.216.34",
        "hooks.example.test",
        Some("hooks.example.test"),
        "global",
    );
}

#[test]
fn r6_11_allows_a_name_answer_inside_an_allowed_range() {
    let case = DeliveryCase {
        url: "https://hooks.example.test/hook",
        answers: &["10.0.0.7"],
        recheck: &[],
        ranges: &["10.0.0.0/8"],
        redirect: None,
    };
    assert_allow(
        &case,
        "10.0.0.7",
        "hooks.example.test",
        Some("hooks.example.test"),
        "allowed_range",
    );
}
