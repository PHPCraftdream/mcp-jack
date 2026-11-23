//! Unit tests of the server rules of the modern profile (spec 04 sections 3
//! and 5): the era decision `S3`, the request rules `S1`, `S2`, `S4`-`S6` and
//! `S8`, and the era-neutral `tools/call` classification refusal.
//!
//! A [`ModernRequest`] only borrows its header slice, while a test writes its
//! headers as pairs, so [`TestRequest`] is the `request` helper of these
//! tests: it owns the `Vec<HeaderField>` built from the pairs and hands out
//! the borrowing request on demand. [`fields`] gives the expected header list
//! for the same pairs, so a test states its headers once.

use super::{
    classify_request, decide_era, Era, HeaderField, ModernOutcome, ModernRequest, Profile, Refusal,
    RefusalReason,
};
use crate::modern::{META_VERSION_KEY, TOOLS_CALL_NAME_MESSAGE};

/// A modern-era `tools/list` request: its `_meta` mirror carries the same
/// version as the `MCP-Protocol-Version` header the tests send.
const MODERN_TOOLS_LIST: &str = concat!(
    r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","#,
    r#""params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#
);

/// A `tools/call` request dated in a pre-2026 `_meta` version, so a modern
/// `MCP-Protocol-Version` header disagrees with it.
const TOOLS_CALL_LEGACY_META: &str = concat!(
    r#"{"jsonrpc":"2.0","id":"abc","method":"tools/call","#,
    r#""params":{"name":"demo","_meta":{"#,
    r#""io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}"#
);

/// The same mismatching `tools/call` as a notification: no `id` member.
const TOOLS_CALL_NOTIFICATION_LEGACY_META: &str = concat!(
    r#"{"jsonrpc":"2.0","method":"tools/call","#,
    r#""params":{"name":"demo","_meta":{"#,
    r#""io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}"#
);

/// The same mismatching `tools/call` with an integer `id`.
const TOOLS_CALL_ID7_LEGACY_META: &str = concat!(
    r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","#,
    r#""params":{"name":"demo","_meta":{"#,
    r#""io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}"#
);

/// A legacy-era `tools/call` with a string `params.name`, so the
/// classification refusal does not fire and the era alone decides.
const LEGACY_TOOLS_CALL: &str =
    r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"demo"}}"#;

/// One request under test: owns the [`HeaderField`] list a [`ModernRequest`]
/// borrows, so a test can build the request from plain string pairs.
struct TestRequest<'a> {
    /// HTTP method, exactly as received.
    method: &'a str,
    /// Request target; the rules never read it.
    target: &'a str,
    /// Received headers in received order, built from the test's pairs.
    headers: Vec<HeaderField>,
    /// Verified body bytes.
    body: &'a str,
}

impl<'a> TestRequest<'a> {
    /// Builds the request from `(name, value)` pairs in received order.
    fn new(method: &'a str, headers: &[(&str, &str)], body: &'a str) -> Self {
        Self {
            method,
            target: "/mcp",
            headers: fields(headers),
            body,
        }
    }

    /// The borrowing request the rules inspect.
    fn request(&self) -> ModernRequest<'_> {
        ModernRequest {
            method: self.method,
            target: self.target,
            headers: &self.headers,
            body: self.body.as_bytes(),
        }
    }

    /// Classifies the request under `profile`.
    fn classify(&self, profile: Profile) -> ModernOutcome {
        classify_request(profile, &self.request())
    }
}

/// Builds the header list of one request from `(name, value)` pairs, keeping
/// their order and casing.
fn fields(pairs: &[(&str, &str)]) -> Vec<HeaderField> {
    pairs
        .iter()
        .map(|(name, value)| HeaderField::new(*name, *value))
        .collect()
}

/// The refusal of a `Refuse` outcome; panics on any other variant.
fn refused(outcome: &ModernOutcome) -> &Refusal {
    match outcome {
        ModernOutcome::Refuse(refusal) => refusal,
        other => panic!("expected Refuse, got {other:?}"),
    }
}

/// The header list of a `Forward` outcome; panics on any other variant.
fn forwarded(outcome: &ModernOutcome) -> &[HeaderField] {
    match outcome {
        ModernOutcome::Forward { headers, .. } => headers,
        other => panic!("expected Forward, got {other:?}"),
    }
}

/// The era of a `Forward` outcome; panics on any other variant.
fn forwarded_era(outcome: &ModernOutcome) -> Era {
    match outcome {
        ModernOutcome::Forward { era, .. } => *era,
        other => panic!("expected Forward, got {other:?}"),
    }
}

#[test]
fn era_decision_table() {
    // The `_meta` key the modern bodies below rely on.
    assert_eq!(META_VERSION_KEY, "io.modelcontextprotocol/protocolVersion");

    let pre2026 = [HeaderField::new("MCP-Protocol-Version", "2025-11-25")];
    let modern = [HeaderField::new("mcp-protocol-version", "2026-07-28")];
    let malformed = [HeaderField::new("Mcp-Protocol-Version", "2026-7-28")];

    // Spec 04 section 3, `Profile::Both`, one row per line.
    let rows: &[(&str, &[HeaderField], Option<&str>, Era)] = &[
        ("no header and no meta", &[], None, Era::Legacy),
        ("pre-2026 header", &pre2026, None, Era::Legacy),
        ("modern header only", &modern, None, Era::Modern),
        ("modern meta only", &[], Some("2026-07-28"), Era::Modern),
        (
            "modern header with pre-2026 meta",
            &modern,
            Some("2025-11-25"),
            Era::Modern,
        ),
        (
            "malformed header with modern meta",
            &malformed,
            Some("2026-07-28"),
            Era::Modern,
        ),
        (
            "malformed header without meta",
            &malformed,
            None,
            Era::Legacy,
        ),
    ];
    for (row, headers, meta, want) in rows {
        assert_eq!(decide_era(Profile::Both, headers, *meta), *want, "{row}");
    }

    // The unconditional profiles ignore both signals.
    assert_eq!(
        decide_era(Profile::Legacy, &modern, Some("2026-07-28")),
        Era::Legacy
    );
    assert_eq!(decide_era(Profile::Modern, &[], None), Era::Modern);
}

#[test]
fn era_decision_repeated_header_any_modern_value() {
    let pairs = [
        ("MCP-Protocol-Version", "2025-11-25"),
        ("mcp-protocol-version", "2026-07-28"),
    ];
    // Ambiguity must not buy the legacy path.
    assert_eq!(
        decide_era(Profile::Both, &fields(&pairs), None),
        Era::Modern
    );

    let request = TestRequest::new("POST", &pairs, MODERN_TOOLS_LIST);
    let outcome = request.classify(Profile::Both);
    // A repeated header is `header_repeated` whatever its value: the outcome is
    // a refusal, so only the refusal shape is asserted here (the era helpers
    // panic on a refusal and would contradict this expectation).
    assert_eq!(refused(&outcome).reason, RefusalReason::HeaderRepeated);
}

#[test]
fn legacy_era_never_applies_section_5() {
    // No modern signal: the malformed `Mcp-Name`, the repeated `Mcp-Method`,
    // the NUL in `Mcp-Param-X` and the session header must all be forwarded
    // untouched, because no rule of section 5 runs in the legacy era.
    let pairs = [
        ("Mcp-Name", "=?base64?YQ?="),
        ("Mcp-Method", "tools/call"),
        ("mcp-method", "tools/call"),
        ("Mcp-Param-X", "a\0b"),
        ("Mcp-Session-Id", "session-1"),
        ("X-Last", "1"),
    ];
    let request = TestRequest::new("POST", &pairs, LEGACY_TOOLS_CALL);
    let outcome = request.classify(Profile::Both);
    assert_eq!(forwarded_era(&outcome), Era::Legacy);
    assert_eq!(forwarded(&outcome), fields(&pairs).as_slice());
}

#[test]
fn header_syntax_repetition_and_field_value() {
    // S1, first half: a second mirror header is `header_repeated` whatever its
    // value and casing.
    let repeated: &[&[(&str, &str)]] = &[
        &[
            ("MCP-Protocol-Version", "2025-11-25"),
            ("mcp-protocol-version", "2026-07-28"),
        ],
        &[
            ("MCP-Protocol-Version", "2026-07-28"),
            ("Mcp-Method", "tools/list"),
            ("mcp-method", "tools/list"),
        ],
        &[
            ("MCP-Protocol-Version", "2026-07-28"),
            ("Mcp-Name", "a"),
            ("mcp-name", "a"),
        ],
    ];
    for headers in repeated {
        let outcome = TestRequest::new("POST", headers, MODERN_TOOLS_LIST).classify(Profile::Both);
        assert_eq!(
            refused(&outcome).reason,
            RefusalReason::HeaderRepeated,
            "{headers:?}"
        );
    }

    // S1, second half: LF, CR, NUL, DEL and a non-ASCII character are all
    // outside the field-value syntax, in each of the three mirrors.
    let bad_values = ["a\nb", "a\rb", "a\0b", "a\u{7f}b", "a\u{e9}b"];
    for value in bad_values {
        // A version header that is not a modern version cannot signal the
        // modern era, so that case takes its era from the body `_meta`.
        let version_only = TestRequest::new(
            "POST",
            &[("MCP-Protocol-Version", value)],
            MODERN_TOOLS_LIST,
        )
        .classify(Profile::Both);
        assert_eq!(
            refused(&version_only).reason,
            RefusalReason::HeaderValueInvalid,
            "MCP-Protocol-Version {value:?}"
        );

        let method = TestRequest::new(
            "POST",
            &[
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", value),
            ],
            MODERN_TOOLS_LIST,
        )
        .classify(Profile::Both);
        assert_eq!(
            refused(&method).reason,
            RefusalReason::HeaderValueInvalid,
            "Mcp-Method {value:?}"
        );

        let name = TestRequest::new(
            "POST",
            &[("MCP-Protocol-Version", "2026-07-28"), ("Mcp-Name", value)],
            MODERN_TOOLS_LIST,
        )
        .classify(Profile::Both);
        assert_eq!(
            refused(&name).reason,
            RefusalReason::HeaderValueInvalid,
            "Mcp-Name {value:?}"
        );
    }
}

#[test]
fn param_headers_are_only_syntax_checked() {
    let modern = [
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", "tools/list"),
    ];

    // A NUL in a recognised parameter header is outside the syntax.
    let pairs = [
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", "tools/list"),
        ("Mcp-Param-X", "a\0b"),
    ];
    let outcome = TestRequest::new("POST", &pairs, MODERN_TOOLS_LIST).classify(Profile::Both);
    assert_eq!(refused(&outcome).reason, RefusalReason::HeaderValueInvalid);

    // HTAB is inside the syntax and the value reaches the handler unchanged:
    // no parameter header is decoded or rewritten.
    let tab = [modern[0], modern[1], ("Mcp-Param-X", "a\tb")];
    let outcome = TestRequest::new("POST", &tab, MODERN_TOOLS_LIST).classify(Profile::Both);
    assert_eq!(forwarded_era(&outcome), Era::Modern);
    assert_eq!(forwarded(&outcome), fields(&tab).as_slice());

    // The bare prefix has an empty `{Name}`: not a recognised parameter
    // header, so not syntax-checked, forwarded like any unknown header.
    let bare = [modern[0], modern[1], ("Mcp-Param-", "a\0b")];
    let outcome = TestRequest::new("POST", &bare, MODERN_TOOLS_LIST).classify(Profile::Both);
    assert_eq!(forwarded(&outcome), fields(&bare).as_slice());
}

#[test]
fn method_must_be_post_in_the_modern_era() {
    for method in ["GET", "PUT", "DELETE", "HEAD"] {
        let outcome = TestRequest::new(method, &[], "").classify(Profile::Modern);
        let refusal = refused(&outcome);
        assert_eq!(refusal.reason, RefusalReason::MethodNotAllowed, "{method}");
        assert_eq!(refusal.reason.http_status(), 405, "{method}");
        assert_eq!(refusal.reason.code(), -32600, "{method}");
        assert_eq!(refusal.id, None, "{method}");
    }

    let pairs = [
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", "tools/list"),
    ];
    let outcome = TestRequest::new("POST", &pairs, MODERN_TOOLS_LIST).classify(Profile::Modern);
    assert_eq!(forwarded_era(&outcome), Era::Modern);
    assert_eq!(forwarded(&outcome), fields(&pairs).as_slice());
}

#[test]
fn session_headers_are_stripped_in_the_modern_era() {
    let pairs = [
        ("Mcp-Session-Id", "session-1"),
        ("X-First", "1"),
        ("Last-Event-ID", "7"),
        ("MCP-Protocol-Version", "2026-07-28"),
        ("mcp-session-id", "session-2"),
        ("Mcp-Method", "tools/list"),
        ("X-Last", "2"),
    ];
    let outcome = TestRequest::new("POST", &pairs, MODERN_TOOLS_LIST).classify(Profile::Both);
    assert_eq!(forwarded_era(&outcome), Era::Modern);

    let expected = [
        ("X-First", "1"),
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", "tools/list"),
        ("X-Last", "2"),
    ];
    assert_eq!(forwarded(&outcome), fields(&expected).as_slice());
}

#[test]
fn forwarded_headers_keep_order_and_params() {
    // A repeated parameter header keeps both values in order, the sentinel of
    // `Mcp-Param-C` is not decoded and nothing is reordered.
    let pairs = [
        ("Mcp-Param-A", "a"),
        ("Mcp-Param-B", "b1"),
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Param-B", "b2"),
        ("Mcp-Param-C", "=?base64?SGVsbG8=?="),
        ("Mcp-Method", "tools/list"),
        ("X-Unknown", "u"),
    ];
    let outcome = TestRequest::new("POST", &pairs, MODERN_TOOLS_LIST).classify(Profile::Both);
    assert_eq!(forwarded_era(&outcome), Era::Modern);
    assert_eq!(forwarded(&outcome), fields(&pairs).as_slice());
}

#[test]
fn refusal_echoes_the_request_id() {
    let version = [("MCP-Protocol-Version", "2026-07-28")];

    let outcome =
        TestRequest::new("POST", &version, TOOLS_CALL_LEGACY_META).classify(Profile::Both);
    let refusal = refused(&outcome);
    assert_eq!(refusal.reason, RefusalReason::VersionMismatch);
    assert_eq!(refusal.id, Some("\"abc\"".to_string()));

    let outcome = TestRequest::new("POST", &version, TOOLS_CALL_NOTIFICATION_LEGACY_META)
        .classify(Profile::Both);
    let refusal = refused(&outcome);
    assert_eq!(refusal.reason, RefusalReason::VersionMismatch);
    assert_eq!(refusal.id, None);

    let outcome =
        TestRequest::new("POST", &version, TOOLS_CALL_ID7_LEGACY_META).classify(Profile::Both);
    let refusal = refused(&outcome);
    assert_eq!(refusal.reason, RefusalReason::VersionMismatch);
    assert_eq!(refusal.id, Some("7".to_string()));
}

#[test]
fn classification_refusal_for_tools_call_without_name() {
    let bodies = [
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":7}}"#,
    ];
    for body in bodies {
        // Era-neutral: the body is refused before `S3`, whatever the profile.
        for profile in [Profile::Both, Profile::Legacy] {
            let outcome = TestRequest::new("POST", &[], body).classify(profile);
            match outcome {
                ModernOutcome::ClassificationRefusal { message } => {
                    assert_eq!(message, TOOLS_CALL_NAME_MESSAGE, "{body} {profile:?}");
                }
                other => panic!("expected ClassificationRefusal, got {other:?}"),
            }
        }
    }
}
