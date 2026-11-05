//! Conformance runner for the policy engine, driven by the shared spec
//! fixtures: load-vectors.json (parse-time rules), the two policy documents
//! (evaluation order and precedence) and the glob matcher semantics.

mod common;

use common::fixtures::*;

use mcp_jack::server::policy::{Decision, Policy, PolicyError};
use mcp_jack::syntax::match_pattern;

#[test]
fn policy_load_vectors() {
    let vectors = load_load_vectors().expect("load load-vectors.json");
    assert!(
        !vectors.policies.is_empty(),
        "load-vectors.json has no policy cases"
    );
    for case in &vectors.policies {
        let text = serde_json::to_string(&case.document).expect("document");
        let parsed = Policy::parse(text.as_bytes());
        match case.expect.as_str() {
            "valid" => {
                assert!(
                    parsed.is_ok(),
                    "case {}: expected valid, got Err({:?})",
                    case.id,
                    parsed.err()
                );
            }
            "invalid" => {
                let err = match parsed {
                    Err(PolicyError { reason }) => reason,
                    Ok(_) => panic!("case {}: expected invalid, parsed Ok", case.id),
                };
                // Each invalid fixture maps to one parser branch; the reason
                // proves the right rule fired (e.g. invalid-missing-scope must
                // hit the contains_key("scope") branch, not the null branch).
                if !case.reason.is_empty() {
                    assert_eq!(err, case.reason, "case {}: wrong failure reason", case.id);
                }
            }
            other => panic!("unknown expectation {} for policy case {}", other, case.id),
        }
    }
}

#[test]
fn evaluate_default_fixture_policy() {
    let doc = load_default_policy().expect("load policy.json");
    let text = serde_json::to_string(&doc).expect("document");
    let policy = Policy::parse(text.as_bytes()).expect("parse policy.json");
    // Table ported from server/policy_test.go; expected values are re-derived
    // from the fixture rules (deny precedes the general svc.* rule,
    // svc.config.set precedes svc.*).
    let cases: &[(&str, Option<&str>, Decision)] = &[
        (
            "ping",
            None,
            Decision {
                allowed: true,
                scope: None,
            },
        ),
        (
            "tools/list",
            None,
            Decision {
                allowed: true,
                scope: None,
            },
        ),
        (
            "notifications/initialized",
            None,
            Decision {
                allowed: true,
                scope: None,
            },
        ),
        (
            "tools/call",
            Some("svc.status"),
            Decision {
                allowed: true,
                scope: Some("read".into()),
            },
        ),
        // '*' spans dots.
        (
            "tools/call",
            Some("svc.logs.query"),
            Decision {
                allowed: true,
                scope: Some("read".into()),
            },
        ),
        // Exact rule precedes svc.*.
        (
            "tools/call",
            Some("svc.config.set"),
            Decision {
                allowed: true,
                scope: Some("config:write".into()),
            },
        ),
        (
            "tools/call",
            Some("svc.reload"),
            Decision {
                allowed: true,
                scope: Some("lifecycle".into()),
            },
        ),
        (
            "tools/call",
            Some("svc.restart"),
            Decision {
                allowed: true,
                scope: Some("lifecycle".into()),
            },
        ),
        // Deny rule wins over the later svc.*.
        (
            "tools/call",
            Some("svc.danger.wipe"),
            Decision {
                allowed: false,
                scope: None,
            },
        ),
        (
            "tools/call",
            Some("other.tool"),
            Decision {
                allowed: false,
                scope: None,
            },
        ),
        (
            "resources/read",
            None,
            Decision {
                allowed: false,
                scope: None,
            },
        ),
    ];
    for (method, tool, want) in cases {
        let got = policy.evaluate(method, *tool);
        assert_eq!(
            got, *want,
            "method {:?} tool {:?}: got {:?}, want {:?}",
            method, tool, got, want
        );
    }
}

#[test]
fn evaluate_wildcard_fixture_policy() {
    let doc = load_wildcard_policy().expect("load policy-wildcard.json");
    let text = serde_json::to_string(&doc).expect("document");
    let policy = Policy::parse(text.as_bytes()).expect("parse policy-wildcard.json");
    let cases: &[(&str, Option<&str>, Decision)] = &[
        // null scope = any authenticated key.
        (
            "tools/call",
            Some("other.tool"),
            Decision {
                allowed: true,
                scope: None,
            },
        ),
        (
            "ping",
            None,
            Decision {
                allowed: false,
                scope: None,
            },
        ),
        // Rule has no tool member: tool ignored.
        (
            "tools/call",
            None,
            Decision {
                allowed: true,
                scope: None,
            },
        ),
    ];
    for (method, tool, want) in cases {
        let got = policy.evaluate(method, *tool);
        assert_eq!(
            got, *want,
            "method {:?} tool {:?}: got {:?}, want {:?}",
            method, tool, got, want
        );
    }
}

#[test]
fn policy_pattern_behavior() {
    // Patterns appearing in the two fixture policies; expectations re-derived
    // from the matcher semantics: '*' matches any run of characters including
    // none and newlines, everything else literal, case-sensitive.
    let cases: &[(&str, &str, bool)] = &[
        // Pattern requires the literal dot.
        ("svc.*", "svc", false),
        ("svc.*", "svc.", true),
        ("svc.*", "svc.config.set", true),
        ("svc.danger.*", "svc.danger", false),
        ("svc.danger.*", "svc.danger.wipe", true),
        ("notifications/*", "notifications/initialized", true),
        // '*' spans slashes.
        ("notifications/*", "notifications/a/b", true),
        ("tools/call", "tools/call", true),
        // Case-sensitive.
        ("tools/call", "TOOLS/CALL", false),
        ("ping", "pinging", false),
    ];
    for (pattern, input, want) in cases {
        let got = match_pattern(pattern, input);
        assert!(
            got == *want,
            "pattern {:?} input {:?}: got {}, want {}",
            pattern,
            input,
            got,
            want
        );
    }
}
