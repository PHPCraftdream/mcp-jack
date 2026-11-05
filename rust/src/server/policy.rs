//! Policy loading, validation, first-match-wins evaluation (Go: server/policy.go).

use std::fmt;

use crate::syntax::{match_pattern, valid_scope};

/// Load-time validation failure of a policy document (spec 02 section 3).
/// `reason` is a short stable identifier, identical to the Go strings and to
/// the informative `reason` field of the load-vectors policy cases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    pub reason: String,
}

impl PolicyError {
    fn new(reason: &'static str) -> Self {
        Self {
            reason: reason.to_string(),
        }
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "server: invalid policy: {}", self.reason)
    }
}

impl std::error::Error for PolicyError {}

/// The policy verdict for one operation (Go: Decision).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// False when no rule matched or a deny rule matched.
    pub allowed: bool,
    /// The scope the caller must hold; None means any authenticated key.
    pub scope: Option<String>,
}

#[derive(Debug, Clone)]
struct PolicyRule {
    method: String,
    /// None: any tool.
    tool: Option<String>,
    deny: bool,
    /// None: any authenticated key (allow rules only).
    scope: Option<String>,
}

/// An operator-owned list of first-match-wins rules; anything no rule allows
/// is denied (spec 02 section 3).
#[derive(Debug, Clone)]
pub struct Policy {
    rules: Vec<PolicyRule>,
}

impl Policy {
    /// Validates and compiles a policy document (Go: ParsePolicy). Works on
    /// raw JSON via serde_json::Map so a MISSING "scope" can be told apart
    /// from `"scope": null` (an allow rule must carry the key; null means any
    /// authenticated key). An Option<T> serde field would merge absent and
    /// null, which the spec distinguishes.
    pub fn parse(data: &[u8]) -> Result<Policy, PolicyError> {
        let doc: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(data).map_err(|_| PolicyError::new("document"))?;
        if !only_keys(&doc, &["version", "rules"]) {
            return Err(PolicyError::new("document"));
        }
        // Go unmarshals the version into float64 and compares to 1, so 1 and
        // 1.0 both pass; strings, bools and a missing key fail.
        let version_ok = doc
            .get("version")
            .and_then(|v| v.as_f64())
            .map(|v| v == 1.0)
            .unwrap_or(false);
        if !version_ok {
            return Err(PolicyError::new("document"));
        }
        let rules = doc
            .get("rules")
            .filter(|v| !v.is_null())
            .and_then(|v| v.as_array())
            .ok_or_else(|| PolicyError::new("document"))?;

        let mut compiled = Vec::with_capacity(rules.len());
        for raw in rules {
            compiled.push(parse_rule(raw)?);
        }
        Ok(Policy { rules: compiled })
    }

    /// Verdict for a method and, for tools/call, a tool name. First match in
    /// document order wins; no match is a denial. `tool` is None when the
    /// request is not a tools/call carrying a string tool name.
    pub fn evaluate(&self, method: &str, tool: Option<&str>) -> Decision {
        for rule in &self.rules {
            if !match_pattern(&rule.method, method) {
                continue;
            }
            if let Some(rule_tool) = &rule.tool {
                let matched =
                    method == "tools/call" && tool.is_some_and(|t| match_pattern(rule_tool, t));
                if !matched {
                    continue;
                }
            }
            if rule.deny {
                return Decision {
                    allowed: false,
                    scope: None,
                };
            }
            return Decision {
                allowed: true,
                scope: rule.scope.clone(),
            };
        }
        Decision {
            allowed: false,
            scope: None,
        }
    }
}

fn parse_rule(raw: &serde_json::Value) -> Result<PolicyRule, PolicyError> {
    // Members are inspected as a Map with contains_key-style checks because a
    // serde derive with Option<String> would merge a missing scope with a null
    // one, which the spec distinguishes.
    let rule: serde_json::Map<String, serde_json::Value> =
        serde_json::from_value(raw.clone()).map_err(|_| PolicyError::new("unknown_field"))?;
    if !only_keys(&rule, &["match", "scope", "effect"]) {
        return Err(PolicyError::new("unknown_field"));
    }
    let m: serde_json::Map<String, serde_json::Value> = serde_json::from_value(
        rule.get("match")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
    .map_err(|_| PolicyError::new("unknown_field"))?;
    if !only_keys(&m, &["method", "tool"]) {
        return Err(PolicyError::new("unknown_field"));
    }

    let method = json_string(m.get("method")).filter(|s| !s.is_empty());
    let method = match method {
        Some(m) => m,
        None => return Err(PolicyError::new("method")),
    };
    let mut compiled = PolicyRule {
        method,
        tool: None,
        deny: false,
        scope: None,
    };
    if let Some(raw_tool) = m.get("tool") {
        let tool = json_string(Some(raw_tool)).filter(|s| !s.is_empty());
        let tool = match tool {
            Some(t) => t,
            None => return Err(PolicyError::new("tool")),
        };
        if compiled.method != "tools/call" {
            return Err(PolicyError::new("tool_without_tools_call"));
        }
        compiled.tool = Some(tool);
    }

    // An ABSENT effect follows the documented default "allow" (spec 02
    // section 3 field table: 'Optional. "allow" (default) or "deny"'); a
    // PRESENT effect must be exactly the string "allow" or "deny", because
    // section 3 rejects a policy whose effect "is neither allow nor deny" —
    // JSON null is a present value that is neither. Go (server/policy.go)
    // and the JS reference treat an explicit null as absent; the spec wins
    // (reported Go divergence).
    let mut effect = "allow";
    if let Some(raw_effect) = rule.get("effect") {
        match json_string(Some(raw_effect)).as_deref() {
            Some("allow") => effect = "allow",
            Some("deny") => effect = "deny",
            _ => return Err(PolicyError::new("effect")),
        }
    }

    let has_scope = rule.contains_key("scope");
    if effect == "deny" {
        if has_scope {
            return Err(PolicyError::new("scope_with_deny"));
        }
        compiled.deny = true;
        return Ok(compiled);
    }
    if !has_scope {
        return Err(PolicyError::new("missing_scope"));
    }
    let raw_scope = rule.get("scope").unwrap();
    if !raw_scope.is_null() {
        let scope = match json_string(Some(raw_scope)) {
            Some(s) => s,
            None => return Err(PolicyError::new("malformed_scope")),
        };
        if !valid_scope(&scope) {
            return Err(PolicyError::new("malformed_scope"));
        }
        if scope == "admin" {
            return Err(PolicyError::new("reserved_scope"));
        }
        compiled.scope = Some(scope);
    }
    Ok(compiled)
}

/// True when every key of `m` is one of `allowed`.
fn only_keys(m: &serde_json::Map<String, serde_json::Value>, allowed: &[&str]) -> bool {
    m.keys().all(|k| allowed.contains(&k.as_str()))
}

/// Returns Some only for a JSON string; null, numbers, bools, arrays and
/// objects are None (mirrors Go jsonString, which must not accept null).
fn json_string(v: Option<&serde_json::Value>) -> Option<String> {
    v.and_then(|v| v.as_str()).map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(doc: &str) -> Policy {
        Policy::parse(doc.as_bytes()).expect("policy should parse")
    }

    fn parse_err(doc: &str) -> String {
        Policy::parse(doc.as_bytes())
            .expect_err("policy should be rejected")
            .reason
    }

    fn eval(policy: &Policy, method: &str, tool: Option<&str>) -> Decision {
        policy.evaluate(method, tool)
    }

    #[test]
    fn display_mentions_reason() {
        let e = PolicyError::new("document");
        assert_eq!(e.to_string(), "server: invalid policy: document");
    }

    #[test]
    fn parse_document_rejections() {
        for doc in [
            "{}",
            r#"{"version":2,"rules":[]}"#,
            r#"{"version":1}"#,
            r#"{"version":1,"rules":null}"#,
            r#"{"version":1,"rules":{}}"#,
            r#"{"version":"1","rules":[]}"#,
            r#"{"version":1,"rules":[],"comment":"x"}"#,
            "[]",
            "null",
            "5",
            r#"{"version":1,"version":2,"rules":[]}"#,
        ] {
            assert_eq!(parse_err(doc), "document", "doc: {doc}");
        }
    }

    #[test]
    fn parse_rule_rejections() {
        let cases: &[(&str, &str)] = &[
            (
                r#"{"version":1,"rules":[{"match":{"method":"ping","uri":"x"},"scope":null}]}"#,
                "unknown_field",
            ),
            (
                r#"{"version":1,"rules":[{"match":{"method":"ping"},"scope":null,"comment":"x"}]}"#,
                "unknown_field",
            ),
            (
                r#"{"version":1,"rules":[{"match":null,"scope":null}]}"#,
                "unknown_field",
            ),
            (r#"{"version":1,"rules":[{"scope":null}]}"#, "unknown_field"),
            (
                r#"{"version":1,"rules":[{"match":{},"scope":null}]}"#,
                "method",
            ),
            (
                r#"{"version":1,"rules":[{"match":{"method":""},"scope":null}]}"#,
                "method",
            ),
            (
                r#"{"version":1,"rules":[{"match":{"method":7},"scope":null}]}"#,
                "method",
            ),
            (
                r#"{"version":1,"rules":[{"match":{"method":"ping","tool":"x"},"scope":null}]}"#,
                "tool_without_tools_call",
            ),
            (
                r#"{"version":1,"rules":[{"match":{"method":"tools/*","tool":"x"},"scope":null}]}"#,
                "tool_without_tools_call",
            ),
            (
                r#"{"version":1,"rules":[{"match":{"method":"tools/call","tool":""},"scope":null}]}"#,
                "tool",
            ),
            (
                r#"{"version":1,"rules":[{"match":{"method":"tools/call","tool":7},"scope":null}]}"#,
                "tool",
            ),
            (
                r#"{"version":1,"rules":[{"match":{"method":"ping"},"scope":null,"effect":"permit"}]}"#,
                "effect",
            ),
            (
                r#"{"version":1,"rules":[{"match":{"method":"ping"},"scope":null,"effect":3}]}"#,
                "effect",
            ),
            (
                r#"{"version":1,"rules":[{"match":{"method":"ping"},"scope":null,"effect":null}]}"#,
                "effect",
            ),
            (
                r#"{"version":1,"rules":[{"match":{"method":"ping"},"scope":"read","effect":"deny"}]}"#,
                "scope_with_deny",
            ),
            (
                r#"{"version":1,"rules":[{"match":{"method":"ping"}}]}"#,
                "missing_scope",
            ),
            (
                r#"{"version":1,"rules":[{"match":{"method":"ping"},"scope":"Read"}]}"#,
                "malformed_scope",
            ),
            (
                r#"{"version":1,"rules":[{"match":{"method":"ping"},"scope":"a:b-"}]}"#,
                "malformed_scope",
            ),
            (
                r#"{"version":1,"rules":[{"match":{"method":"ping"},"scope":"admin"}]}"#,
                "reserved_scope",
            ),
        ];
        for (doc, reason) in cases {
            assert_eq!(&parse_err(doc), reason, "doc: {doc}");
        }
    }

    #[test]
    fn parse_accepts_and_defaults() {
        let empty = parse_ok(r#"{"version":1,"rules":[]}"#);
        assert_eq!(
            eval(&empty, "ping", None),
            Decision {
                allowed: false,
                scope: None
            }
        );
        assert!(Policy::parse(br#"{"version":1.0,"rules":[]}"#).is_ok());
        assert!(Policy::parse(br#"{"version":1,"rules":[{"match":{"method":"tools/call","tool":"x.*"},"effect":"deny"}]}"#).is_ok());
        assert!(Policy::parse(
            br#"{"version":1,"rules":[{"match":{"method":"ping"},"scope":null}]}"#
        )
        .is_ok());
    }

    #[test]
    fn evaluate_matches_go_table() {
        let policy = parse_ok(
            r#"{"version":1,"rules":[
                {"match":{"method":"ping"},"scope":null},
                {"match":{"method":"tools/list"},"scope":null},
                {"match":{"method":"notifications/*"},"scope":null},
                {"match":{"method":"tools/call","tool":"svc.danger.*"},"effect":"deny"},
                {"match":{"method":"tools/call","tool":"svc.config.set"},"scope":"config:write"},
                {"match":{"method":"tools/call","tool":"svc.reload"},"scope":"lifecycle"},
                {"match":{"method":"tools/call","tool":"svc.restart"},"scope":"lifecycle"},
                {"match":{"method":"tools/call","tool":"svc.*"},"scope":"read"}
            ]}"#,
        );
        assert_eq!(
            eval(&policy, "ping", None),
            Decision {
                allowed: true,
                scope: None
            }
        );
        assert_eq!(
            eval(&policy, "tools/list", None),
            Decision {
                allowed: true,
                scope: None
            }
        );
        assert_eq!(
            eval(&policy, "notifications/initialized", None),
            Decision {
                allowed: true,
                scope: None
            }
        );
        assert_eq!(
            eval(&policy, "tools/call", Some("svc.status")),
            Decision {
                allowed: true,
                scope: Some("read".into())
            }
        );
        // '*' spans dots.
        assert_eq!(
            eval(&policy, "tools/call", Some("svc.logs.query")),
            Decision {
                allowed: true,
                scope: Some("read".into())
            }
        );
        // Specific rule first.
        assert_eq!(
            eval(&policy, "tools/call", Some("svc.config.set")),
            Decision {
                allowed: true,
                scope: Some("config:write".into())
            }
        );
        assert_eq!(
            eval(&policy, "tools/call", Some("svc.reload")),
            Decision {
                allowed: true,
                scope: Some("lifecycle".into())
            }
        );
        assert_eq!(
            eval(&policy, "tools/call", Some("svc.restart")),
            Decision {
                allowed: true,
                scope: Some("lifecycle".into())
            }
        );
        // Deny beats later svc.*.
        assert_eq!(
            eval(&policy, "tools/call", Some("svc.danger.wipe")),
            Decision {
                allowed: false,
                scope: None
            }
        );
        assert_eq!(
            eval(&policy, "tools/call", Some("other.tool")),
            Decision {
                allowed: false,
                scope: None
            }
        );
        assert_eq!(
            eval(&policy, "resources/read", None),
            Decision {
                allowed: false,
                scope: None
            }
        );

        let wildcard =
            parse_ok(r#"{"version":1,"rules":[{"match":{"method":"tools/call"},"scope":null}]}"#);
        assert_eq!(
            eval(&wildcard, "tools/call", Some("other.tool")),
            Decision {
                allowed: true,
                scope: None
            }
        );
        assert_eq!(
            eval(&wildcard, "ping", None),
            Decision {
                allowed: false,
                scope: None
            }
        );
    }

    #[test]
    fn evaluate_first_match_wins_and_tool_binding() {
        let first = parse_ok(
            r#"{"version":1,"rules":[
                {"match":{"method":"tools/call","tool":"svc.*"},"scope":"read"},
                {"match":{"method":"tools/call","tool":"svc.a"},"scope":"config:write"}
            ]}"#,
        );
        assert_eq!(
            eval(&first, "tools/call", Some("svc.a")),
            Decision {
                allowed: true,
                scope: Some("read".into())
            }
        );
        let second = parse_ok(
            r#"{"version":1,"rules":[
                {"match":{"method":"tools/call","tool":"svc.a"},"scope":"config:write"},
                {"match":{"method":"tools/call","tool":"svc.*"},"scope":"read"}
            ]}"#,
        );
        assert_eq!(
            eval(&second, "tools/call", Some("svc.a")),
            Decision {
                allowed: true,
                scope: Some("config:write".into())
            }
        );

        // Rule with a tool does not match when no tool argument is carried.
        let tool_bound = parse_ok(
            r#"{"version":1,"rules":[{"match":{"method":"tools/call","tool":"x.*"},"scope":null}]}"#,
        );
        assert_eq!(
            eval(&tool_bound, "tools/call", None),
            Decision {
                allowed: false,
                scope: None
            }
        );

        // A rule without tool ignores the tool argument.
        let no_tool =
            parse_ok(r#"{"version":1,"rules":[{"match":{"method":"ping"},"scope":null}]}"#);
        assert_eq!(
            eval(&no_tool, "ping", Some("t")),
            Decision {
                allowed: true,
                scope: None
            }
        );

        // Deny without scope.
        let deny =
            parse_ok(r#"{"version":1,"rules":[{"match":{"method":"ping"},"effect":"deny"}]}"#);
        assert_eq!(
            eval(&deny, "ping", None),
            Decision {
                allowed: false,
                scope: None
            }
        );
    }
}
