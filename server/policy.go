package server

import (
	"bytes"
	"encoding/json"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// PolicyError is a load-time validation failure of a policy document
// (spec 02 section 3). Reason is a short stable identifier.
type PolicyError struct{ Reason string }

func (e *PolicyError) Error() string { return "server: invalid policy: " + e.Reason }

type policyRule struct {
	method string
	tool   *string // nil: any tool
	deny   bool
	scope  *string // nil: any authenticated key (allow rules only)
}

// Policy is an operator-owned list of first-match-wins rules; anything no rule
// allows is denied (spec 02 section 3).
type Policy struct{ rules []policyRule }

// Decision is the policy verdict for one operation.
type Decision struct {
	// Allowed is false when no rule matched or a deny rule matched.
	Allowed bool
	// Scope is the scope the caller must hold; nil means any authenticated key.
	Scope *string
}

// ParsePolicy validates and compiles a policy document. It works on raw JSON
// so a missing "scope" can be told apart from a null one.
func ParsePolicy(data []byte) (*Policy, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil || doc == nil || !onlyKeys(doc, "version", "rules") {
		return nil, &PolicyError{"document"}
	}
	var version float64
	if err := json.Unmarshal(doc["version"], &version); err != nil || version != 1 {
		return nil, &PolicyError{"document"}
	}
	if isJSONNull(doc["rules"]) {
		return nil, &PolicyError{"document"}
	}
	var rawRules []json.RawMessage
	if err := json.Unmarshal(doc["rules"], &rawRules); err != nil {
		return nil, &PolicyError{"document"}
	}

	p := &Policy{rules: make([]policyRule, 0, len(rawRules))}
	for _, raw := range rawRules {
		rule, reason := parseRule(raw)
		if reason != "" {
			return nil, &PolicyError{reason}
		}
		p.rules = append(p.rules, rule)
	}
	return p, nil
}

func parseRule(raw json.RawMessage) (policyRule, string) {
	var r map[string]json.RawMessage
	if err := json.Unmarshal(raw, &r); err != nil || r == nil || !onlyKeys(r, "match", "scope", "effect") {
		return policyRule{}, "unknown_field"
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(r["match"], &m); err != nil || m == nil || !onlyKeys(m, "method", "tool") {
		return policyRule{}, "unknown_field"
	}

	method, ok := jsonString(m["method"])
	if !ok || method == "" {
		return policyRule{}, "method"
	}
	rule := policyRule{method: method}
	if rawTool, has := m["tool"]; has {
		tool, ok := jsonString(rawTool)
		if !ok || tool == "" {
			return policyRule{}, "tool"
		}
		if method != "tools/call" {
			return policyRule{}, "tool_without_tools_call"
		}
		rule.tool = &tool
	}

	effect := "allow"
	if rawEffect, has := r["effect"]; has && !isJSONNull(rawEffect) {
		e, ok := jsonString(rawEffect)
		if !ok || (e != "allow" && e != "deny") {
			return policyRule{}, "effect"
		}
		effect = e
	}

	_, hasScope := r["scope"]
	if effect == "deny" {
		if hasScope {
			return policyRule{}, "scope_with_deny"
		}
		rule.deny = true
		return rule, ""
	}
	if !hasScope {
		return policyRule{}, "missing_scope"
	}
	if !isJSONNull(r["scope"]) {
		scope, ok := jsonString(r["scope"])
		if !ok || !jack.ValidScope(scope) {
			return policyRule{}, "malformed_scope"
		}
		if scope == "admin" {
			return policyRule{}, "reserved_scope"
		}
		rule.scope = &scope
	}
	return rule, ""
}

// Evaluate returns the verdict for a method and, for tools/call, a tool name.
func (p *Policy) Evaluate(method, tool string, hasTool bool) Decision {
	for _, rule := range p.rules {
		if !jack.MatchPattern(rule.method, method) {
			continue
		}
		if rule.tool != nil && !(method == "tools/call" && hasTool && jack.MatchPattern(*rule.tool, tool)) {
			continue
		}
		if rule.deny {
			return Decision{}
		}
		return Decision{Allowed: true, Scope: rule.scope}
	}
	return Decision{}
}

func onlyKeys(m map[string]json.RawMessage, allowed ...string) bool {
	for k := range m {
		found := false
		for _, a := range allowed {
			if k == a {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// isJSONNull reports whether raw is the JSON null literal.
func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// jsonString decodes raw only when it is a JSON string; encoding/json would
// also accept null for a string target, which the protocol must not.
func jsonString(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err != nil {
		return "", false
	}
	return s, true
}
