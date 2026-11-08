package server

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/PHPCraftdream/mcp-jack/spec"
)

// FuzzClassifyBody checks that the JSON-RPC body classifier never panics and
// never accepts a body that is not valid UTF-8, a JSON object with an exact
// "jsonrpc": "2.0" member.
func FuzzClassifyBody(f *testing.F) {
	vectors, err := spec.LoadRequestVectors()
	if err != nil {
		f.Fatalf("LoadRequestVectors: %v", err)
	}
	for _, c := range vectors.Cases {
		body, err := c.Request.Body()
		if err != nil {
			f.Fatalf("Body: %v", err)
		}
		f.Add(body)
	}
	pingSeed := []byte(`{"jsonrpc":"2.0","method":"ping"}`)
	emptySeed := []byte(`[]`)
	f.Add(pingSeed)
	f.Add([]byte(`null`))
	f.Add(emptySeed)

	f.Fuzz(func(t *testing.T, body []byte) {
		// Acceptance and rejection witnesses: the campaign must classify the
		// canonical ping request and refuse non-object bodies, so a classifier
		// that accepts or rejects everything fails the campaign.
		msg, ok := classifyBody(body)
		if bytes.Equal(body, pingSeed) && !ok {
			t.Fatalf("acceptance witness: canonical ping request not classified")
		}
		if bytes.Equal(body, emptySeed) && ok {
			t.Fatalf("rejection witness: empty array classified as a message")
		}
		if !ok {
			return
		}
		if !utf8.Valid(body) {
			t.Fatalf("accepted a body that is not valid UTF-8")
		}
		if msg.kind != kindRequest && msg.kind != kindResponse {
			t.Fatalf("unknown kind %d", msg.kind)
		}
		if msg.hasTool && msg.method != "tools/call" {
			t.Fatalf("classifier reported a tool for a method other than tools/call")
		}
		if msg.kind == kindResponse && (msg.method != "" || msg.hasTool) {
			t.Fatalf("a response carries a method or tool")
		}
	})
}

// FuzzParsePolicy checks that the policy compiler never panics on raw JSON,
// only fails with a PolicyError whose Reason is a stable identifier, that
// Evaluate is deterministic, and that no accepted policy can ever grant the
// reserved "admin" scope or attach a scope to a denial (spec 02 section 3).
func FuzzParsePolicy(f *testing.F) {
	vectors, err := spec.LoadLoadVectors()
	if err != nil {
		f.Fatalf("LoadLoadVectors: %v", err)
	}
	for _, c := range vectors.Policies {
		f.Add([]byte(c.Document))
	}
	f.Add([]byte(`{"version":1,"rules":[]}`))
	f.Add([]byte(`{"version":1,"rules":[{"match":{"method":"tools/call","tool":"mcp__x__*"},"effect":"allow","scope":"admin"}]}`))
	f.Add([]byte(`{"version":1,"rules":[{"match":{"method":"tools/call"},"effect":"deny","scope":"reader"}]}`))
	f.Add([]byte(`{"version":1,"rules":[{"match":{"method":"tools/call","tool":"mcp__x__*"},"effect":"allow","scope":null}]}`))
	f.Add([]byte(`{"version":1,"rules":[{"match":{"method":"mcp__*"},"effect":"allow","scope":null}]}`))

	// The two structurally valid handcrafted seeds: the campaign must accept
	// them, not only observe rejections (an always-rejecting parser would
	// otherwise pass every invariant below).
	validSeeds := [][]byte{
		[]byte(`{"version":1,"rules":[]}`),
		[]byte(`{"version":1,"rules":[{"match":{"method":"mcp__*"},"effect":"allow","scope":null}]}`),
	}

	// The invalid handcrafted seeds: the campaign must refuse them with their
	// normative classes, not silently accept a default-deny policy.
	invalidSeeds := []struct {
		document []byte
		reason   string
	}{
		{[]byte(`{"version":1,"rules":[{"match":{"method":"tools/call","tool":"mcp__x__*"},"effect":"allow","scope":"admin"}]}`), "reserved_scope"},
		{[]byte(`{"version":1,"rules":[{"match":{"method":"tools/call"},"effect":"deny","scope":"reader"}]}`), "scope_with_deny"},
	}

	// probes: method, tool, hasTool
	probes := [][3]string{
		{"tools/call", "", "0"},
		{"tools/call", "admin", "1"},
		{"admin", "", "0"},
		{"mcp__x__t", "t", "1"},
		{"", "x", "0"},
		{strings.Repeat("a", 512), "t", "1"},
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		isSeed := bytes.Equal(data, validSeeds[0]) || bytes.Equal(data, validSeeds[1])
		p, err := ParsePolicy(data)
		if isSeed && err != nil {
			t.Fatalf("acceptance witness: valid policy seed rejected: %v", err)
		}
		for _, invalid := range invalidSeeds {
			if bytes.Equal(data, invalid.document) && err == nil {
				t.Fatalf("rejection witness: invalid policy seed accepted, want %s", invalid.reason)
			}
		}
		if err != nil {
			var pe *PolicyError
			if !errors.As(err, &pe) {
				t.Fatalf("error %v is not a *PolicyError", err)
			}
			if !knownPolicyReason(pe.Reason) {
				t.Fatalf("unknown policy reason %q", pe.Reason)
			}
			for _, invalid := range invalidSeeds {
				if bytes.Equal(data, invalid.document) && pe.Reason != invalid.reason {
					t.Fatalf("rejection witness: invalid policy seed failed with %q, want %q", pe.Reason, invalid.reason)
				}
			}
			return
		}
		if isSeed {
			if d := p.Evaluate("admin", "", false); d.Allowed {
				t.Fatalf("acceptance witness: default-deny broken for the valid seed")
			}
		}
		for _, probe := range probes {
			d := p.Evaluate(probe[0], probe[1], probe[2] == "1")
			again := p.Evaluate(probe[0], probe[1], probe[2] == "1")
			if d != again {
				t.Fatalf("Evaluate is not deterministic for a fixed probe")
			}
			if !d.Allowed && d.Scope != nil {
				t.Fatalf("a denial carries a scope")
			}
			if d.Scope != nil {
				if !d.Allowed {
					t.Fatalf("a scoped decision is not allowed")
				}
				if *d.Scope == "admin" || *d.Scope == "" {
					t.Fatalf("a policy granted a reserved or empty scope")
				}
			}
		}
	})
}

// knownPolicyReason reports whether reason is one of the stable identifiers
// the parser can emit.
func knownPolicyReason(reason string) bool {
	switch reason {
	case "document", "unknown_field", "method", "tool", "tool_without_tools_call",
		"effect", "scope_with_deny", "missing_scope", "malformed_scope", "reserved_scope":
		return true
	}
	return false
}
