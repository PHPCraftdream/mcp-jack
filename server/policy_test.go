package server

import (
	"errors"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/spec"
)

func TestPolicyLoadVectors(t *testing.T) {
	vectors, err := spec.LoadLoadVectors()
	if err != nil {
		t.Fatalf("LoadLoadVectors: %v", err)
	}
	if len(vectors.Policies) == 0 {
		t.Fatal("no policy load vectors")
	}
	for _, c := range vectors.Policies {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			p, err := ParsePolicy(c.Document)
			switch c.Expect {
			case "valid":
				if err != nil || p == nil {
					t.Fatalf("ParsePolicy rejected a valid document: %v", err)
				}
			case "invalid":
				if err == nil {
					t.Fatalf("ParsePolicy accepted an invalid document (%s)", c.Reason)
				}
				var pe *PolicyError
				if !errors.As(err, &pe) {
					t.Fatalf("error is %T, want *PolicyError", err)
				}
			default:
				t.Fatalf("unknown expectation %q", c.Expect)
			}
		})
	}
}

func loadTestPolicy(t *testing.T, file string) *Policy {
	t.Helper()
	data, err := spec.Fixture(file)
	if err != nil {
		t.Fatalf("Fixture(%s): %v", file, err)
	}
	p, err := ParsePolicy(data)
	if err != nil {
		t.Fatalf("ParsePolicy(%s): %v", file, err)
	}
	return p
}

func TestPolicyEvaluate(t *testing.T) {
	read, config, lifecycle := "read", "config:write", "lifecycle"
	type want struct {
		allowed bool
		scope   *string
	}
	cases := []struct {
		name    string
		file    string
		method  string
		tool    string
		hasTool bool
		want    want
	}{
		{"ping", "policy.json", "ping", "", false, want{true, nil}},
		{"tools/list", "policy.json", "tools/list", "", false, want{true, nil}},
		{"notification glob", "policy.json", "notifications/initialized", "", false, want{true, nil}},
		{"read tool", "policy.json", "tools/call", "svc.status", true, want{true, &read}},
		{"glob keeps dots literal inside the prefix", "policy.json", "tools/call", "svc.logs.query", true, want{true, &read}},
		{"specific rule before svc.*", "policy.json", "tools/call", "svc.config.set", true, want{true, &config}},
		{"reload", "policy.json", "tools/call", "svc.reload", true, want{true, &lifecycle}},
		{"restart", "policy.json", "tools/call", "svc.restart", true, want{true, &lifecycle}},
		{"deny rule wins over the later svc.*", "policy.json", "tools/call", "svc.danger.wipe", true, want{false, nil}},
		{"unmatched tool", "policy.json", "tools/call", "other.tool", true, want{false, nil}},
		{"unmatched method", "policy.json", "resources/read", "", false, want{false, nil}},
		{"wildcard allows any tool", "policy-wildcard.json", "tools/call", "other.tool", true, want{true, nil}},
		{"wildcard does not allow ping", "policy-wildcard.json", "ping", "", false, want{false, nil}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			d := loadTestPolicy(t, c.file).Evaluate(c.method, c.tool, c.hasTool)
			if d.Allowed != c.want.allowed {
				t.Fatalf("Allowed = %v, want %v", d.Allowed, c.want.allowed)
			}
			switch {
			case d.Scope == nil && c.want.scope == nil:
			case d.Scope != nil && c.want.scope != nil && *d.Scope == *c.want.scope:
			default:
				t.Fatalf("Scope = %v, want %v", d.Scope, c.want.scope)
			}
		})
	}
}

func TestClassifyBody(t *testing.T) {
	cases := []struct {
		name string
		body string
		ok   bool
		kind int
	}{
		{"request", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, true, kindRequest},
		{"notification", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, true, kindRequest},
		{"response with result", `{"jsonrpc":"2.0","id":1,"result":{}}`, true, kindResponse},
		{"response with error", `{"jsonrpc":"2.0","id":"a","error":{"code":1,"message":"x"}}`, true, kindResponse},
		{"response with a null id", `{"jsonrpc":"2.0","id":null,"result":1}`, true, kindResponse},
		{"empty", ``, false, 0},
		{"null", `null`, false, 0},
		{"array batch", `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, false, 0},
		{"member names are case-sensitive", `{"JSONRPC":"2.0","method":"ping"}`, false, 0},
		{"wrong version", `{"jsonrpc":"1.0","method":"ping"}`, false, 0},
		{"version is not a string", `{"jsonrpc":2.0,"method":"ping"}`, false, 0},
		{"method is null", `{"jsonrpc":"2.0","method":null}`, false, 0},
		{"method is a number", `{"jsonrpc":"2.0","method":7}`, false, 0},
		{"response with both result and error", `{"jsonrpc":"2.0","id":1,"result":1,"error":2}`, false, 0},
		{"response without id", `{"jsonrpc":"2.0","result":1}`, false, 0},
		{"tools/call without params", `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`, false, 0},
		{"tools/call with a numeric name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":7}}`, false, 0},
		{"tools/call with a null name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":null}}`, false, 0},
		{"invalid UTF-8", "{\"jsonrpc\":\"2.0\",\"method\":\"p\xffng\"}", false, 0},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			msg, ok := classifyBody([]byte(c.body))
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if ok && msg.kind != c.kind {
				t.Fatalf("kind = %d, want %d", msg.kind, c.kind)
			}
		})
	}
}
