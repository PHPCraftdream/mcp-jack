package server

import "testing"

// TestClassifyBody pins the body-classification rules of spec 02 section 4:
// request/notification/response shapes, case-sensitive member names, strict
// typing of jsonrpc/method/name, and invalid UTF-8 rejection.
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
