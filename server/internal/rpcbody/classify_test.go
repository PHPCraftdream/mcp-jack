package rpcbody

import (
	"strings"
	"testing"
)

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
		{"request", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, true, KindRequest},
		{"notification", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, true, KindRequest},
		{"response with result", `{"jsonrpc":"2.0","id":1,"result":{}}`, true, KindResponse},
		{"response with error", `{"jsonrpc":"2.0","id":"a","error":{"code":1,"message":"x"}}`, true, KindResponse},
		{"response with a null id", `{"jsonrpc":"2.0","id":null,"result":1}`, true, KindResponse},
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
		{"lone surrogate escape in method", `{"jsonrpc":"2.0","id":1,"method":"pi\ud800ng"}`, false, 0},
		{"lone surrogate escape in a member name", `{"jsonrpc":"2.0","id":1,"m\ud800":1,"method":"ping"}`, false, 0},
		{"lone surrogate escape in params.name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"stat\udc00us"}}`, false, 0},
		{"lone surrogate escape after a valid pair", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"\ud83d\ude00\ud800"}}`, false, 0},
		{"paired surrogate escape is accepted", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"\ud83d\ude00"}}`, true, KindRequest},
		{"escaped backslash is not a surrogate escape", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"a\\ud800b"}}`, true, KindRequest},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			msg, ok := Classify([]byte(c.body))
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if ok && msg.Kind != c.kind {
				t.Fatalf("kind = %d, want %d", msg.Kind, c.kind)
			}
		})
	}
}

// TestClassifyBodyDepth pins the 128-level nesting maximum and the
// string-skip rule of the pre-parse scan (spec 02 section 4 step 2).
func TestClassifyBodyDepth(t *testing.T) {
	okBody := func(levels int) string {
		return `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":` +
			strings.Repeat("[", levels) + strings.Repeat("]", levels) + `}}`
	}
	if _, ok := Classify([]byte(okBody(126))); !ok {
		t.Fatal("128 container levels must classify")
	}
	if _, ok := Classify([]byte(okBody(127))); ok {
		t.Fatal("129 container levels must be rejected before parsing")
	}
	// Braces and brackets inside string values never count toward depth.
	inString := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"` +
		strings.Repeat("[[", 200) + strings.Repeat("]]", 200) + `"}}`
	if _, ok := Classify([]byte(inString)); !ok {
		t.Fatal("containers inside string values must not count toward depth")
	}
	// Sibling members do not accumulate depth.
	siblings := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":{"b":{"c":1}},"d":{"e":{"f":2}}}}`
	if _, ok := Classify([]byte(siblings)); !ok {
		t.Fatal("sibling members must not accumulate depth")
	}
}
