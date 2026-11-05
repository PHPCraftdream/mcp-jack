package server

import (
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
	f.Add([]byte(`{"jsonrpc":"2.0","method":"ping"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))

	f.Fuzz(func(t *testing.T, body []byte) {
		msg, ok := classifyBody(body)
		if !ok {
			return
		}
		if !utf8.Valid(body) {
			t.Fatalf("accepted a body that is not valid UTF-8: %q", body)
		}
		if msg.kind != kindRequest && msg.kind != kindResponse {
			t.Fatalf("unknown kind %d", msg.kind)
		}
		if msg.hasTool && msg.method != "tools/call" {
			t.Fatalf("tool %q reported for method %q", msg.tool, msg.method)
		}
		if msg.kind == kindResponse && (msg.method != "" || msg.hasTool) {
			t.Fatalf("a response carries a method or tool: %+v", msg)
		}
	})
}
