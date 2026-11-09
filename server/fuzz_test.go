package server

import (
	"bytes"
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
