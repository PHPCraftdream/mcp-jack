package modernvectors

import (
	"encoding/json"
	"testing"

	clientmodern "github.com/PHPCraftdream/mcp-jack/client/modern"
)

// encodingCase is one case of header-encoding-vectors.json.
type encodingCase struct {
	ID          string          `json:"id"`
	Kind        string          `json:"kind"`
	Rule        string          `json:"rule"`
	Version     string          `json:"version"`
	Method      string          `json:"method"`
	Params      json.RawMessage `json:"params"`
	Type        string          `json:"type"`
	Value       json.RawMessage `json:"value"`
	HeaderValue string          `json:"header_value"`
	Expect      json.RawMessage `json:"expect"`
}

// encodingVectorFile is header-encoding-vectors.json.
type encodingVectorFile struct {
	Cases []encodingCase `json:"cases"`
}

func TestModernHeaderEncodingVectors(t *testing.T) {
	raw := fixtureFile(t, "header-encoding-vectors.json")
	var corpus encodingVectorFile
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("decode header-encoding-vectors.json: %v", err)
	}
	if len(corpus.Cases) != 51 {
		t.Fatalf("header-encoding-vectors.json: got %d cases, want 51", len(corpus.Cases))
	}

	pass := 0
	for i := range corpus.Cases {
		c := corpus.Cases[i]
		t.Run(c.ID, func(t *testing.T) {
			switch c.Kind {
			case "build":
				var params map[string]any
				if err := json.Unmarshal(c.Params, &params); err != nil {
					t.Fatalf("decode params: %v", err)
				}
				rm, err := clientmodern.BuildRequestMirrors(c.Version, c.Method, params, nil)
				if err != nil {
					t.Fatalf("BuildRequestMirrors: %v", err)
				}
				got := map[string]any{
					"meta":    rm.Meta,
					"headers": headerPairs(rm.Headers),
				}
				assertCase(t, c.ID, c.Expect, got)

			case "encode":
				value := decodeAny(t, c.Value)
				text, ok := clientmodern.TextOfValue(value, c.Type)
				if !ok {
					t.Fatalf("TextOfValue(%s, %q) = false", c.Value, c.Type)
				}
				headerValue := clientmodern.EncodeHeaderValue(text)
				assertCase(t, c.ID, c.Expect, map[string]any{"header_value": headerValue})

				var expect struct {
					HeaderValue string `json:"header_value"`
				}
				if err := json.Unmarshal(c.Expect, &expect); err != nil {
					t.Fatalf("decode expect: %v", err)
				}
				decoded, ok := clientmodern.DecodeHeaderValue(expect.HeaderValue)
				if !ok {
					t.Fatalf("DecodeHeaderValue(%q) = false, want the encoded text", expect.HeaderValue)
				}
				if decoded != text {
					t.Fatalf("encode/decode round trip: got %q, want %q", decoded, text)
				}

			case "decode":
				text, ok := clientmodern.DecodeHeaderValue(c.HeaderValue)
				var got map[string]any
				if ok {
					got = map[string]any{"ok": true, "text": text}
				} else {
					got = map[string]any{"ok": false, "reason": "bad_encoding"}
				}
				assertCase(t, c.ID, c.Expect, got)

			default:
				t.Fatalf("unknown kind %q", c.Kind)
			}
			pass++
		})
	}
	summary(t, "header-encoding", pass)
}
