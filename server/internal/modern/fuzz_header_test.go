package modern

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	clientmodern "github.com/PHPCraftdream/mcp-jack/client/modern"
)

const headerFixtureDir = "../../../spec/fixtures/modern"

type encodingFixture struct {
	Cases []struct {
		Kind        string          `json:"kind"`
		Value       json.RawMessage `json:"value"`
		HeaderValue string          `json:"header_value"`
		Expect      struct {
			OK bool `json:"ok"`
		} `json:"expect"`
	} `json:"cases"`
}

type annotationFixture struct {
	Cases []struct {
		Kind string `json:"kind"`
		Tool struct {
			InputSchema json.RawMessage `json:"inputSchema"`
		} `json:"tool"`
		Event struct {
			InputSchema json.RawMessage `json:"inputSchema"`
		} `json:"event"`
		Arguments json.RawMessage `json:"arguments"`
		Expect    struct {
			Valid   bool   `json:"valid"`
			Outcome string `json:"outcome"`
		} `json:"expect"`
	} `json:"cases"`
}

func fixtureBytes(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(headerFixtureDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// FuzzModernHeaderBoundaries covers C3/C4, C5/C6, and server S3-S6 mirror checks.
func FuzzModernHeaderBoundaries(f *testing.F) {
	// Both named specifications are consumed as seed sources. Add header inputs
	// from C3/C4 and schema/argument documents from C5/C6.
	var enc encodingFixture
	if err := json.Unmarshal(
		mustReadFixture("header-encoding-vectors.json"),
		&enc,
	); err != nil {
		f.Fatal(err)
	}
	for _, c := range enc.Cases {
		if c.Kind == "decode" {
			f.Add([]byte(c.HeaderValue))
		} else if c.Kind == "encode" {
			var value string
			if err := json.Unmarshal(c.Value, &value); err == nil {
				f.Add([]byte(value))
			} else if len(c.Value) != 0 {
				// Preserve non-string JSON values as seed bytes, with a size cap.
				seed := c.Value
				if len(seed) > 4096 {
					seed = seed[:4096]
				}
				f.Add(append([]byte(nil), seed...))
			}
		}
	}
	var ann annotationFixture
	if err := json.Unmarshal(
		mustReadFixture("x-mcp-header-vectors.json"),
		&ann,
	); err != nil {
		f.Fatal(err)
	}
	for _, c := range ann.Cases {
		if len(c.Tool.InputSchema) != 0 {
			f.Add(append([]byte(nil), c.Tool.InputSchema...))
		}
		if len(c.Event.InputSchema) != 0 {
			f.Add(append([]byte(nil), c.Event.InputSchema...))
		}
		if len(c.Arguments) != 0 {
			f.Add(append([]byte(nil), c.Arguments...))
		}
	}
	for _, s := range []string{
		"",
		strings.Repeat("a", 1024),
		"\x00",
		"\r\n",
		string([]byte{0xff, 0xfe}),
		"=?base64?@@@@?=",
		"=?base64?SGVsbG8?=",
		"=?base64?/w==?=",
		"=?base64??=",
		"000000000000000000000000000000000",
		"1.5",
		"-0",
		"01",
		`{"properties":{"x":{"type":"string","x-mcp-header":"X"}}}`,
		`{"x":"v"}`,
	} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		text := string(input)
		decoded, ok := clientmodern.DecodeHeaderValue(text) // Must not panic for arbitrary bytes.
		if utf8.Valid(input) {
			encoded := clientmodern.EncodeHeaderValue(text)
			roundTrip, valid := clientmodern.DecodeHeaderValue(encoded)
			if !valid || roundTrip != text {
				t.Fatalf("valid UTF-8 encode/decode identity failed for %q", text)
			}
		}
		_, _ = decoded, ok

		// Exercise validation and projection against arbitrary schema/argument
		// bytes, and a generated safe annotation whose value is fuzzed.
		_ = clientmodern.ValidateAnnotations(input)
		_, _ = clientmodern.ProjectArguments(input, input)
		schema, _ := json.Marshal(map[string]any{
			"properties": map[string]any{
				"value": map[string]any{"type": "string", "x-mcp-header": "X-Fuzz"},
			},
		})
		args, _ := json.Marshal(map[string]any{"value": text})
		if utf8.Valid(input) && clientmodern.ValidateAnnotations(schema).Valid {
			projected, err := clientmodern.ProjectArguments(schema, args)
			if err != nil {
				t.Fatalf("project valid fuzzed string: %v", err)
			}
			if len(projected) != 1 || projected[0].Name != "Mcp-Param-X-Fuzz" {
				t.Fatalf("projected headers = %#v, want one Mcp-Param-X-Fuzz header", projected)
			}
			value, valid := clientmodern.DecodeHeaderValue(projected[0].Value)
			if !valid || value != text {
				t.Fatalf("projected value = %q (valid=%v), want decoded %q", value, valid, text)
			}
		}

		// A valid modern request with each mirror independently mismatched must
		// reach its specific refusal path. Version stays syntactically valid;
		// method and name values are safe, fuzz-derived strings.
		body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"right","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`)
		mirrors := []Header{
			{Name: "MCP-Protocol-Version", Value: "2026-07-28"},
			{Name: "Mcp-Method", Value: "tools/call"},
			{Name: "Mcp-Name", Value: "right"},
		}
		wantReasons := []string{
			"Header mismatch: MCP-Protocol-Version does not match params._meta protocolVersion",
			"Header mismatch: Mcp-Method does not match the body method",
			"Header mismatch: Mcp-Name does not match the body value",
		}
		mismatches := []string{"2026-07-29", "fuzz-method-" + hex.EncodeToString(input), "fuzz-name-" + hex.EncodeToString(input)}
		for i := range mirrors {
			hs := append([]Header(nil), mirrors...)
			hs[i].Value = mismatches[i]
			out := Classify(ProfileModern, Request{
				Method:  "POST",
				Target:  "/mcp",
				Headers: hs,
				Body:    body,
			})
			if out.Kind != KindRefuse || out.Error.Message != wantReasons[i] {
				t.Fatalf("%s mismatch outcome = kind %v, error %q; want KindRefuse with %q", mirrors[i].Name, out.Kind, out.Error.Message, wantReasons[i])
			}
		}
	})
}

func mustReadFixture(name string) []byte {
	b, err := os.ReadFile(filepath.Join(headerFixtureDir, name))
	if err != nil {
		panic(err)
	}
	return b
}

func TestHeaderFixtureRejectedCases(t *testing.T) {
	var enc encodingFixture
	if err := json.Unmarshal(fixtureBytes(t, "header-encoding-vectors.json"), &enc); err != nil {
		t.Fatal(err)
	}
	for _, c := range enc.Cases {
		if c.Kind == "decode" && !c.Expect.OK {
			if _, ok := clientmodern.DecodeHeaderValue(c.HeaderValue); ok {
				t.Errorf("decode fixture %q unexpectedly accepted", c.HeaderValue)
			}
		}
	}
	var ann annotationFixture
	if err := json.Unmarshal(fixtureBytes(t, "x-mcp-header-vectors.json"), &ann); err != nil {
		t.Fatal(err)
	}
	for _, c := range ann.Cases {
		schema := c.Tool.InputSchema
		if len(schema) == 0 {
			schema = c.Event.InputSchema
		}
		switch c.Kind {
		case "validate", "validate-event":
			if !c.Expect.Valid && clientmodern.ValidateAnnotations(schema).Valid {
				t.Errorf("invalid annotation fixture unexpectedly accepted")
			}
		case "project", "project-event":
			if c.Expect.Outcome == "refuse" {
				if _, err := clientmodern.ProjectArguments(schema, c.Arguments); err == nil {
					t.Errorf("rejected projection fixture unexpectedly accepted")
				}
			}
		}
	}
}
