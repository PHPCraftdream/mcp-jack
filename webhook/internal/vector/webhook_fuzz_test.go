package vector

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/dsig"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/wire"
)

const fuzzLimit = 256 << 10

// collectStringFields walks the fixture objects and collects the requested
// string-valued fields. The generated vectors contain many unrelated case kinds.
func collectStringFields(value any, field string, out *[]string) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if key == field {
				if text, ok := child.(string); ok {
					*out = append(*out, text)
				}
			}
			collectStringFields(child, field, out)
		}
	case []any:
		for _, child := range v {
			collectStringFields(child, field, out)
		}
	}
}

func fixtureStrings(t interface {
	Helper()
	Fatalf(string, ...any)
}, name, field string) []string {
	t.Helper()
	path := RepoPath("spec", "fixtures", "modern", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
	var values []string
	collectStringFields(root, field, &values)
	return values
}

func FuzzWebhookHeaderAndWireBody(f *testing.F) {
	// Seed directly from the checked-in signature and receiver vector corpora.
	headers := fixtureStrings(f, "webhook-signature-vectors.json", "signature_header")
	w1Headers := fixtureStrings(f, "webhook-w1-vectors.json", "header")
	bodies := fixtureStrings(f, "webhook-receiver-vectors.json", "body_text")
	for _, header := range headers {
		f.Add(header, []byte(`{"eventId":"evt_1","name":"test","timestamp":"2026-01-01T00:00:00Z","data":{}}`))
	}
	for _, header := range w1Headers {
		f.Add(header, []byte(`{"eventId":"evt_1","name":"test","timestamp":"2026-01-01T00:00:00Z","data":{}}`))
	}
	for _, body := range bodies {
		f.Add("v1,AA==", []byte(body))
	}

	// A small number of paired fixture seeds exercise the header and body
	// parsers together without letting generated vector sizes dominate the corpus.
	for _, headerSet := range [][]string{headers, w1Headers} {
		added := 0
		for i := 0; i < len(headerSet) && i < len(bodies) && added < 3; i++ {
			if len(headerSet[i]) > 4<<10 || len(bodies[i]) > 4<<10 {
				continue
			}
			f.Add(headerSet[i], []byte(bodies[i]))
			added++
		}
	}

	// Handwritten malformed and boundary seeds, paired to exercise both paths.
	hand := []struct {
		header string
		body   []byte
	}{
		{"", nil},
		{"v1,AA==", []byte(`{}`)},
		{"v1,AA==", []byte(`{"type":"terminated","error":{"code":1.5,"message":"x"}}`)},
		{"v1,AA==", []byte(`{"type":"terminated","error":{"code":-32024,"message":"x"}}`)},
		{"v1,AA==", []byte(`{"type":"terminated","error":{"code":01,"message":"x"}}`)},
		{"v1,AA== v1,AA==", []byte(`{"eventId":"x","name":"n","timestamp":"2026-01-01T00:00:00Z","data":{}}`)},
		{"v1,AA==\r\nv1,AA==", []byte{'{', 0, '}'}},
		{"v1,AA==", []byte{0xff, 0xfe, '{'}},
		{"w1 kid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,sig=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", []byte(`{"type":"gap","cursor":null}`)},
		{strings.Repeat("x", 4096), make([]byte, fuzzLimit-1)},
		{"v1,AA== v1,AA==", []byte(`{"eventId":"evt_1","name":"x","timestamp":"2026-01-01T00:00:00Z","data":{"a":1,"a":2}}`)},
		{"v1,AA==", []byte(`{"eventId":"evt_1","name":"x","timestamp":"2026-01-01T00:00:00Z","data":{"n":1e999}}`)},
	}
	for _, seed := range hand {
		f.Add(seed.header, seed.body)
	}

	f.Fuzz(func(t *testing.T, header string, body []byte) {
		if len(header) > 4096 {
			header = header[:4096]
		}
		if len(body) > fuzzLimit {
			body = body[:fuzzLimit]
		}

		entries, parseCode := dsig.ParseHeader(header)
		switch parseCode {
		case "", "malformed_signature_header":
		default:
			t.Fatalf("ParseHeader returned unexpected code %q", parseCode)
		}
		if parseCode == "" {
			if len(entries) == 0 {
				t.Fatalf("ParseHeader accepted header without entries")
			}
			parts := make([]string, len(entries))
			for i, entry := range entries {
				if entry.Scheme == "" || entry.Value == "" {
					t.Fatalf("ParseHeader returned empty scheme or value")
				}
				parts[i] = entry.Scheme + "," + entry.Value
			}
			reparsed, code := dsig.ParseHeader(strings.Join(parts, " "))
			if code != "" || !reflect.DeepEqual(entries, reparsed) {
				t.Fatalf("standard header failed equivalent reparse")
			}
			decoded, decodeCode := dsig.DecodeValues(entries)
			switch decodeCode {
			case "":
				if len(decoded) != len(entries) {
					t.Fatalf("DecodeValues returned %d entries for %d inputs", len(decoded), len(entries))
				}
				for i, entry := range decoded {
					wantLen := 64
					if entries[i].Scheme == "v1" {
						wantLen = 32
					}
					if len(entry.Sig) != wantLen {
						t.Fatalf("DecodeValues returned signature length %d, want %d", len(entry.Sig), wantLen)
					}
				}
			case "malformed_signature":
			default:
				t.Fatalf("DecodeValues returned unexpected code %q", decodeCode)
			}
			schemeCode := dsig.CheckSchemes(entries)
			switch schemeCode {
			case "", "unsupported_signature_scheme":
			default:
				t.Fatalf("CheckSchemes returned unexpected code %q", schemeCode)
			}
		}

		kid, sig, ok := dsig.ParseW1Header(header)
		if ok {
			if len(kid) != 43 || len(sig) != 86 {
				t.Fatalf("ParseW1Header accepted invalid field lengths")
			}
			canonical := dsig.W1HeaderValue(kid, sig)
			kidAgain, sigAgain, okAgain := dsig.ParseW1Header(canonical)
			if !okAgain || kid != kidAgain || sig != sigAgain {
				t.Fatalf("accepted w1 header failed consistent reparse")
			}
		}

		message, bodyCode := wire.Parse(body)
		switch bodyCode {
		case "malformed_body", "unknown_envelope_type":
			if !reflect.DeepEqual(message, wire.Message{}) {
				t.Fatalf("Parse returned message with error code %q", bodyCode)
			}
		case "":
			switch message.Kind {
			case wire.KindEvent, wire.KindGap, wire.KindTerminated, wire.KindVerification:
			default:
				t.Fatalf("Parse returned invalid message kind %q", message.Kind)
			}
			if message.Cursor != nil && !wire.ValidCursor(message.Cursor) {
				t.Fatalf("Parse returned invalid cursor %q", *message.Cursor)
			}
			original := append([]byte(nil), body...)
			if !reflect.DeepEqual([]byte(message.Raw), original) {
				t.Fatalf("Parse did not preserve a raw body copy")
			}
			if len(body) > 0 {
				body[0] ^= 0xff
				if !reflect.DeepEqual([]byte(message.Raw), original) {
					t.Fatalf("Parse raw body aliases input")
				}
				body[0] ^= 0xff
			}
		default:
			t.Fatalf("Parse returned unexpected reason code %q", bodyCode)
		}
		// Grammar helpers must agree on timestamp acceptance and parsing; the
		// predicates consume the exact arbitrary bytes, including invalid UTF-8.
		for _, text := range []string{header, string(body)} {
			_, timestampOK := wire.ParseTimestamp(text)
			if got := wire.ValidTimestamp(text); got != timestampOK {
				t.Fatalf("ValidTimestamp and ParseTimestamp disagree")
			}
			if _, ok := wire.ParseTimestamp(text); ok && !wire.ValidTimestamp(text) {
				t.Fatalf("ParseTimestamp accepted invalid timestamp grammar")
			}
			if wire.ValidWebhookID(text) {
				if len(text) < 8 || len(text) > 128 {
					t.Fatalf("ValidWebhookID accepted invalid length %d", len(text))
				}
				for i := 0; i < len(text); i++ {
					c := text[i]
					if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
						t.Fatalf("ValidWebhookID accepted invalid byte %#x", c)
					}
				}
			}
			if wire.ValidSubscriptionID(text) {
				if len(text) != len("sub_")+16 || !strings.HasPrefix(text, "sub_") {
					t.Fatalf("ValidSubscriptionID accepted invalid shape")
				}
				for i := len("sub_"); i < len(text); i++ {
					c := text[i]
					if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
						t.Fatalf("ValidSubscriptionID accepted invalid byte %#x", c)
					}
				}
			}
		}
	})
}

func TestWebhookWireGrammarBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		text                        string
		id, timestamp, subscription bool
	}{
		{"empty", "", false, false, false},
		{"id lower bound", "abcdefgh", true, false, false},
		{"id upper bound", strings.Repeat("a", 128), true, false, false},
		{"id too long", strings.Repeat("a", 129), false, false, false},
		{"timestamp zero", "0", false, true, false},
		{"timestamp max", "999999999999", true, true, false},
		{"timestamp huge", "1000000000000", true, false, false},
		{"timestamp fraction", "1.5", false, false, false},
		{"timestamp negative", "-1", false, false, false},
		{"timestamp leading zero", "01", false, false, false},
		{"subscription valid", "sub_0123456789abcdef", true, false, true},
		{"subscription duplicate-like", "sub_0123456789abcdefsub_0123456789abcdef", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := wire.ValidWebhookID(tc.text); got != tc.id {
				t.Errorf("ValidWebhookID = %v", got)
			}
			if got := wire.ValidTimestamp(tc.text); got != tc.timestamp {
				t.Errorf("ValidTimestamp = %v", got)
			}
			if got := wire.ValidSubscriptionID(tc.text); got != tc.subscription {
				t.Errorf("ValidSubscriptionID = %v", got)
			}
			_, _ = wire.ParseTimestamp(tc.text)
		})
	}
}
