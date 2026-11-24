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
		if parseCode == "" {
			parts := make([]string, len(entries))
			for i, entry := range entries {
				parts[i] = entry.Scheme + "," + entry.Value
			}
			reparsed, code := dsig.ParseHeader(strings.Join(parts, " "))
			if code != "" || !reflect.DeepEqual(entries, reparsed) {
				t.Fatalf("standard header failed equivalent reparse")
			}
			decoded, decodeCode := dsig.DecodeValues(entries)
			if decodeCode == "" {
				decodedAgain, code := dsig.DecodeValues(reparsed)
				if code != "" || !reflect.DeepEqual(decoded, decodedAgain) {
					t.Fatalf("decoded entries changed on reparse")
				}
			}
		}

		kid, sig, ok := dsig.ParseW1Header(header)
		if ok {
			canonical := dsig.W1HeaderValue(kid, sig)
			kidAgain, sigAgain, okAgain := dsig.ParseW1Header(canonical)
			if !okAgain || kid != kidAgain || sig != sigAgain {
				t.Fatalf("accepted w1 header failed consistent reparse")
			}
		}

		_, _ = wire.Parse(body)
		// Exercise the standalone grammar helpers with both fuzz inputs. These
		// checks deliberately assert no expected outcome for arbitrary bytes.
		for _, text := range []string{header, string(body)} {
			_ = wire.ValidWebhookID(text)
			_, _ = wire.ParseTimestamp(text)
			_ = wire.ValidTimestamp(text)
			_ = wire.ValidSubscriptionID(text)
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
		{"timestamp max", "999999999999", false, true, false},
		{"timestamp huge", "1000000000000", false, false, false},
		{"timestamp fraction", "1.5", false, false, false},
		{"timestamp negative", "-1", false, false, false},
		{"timestamp leading zero", "01", false, false, false},
		{"subscription valid", "sub_0123456789abcdef", false, false, true},
		{"subscription duplicate-like", "sub_0123456789abcdefsub_0123456789abcdef", false, false, false},
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
