package vector_test

import (
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/vector"
)

func TestVectorLoadSSRF(t *testing.T) {
	const name = "ssrf-vectors.json"
	corpus, err := vector.Load(name)
	if err != nil {
		t.Fatal(err)
	}
	vector.Expect(t, corpus, 120, name)
	if corpus.Clock != 1767225600 {
		t.Errorf("clock = %d, want 1767225600", corpus.Clock)
	}
	for i, c := range corpus.Cases {
		if c.ID == "" || c.Kind == "" {
			t.Errorf("case %d: ID = %q, Kind = %q; both must be non-empty", i, c.ID, c.Kind)
		}
	}
}

func TestVectorLoadMissing(t *testing.T) {
	const name = "missing-vector-helper-test.json"
	_, err := vector.Load(name)
	if !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), name) {
		t.Fatalf("Load(%q) error = %v, want a not-exist error naming the file", name, err)
	}
}

func TestVectorRawJSONHelpers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		raw     json.RawMessage
		str     string
		isStr   bool
		isNull  bool
		integer int64
		isInt   bool
	}{
		{name: "string", raw: json.RawMessage(`"hello"`), str: "hello", isStr: true},
		{name: "null", raw: json.RawMessage(`null`), isNull: true},
		{name: "absent", isNull: true},
		{name: "integer", raw: json.RawMessage(`42`), integer: 42, isInt: true},
		{name: "negative integer", raw: json.RawMessage(`-32024`), integer: -32024, isInt: true},
		{name: "exponent", raw: json.RawMessage(`1e3`), integer: 1000, isInt: true},
		{name: "fraction", raw: json.RawMessage(`1.5`)},
		{name: "quoted integer", raw: json.RawMessage(`"42"`), str: "42", isStr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := vector.String(tc.raw); got != tc.str || ok != tc.isStr {
				t.Errorf("String(%s) = (%q, %t), want (%q, %t)", tc.raw, got, ok, tc.str, tc.isStr)
			}
			if got := vector.Null(tc.raw); got != tc.isNull {
				t.Errorf("Null(%s) = %t, want %t", tc.raw, got, tc.isNull)
			}
			if got, ok := vector.Int(tc.raw); got != tc.integer || ok != tc.isInt {
				t.Errorf("Int(%s) = (%d, %t), want (%d, %t)", tc.raw, got, ok, tc.integer, tc.isInt)
			}
		})
	}
}
