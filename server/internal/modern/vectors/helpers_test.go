// Package modernvectors runs the generated modern-profile corpora of spec 04
// section 8 against the real SDK functions. Every test file is test-only.
package modernvectors

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	clientmodern "github.com/PHPCraftdream/mcp-jack/client/modern"
)

// fixtureFile reads <repo>/spec/fixtures/modern/name by walking up from the
// package directory: go test runs with the package directory as the working
// directory.
func fixtureFile(t *testing.T, name string) []byte {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		path := filepath.Join(dir, "spec", "fixtures", "modern", name)
		if raw, readErr := os.ReadFile(path); readErr == nil {
			return raw
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("fixture %s not found above package directory", name)
		}
		dir = parent
	}
}

// decodeAny decodes JSON into any, so numbers are float64.
func decodeAny(t *testing.T, raw []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode JSON: %v\ninput: %s", err, raw)
	}
	return v
}

// normalize marshals v and decodes it back into any, so [][2]string, []string
// and map values compare structurally.
func normalize(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal value: %v", err)
	}
	return decodeAny(t, raw)
}

// assertCase compares want with got structurally and is fatal on a mismatch.
func assertCase(t *testing.T, id string, want, got any) {
	t.Helper()
	wantValue := normalize(t, want)
	gotValue := normalize(t, got)
	if reflect.DeepEqual(wantValue, gotValue) {
		return
	}
	wantJSON, _ := json.MarshalIndent(wantValue, "", "  ")
	gotJSON, _ := json.MarshalIndent(gotValue, "", "  ")
	t.Fatalf("case %s: vector mismatch\ngot:  %s\nwant: %s", id, gotJSON, wantJSON)
}

// headerPairs renders client/modern Header slices as [][2]string.
func headerPairs(headers []clientmodern.Header) [][2]string {
	pairs := make([][2]string, 0, len(headers))
	for _, h := range headers {
		pairs = append(pairs, [2]string{h.Name, h.Value})
	}
	return pairs
}

// summary logs the per-corpus vector summary in the required format.
func summary(t *testing.T, corpus string, pass int) {
	t.Helper()
	t.Logf("VECTOR-SUMMARY corpus=%s sdk=go pass=%d excluded=0 deviation=0", corpus, pass)
}
