// Package vector provides shared helpers for corpus-driven tests.
package vector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// Case is one vector case; Input and Expect stay raw JSON because their shape depends on Kind.
type Case struct {
	ID          string          `json:"id"`
	Rule        string          `json:"rule"`
	Description string          `json:"description"`
	Kind        string          `json:"kind"`
	Input       json.RawMessage `json:"input"`
	Expect      json.RawMessage `json:"expect"`
}

// Corpus is one generated vector file.
type Corpus struct {
	Note  string `json:"note"`
	Clock int64  `json:"clock"`
	Cases []Case `json:"cases"`
}

// Load reads a named corpus from spec/fixtures/modern under the nearest module root.
func Load(name string) (Corpus, error) {
	root, err := repoRoot()
	if err != nil {
		return Corpus{}, err
	}
	path := filepath.Join(root, "spec", "fixtures", "modern", name)
	data, err := os.ReadFile(path)
	if err != nil {
		return Corpus{}, err
	}
	var corpus Corpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		return Corpus{}, fmt.Errorf("decode %q: %w", path, err)
	}
	return corpus, nil
}

// RepoPath joins parts to the nearest module root, or returns an empty string if it cannot be located.
func RepoPath(parts ...string) string {
	root, err := repoRoot()
	if err != nil {
		return ""
	}
	return filepath.Join(append([]string{root}, parts...)...)
}

func repoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for dir := cwd; ; dir = filepath.Dir(dir) {
		marker := filepath.Join(dir, "go.mod")
		info, err := os.Stat(marker)
		if err == nil && !info.IsDir() {
			return dir, nil
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		if filepath.Dir(dir) == dir {
			return "", fmt.Errorf("search from %q through %q for go.mod: %w", cwd, dir, fs.ErrNotExist)
		}
	}
}

// Expect fails the test if the corpus does not contain wantCases cases.
func Expect(t *testing.T, corpus Corpus, wantCases int, label string) {
	t.Helper()
	if got := len(corpus.Cases); got != wantCases {
		t.Fatalf("%s: got %d cases, want %d", label, got, wantCases)
	}
}

// Summary logs the runner's result counts. Call it once per corpus.
func Summary(t *testing.T, corpus string, pass, excluded, deviation int) {
	t.Helper()
	t.Logf("VECTOR-SUMMARY corpus=%s sdk=go pass=%d excluded=%d deviation=%d", corpus, pass, excluded, deviation)
}

// String extracts a JSON string, returning false for any other value.
func String(raw json.RawMessage) (string, bool) {
	var s *string
	if err := json.Unmarshal(raw, &s); err != nil || s == nil {
		return "", false
	}
	return *s, true
}

// Null reports whether raw is absent or a JSON null.
func Null(raw json.RawMessage) bool {
	return len(raw) == 0 || bytes.Equal(bytes.Trim(raw, " \t\r\n"), []byte("null"))
}

// Int extracts a JSON number that is integral as a float64 (like Number.isInteger)
// and fits in an int64.
func Int(raw json.RawMessage) (int64, bool) {
	var n *float64
	if err := json.Unmarshal(raw, &n); err != nil || n == nil {
		return 0, false
	}
	if v := *n; math.Trunc(v) == v && v >= -0x1p63 && v < 0x1p63 {
		return int64(v), true
	}
	return 0, false
}
