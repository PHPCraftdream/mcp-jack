// Package streamvectors runs the generated signed-stream corpora of spec 05
// section 9 against the real SDK: the client vectors of
// spec/fixtures/modern/stream-vectors.json through the public client verifier
// and the build vectors of stream-build-vectors.json through the server
// signer, each built stream checked back through the same verifier. Every file
// in this package is test-only.
package streamvectors

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// summary logs the per-corpus vector summary in the required format.
func summary(t *testing.T, corpus string, pass int) {
	t.Helper()
	t.Logf("VECTOR-SUMMARY corpus=%s sdk=go pass=%d excluded=0 deviation=0", corpus, pass)
}

// scriptedClock is the clock a case pins: every feed moves it to the arrival
// of the bytes fed. The runner is single-goroutine, so no mutex is needed.
type scriptedClock struct {
	at time.Time
}

// Now returns the scripted clock sample.
func (c *scriptedClock) Now() time.Time { return c.at }

// Set moves the scripted clock to at.
func (c *scriptedClock) Set(at time.Time) { c.at = at }

// b64u decodes canonical unpadded base64url.
func b64u(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode base64url %q: %v", s, err)
	}
	return raw
}

// sameJSON reports whether a and b are the same JSON lexeme up to
// insignificant whitespace.
func sameJSON(t *testing.T, a, b json.RawMessage) bool {
	t.Helper()
	var ca, cb bytes.Buffer
	if err := json.Compact(&ca, a); err != nil {
		t.Fatalf("compact JSON %s: %v", a, err)
	}
	if err := json.Compact(&cb, b); err != nil {
		t.Fatalf("compact JSON %s: %v", b, err)
	}
	return bytes.Equal(ca.Bytes(), cb.Bytes())
}

// isRPCResponse reports whether data is the final response of the opening
// request (spec 05 section 6.3): a JSON object with "jsonrpc":"2.0", no method
// member, exactly one of result and error, and the request id.
func isRPCResponse(t *testing.T, data string, requestID json.RawMessage) bool {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &obj); err != nil || obj == nil {
		return false
	}
	var version string
	if raw, ok := obj["jsonrpc"]; !ok || json.Unmarshal(raw, &version) != nil || version != "2.0" {
		return false
	}
	if _, ok := obj["method"]; ok {
		return false
	}
	_, hasResult := obj["result"]
	_, hasError := obj["error"]
	if hasResult == hasError {
		return false
	}
	id, ok := obj["id"]
	if !ok {
		return false
	}
	return sameJSON(t, id, requestID)
}

// dataFill is the run-length form the corpora use for repeated bytes.
type dataFill struct {
	Byte  string `json:"byte"`
	Count int    `json:"count"`
}

// expandMessage returns a vector message as the data value the verifier must
// deliver: the string itself, or count copies of byte for an object holding a
// data_fill (the case-level fill when the object brings none).
func expandMessage(t *testing.T, raw json.RawMessage, fill *dataFill) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var wrapper struct {
		DataFill *dataFill `json:"data_fill"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		t.Fatalf("expand message %s: %v", raw, err)
	}
	use := wrapper.DataFill
	if use == nil {
		use = fill
	}
	if use == nil {
		t.Fatalf("message %s has no data fill", raw)
	}
	if use.Count < 0 {
		t.Fatalf("message %s: negative data fill count %d", raw, use.Count)
	}
	return strings.Repeat(use.Byte, use.Count)
}

// expandChunks decodes the body pieces of a vector: a chunk equal to
// "@data_fill@" is count copies of the case-level fill byte, every other chunk
// is canonical unpadded base64url.
func expandChunks(t *testing.T, chunks []string, fill *dataFill) [][]byte {
	t.Helper()
	out := make([][]byte, 0, len(chunks))
	for _, chunk := range chunks {
		if chunk == "@data_fill@" {
			if fill == nil {
				t.Fatalf("chunk %q without a case-level data fill", chunk)
			}
			out = append(out, []byte(strings.Repeat(fill.Byte, fill.Count)))
			continue
		}
		out = append(out, b64u(t, chunk))
	}
	return out
}
