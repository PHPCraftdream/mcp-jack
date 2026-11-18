// Package jsonvalue holds the strict JSON scalar helpers shared by the
// server state loader and the protocol argument parsers. They live apart so
// both the internal state package and the server package can use them
// without creating an import cycle.
package jsonvalue

import (
	"bytes"
	"encoding/json"
)

// Null reports whether raw is the JSON null literal.
func Null(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// String decodes raw only when it is a JSON string; encoding/json would
// also accept null for a string target, which the protocol must not.
func String(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err != nil {
		return "", false
	}
	return s, true
}
