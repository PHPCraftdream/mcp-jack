package wire

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode"
	"unicode/utf8"

	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
)

const MaxBody = 1 << 20
const ProtocolVersion = "2025-11-25"

// Member-name scopes of uniqueValue. The envelope (the top-level object and its
// params object) is compared case-insensitively, because the gateway and the
// bridge read members there by exact name while an upstream decoder may match
// them case-insensitively: {"method":x,"Method":y} must not pass the filter.
// Free-form values below (arguments, results, capabilities) only reject exact
// duplicates, so legitimate data such as {"Path":1,"PATH":2} stays valid.
const (
	scopeEnvelope = iota
	scopeParams
	scopeData
)

// Object rejects duplicate names at every depth, including escaped duplicates,
// and case-variant duplicates inside the envelope.
func Object(b []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(b) || !json.Valid(b) {
		return nil, command.ErrProtocol
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := uniqueValue(d, scopeEnvelope); err != nil || d.Decode(new(any)) != io.EOF {
		return nil, command.ErrProtocol
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil || m == nil || bytes.TrimSpace(b)[0] != '{' {
		return nil, command.ErrProtocol
	}
	return m, nil
}

func uniqueValue(d *json.Decoder, scope int) error {
	t, err := d.Token()
	if err != nil {
		return command.ErrProtocol
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for d.More() {
			t, err := d.Token()
			name, ok := t.(string)
			if err != nil || !ok {
				return command.ErrProtocol
			}
			key := name
			if scope != scopeData {
				key = foldName(name)
			}
			if seen[key] {
				return command.ErrProtocol
			}
			seen[key] = true
			child := scopeData
			if scope == scopeEnvelope && name == "params" {
				child = scopeParams
			}
			if uniqueValue(d, child) != nil {
				return command.ErrProtocol
			}
		}
	case '[':
		for d.More() {
			if uniqueValue(d, scopeData) != nil {
				return command.ErrProtocol
			}
		}
	default:
		return command.ErrProtocol
	}
	_, err = d.Token()
	return err
}

// foldName maps every rune to the smallest rune of its simple case-folding
// orbit, so names that strings.EqualFold considers equal share one map key
// (byte-identical names included).
func foldName(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		low := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < low {
				low = f
			}
		}
		out = append(out, low)
	}
	return string(out)
}

func Text(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}

func ValidID(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && bytes.TrimSpace(raw)[0] == '"' {
		return true
	}
	var n int64
	return !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) && json.Unmarshal(raw, &n) == nil
}

func SameID(a, b json.RawMessage) bool {
	if !ValidID(a) || !ValidID(b) {
		return false
	}
	var sa, sb string
	if json.Unmarshal(a, &sa) == nil && json.Unmarshal(b, &sb) == nil {
		return sa == sb
	}
	var na, nb int64
	return json.Unmarshal(a, &na) == nil && json.Unmarshal(b, &nb) == nil && na == nb
}

func ResponseObject(b []byte, id json.RawMessage) (map[string]json.RawMessage, error) {
	m, err := Object(b)
	if err != nil || Text(m["jsonrpc"]) != "2.0" || !SameID(m["id"], id) || len(m["method"]) != 0 {
		return nil, command.ErrProtocol
	}
	_, result := m["result"]
	_, failure := m["error"]
	if result == failure {
		return nil, command.ErrProtocol
	}
	if failure {
		e, err := Object(m["error"])
		var code int64
		if err != nil || bytes.Equal(bytes.TrimSpace(e["code"]), []byte("null")) || json.Unmarshal(e["code"], &code) != nil || len(e["message"]) == 0 || bytes.TrimSpace(e["message"])[0] != '"' {
			return nil, command.ErrProtocol
		}
	}
	return m, nil
}
