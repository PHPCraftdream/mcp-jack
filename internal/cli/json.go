package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// object rejects duplicate names at every depth, including escaped duplicates.
func object(b []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(b) || !json.Valid(b) {
		return nil, errProtocol
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := uniqueValue(d); err != nil || d.Decode(new(any)) != io.EOF {
		return nil, errProtocol
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil || m == nil || bytes.TrimSpace(b)[0] != '{' {
		return nil, errProtocol
	}
	return m, nil
}

func uniqueValue(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return errProtocol
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
			if err != nil || !ok || seen[name] {
				return errProtocol
			}
			seen[name] = true
			if uniqueValue(d) != nil {
				return errProtocol
			}
		}
	case '[':
		for d.More() {
			if uniqueValue(d) != nil {
				return errProtocol
			}
		}
	default:
		return errProtocol
	}
	_, err = d.Token()
	return err
}

func text(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}

func validID(raw json.RawMessage) bool {
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

func sameID(a, b json.RawMessage) bool {
	if !validID(a) || !validID(b) {
		return false
	}
	var sa, sb string
	if json.Unmarshal(a, &sa) == nil && json.Unmarshal(b, &sb) == nil {
		return sa == sb
	}
	var na, nb int64
	return json.Unmarshal(a, &na) == nil && json.Unmarshal(b, &nb) == nil && na == nb
}

func responseObject(b []byte, id json.RawMessage) (map[string]json.RawMessage, error) {
	m, err := object(b)
	if err != nil || text(m["jsonrpc"]) != "2.0" || !sameID(m["id"], id) || len(m["method"]) != 0 {
		return nil, errProtocol
	}
	_, result := m["result"]
	_, failure := m["error"]
	if result == failure {
		return nil, errProtocol
	}
	if failure {
		e, err := object(m["error"])
		var code int64
		if err != nil || bytes.Equal(bytes.TrimSpace(e["code"]), []byte("null")) || json.Unmarshal(e["code"], &code) != nil || len(e["message"]) == 0 || bytes.TrimSpace(e["message"])[0] != '"' {
			return nil, errProtocol
		}
	}
	return m, nil
}
