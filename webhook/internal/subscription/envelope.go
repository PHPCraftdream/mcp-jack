package subscription

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxCursorLen is the maximum length of a cursor in bytes.
const MaxCursorLen = 512

// GapEnvelope emits the exact R8.7 body for cursor.
func GapEnvelope(cursor string) []byte {
	var b strings.Builder
	b.WriteString(`{"type":"gap","cursor":`)
	writeJSONString(&b, cursor)
	b.WriteByte('}')
	return []byte(b.String())
}

// EnvelopeError is a refusal to emit an invalid envelope.
type EnvelopeError struct {
	Code string
}

func (e *EnvelopeError) Error() string { return e.Code }

// TerminatedEnvelope emits the exact R8.8 body. Empty data is omitted;
// otherwise data must be a raw JSON object, compacted without re-encoding.
func TerminatedEnvelope(code int64, message string, data json.RawMessage) ([]byte, *EnvelopeError) {
	var compact bytes.Buffer
	if len(data) > 0 {
		object := bytes.Trim(data, " \t\r\n")
		if len(object) == 0 || object[0] != '{' || !utf8.Valid(object) || json.Compact(&compact, object) != nil {
			return nil, &EnvelopeError{Code: "invalid_envelope"}
		}
	}

	var b strings.Builder
	b.WriteString(`{"type":"terminated","error":{"code":`)
	b.WriteString(strconv.FormatInt(code, 10))
	b.WriteString(`,"message":`)
	writeJSONString(&b, message)
	if len(data) > 0 {
		b.WriteString(`,"data":`)
		b.Write(compact.Bytes())
	}
	b.WriteString("}}")
	return []byte(b.String()), nil
}

// CursorOK reports whether v is nil or a non-empty printable ASCII cursor.
func CursorOK(v *string) bool {
	if v == nil {
		return true
	}
	s := *v
	if len(s) == 0 || len(s) > MaxCursorLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
