package modern

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// jsonKind is the JSON type of a jsonValue. The values are listed in the order
// object, array, string, number, bool, null.
type jsonKind int

const (
	// jsonObject is a JSON object, whose members are kept in document order.
	jsonObject jsonKind = iota
	// jsonArray is a JSON array, whose items are kept in document order.
	jsonArray
	// jsonString is a JSON string.
	jsonString
	// jsonNumber is a JSON number, kept as its raw json.Number text.
	jsonNumber
	// jsonBool is a JSON boolean.
	jsonBool
	// jsonNull is the JSON null value.
	jsonNull
)

// jsonValue is one node of a JSON document tree that keeps object members in
// document order. encoding/json maps lose that order, but both the duplicate
// and order rules of C5 and the depth-first projection order of C6 depend on
// it.
//
// Duplicate member names are kept as separate members, so a traversal visits
// each occurrence in document order; member resolves such a name to its last
// occurrence, as a JSON object model does.
type jsonValue struct {
	kind    jsonKind
	members []jsonMember // object members, in document order
	items   []*jsonValue // array items, in document order
	text    string       // string text, or the raw json.Number text
	boolean bool         // boolean value
}

// jsonMember is one object member of a jsonValue.
type jsonMember struct {
	name  string
	value *jsonValue
}

// errJSONToken reports a token stream that cannot be part of a single JSON
// value, such as a closing delimiter without its opening one.
var errJSONToken = errors.New("modern: unexpected JSON token")

// parseJSONValue parses raw as exactly one JSON value and keeps object member
// order. Numbers are kept as json.Number text. The second result is false on
// malformed JSON or on trailing data after the value.
func parseJSONValue(raw []byte) (*jsonValue, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := parseJSONToken(dec)
	if err != nil {
		return nil, false
	}
	// The value must be the whole document: only whitespace may follow it.
	// Besides io.EOF, Token also reports a syntax error for trailing data.
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return value, true
}

// parseJSONToken reads one value whose first token has not been consumed yet.
func parseJSONToken(dec *json.Decoder) (*jsonValue, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	return parseJSONFromToken(dec, tok)
}

// parseJSONFromToken builds the value that starts with the already consumed
// token tok.
func parseJSONFromToken(dec *json.Decoder, tok json.Token) (*jsonValue, error) {
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return parseJSONObject(dec)
		case '[':
			return parseJSONArray(dec)
		}
		return nil, errJSONToken
	case string:
		return &jsonValue{kind: jsonString, text: t}, nil
	case json.Number:
		return &jsonValue{kind: jsonNumber, text: t.String()}, nil
	case bool:
		return &jsonValue{kind: jsonBool, boolean: t}, nil
	case nil:
		return &jsonValue{kind: jsonNull}, nil
	}
	return nil, errJSONToken
}

// parseJSONObject reads an object whose opening delimiter was consumed.
func parseJSONObject(dec *json.Decoder) (*jsonValue, error) {
	value := &jsonValue{kind: jsonObject}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, ok := keyTok.(string)
		if !ok {
			return nil, errJSONToken
		}
		member, err := parseJSONToken(dec)
		if err != nil {
			return nil, err
		}
		value.members = append(value.members, jsonMember{name: name, value: member})
	}
	if err := parseJSONClose(dec, '}'); err != nil {
		return nil, err
	}
	return value, nil
}

// parseJSONArray reads an array whose opening delimiter was consumed.
func parseJSONArray(dec *json.Decoder) (*jsonValue, error) {
	value := &jsonValue{kind: jsonArray}
	for dec.More() {
		item, err := parseJSONToken(dec)
		if err != nil {
			return nil, err
		}
		value.items = append(value.items, item)
	}
	if err := parseJSONClose(dec, ']'); err != nil {
		return nil, err
	}
	return value, nil
}

// parseJSONClose consumes the closing delimiter that ends the current
// container and checks that it is want.
func parseJSONClose(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != want {
		return errJSONToken
	}
	return nil
}

// member returns the value of the member named name. The last occurrence wins
// when an object repeats a name. The second result is false when the member is
// absent or the receiver is not an object.
func (v *jsonValue) member(name string) (*jsonValue, bool) {
	if !v.isObject() {
		return nil, false
	}
	for i := len(v.members) - 1; i >= 0; i-- {
		if v.members[i].name == name {
			return v.members[i].value, true
		}
	}
	return nil, false
}

// isObject reports whether v is a JSON object.
func (v *jsonValue) isObject() bool { return v != nil && v.kind == jsonObject }

// isNull reports whether v is the JSON null value.
func (v *jsonValue) isNull() bool { return v != nil && v.kind == jsonNull }

// objectMembers returns the object members of v in document order, or nil when
// v is not an object.
func (v *jsonValue) objectMembers() []jsonMember {
	if !v.isObject() {
		return nil
	}
	return v.members
}

// arrayItems returns the array items of v in document order, or nil when v is
// not an array.
func (v *jsonValue) arrayItems() []*jsonValue {
	if v == nil || v.kind != jsonArray {
		return nil
	}
	return v.items
}
