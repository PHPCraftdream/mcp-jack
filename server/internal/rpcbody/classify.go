// Package rpcbody classifies JSON-RPC request bodies for the server
// verifier (spec 02 section 4).
package rpcbody

import (
	"bytes"
	"encoding/json"
	"unicode/utf8"

	"github.com/PHPCraftdream/mcp-jack/server/internal/jsonvalue"
)

const (
	// KindRequest marks a request or a notification.
	KindRequest = 1
	// KindResponse marks a client answer to a server-initiated request.
	KindResponse = 2
)

// RPCMessage is the part of a JSON-RPC object the verifier needs.
type RPCMessage struct {
	Kind      int
	ID        json.RawMessage
	Method    string
	Tool      string
	HasTool   bool
	Arguments json.RawMessage
}

// Reasons reported by ClassifyReason for a body it refuses.
const (
	// ReasonNone marks an acceptable body.
	ReasonNone = iota
	// ReasonUnacceptable marks any refusal other than the tools/call name rule.
	ReasonUnacceptable
	// ReasonToolName marks a tools/call body whose params.name is not a string
	// (spec 02 section 2 item 4).
	ReasonToolName
)

// ClassifyReason is Classify with the reason a body was refused.
func ClassifyReason(body []byte) (RPCMessage, int) {
	if !utf8.Valid(body) {
		return RPCMessage{}, ReasonUnacceptable
	}
	if unacceptableBody(body) || hasDuplicateMember(body) {
		return RPCMessage{}, ReasonUnacceptable
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil || m == nil {
		return RPCMessage{}, ReasonUnacceptable
	}
	if version, ok := jsonvalue.String(m["jsonrpc"]); !ok || version != "2.0" {
		return RPCMessage{}, ReasonUnacceptable
	}

	rawMethod, hasMethod := m["method"]
	if !hasMethod {
		_, hasID := m["id"]
		_, hasResult := m["result"]
		_, hasError := m["error"]
		if hasID && hasResult != hasError {
			return RPCMessage{Kind: KindResponse, ID: m["id"]}, ReasonNone
		}
		return RPCMessage{}, ReasonUnacceptable
	}
	method, ok := jsonvalue.String(rawMethod)
	if !ok {
		return RPCMessage{}, ReasonUnacceptable
	}
	msg := RPCMessage{Kind: KindRequest, ID: m["id"], Method: method}
	if method == "tools/call" {
		var params map[string]json.RawMessage
		if err := json.Unmarshal(m["params"], &params); err != nil || params == nil {
			return RPCMessage{}, ReasonUnacceptable
		}
		name, ok := jsonvalue.String(params["name"])
		if !ok {
			return RPCMessage{}, ReasonToolName
		}
		msg.Tool, msg.HasTool, msg.Arguments = name, true, params["arguments"]
	}
	return msg, ReasonNone
}

// Classify implements the body rules of spec 02 section 4. UTF-8 is
// validated before decoding because encoding/json silently replaces invalid
// bytes, and members are looked up through a map because encoding/json would
// match struct fields case-insensitively. unacceptableBody rejects lone
// surrogate escapes and over-deep nesting before decoding (spec 02 section 4
// step 2); hasDuplicateMember rejects repeated member names so no member is
// silently dropped by the map decoding.
func Classify(body []byte) (RPCMessage, bool) {
	msg, reason := ClassifyReason(body)
	return msg, reason == ReasonNone
}

// maxBodyDepth is the maximum nesting depth of arrays and objects the body
// may reach (spec 02 section 4 step 2).
const maxBodyDepth = 128

// unacceptableBody reports whether the body text is unacceptable before
// parsing (spec 02 section 4 step 2): a \uXXXX string escape that does not
// form a Unicode scalar value (a lone or unpaired surrogate), or nesting
// deeper than maxBodyDepth levels of arrays and objects. One byte pass,
// constant extra space, no recursion: encoding/json would silently replace a
// lone surrogate with U+FFFD, and Go's decoder otherwise accepts any depth up
// to its own internal limit.
func unacceptableBody(body []byte) bool {
	inString, depth := false, 0
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !inString {
			switch c {
			case '"':
				inString = true
			case '{', '[':
				depth++
				if depth > maxBodyDepth {
					return true
				}
			case '}', ']':
				if depth > 0 {
					depth--
				}
			}
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			if i+1 >= len(body) {
				return true
			}
			if body[i+1] != 'u' {
				i++ // two-char escape; an escaped backslash keeps the string going
				continue
			}
			if i+6 > len(body) {
				return true
			}
			v := hex4(body[i+2 : i+6])
			if v < 0 {
				i++ // not a \uXXXX escape: invalid JSON, the parser rejects it
				continue
			}
			if v >= 0xdc00 && v <= 0xdfff {
				return true // lone low surrogate
			}
			if v < 0xd800 || v > 0xdbff {
				i += 5 // ordinary \uXXXX escape
				continue
			}
			// A high surrogate must be followed immediately by \uDC00..\uDFFF.
			if i+12 <= len(body) && body[i+6] == '\\' && body[i+7] == 'u' {
				if low := hex4(body[i+8 : i+12]); low >= 0xdc00 && low <= 0xdfff {
					i += 11 // consume both escapes
					continue
				}
			}
			return true // unpaired high surrogate
		}
	}
	return false
}

// memberFrame tracks one open container of the duplicate-name scan.
type memberFrame struct {
	names    map[string]struct{} // nil for an array
	wantName bool
}

// hasDuplicateMember reports whether any object, at any depth, repeats a
// member name after unescaping. Memory is one name set per open object; the
// token decoder does the unescaping. Malformed JSON returns false: the parser
// rejects it afterwards.
func hasDuplicateMember(body []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // huge literals like 1e999 must not error the token scan and hide later duplicates
	var stack []*memberFrame
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		var top *memberFrame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if d, isDelim := tok.(json.Delim); isDelim {
			switch d {
			case '{':
				stack = append(stack, &memberFrame{names: map[string]struct{}{}, wantName: true})
			case '[':
				stack = append(stack, &memberFrame{})
			default:
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].names != nil {
					stack[len(stack)-1].wantName = true
				}
			}
			continue
		}
		if top == nil || top.names == nil {
			continue
		}
		if name, isString := tok.(string); isString && top.wantName {
			if _, dup := top.names[name]; dup {
				return true
			}
			top.names[name] = struct{}{}
			top.wantName = false
			continue
		}
		top.wantName = true
	}
}

// hex4 parses exactly four ASCII hex digits, or -1.
func hex4(b []byte) int {
	if len(b) != 4 {
		return -1
	}
	v := 0
	for _, c := range b {
		var d int
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = int(c-'A') + 10
		default:
			return -1
		}
		v = v<<4 | d
	}
	return v
}
