// Package modern implements the server rules of spec 04 sections 3 and 5: the
// era decision S3 and, in the modern era only, rules S1-S12 in that order. A
// request S3 classifies as legacy-era is forwarded untouched. The transport
// layer behind the public server.Profile option calls Classify after
// authentication.
package modern

import (
	"encoding/json"

	"github.com/PHPCraftdream/mcp-jack/server/internal/rpcbody"
)

// Profile is the server deployment profile (spec 04 section 3).
type Profile string

const (
	// ProfileLegacy serves every request as legacy-era.
	ProfileLegacy Profile = "legacy"
	// ProfileModern serves every request as modern-era.
	ProfileModern Profile = "modern"
	// ProfileBoth decides the era per request by S3.
	ProfileBoth Profile = "both"
)

// ValidProfile reports whether p is one of the three profiles. The empty
// string is not valid: callers treat an unset field as ProfileLegacy.
func ValidProfile(p Profile) bool {
	switch p {
	case ProfileLegacy, ProfileModern, ProfileBoth:
		return true
	}
	return false
}

// ModernMin is the first modern-era protocol version (MODERN-MIN).
const ModernMin = "2026-07-28"

// MetaVersionKey is the params._meta member carrying the protocol version.
const MetaVersionKey = "io.modelcontextprotocol/protocolVersion"

// Jack's implementation identity for
// result._meta["io.modelcontextprotocol/serverInfo"] in the modern era
// (spec 04 C7).
const (
	ImplementationName    = "mcp-jack"
	ImplementationVersion = "0.2.0"
)

// ClassificationMessage is the fixed message of the spec 02 section 2 item 4
// classification refusal (tools/call without a string params.name).
const ClassificationMessage = "tools/call requires a string params.name"

// ClassificationCode is the string error code of that refusal.
const ClassificationCode = "invalid_request"

// Values of Request.BodyRefusal, aliased to the rpcbody reason constants.
const (
	// BodyRefusalNone marks an acceptable body.
	BodyRefusalNone = rpcbody.ReasonNone
	// BodyRefusalUnacceptable marks a body the classification layer refused.
	BodyRefusalUnacceptable = rpcbody.ReasonUnacceptable
	// BodyRefusalToolName marks a tools/call body without a string params.name.
	BodyRefusalToolName = rpcbody.ReasonToolName
)

// Header is one received header field, preserving name casing and order. It
// is one header of the classification-level list; Name keeps the received
// casing.
type Header struct {
	Name  string
	Value string
}

// Request is a request that has already passed authentication (spec 01
// section 4 steps 1-8). Body is the exact verified body bytes; it is nil or
// empty for a non-POST request. BodyRefusal is the body classification verdict
// as a BodyRefusal value (BodyRefusalNone for an acceptable body).
type Request struct {
	Method      string
	Target      string
	Headers     []Header
	Body        []byte
	BodyRefusal int
}

// Kind is the outcome family.
type Kind uint8

const (
	// KindNone means this is not a modern-profile outcome; the caller keeps
	// the verifier's own answer (only reachable for an unacceptable body).
	KindNone Kind = iota
	// KindForward hands the request to the wrapped handler.
	KindForward
	// KindRefuse is a signed JSON-RPC refusal of S1, S2, S4, S5 or S6.
	KindRefuse
	// KindRefuseInvalidRequest is the era-neutral classification refusal.
	KindRefuseInvalidRequest
)

// Forward is the exact request the wrapped handler must receive.
type Forward struct {
	Method string
	Target string
	// Headers is the exact S9 order and casing of the classification-level
	// header list. Go's net/http represents headers as a map, so the HTTP
	// transport layer cannot guarantee wire header order or received casing;
	// this slice is the authoritative S9 result for tests and for the
	// forwarding decision.
	Headers []Header
}

// RPCError is the JSON-RPC error member of a signed refusal.
type RPCError struct {
	Code    int
	Message string
}

// Outcome is the classification-level outcome.
type Outcome struct {
	Kind          Kind
	Era           string // "legacy" or "modern"; "" for a classification refusal
	Forward       Forward
	Signed        bool
	HTTPStatus    int
	ContentType   string
	JSONRPC       string
	ID            []byte // raw JSON id for a JSON-RPC refusal; nil means null
	Error         RPCError
	ErrorCode     string // string code of the classification refusal
	ConsumesNonce bool
}

// Wire renders the outcome with exactly the reference/vector JSON shape (used
// by tests and by nothing else): keys "outcome", "era", "forward", "signed",
// "http_status", "content_type", "jsonrpc", "id", "error", "consumes_nonce",
// present or absent per family:
//
//	forward: outcome="forward", era, forward{method,target,headers}, consumes_nonce=true
//	refusal: outcome="refuse", era, signed=true, http_status, content_type,
//	         jsonrpc="2.0", id (JSON value; null when absent), error{code,message},
//	         consumes_nonce=true
//	classification refusal: outcome="refuse_invalid_request", era=null, signed=true,
//	         http_status=400, content_type, error{code:"invalid_request", message},
//	         consumes_nonce=true, no jsonrpc and no id member
//
// It returns nil for KindNone.
func (o Outcome) Wire() map[string]any {
	switch o.Kind {
	case KindForward:
		headers := make([][2]string, len(o.Forward.Headers))
		for i, h := range o.Forward.Headers {
			headers[i] = [2]string{h.Name, h.Value}
		}
		return map[string]any{
			"outcome": "forward",
			"era":     o.Era,
			"forward": map[string]any{
				"method":  o.Forward.Method,
				"target":  o.Forward.Target,
				"headers": headers,
			},
			"consumes_nonce": true,
		}
	case KindRefuse:
		return map[string]any{
			"outcome":        "refuse",
			"era":            o.Era,
			"signed":         true,
			"http_status":    o.HTTPStatus,
			"content_type":   o.ContentType,
			"jsonrpc":        o.JSONRPC,
			"id":             wireID(o.ID),
			"error":          map[string]any{"code": o.Error.Code, "message": o.Error.Message},
			"consumes_nonce": true,
		}
	case KindRefuseInvalidRequest:
		return map[string]any{
			"outcome":        "refuse_invalid_request",
			"era":            nil,
			"signed":         true,
			"http_status":    o.HTTPStatus,
			"content_type":   o.ContentType,
			"error":          map[string]any{"code": o.ErrorCode, "message": o.Error.Message},
			"consumes_nonce": true,
		}
	}
	return nil
}

// wireID is the JSON form of a refusal id: null when no id was carried.
func wireID(id []byte) any {
	if len(id) == 0 {
		return nil
	}
	return json.RawMessage(id)
}
