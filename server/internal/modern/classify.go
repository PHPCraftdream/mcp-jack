package modern

import (
	"bytes"
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

// Canonical header names of spec 04 section 2, lowercased for the
// case-insensitive comparison.
const (
	headerVersion     = "mcp-protocol-version"
	headerMethod      = "mcp-method"
	headerName        = "mcp-name"
	paramPrefix       = "mcp-param-"
	headerSession     = "mcp-session-id"
	headerLastEventID = "last-event-id"
)

// Era names.
const (
	eraLegacy = "legacy"
	eraModern = "modern"
)

// bodyKind is the JSON-RPC shape of an acceptable body.
type bodyKind uint8

const (
	bodyNone bodyKind = iota
	bodyRequest
	bodyNotification
	bodyResponse
)

// bodyFields is the part of an acceptable JSON-RPC body the rules read.
type bodyFields struct {
	kind    bodyKind
	method  string
	id      []byte // raw JSON id of a request object
	meta    string // params._meta[MetaVersionKey] when it is a string
	hasMeta bool
	params  map[string]json.RawMessage
}

// Classify implements S3 and, in the modern era only, S1-S12 in that order
// (spec 04 section 5). It never refuses a request that S3 classifies as
// legacy-era: that request is forwarded with its headers untouched. A profile
// other than ProfileModern or ProfileBoth is treated as legacy.
//
// The returned Forward.Headers follows S9 in slice order; wire order is not
// guaranteed by Go's HTTP stack.
func Classify(profile Profile, req Request) Outcome {
	// Body classification (spec 02 section 2) runs first and is era-neutral.
	switch req.BodyRefusal {
	case BodyRefusalUnacceptable:
		return Outcome{Kind: KindNone}
	case BodyRefusalToolName:
		return Outcome{
			Kind:          KindRefuseInvalidRequest,
			Signed:        true,
			HTTPStatus:    400,
			ContentType:   "application/json",
			Error:         RPCError{Message: ClassificationMessage},
			ErrorCode:     ClassificationCode,
			ConsumesNonce: true,
		}
	}

	var body bodyFields
	if req.Method == "POST" && len(req.Body) > 0 {
		parsed, ok := parseBody(req.Body)
		if !ok {
			return Outcome{Kind: KindNone}
		}
		body = parsed
	}

	// S3: any well-formed modern version in a header instance or in the signed
	// _meta version selects the modern era. Ambiguity never buys the legacy
	// path, so a repeated header counts when any of its values is modern.
	era := eraLegacy
	switch profile {
	case ProfileModern:
		era = eraModern
	case ProfileBoth:
		if modernSignal(req.Headers, body) {
			era = eraModern
		}
	}

	// Legacy era: 01 and 02 apply byte-identically, no rule of section 5 runs
	// (S1 included), so the header list is forwarded unfiltered.
	if era == eraLegacy {
		return forwardOutcome(eraLegacy, req.Method, req.Target, req.Headers)
	}

	if req.Method == "POST" && body.kind == bodyNone {
		// A POST always carries a classified body (spec 02 section 2); without
		// one no mirror can be checked, so the caller keeps its own answer.
		return Outcome{Kind: KindNone}
	}

	// S10: the refusal echoes the id only when it is a string or an integer.
	requestID := refusalID(body.id)

	// S1: header syntax, modern era only.
	for _, name := range []string{headerVersion, headerMethod, headerName} {
		if countHeader(req.Headers, name) > 1 {
			return refuse("header_repeated", era, requestID)
		}
	}
	for _, h := range req.Headers {
		name := strings.ToLower(h.Name)
		if !isMirrorName(name) && !isParamName(name) {
			continue
		}
		if !isFieldValue(h.Value) {
			return refuse("header_value_invalid", era, requestID)
		}
	}

	// S2: only POST is defined by the modern era.
	if req.Method != "POST" {
		return refuse("method_not_allowed", era, nil)
	}

	isRequest := body.kind == bodyRequest

	// S12: a client-sent response object has no mirror obligation.
	if body.kind != bodyResponse {
		// S4: version mirror.
		version, hasVersion := lookupHeader(req.Headers, headerVersion)
		if !hasVersion {
			if isRequest {
				return refuse("version_header_missing", era, requestID)
			}
		} else {
			if !isVersion(version) {
				return refuse("version_header_malformed", era, requestID)
			}
			if !body.hasMeta {
				return refuse("version_meta_missing", era, requestID)
			}
			if version != body.meta {
				return refuse("version_mismatch", era, requestID)
			}
		}

		// S5: Mcp-Method mirror.
		method, hasMethod := lookupHeader(req.Headers, headerMethod)
		if !hasMethod {
			if isRequest {
				return refuse("method_header_missing", era, requestID)
			}
		} else if method != body.method {
			return refuse("method_header_mismatch", era, requestID)
		}

		// S6: Mcp-Name mirror. The source table is closed, so a method without
		// a row must not carry the header.
		mirroredName, hasName := lookupHeader(req.Headers, headerName)
		source, hasSource := nameSource(body.method)
		if !hasSource {
			if hasName {
				return refuse("name_header_not_applicable", era, requestID)
			}
		} else {
			value, ok := body.sourceValue(source)
			if !ok {
				if body.method == "tools/call" {
					// Classification refused such a body before S3.
					return Outcome{Kind: KindNone}
				}
				return refuse("name_source_missing", era, requestID)
			}
			if !hasName {
				if isRequest {
					return refuse("name_header_missing", era, requestID)
				}
			} else {
				decoded, ok := decodeHeaderValue(mirroredName)
				if !ok {
					return refuse("name_header_bad_encoding", era, requestID)
				}
				if decoded != value {
					return refuse("name_header_mismatch", era, requestID)
				}
			}
		}
	}

	// S8: session and resume headers never reach the handler in the modern era.
	forwarded := make([]Header, 0, len(req.Headers))
	for _, h := range req.Headers {
		name := strings.ToLower(h.Name)
		if name == headerSession || name == headerLastEventID {
			continue
		}
		forwarded = append(forwarded, h)
	}
	// S9: everything else is forwarded unchanged, casing and order preserved.
	// This is the classification-level slice order: the HTTP transport layer
	// cannot promise the same wire order (see Forward.Headers).
	return forwardOutcome(eraModern, req.Method, req.Target, forwarded)
}

// refusalID returns the raw JSON id to echo in a specification 04 S10 refusal:
// a JSON string or a JSON number that is an integer (an exponent form is
// accepted when its value is integral). Every other value, including a
// fractional number, a non-integral exponent, null, a boolean, an array and an
// object, yields nil so the refusal carries null.
func refusalID(raw json.RawMessage) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	if trimmed[0] == '"' {
		return trimmed
	}
	if trimmed[0] != '-' && (trimmed[0] < '0' || trimmed[0] > '9') {
		return nil
	}
	value, err := strconv.ParseFloat(string(trimmed), 64)
	if err != nil || math.IsInf(value, 0) || math.IsNaN(value) {
		return nil
	}
	if value != math.Trunc(value) {
		return nil
	}
	return trimmed
}

// parseBody decodes an acceptable JSON-RPC object body. It reports false when
// the bytes are not a JSON object.
func parseBody(raw []byte) (bodyFields, bool) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return bodyFields{}, false
	}
	var b bodyFields
	if !isJSONString(members["method"]) {
		b.kind = bodyResponse
		return b, true
	}
	b.method, _ = jsonStringOf(members["method"])
	if id, ok := members["id"]; ok && (isJSONString(id) || isJSONNumber(id)) {
		b.kind = bodyRequest
		b.id = bytes.TrimSpace(id)
	} else {
		b.kind = bodyNotification
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(members["params"], &params); err == nil && params != nil {
		b.params = params
	}
	// params._meta is a mirror source only for a request or a notification
	// (spec/tools/modern/headers/reference/server.mjs metaVersion); a
	// client-sent response object keeps both meta fields at their zero value.
	if b.kind == bodyRequest || b.kind == bodyNotification {
		b.meta, b.hasMeta = metaVersion(b.params)
	}
	return b, true
}

// metaVersion reads params._meta[MetaVersionKey]; a root-level _meta is never a
// mirror source and a member that is not a string counts as absent.
func metaVersion(params map[string]json.RawMessage) (string, bool) {
	if params == nil {
		return "", false
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(params["_meta"], &meta); err != nil || meta == nil {
		return "", false
	}
	return jsonStringOf(meta[MetaVersionKey])
}

// sourceValue returns the string value of params[key].
func (b bodyFields) sourceValue(key string) (string, bool) {
	raw, ok := b.params[key]
	if !ok {
		return "", false
	}
	return jsonStringOf(raw)
}

// modernSignal reports whether a header instance or the signed _meta version is
// a well-formed modern version.
func modernSignal(headers []Header, body bodyFields) bool {
	for _, h := range headers {
		if strings.ToLower(h.Name) == headerVersion && isModernVersion(h.Value) {
			return true
		}
	}
	return body.hasMeta && isModernVersion(body.meta)
}

// isMirrorName reports whether an already lowercased name is one of the three
// single-instance mirror headers.
func isMirrorName(name string) bool {
	return name == headerVersion || name == headerMethod || name == headerName
}

// isParamName reports whether an already lowercased name is a recognised
// Mcp-Param-{Name} header. "Mcp-Param-" alone has an empty {Name} and is not
// recognised.
func isParamName(name string) bool {
	return len(name) > len(paramPrefix) && strings.HasPrefix(name, paramPrefix)
}

// lookupHeader returns the value of the first header whose name matches
// case-insensitively.
func lookupHeader(headers []Header, lowerName string) (string, bool) {
	for _, h := range headers {
		if strings.ToLower(h.Name) == lowerName {
			return h.Value, true
		}
	}
	return "", false
}

// countHeader returns how many headers match case-insensitively.
func countHeader(headers []Header, lowerName string) int {
	n := 0
	for _, h := range headers {
		if strings.ToLower(h.Name) == lowerName {
			n++
		}
	}
	return n
}

// forwardOutcome renders an S9 forward, copying the header list.
func forwardOutcome(era, method, target string, headers []Header) Outcome {
	kept := make([]Header, len(headers))
	copy(kept, headers)
	return Outcome{
		Kind:          KindForward,
		Era:           era,
		Forward:       Forward{Method: method, Target: target, Headers: kept},
		ConsumesNonce: true,
	}
}

// isJSONString reports whether raw is a JSON string token.
func isJSONString(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '"'
}

// jsonStringOf decodes raw only when it is a JSON string.
func jsonStringOf(raw json.RawMessage) (string, bool) {
	if !isJSONString(raw) {
		return "", false
	}
	var s string
	if err := json.Unmarshal(bytes.TrimSpace(raw), &s); err != nil {
		return "", false
	}
	return s, true
}

// isJSONNumber reports whether raw starts a JSON number token.
func isJSONNumber(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return false
	}
	return trimmed[0] == '-' || (trimmed[0] >= '0' && trimmed[0] <= '9')
}
