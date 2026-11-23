package modern

import (
	"bytes"
	"encoding/json"
	"math/big"
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
// a JSON string, or a JSON number whose exact value is an integer within the
// int64 range. Specification 04 section 5 S10 says "string or integer" and
// states no magnitude limit, so the int64 range of a JSON-RPC integer id
// applies. Integrality is decided from the token text with exact arithmetic: an
// exponent is accepted when it denotes an integer, a fraction only when its
// exact value is integral, and no float64 rounding is involved. Every other
// value, including a non-integral fraction, an out-of-range magnitude, null, a
// boolean, an array and an object, yields nil so the refusal carries null.
func refusalID(raw json.RawMessage) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	if trimmed[0] == '"' {
		return trimmed
	}
	if !exactInteger(string(trimmed)) {
		return nil
	}
	return trimmed
}

// exactInteger reports whether the JSON number token text denotes an integer
// that fits in int64. The token must match
// -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?; the mantissa digits are
// scaled by the exponent exactly, so 9007199254740992.5 is not an integer and
// 1e400 is out of range.
func exactInteger(text string) bool {
	negative := strings.HasPrefix(text, "-")
	if negative {
		text = text[1:]
	}
	mantissa, exponentText := text, "0"
	if i := strings.IndexAny(text, "eE"); i >= 0 {
		mantissa, exponentText = text[:i], text[i+1:]
	}
	intPart, fracPart := mantissa, ""
	hasFraction := false
	if i := strings.IndexByte(mantissa, '.'); i >= 0 {
		intPart, fracPart, hasFraction = mantissa[:i], mantissa[i+1:], true
	}
	if !decimalDigits(intPart) || (hasFraction && !decimalDigits(fracPart)) {
		return false
	}
	if len(intPart) > 1 && intPart[0] == '0' {
		return false
	}
	if !signedDigits(exponentText) {
		return false
	}
	digits := strings.TrimLeft(intPart+fracPart, "0")
	if digits == "" {
		// The exact value is zero, whatever the sign, fraction or exponent.
		return true
	}
	exponent, ok := boundedExponent(exponentText)
	if !ok {
		return false
	}
	scale := exponent - len(fracPart)
	if scale < 0 {
		trim := -scale
		if trim >= len(digits) || strings.Trim(digits[len(digits)-trim:], "0") != "" {
			// A non-zero digit sits below the decimal point.
			return false
		}
		digits = digits[:len(digits)-trim]
		scale = 0
	}
	if len(digits)+scale > 19 {
		// A 19-digit magnitude may still exceed max int64; IsInt64 decides.
		return false
	}
	value, ok := new(big.Int).SetString(digits, 10)
	if !ok {
		return false
	}
	if scale > 0 {
		value.Mul(value, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scale)), nil))
	}
	if negative {
		value.Neg(value)
	}
	return value.IsInt64()
}

// decimalDigits reports whether text is one or more ASCII digits.
func decimalDigits(text string) bool {
	if text == "" {
		return false
	}
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return false
		}
	}
	return true
}

// signedDigits reports whether text is an optional sign followed by one or more
// ASCII digits: the JSON number exponent grammar.
func signedDigits(text string) bool {
	if text != "" && (text[0] == '+' || text[0] == '-') {
		text = text[1:]
	}
	return decimalDigits(text)
}

// boundedExponent parses the exponent of a JSON number token. An exponent of
// more than five digits cannot bring a non-zero mantissa into the int64 range,
// so it is refused before any big-integer work.
func boundedExponent(text string) (int, bool) {
	negative := strings.HasPrefix(text, "-")
	if negative || strings.HasPrefix(text, "+") {
		text = text[1:]
	}
	if !decimalDigits(text) || len(text) > 5 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(text); i++ {
		n = n*10 + int(text[i]-'0')
	}
	if negative {
		n = -n
	}
	return n, true
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
	return headerModernSignal(headers) || (body.hasMeta && isModernVersion(body.meta))
}

// headerModernSignal reports whether any MCP-Protocol-Version instance (name
// compared case-insensitively) is a well-formed modern version.
func headerModernSignal(headers []Header) bool {
	for _, h := range headers {
		if strings.ToLower(h.Name) == headerVersion && isModernVersion(h.Value) {
			return true
		}
	}
	return false
}

// EraFromHeaders implements the header-only part of S3 for a caller that must
// decide the era of a request before reading a body or authenticating: spec 04
// section 3, "Non-POST under both: there is no body, so only H counts". It
// returns "legacy" or "modern" (the Outcome.Era values). ProfileModern is always
// modern; any profile other than ProfileModern and ProfileBoth is always legacy.
func EraFromHeaders(profile Profile, headers []Header) string {
	if profile == ProfileModern {
		return eraModern
	}
	if profile != ProfileBoth {
		return eraLegacy
	}
	if headerModernSignal(headers) {
		return eraModern
	}
	return eraLegacy
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
