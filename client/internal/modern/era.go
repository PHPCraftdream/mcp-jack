package modern

import (
	"bytes"
	"math"
	"strconv"
)

// Era is the era a verified response proves, or EraNone when it proves none.
type Era string

// The closed era vocabulary of C9.
const (
	// EraNone is the era of a response that carries no era signal.
	EraNone Era = "none"
	// EraLegacy is the pre-modern era selected by a legacy signal.
	EraLegacy Era = "legacy"
	// EraModern is the 2026-07-28 era.
	EraModern Era = "modern"
)

// EraAction is the operation the era detection prescribes.
type EraAction string

// The closed era-action vocabulary of C9.
const (
	// ActionStayModern keeps talking the modern era to this origin.
	ActionStayModern EraAction = "stay_modern"
	// ActionFallbackInitialize falls back to initialize and stays legacy for
	// this origin.
	ActionFallbackInitialize EraAction = "fallback_initialize"
	// ActionRetryWithSupported retries the request with the mutually
	// implemented versions in EraDecision.Supported.
	ActionRetryWithSupported EraAction = "retry_with_supported"
	// ActionAbort fails the operation.
	ActionAbort EraAction = "abort"
)

// EraDecision is the C9 outcome. Reason is "" when the vocabulary has null;
// Supported is set only for ActionRetryWithSupported.
type EraDecision struct {
	// Era is the era the response proves, or EraNone.
	Era Era
	// Action is the operation the detection prescribes.
	Action EraAction
	// Reason is the closed reason token, "" when the vocabulary has null.
	Reason string
	// Supported is the mutually implemented version list of
	// ActionRetryWithSupported, in the server's order.
	Supported []string
}

// The closed C9 reason vocabulary. Each token maps to one row of the decision
// table of spec 04 section 6.
const (
	// reasonUnverified reports a response that is unsigned or failed
	// verification, so it proves no era.
	reasonUnverified = "unverified"
	// reasonNoEraSignal reports a status, or a network failure, outside the
	// decision table.
	reasonNoEraSignal = "no_era_signal"
	// reasonUnsupportedVersionNoOverlap reports a -32022 refusal whose
	// supported list is unusable or has no version the client implements.
	reasonUnsupportedVersionNoOverlap = "unsupported_version_no_overlap"
	// reasonJackEnvelope reports Jack's own {"error":{...}} envelope with a
	// string code and no jsonrpc member.
	reasonJackEnvelope = "jack_envelope"
	// reasonNoModernError reports a 400, 404 or 405 body that is not a
	// recognised modern JSON-RPC error.
	reasonNoModernError = "no_modern_error"
	// reasonModernMethodNotFound reports a 404 with a recognised -32601
	// error: the server is modern but does not serve that method.
	reasonModernMethodNotFound = "modern_method_not_found"
)

// The JSON-RPC error codes the decision table reads. Recognition itself is
// structural and independent of the code.
const (
	// codeUnsupportedProtocolVersion is the -32020 refusal.
	codeUnsupportedProtocolVersion = -32020
	// codeHeaderMismatch is the -32021 refusal.
	codeHeaderMismatch = -32021
	// codeUnsupportedClientVersions is the -32022 refusal.
	codeUnsupportedClientVersions = -32022
	// codeMethodNotFound is the -32601 error.
	codeMethodNotFound = -32601
)

// RecognisedError reports a structurally recognised JSON-RPC error: a JSON
// object whose "jsonrpc" is exactly "2.0", that has an "id" member (null
// allowed, the member must be present, value null/string/number), and whose
// "error" is an object with an integer "code" and a string "message".
//
// A body that is missing, empty, only whitespace, not JSON, an array or not an
// object is never recognised, and neither is a bare {"error":{"code":...}}
// object. An integer code is a JSON number that is integral, so -32020 and
// -32020.0 are both integers while "-32020" is not; a number outside the Go int
// range is not usable as a code and is not recognised.
func RecognisedError(body []byte) (code int, message string, ok bool) {
	errorValue := recognisedErrorValue(body)
	if errorValue == nil {
		return 0, "", false
	}
	code, _ = integerMember(errorValue, "code")
	message, _ = stringMember(errorValue, "message")
	return code, message, true
}

// DetectEra implements C9 from a verified response only.
//
// The status selects the row of the decision table and the body only qualifies
// it: an unverified response always yields EraNone/abort, an unlisted status
// always yields no signal, and the body is read only for 400 and 404.
func DetectEra(status int, verified bool, body []byte, clientVersions []string) EraDecision {
	if !verified {
		return EraDecision{Era: EraNone, Action: ActionAbort, Reason: reasonUnverified}
	}
	if status >= 200 && status <= 299 {
		return EraDecision{Era: EraModern, Action: ActionStayModern}
	}
	switch status {
	case 400:
		return detectBadRequest(body, clientVersions)
	case 404:
		if errorValue := recognisedErrorValue(body); errorValue != nil {
			if code, ok := integerMember(errorValue, "code"); ok && code == codeMethodNotFound {
				return EraDecision{
					Era:    EraModern,
					Action: ActionStayModern,
					Reason: reasonModernMethodNotFound,
				}
			}
		}
		return EraDecision{Era: EraLegacy, Action: ActionFallbackInitialize, Reason: reasonNoModernError}
	case 405:
		return EraDecision{Era: EraLegacy, Action: ActionFallbackInitialize, Reason: reasonNoModernError}
	}
	return EraDecision{Era: EraNone, Action: ActionAbort, Reason: reasonNoEraSignal}
}

// DetectEraAttempt is DetectEra for a client that has just sent
// attemptedVersion. A retry_with_supported outcome additionally requires the
// server's supported list to offer a version other than the one already
// attempted: when the filtered list is empty the outcome becomes
// abort/unsupported_version_no_overlap, because retrying the same version
// cannot succeed. An empty attemptedVersion leaves the decision unchanged.
func DetectEraAttempt(status int, verified bool, body []byte, clientVersions []string, attemptedVersion string) EraDecision {
	decision := DetectEra(status, verified, body, clientVersions)
	if decision.Action != ActionRetryWithSupported || attemptedVersion == "" {
		return decision
	}
	filtered := make([]string, 0, len(decision.Supported))
	for _, version := range decision.Supported {
		if version != attemptedVersion {
			filtered = append(filtered, version)
		}
	}
	if len(filtered) == 0 {
		return EraDecision{Era: EraModern, Action: ActionAbort, Reason: reasonUnsupportedVersionNoOverlap}
	}
	decision.Supported = filtered
	return decision
}

// detectBadRequest applies the 400 rows of the decision table.
func detectBadRequest(body []byte, clientVersions []string) EraDecision {
	if errorValue := recognisedErrorValue(body); errorValue != nil {
		code, _ := integerMember(errorValue, "code")
		switch code {
		case codeUnsupportedProtocolVersion, codeHeaderMismatch:
			return EraDecision{Era: EraModern, Action: ActionStayModern}
		case codeUnsupportedClientVersions:
			return decideUnsupportedVersions(errorValue, clientVersions)
		}
	}
	reason := reasonNoModernError
	if isJackEnvelope(body) {
		reason = reasonJackEnvelope
	}
	return EraDecision{Era: EraLegacy, Action: ActionFallbackInitialize, Reason: reason}
}

// decideUnsupportedVersions applies the -32022 row: the server's supported
// list is filtered to the client's versions, preserving the server order.
func decideUnsupportedVersions(errorValue *jsonValue, clientVersions []string) EraDecision {
	supported, ok := supportedVersions(errorValue)
	if ok {
		if mutual := mutualVersions(supported, clientVersions); len(mutual) > 0 {
			return EraDecision{Era: EraModern, Action: ActionRetryWithSupported, Supported: mutual}
		}
	}
	return EraDecision{
		Era:    EraModern,
		Action: ActionAbort,
		Reason: reasonUnsupportedVersionNoOverlap,
	}
}

// supportedVersions returns the usable supported list of a -32022 error: a
// data object whose "supported" member is an array whose elements are all
// strings. Any other shape - an absent member, a non-array, or an array with a
// non-string element - is not usable at all. An empty array is usable and
// simply has no common version.
func supportedVersions(errorValue *jsonValue) ([]string, bool) {
	data, ok := errorValue.member("data")
	if !ok || !data.isObject() {
		return nil, false
	}
	supported, ok := data.member("supported")
	if !ok || supported.kind != jsonArray {
		return nil, false
	}
	versions := make([]string, 0, len(supported.items))
	for _, item := range supported.items {
		if item == nil || item.kind != jsonString {
			return nil, false
		}
		versions = append(versions, item.text)
	}
	return versions, true
}

// mutualVersions keeps the versions of supported that the client implements,
// in the server's order and with the server's duplicates.
func mutualVersions(supported, clientVersions []string) []string {
	mutual := make([]string, 0, len(supported))
	for _, version := range supported {
		for _, clientVersion := range clientVersions {
			if version == clientVersion {
				mutual = append(mutual, version)
				break
			}
		}
	}
	return mutual
}

// recognisedErrorValue parses body and returns its error object when the body
// is a recognised JSON-RPC error, or nil when it is not.
func recognisedErrorValue(body []byte) *jsonValue {
	root, ok := parseBodyObject(body)
	if !ok {
		return nil
	}
	version, ok := stringMember(root, "jsonrpc")
	if !ok || version != "2.0" {
		return nil
	}
	// The id member must be present; its value may be null, a string or a
	// number, but not a boolean, an array or an object.
	if !hasMember(root, "id") {
		return nil
	}
	id, _ := root.member("id")
	if id == nil || (id.kind != jsonNull && id.kind != jsonString && id.kind != jsonNumber) {
		return nil
	}
	errorValue, ok := root.member("error")
	if !ok || !errorValue.isObject() {
		return nil
	}
	if _, ok := integerMember(errorValue, "code"); !ok {
		return nil
	}
	if _, ok := stringMember(errorValue, "message"); !ok {
		return nil
	}
	return errorValue
}

// isJackEnvelope reports Jack's own {"error":{...}} envelope: a JSON object
// with no "jsonrpc" member whose "error" is an object with a string "code". A
// body carrying any jsonrpc member, whatever its value, is never Jack's
// envelope.
func isJackEnvelope(body []byte) bool {
	root, ok := parseBodyObject(body)
	if !ok {
		return false
	}
	if hasMember(root, "jsonrpc") {
		return false
	}
	errorValue, ok := root.member("error")
	if !ok || !errorValue.isObject() {
		return false
	}
	_, ok = stringMember(errorValue, "code")
	return ok
}

// parseBodyObject parses body as exactly one JSON object. A body that is
// missing, empty, only whitespace, not JSON, an array or a scalar is not an
// object.
func parseBodyObject(body []byte) (*jsonValue, bool) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, false
	}
	root, ok := parseJSONValue(body)
	if !ok || !root.isObject() {
		return nil, false
	}
	return root, true
}

// hasMember reports whether node is an object with a member named name, even
// when the name is repeated.
func hasMember(node *jsonValue, name string) bool {
	for _, m := range node.objectMembers() {
		if m.name == name {
			return true
		}
	}
	return false
}

// integerMember returns the value of the member named name as an integer, using
// the last occurrence of a repeated name. The second result is false when the
// member is absent, is not a JSON number, or is a number that is not integral
// or does not fit the Go int range.
func integerMember(node *jsonValue, name string) (int, bool) {
	member, ok := node.member(name)
	if !ok || member.kind != jsonNumber {
		return 0, false
	}
	return parseJSONInteger(member.text)
}

// twoTo63 is 2^63, the first float64 above the int64 range.
const twoTo63 = 1 << 63

// parseJSONInteger reports whether the JSON number lexeme text is an integer in
// the sense of Number.isInteger and, if so, its int value: the value must be
// integral and inside the int64 range. -32020 and -32020.0 are integers, 1e3 is
// 1000 and 1.5 is not.
func parseJSONInteger(text string) (int, bool) {
	if n, err := strconv.ParseInt(text, 10, 64); err == nil {
		return int(n), true
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil {
		// The decoder validated the lexeme, so only range overflow is
		// possible; JSON.parse maps it to ±Infinity, which is not an
		// integer.
		return 0, false
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) {
		return 0, false
	}
	if f < -twoTo63 || f >= twoTo63 {
		return 0, false
	}
	return int(f), true
}
