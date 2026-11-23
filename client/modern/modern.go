// Package modern provides the Go client helpers of the MCP 2026-07-28 modern
// profile: spec 04 section 6 (C1-C6, C9 and C11) plus the private result cache
// of C8.
//
// Nothing in this package changes the mcp-jack/v1 wire bytes. It builds the
// request `_meta` object and its mirror headers, validates and filters the
// `x-mcp-header` annotations of a tool or event inputSchema, projects
// arguments into Mcp-Param-* headers, encodes and decodes header values
// (section 4), detects the era from a verified response and keeps a private
// cache keyed by the exact request. It is pure client-side code with no I/O.
//
// The package is a thin public facade over the implementation in
// github.com/PHPCraftdream/mcp-jack/client/internal/modern: every type is an
// alias and every function is a one-line wrapper, so the two packages share
// exactly the same values.
package modern

import impl "github.com/PHPCraftdream/mcp-jack/client/internal/modern"

// ModernMin is MODERN-MIN, the first modern-era protocol version.
const ModernMin = impl.ModernMin

// MetaVersionKey is the `_meta` member carrying the protocol version.
const MetaVersionKey = impl.MetaVersionKey

// MetaClientCapabilitiesKey is the `_meta` member carrying the client
// capabilities object.
const MetaClientCapabilitiesKey = impl.MetaClientCapabilitiesKey

// MetaClientInfoKey is the `_meta` member carrying the optional client
// implementation info.
const MetaClientInfoKey = impl.MetaClientInfoKey

// AnnotationKey is the schema keyword that marks a property as mirrored into
// an Mcp-Param header.
const AnnotationKey = impl.AnnotationKey

// SafeIntMax is 2^53-1, the largest integer a JSON number represents exactly
// and the bound of the section 4 integer text conversion.
const SafeIntMax = impl.SafeIntMax

// ProjectionReason is the reason token of C6 when a present argument does not
// match its annotated type.
const ProjectionReason = impl.ProjectionReason

// The closed C5/C11 annotation-check reason list.
const (
	// ReasonAnnotationNameNotString reports an x-mcp-header value that is not
	// a JSON string.
	ReasonAnnotationNameNotString = impl.ReasonAnnotationNameNotString
	// ReasonAnnotationNameEmpty reports an empty x-mcp-header value.
	ReasonAnnotationNameEmpty = impl.ReasonAnnotationNameEmpty
	// ReasonAnnotationNameControl reports a name with a control byte,
	// including CR and LF.
	ReasonAnnotationNameControl = impl.ReasonAnnotationNameControl
	// ReasonAnnotationNameNotToken reports a name that fails the RFC 9110
	// token syntax.
	ReasonAnnotationNameNotToken = impl.ReasonAnnotationNameNotToken
	// ReasonAnnotationNameDuplicate reports a name case-insensitively equal to
	// another annotation name in the same inputSchema.
	ReasonAnnotationNameDuplicate = impl.ReasonAnnotationNameDuplicate
	// ReasonAnnotationTypeNotPrimitive reports a property type that is not
	// exactly "string", "integer" or "boolean".
	ReasonAnnotationTypeNotPrimitive = impl.ReasonAnnotationTypeNotPrimitive
	// ReasonAnnotationIntegerRangeInvalid reports an integer property whose
	// minimum or maximum exceeds the section 4 integer range.
	ReasonAnnotationIntegerRangeInvalid = impl.ReasonAnnotationIntegerRangeInvalid
	// ReasonAnnotationNotStaticallyReachable reports an annotation that does
	// not sit below a chain of `properties` member names.
	ReasonAnnotationNotStaticallyReachable = impl.ReasonAnnotationNotStaticallyReachable
)

// ErrHeaderProjectionInvalidValue is returned by ProjectArguments when a
// present argument does not match the type of its annotation (C6). The
// sentinel is returned unwrapped, so errors.Is always works.
var ErrHeaderProjectionInvalidValue = impl.ErrHeaderProjectionInvalidValue

// Header is one HTTP header of a modern-profile request. Names use the
// canonical spellings of section 2; values are already encoded. Go's net/http
// represents headers as a map, so the HTTP stack cannot preserve the C2 emit
// order or the canonical spelling on the wire; the order of the Header slices
// this package returns is the authoritative C2 order.
type Header = impl.Header

// AnnotationCheck is the C5 verdict for one tool or event inputSchema.
type AnnotationCheck = impl.AnnotationCheck

// Definition is one tool or event type descriptor whose inputSchema carries
// x-mcp-header annotations.
type Definition = impl.Definition

// Exclusion reports a definition dropped from a tools/list or events/list
// result and why.
type Exclusion = impl.Exclusion

// RequestMirrors is the params._meta object and the mirror headers of one
// modern-era request (C1/C2).
type RequestMirrors = impl.RequestMirrors

// Era is the era a verified response proves, or EraNone when it proves none.
type Era = impl.Era

// EraAction is the operation the era detection prescribes.
type EraAction = impl.EraAction

// EraDecision is the C9 outcome of one verified response.
type EraDecision = impl.EraDecision

// CacheKey is the exact request a cached result is bound to: method, request
// parameters and era.
type CacheKey = impl.CacheKey

// ResultCache is a private cache of verified results (C8). It is safe for
// concurrent use and holds no package-level state.
type ResultCache = impl.ResultCache

// The closed era vocabulary of C9.
const (
	// EraNone is the era of a response that carries no era signal.
	EraNone = impl.EraNone
	// EraLegacy is the pre-modern era selected by a legacy signal.
	EraLegacy = impl.EraLegacy
	// EraModern is the 2026-07-28 era.
	EraModern = impl.EraModern
)

// The closed era-action vocabulary of C9.
const (
	// ActionStayModern keeps talking the modern era to this origin.
	ActionStayModern = impl.ActionStayModern
	// ActionFallbackInitialize falls back to initialize and stays legacy for
	// this origin.
	ActionFallbackInitialize = impl.ActionFallbackInitialize
	// ActionRetryWithSupported retries the request with the mutually
	// implemented versions in EraDecision.Supported.
	ActionRetryWithSupported = impl.ActionRetryWithSupported
	// ActionAbort fails the operation.
	ActionAbort = impl.ActionAbort
)

// IsVersion reports whether s is exactly 4DIGIT "-" 2DIGIT "-" 2DIGIT.
func IsVersion(s string) bool { return impl.IsVersion(s) }

// CompareVersion compares two versions byte-wise and returns -1, 0 or 1.
func CompareVersion(a, b string) int { return impl.CompareVersion(a, b) }

// IsFieldValue reports whether s satisfies the RFC 9110 field-value syntax
// after OWS removal.
func IsFieldValue(s string) bool { return impl.IsFieldValue(s) }

// IsToken reports whether s is 1*tchar (RFC 9110 section 5.6.2).
func IsToken(s string) bool { return impl.IsToken(s) }

// IsSentinel reports whether s has the shape "=?base64?" base64 "?=".
func IsSentinel(s string) bool { return impl.IsSentinel(s) }

// EncodeHeaderValue applies C3: a text that needs escaping is sent as
// "=?base64?" plus standard base64 of its UTF-8 bytes plus "?=", and every
// other text is sent as itself.
func EncodeHeaderValue(text string) string { return impl.EncodeHeaderValue(text) }

// DecodeHeaderValue applies C4: a value that is not sentinel shaped is plain
// text and decodes to itself. The second result is false when a sentinel's
// inner text is not canonical standard base64 of valid UTF-8.
func DecodeHeaderValue(value string) (string, bool) { return impl.DecodeHeaderValue(value) }

// TextOfValue converts a decoded JSON value to the header text of section 4
// for typ "string", "integer" or "boolean". The second result is false when
// the value is not representable as that type.
func TextOfValue(value any, typ string) (string, bool) { return impl.TextOfValue(value, typ) }

// NameSource returns the S6 name source field of method inside params, and
// whether the method has one at all.
func NameSource(method string) (field string, ok bool) { return impl.NameSource(method) }

// BuildRequestMirrors builds the C1 _meta object and the C2 headers in the
// authoritative C2 emit order (MCP-Protocol-Version, Mcp-Method, Mcp-Name; the
// caller appends the Mcp-Param-* headers after these). Go's net/http represents
// headers as a map, so the HTTP stack cannot preserve that order or the
// canonical spelling on the wire; the returned slice is the authoritative C2
// order. clientInfo is included only when non-nil.
func BuildRequestMirrors(version, method string, params map[string]any, clientInfo map[string]any) (RequestMirrors, error) {
	return impl.BuildRequestMirrors(version, method, params, clientInfo)
}

// ValidateAnnotations reports the C5 verdict for a tool or event inputSchema.
func ValidateAnnotations(inputSchema []byte) AnnotationCheck {
	return impl.ValidateAnnotations(inputSchema)
}

// FilterDefinitions validates each definition and keeps the valid ones in
// input order; the others are reported with their reason.
func FilterDefinitions(defs []Definition) (kept []Definition, excluded []Exclusion) {
	return impl.FilterDefinitions(defs)
}

// ProjectArguments projects the annotated arguments into Mcp-Param-* headers in
// depth-first document order (C6). The caller must have validated the schema
// first. A present argument of the wrong type yields
// ErrHeaderProjectionInvalidValue.
func ProjectArguments(inputSchema, arguments []byte) ([]Header, error) {
	return impl.ProjectArguments(inputSchema, arguments)
}

// RecognisedError reports a structurally recognised JSON-RPC error and its
// integer code and message.
func RecognisedError(body []byte) (code int, message string, ok bool) {
	return impl.RecognisedError(body)
}

// DetectEra implements C9 from a verified response only.
func DetectEra(status int, verified bool, body []byte, clientVersions []string) EraDecision {
	return impl.DetectEra(status, verified, body, clientVersions)
}

// DetectEraAttempt is DetectEra for a client that has just sent
// attemptedVersion: a retry_with_supported outcome additionally requires a
// supported version other than the one already attempted, and otherwise
// becomes abort/unsupported_version_no_overlap. An empty attemptedVersion
// leaves the decision unchanged.
func DetectEraAttempt(status int, verified bool, body []byte, clientVersions []string, attemptedVersion string) EraDecision {
	return impl.DetectEraAttempt(status, verified, body, clientVersions, attemptedVersion)
}

// NewResultCache returns an empty private result cache.
func NewResultCache() *ResultCache { return impl.NewResultCache() }
