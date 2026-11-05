package jack

import (
	"strconv"
	"strings"
)

// Jack-Auth header grammar of spec 01 sections 3 and 5, parsed strictly.
// RequestAuth and ResponseAuth hold the parameter values as sent.

// RequestAuth holds the parsed parameters of a v1 request Jack-Auth header.
// Kid, Nonce and Sig are the canonical header values as sent.
type RequestAuth struct {
	Kid   string
	TS    int64
	Nonce string
	Sig   string
}

// ResponseAuth holds the parsed parameters of a v1 response Jack-Auth header.
type ResponseAuth struct {
	Kid string
	TS  int64
	Sig string
}

// Byte lengths required by spec 01 section 2 (sizes of kid, nonce, sig).
const (
	kidLen   = 32
	nonceLen = 16
	sigLen   = 64
)

// authParams is one parsed header: name -> value, in header order.
type authParams map[string]string

// parseAuthValues implements the shared grammar. Any violation is a *Error with
// HTTPStatus 401: missing_auth, malformed_auth or unsupported_version.
// allowed is the exact parameter set; lengths maps the names that must decode
// to a fixed number of bytes via DecodeBase64URLFixed.
func parseAuthValues(values []string, allowed []string, lengths map[string]int) (authParams, error) {
	if len(values) == 0 {
		return nil, newError(401, CodeMissingAuth, "missing Jack-Auth header")
	}
	if len(values) > 1 {
		// Spec 01 section 4 step 2: a header may appear at most once.
		return nil, newError(401, CodeMalformedAuth, "Jack-Auth header present more than once")
	}
	value := values[0]

	// Scheme: the value up to the first space (spec 01 section 3).
	sp := strings.IndexByte(value, ' ')
	scheme := value
	if sp >= 0 {
		scheme = value[:sp]
	}
	if scheme != "v1" {
		if isVersionScheme(scheme) {
			return nil, newError(401, CodeUnsupportedVersion, "unsupported Jack-Auth version")
		}
		return nil, newError(401, CodeMalformedAuth, "malformed Jack-Auth scheme")
	}
	if sp < 0 {
		return nil, newError(401, CodeMalformedAuth, "missing Jack-Auth parameters")
	}

	// Parameters: comma-separated name=value, no whitespace anywhere
	// (spec 01 section 3 grammar).
	rest := value[sp+1:]
	params := make(authParams, len(allowed))
	for _, part := range strings.Split(rest, ",") {
		eq := strings.IndexByte(part, '=')
		// The grammar ^[a-z]+=[A-Za-z0-9_-]+$ allows exactly one '='.
		if eq < 0 || eq == 0 || eq == len(part)-1 || strings.IndexByte(part[eq+1:], '=') >= 0 {
			return nil, newError(401, CodeMalformedAuth, "malformed Jack-Auth parameter")
		}
		name, val := part[:eq], part[eq+1:]
		if !lowerAlpha(name) || !paramValueCharset(val) {
			return nil, newError(401, CodeMalformedAuth, "malformed Jack-Auth parameter")
		}
		if !allowedName(name, allowed) {
			return nil, newError(401, CodeMalformedAuth, "unknown Jack-Auth parameter")
		}
		if _, dup := params[name]; dup {
			return nil, newError(401, CodeMalformedAuth, "repeated Jack-Auth parameter")
		}
		params[name] = val
	}
	for _, name := range allowed {
		if _, ok := params[name]; !ok {
			return nil, newError(401, CodeMalformedAuth, "missing Jack-Auth parameter "+name)
		}
	}

	// ts: whole seconds, no sign, no leading zeros, at most 12 digits
	// (spec 01 section 3).
	rawTS := params["ts"]
	if !validTS(rawTS) {
		return nil, newError(401, CodeMalformedAuth, "malformed ts")
	}
	ts, err := strconv.ParseInt(rawTS, 10, 64)
	if err != nil {
		return nil, newError(401, CodeMalformedAuth, "malformed ts")
	}

	// Fixed-length base64url values: kid 32, nonce 16, sig 64 bytes
	// (spec 01 sections 2 and 3).
	for name, size := range lengths {
		v, ok := params[name]
		if !ok {
			continue
		}
		if _, err := DecodeBase64URLFixed(v, size); err != nil {
			return nil, newError(401, CodeMalformedAuth, "malformed "+name)
		}
	}

	params["ts"] = strconv.FormatInt(ts, 10)
	return params, nil
}

// isVersionScheme reports whether s is exactly "v" plus one or more ASCII digits
// (spec 01 section 3: such a scheme is unsupported_version, any other is malformed_auth).
func isVersionScheme(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// lowerAlpha reports whether s matches ^[a-z]+$ (parameter names, spec 01 section 3).
func lowerAlpha(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return true
}

// paramValueCharset reports whether s is non-empty and only A-Za-z0-9_-
// (spec 01 section 3).
func paramValueCharset(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// allowedName reports whether name is in allowed.
func allowedName(name string, allowed []string) bool {
	for _, a := range allowed {
		if a == name {
			return true
		}
	}
	return false
}

// validTS reports whether s matches ^(0|[1-9][0-9]{0,11})$ (spec 01 section 3).
func validTS(s string) bool {
	if len(s) == 0 || len(s) > 12 {
		return false
	}
	if s[0] == '0' {
		return len(s) == 1
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ParseRequestAuth parses the Jack-Auth header values of one HTTP request (the
// caller collects the values of all headers named Jack-Auth case-insensitively,
// in order) and returns *Error with CodeMissingAuth, CodeMalformedAuth or
// CodeUnsupportedVersion.
func ParseRequestAuth(values []string) (RequestAuth, error) {
	p, err := parseAuthValues(values, []string{"kid", "ts", "nonce", "sig"},
		map[string]int{"kid": kidLen, "nonce": nonceLen, "sig": sigLen})
	if err != nil {
		return RequestAuth{}, err
	}
	return RequestAuth{Kid: p["kid"], TS: mustTS(p), Nonce: p["nonce"], Sig: p["sig"]}, nil
}

// ParseResponseAuth is ParseRequestAuth for response headers, whose parameter
// set is exactly kid, ts, sig (spec 01 section 5).
func ParseResponseAuth(values []string) (ResponseAuth, error) {
	p, err := parseAuthValues(values, []string{"kid", "ts", "sig"},
		map[string]int{"kid": kidLen, "sig": sigLen})
	if err != nil {
		return ResponseAuth{}, err
	}
	return ResponseAuth{Kid: p["kid"], TS: mustTS(p), Sig: p["sig"]}, nil
}

// mustTS converts the already validated ts entry to int64.
func mustTS(p authParams) int64 {
	ts, _ := strconv.ParseInt(p["ts"], 10, 64)
	return ts
}

// FormatRequestAuth renders the canonical request header value
// "v1 kid=...,ts=...,nonce=...,sig=..." (spec 01 section 3).
func FormatRequestAuth(a RequestAuth) string {
	return "v1 kid=" + a.Kid + ",ts=" + strconv.FormatInt(a.TS, 10) + ",nonce=" + a.Nonce + ",sig=" + a.Sig
}

// FormatResponseAuth renders the canonical response header value
// "v1 kid=...,ts=...,sig=..." (spec 01 section 5).
func FormatResponseAuth(a ResponseAuth) string {
	return "v1 kid=" + a.Kid + ",ts=" + strconv.FormatInt(a.TS, 10) + ",sig=" + a.Sig
}
