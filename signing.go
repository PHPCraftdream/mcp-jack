package jack

import "strconv"

// All strings are UTF-8, joined with a single LF, no trailing LF
// (spec 01 sections 3.1 and 5, spec 03 section 3.1); ts is plain decimal.

// RequestSigningString builds the eight-line v1 request signing string:
// "mcp-jack/v1/request", method, target, aud, kid, ts, nonce, body-hash (spec 01 section 3.1).
// body is hashed over its exact bytes.
func RequestSigningString(method, target, aud, kid string, ts int64, nonce string, body []byte) string {
	return joinLines(
		"mcp-jack/v1/request",
		method,
		target,
		aud,
		kid,
		strconv.FormatInt(ts, 10),
		nonce,
		BodyHash(body),
	)
}

// ResponseSigningString builds the six-line v1 response signing string:
// "mcp-jack/v1/response", status (decimal), request-sig, kid, ts, body-hash (spec 01 section 5).
func ResponseSigningString(status int, requestSig, kid string, ts int64, body []byte) string {
	return joinLines(
		"mcp-jack/v1/response",
		strconv.Itoa(status),
		requestSig,
		kid,
		strconv.FormatInt(ts, 10),
		BodyHash(body),
	)
}

// RotateProofString builds the five-line rotate proof string:
// "mcp-jack/v1/rotate", aud, old kid, new kid, ts (spec 03 section 3.1).
func RotateProofString(aud, oldKid, newKid string, ts int64) string {
	return joinLines(
		"mcp-jack/v1/rotate",
		aud,
		oldKid,
		newKid,
		strconv.FormatInt(ts, 10),
	)
}

// joinLines concatenates parts with "\n" and no trailing newline.
func joinLines(parts ...string) string {
	out := make([]byte, 0, 128)
	for i, p := range parts {
		if i > 0 {
			out = append(out, '\n')
		}
		out = append(out, p...)
	}
	return string(out)
}
