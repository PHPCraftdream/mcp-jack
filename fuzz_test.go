package jack_test

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

// FuzzParseRequestAuth checks that the strict header parser never panics, only
// fails with a 401 protocol error, and that whatever it accepts survives a
// format and parse round trip with strictly decodable values.
func FuzzParseRequestAuth(f *testing.F) {
	vectors, err := spec.LoadRequestVectors()
	if err != nil {
		f.Fatalf("LoadRequestVectors: %v", err)
	}
	for _, c := range vectors.Cases {
		for _, v := range jackAuthValues(c.Request.Headers) {
			f.Add(v)
		}
	}
	f.Add("")
	f.Add("v1 ")
	reqKid := jack.EncodeBase64URL(bytes.Repeat([]byte{0x44}, 32))
	reqNonce := jack.EncodeBase64URL(bytes.Repeat([]byte{0x55}, 16))
	reqSig := jack.EncodeBase64URL(bytes.Repeat([]byte{0x66}, 64))
	reqValid := "v1 kid=" + reqKid + ",ts=1,nonce=" + reqNonce + ",sig=" + reqSig
	f.Add(reqValid)
	reqUnknownParam := reqValid + ",aud=zzz"
	f.Add(reqUnknownParam)

	f.Fuzz(func(t *testing.T, value string) {
		a, err := jack.ParseRequestAuth([]string{value})
		// Rejection witnesses: an unknown parameter violates the section 3
		// grammar and an empty header cannot parse, so a parser that accepts
		// everything fails the campaign.
		if value == reqUnknownParam && err == nil {
			t.Fatalf("rejection witness: unknown Jack-Auth parameter accepted")
		}
		if value == "" && err == nil {
			t.Fatalf("rejection witness: empty header accepted")
		}
		// The campaign must exercise the request acceptance path, not only
		// rejections; the seed is canonical so re-formatting must be byte-identical.
		if value == reqValid {
			if err != nil {
				t.Fatalf("acceptance witness: the canonical valid request seed must parse, got %v", err)
			}
			if got := jack.FormatRequestAuth(a); got != reqValid {
				t.Fatalf("acceptance witness: canonical formatting changed the request seed")
			}
		}
		if err != nil {
			var je *jack.Error
			if !errors.As(err, &je) || je.HTTPStatus != 401 {
				t.Fatalf("error %v is not a 401 *jack.Error", err)
			}
			return
		}
		again, err := jack.ParseRequestAuth([]string{jack.FormatRequestAuth(a)})
		if err != nil || again != a {
			t.Fatalf("round trip of the accepted request auth failed: %v", err)
		}
		if _, err := jack.DecodeBase64URLFixed(a.Kid, 32); err != nil {
			t.Fatalf("accepted kid does not decode to 32 bytes: %v", err)
		}
		if _, err := jack.DecodeBase64URLFixed(a.Nonce, 16); err != nil {
			t.Fatalf("accepted nonce does not decode to 16 bytes: %v", err)
		}
		if _, err := jack.DecodeBase64URLFixed(a.Sig, 64); err != nil {
			t.Fatalf("accepted sig does not decode to 64 bytes: %v", err)
		}
		if a.TS < 0 {
			t.Fatalf("accepted a negative ts %d", a.TS)
		}
	})
}

// FuzzParseResponseAuth checks the strict response-header parser the same way
// FuzzParseRequestAuth checks the request parser: it never panics, only fails
// with a 401 protocol error, never accepts a nonce parameter (the response
// grammar of spec 01 section 5 forbids it), and whatever it accepts survives a
// format and parse round trip with strictly decodable values.
func FuzzParseResponseAuth(f *testing.F) {
	vectors, err := spec.LoadResponseVectors()
	if err != nil {
		f.Fatalf("LoadResponseVectors: %v", err)
	}
	for _, c := range vectors.Cases {
		for _, v := range jackAuthValues(c.Response.Headers) {
			f.Add(v)
		}
	}
	kid := jack.EncodeBase64URL(bytes.Repeat([]byte{0x11}, 32))
	sig := jack.EncodeBase64URL(bytes.Repeat([]byte{0x22}, 64))
	valid := "v1 kid=" + kid + ",ts=1,sig=" + sig
	f.Add(valid)
	f.Add(valid + ",nonce=" + jack.EncodeBase64URL(bytes.Repeat([]byte{0x33}, 16)))
	f.Add("")
	f.Add("v1 ")

	f.Fuzz(func(t *testing.T, value string) {
		a, err := jack.ParseResponseAuth([]string{value})
		// The campaign must exercise the acceptance path, not only rejections;
		// the seed is in canonical form so re-formatting must be byte-identical.
		if value == valid {
			if err != nil {
				t.Fatalf("acceptance witness: the canonical valid seed must parse, got %v", err)
			}
			if got := jack.FormatResponseAuth(a); got != valid {
				t.Fatalf("acceptance witness: canonical formatting changed the response seed")
			}
		}
		if err != nil {
			var je *jack.Error
			if !errors.As(err, &je) || je.HTTPStatus != 401 {
				t.Fatalf("error %v is not a 401 *jack.Error", err)
			}
			return
		}
		if strings.Contains(value, "nonce=") {
			t.Fatalf("response parser accepted a nonce parameter")
		}
		again, err := jack.ParseResponseAuth([]string{jack.FormatResponseAuth(a)})
		if err != nil || again != a {
			t.Fatalf("round trip of the accepted response auth failed: %v", err)
		}
		if _, err := jack.DecodeBase64URLFixed(a.Kid, 32); err != nil {
			t.Fatalf("accepted kid does not decode to 32 bytes: %v", err)
		}
		if _, err := jack.DecodeBase64URLFixed(a.Sig, 64); err != nil {
			t.Fatalf("accepted sig does not decode to 64 bytes: %v", err)
		}
		if a.TS < 0 {
			t.Fatalf("accepted a negative ts %d", a.TS)
		}
	})
}

// FuzzMatchPattern compares the hand-written matcher with a regular expression
// built from the same pattern, over valid UTF-8 (a regexp reads invalid bytes
// as U+FFFD, the matcher compares bytes, so those inputs are not comparable).
func FuzzMatchPattern(f *testing.F) {
	vectors, err := spec.LoadPatternVectors()
	if err != nil {
		f.Fatalf("LoadPatternVectors: %v", err)
	}
	for _, c := range vectors.Cases {
		f.Add(c.Pattern, c.Input)
	}

	f.Fuzz(func(t *testing.T, pattern, input string) {
		if !utf8.ValidString(pattern) || !utf8.ValidString(input) {
			t.Skip()
		}
		parts := strings.Split(pattern, "*")
		for i := range parts {
			parts[i] = regexp.QuoteMeta(parts[i])
		}
		re, err := regexp.Compile("(?s)^" + strings.Join(parts, ".*") + "$")
		if err != nil {
			t.Skip()
		}
		if got, want := jack.MatchPattern(pattern, input), re.MatchString(input); got != want {
			t.Fatalf("MatchPattern disagrees with the independent regexp oracle")
		}
	})
}
