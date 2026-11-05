package jack_test

import (
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

	f.Fuzz(func(t *testing.T, value string) {
		a, err := jack.ParseRequestAuth([]string{value})
		if err != nil {
			var je *jack.Error
			if !errors.As(err, &je) || je.HTTPStatus != 401 {
				t.Fatalf("error %v is not a 401 *jack.Error", err)
			}
			return
		}
		again, err := jack.ParseRequestAuth([]string{jack.FormatRequestAuth(a)})
		if err != nil || again != a {
			t.Fatalf("round trip of %+v failed: %+v, %v", a, again, err)
		}
		if _, err := jack.DecodeBase64URLFixed(a.Kid, 32); err != nil {
			t.Fatalf("accepted kid %q does not decode: %v", a.Kid, err)
		}
		if _, err := jack.DecodeBase64URLFixed(a.Nonce, 16); err != nil {
			t.Fatalf("accepted nonce %q does not decode: %v", a.Nonce, err)
		}
		if _, err := jack.DecodeBase64URLFixed(a.Sig, 64); err != nil {
			t.Fatalf("accepted sig %q does not decode: %v", a.Sig, err)
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
			t.Fatalf("MatchPattern(%q, %q) = %v, regexp says %v", pattern, input, got, want)
		}
	})
}
