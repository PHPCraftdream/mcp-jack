package jack_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

func jackAuthValues(headers []spec.HeaderPair) []string {
	var values []string
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Jack-Auth") {
			values = append(values, h.Value)
		}
	}
	return values
}

func parseErr(err error) (string, int) {
	var jerr *jack.Error
	if errors.As(err, &jerr) {
		return jerr.Code, jerr.HTTPStatus
	}
	return "", 0
}

func isParseCode(code string) bool {
	switch code {
	case jack.CodeMissingAuth, jack.CodeMalformedAuth, jack.CodeUnsupportedVersion:
		return true
	}
	return false
}

var keyByKid = func() map[string]spec.TestKey {
	m := make(map[string]spec.TestKey)
	keys, err := spec.LoadKeys()
	if err == nil {
		for _, k := range keys.Keys {
			m[k.Kid] = k
		}
	}
	return m
}()

func privateKeyFor(t *testing.T, k spec.TestKey) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(k.SeedHex)
	if err != nil {
		t.Fatalf("hex decode seed for %s: %v", k.Name, err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestRequestHeaderParsing(t *testing.T) {
	vectors, err := spec.LoadRequestVectors()
	if err != nil {
		t.Fatalf("LoadRequestVectors: %v", err)
	}
	for _, c := range vectors.Cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			values := jackAuthValues(c.Request.Headers)
			_, err := jack.ParseRequestAuth(values)
			code, status := parseErr(err)
			if c.Expect.Result == "reject" && isParseCode(c.Expect.Code) {
				if err == nil {
					t.Fatalf("expected parse error with code %q, got nil", c.Expect.Code)
				}
				if code != c.Expect.Code {
					t.Fatalf("code = %q, want %q", code, c.Expect.Code)
				}
				if status != 401 {
					t.Fatalf("status = %d, want 401", status)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRequestAuth: %v", err)
			}
		})
	}
}

func TestRequestAcceptResign(t *testing.T) {
	vectors, err := spec.LoadRequestVectors()
	if err != nil {
		t.Fatalf("LoadRequestVectors: %v", err)
	}
	for _, c := range vectors.Cases {
		c := c
		if c.Expect.Result != "accept" {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			body, err := c.Request.Body()
			if err != nil {
				t.Fatalf("Body: %v", err)
			}
			values := jackAuthValues(c.Request.Headers)
			a, err := jack.ParseRequestAuth(values)
			if err != nil {
				t.Fatalf("ParseRequestAuth: %v", err)
			}
			k, ok := keyByKid[a.Kid]
			if !ok {
				t.Fatalf("no test key for kid %q", a.Kid)
			}
			priv := privateKeyFor(t, k)
			pub := priv.Public().(ed25519.PublicKey)
			if verr := jack.ValidatePublicKey(pub); verr != nil {
				t.Fatalf("ValidatePublicKey: %v", verr)
			}
			if jack.KeyID(pub) != a.Kid {
				t.Fatalf("KeyID = %q, want %q", jack.KeyID(pub), a.Kid)
			}
			sig, err := jack.DecodeBase64URLFixed(a.Sig, 64)
			if err != nil {
				t.Fatalf("DecodeBase64URLFixed: %v", err)
			}
			msg := jack.RequestSigningString(c.Request.Method, c.Request.Target, c.State.Aud, a.Kid, a.TS, a.Nonce, body)
			if want := strings.Join(c.Debug.SigningStringLines, "\n"); want != msg {
				t.Fatalf("signing string mismatch:\n got: %q\nwant: %q", msg, want)
			}
			if !jack.Verify(pub, []byte(msg), sig) {
				t.Fatalf("Verify rejected the signature")
			}
			if jack.EncodeBase64URL(ed25519.Sign(priv, []byte(msg))) != a.Sig {
				t.Fatalf("re-signed header sig does not match %q", a.Sig)
			}
			if jack.FormatRequestAuth(a) != values[0] {
				t.Fatalf("FormatRequestAuth mismatch:\n got: %q\nwant: %q", jack.FormatRequestAuth(a), values[0])
			}
		})
	}
}

func TestStrictSPlusLFixture(t *testing.T) {
	vectors, err := spec.LoadRequestVectors()
	if err != nil {
		t.Fatalf("LoadRequestVectors: %v", err)
	}
	var found bool
	for _, c := range vectors.Cases {
		if c.ID != "sig-noncanonical-s" {
			continue
		}
		found = true
		t.Run(c.ID, func(t *testing.T) {
			body, err := c.Request.Body()
			if err != nil {
				t.Fatalf("Body: %v", err)
			}
			a, err := jack.ParseRequestAuth(jackAuthValues(c.Request.Headers))
			if err != nil {
				t.Fatalf("ParseRequestAuth: %v", err)
			}
			k, ok := keyByKid[a.Kid]
			if !ok {
				t.Fatalf("no test key for kid %q", a.Kid)
			}
			priv := privateKeyFor(t, k)
			pub := priv.Public().(ed25519.PublicKey)
			sig, err := jack.DecodeBase64URLFixed(a.Sig, 64)
			if err != nil {
				t.Fatalf("DecodeBase64URLFixed: %v", err)
			}
			msg := jack.RequestSigningString(c.Request.Method, c.Request.Target, c.State.Aud, a.Kid, a.TS, a.Nonce, body)
			if jack.Verify(pub, []byte(msg), sig) {
				t.Fatalf("Verify accepted a non-canonical (S >= L) signature")
			}
		})
	}
	if !found {
		t.Fatalf("case sig-noncanonical-s not found in request vectors")
	}
}

func TestResponseHeaderParsing(t *testing.T) {
	vectors, err := spec.LoadResponseVectors()
	if err != nil {
		t.Fatalf("LoadResponseVectors: %v", err)
	}
	for _, c := range vectors.Cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			values := jackAuthValues(c.Response.Headers)
			_, err := jack.ParseResponseAuth(values)
			code, status := parseErr(err)
			if c.Expect.Result == "reject" && isParseCode(c.Expect.Code) {
				if err == nil {
					t.Fatalf("expected parse error with code %q, got nil", c.Expect.Code)
				}
				if code != c.Expect.Code {
					t.Fatalf("code = %q, want %q", code, c.Expect.Code)
				}
				if status != 401 {
					t.Fatalf("status = %d, want 401", status)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseResponseAuth: %v", err)
			}
		})
	}
}

func TestResponseAcceptVerify(t *testing.T) {
	vectors, err := spec.LoadResponseVectors()
	if err != nil {
		t.Fatalf("LoadResponseVectors: %v", err)
	}
	for _, c := range vectors.Cases {
		c := c
		if c.Expect.Result != "accept" {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			values := jackAuthValues(c.Response.Headers)
			a, err := jack.ParseResponseAuth(values)
			if err != nil {
				t.Fatalf("ParseResponseAuth: %v", err)
			}
			if a.Kid != c.State.PinnedServerKid {
				t.Fatalf("kid = %q, want pinned %q", a.Kid, c.State.PinnedServerKid)
			}
			pin, err := jack.DecodeBase64URLFixed(c.State.PinnedServerPublicKey, 32)
			if err != nil {
				t.Fatalf("DecodeBase64URLFixed pinned key: %v", err)
			}
			body, berr := c.Response.Body()
			if berr != nil {
				t.Fatalf("Body: %v", berr)
			}
			sig, err := jack.DecodeBase64URLFixed(a.Sig, 64)
			if err != nil {
				t.Fatalf("DecodeBase64URLFixed sig: %v", err)
			}
			msg := jack.ResponseSigningString(c.Response.Status, c.State.RequestSig, a.Kid, a.TS, body)
			if !jack.Verify(pin, []byte(msg), sig) {
				t.Fatalf("Verify rejected the response signature")
			}
			k, ok := keyByKid[c.State.PinnedServerKid]
			if !ok {
				t.Fatalf("no test key for kid %q", c.State.PinnedServerKid)
			}
			priv := privateKeyFor(t, k)
			if jack.EncodeBase64URL(ed25519.Sign(priv, []byte(msg))) != a.Sig {
				t.Fatalf("re-signed response sig does not match %q", a.Sig)
			}
			if jack.FormatResponseAuth(a) != values[0] {
				t.Fatalf("FormatResponseAuth mismatch:\n got: %q\nwant: %q", jack.FormatResponseAuth(a), values[0])
			}
		})
	}
}

func TestAuthHeaderGrammarUnit(t *testing.T) {
	v := jack.FormatRequestAuth(jack.RequestAuth{
		Kid:   strings.Repeat("a", 43),
		TS:    1,
		Nonce: strings.Repeat("b", 22),
		Sig:   strings.Repeat("c", 86),
	})

	cases := []struct {
		name     string
		values   []string
		wantCode string
	}{
		{"missing", nil, jack.CodeMissingAuth},
		{"duplicate", []string{v, v}, jack.CodeMalformedAuth},
		{"v2", []string{strings.Replace(v, "v1", "v2", 1)}, jack.CodeUnsupportedVersion},
		{"V1", []string{strings.Replace(v, "v1", "V1", 1)}, jack.CodeMalformedAuth},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := jack.ParseRequestAuth(tc.values)
			if err == nil {
				t.Fatalf("expected error with code %q, got nil", tc.wantCode)
			}
			code, status := parseErr(err)
			if code != tc.wantCode {
				t.Fatalf("code = %q, want %q", code, tc.wantCode)
			}
			if status != 401 {
				t.Fatalf("status = %d, want 401", status)
			}
		})
	}
}
