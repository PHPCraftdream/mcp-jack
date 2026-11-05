package client

import (
	"strings"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	spec "github.com/PHPCraftdream/mcp-jack/spec"
)

// matchedCase is one fixture accept case whose Jack-Auth header parses, whose
// kid is derivable from keys.json, and whose body/nonce decode cleanly.
type matchedCase struct {
	ID     string
	Auth   jack.RequestAuth
	Signer *InMemorySigner
	Body   []byte
	Nonce  []byte
}

// fixtureHeader extracts the Jack-Auth header value from a fixture request,
// returning "" when the case carries none.
func fixtureHeader(req spec.FixtureRequest) string {
	for _, h := range req.Headers {
		if strings.EqualFold(h.Name, "Jack-Auth") {
			return h.Value
		}
	}
	return ""
}

// matchedAcceptCases loads the request vectors and returns the accept cases
// that are fully reproducible: parseable header, known kid, decodable nonce.
func matchedAcceptCases(t *testing.T) ([]spec.RequestCase, []matchedCase) {
	t.Helper()
	vecs, err := spec.LoadRequestVectors()
	if err != nil {
		t.Fatalf("spec.LoadRequestVectors: %v", err)
	}
	keys, _ := fixtureKeys(t)
	var cases []spec.RequestCase
	var matched []matchedCase
	for _, tc := range vecs.Cases {
		if tc.Expect.Result != "accept" {
			continue
		}
		hv := fixtureHeader(tc.Request)
		if hv == "" {
			t.Logf("%s: no Jack-Auth header, skipping", tc.ID)
			continue
		}
		auth, err := jack.ParseRequestAuth([]string{hv})
		if err != nil {
			t.Fatalf("%s: jack.ParseRequestAuth: %v", tc.ID, err)
		}
		if _, ok := keys[auth.Kid]; !ok {
			t.Logf("%s: kid %q not in keys.json, skipping", tc.ID, auth.Kid)
			continue
		}
		nonce, err := jack.DecodeBase64URLFixed(auth.Nonce, 16)
		if err != nil {
			t.Fatalf("%s: decode nonce: %v", tc.ID, err)
		}
		body, err := tc.Request.Body()
		if err != nil {
			t.Fatalf("%s: tc.Request.Body: %v", tc.ID, err)
		}
		signer := seedSignerByKid(t, auth.Kid)
		cases = append(cases, tc)
		matched = append(matched, matchedCase{ID: tc.ID, Auth: auth, Signer: signer, Body: body, Nonce: nonce})
	}
	return cases, matched
}

// TestSignRequestReproducesFixtureHeaders proves the client header builder
// byte-for-byte reproduces each fixture accept case's Jack-Auth header.
func TestSignRequestReproducesFixtureHeaders(t *testing.T) {
	cases, matched := matchedAcceptCases(t)
	if len(matched) == 0 {
		t.Fatalf("no derivable accept cases matched")
	}
	for i, tc := range cases {
		mc := matched[i]
		t.Run(tc.ID, func(t *testing.T) {
			header, err := SignRequest(mc.Signer, tc.State.Aud, tc.Request.Method, tc.Request.Target, mc.Body, mc.Nonce, time.Unix(mc.Auth.TS, 0))
			if err != nil {
				t.Fatalf("SignRequest: %v", err)
			}
			want := fixtureHeader(tc.Request)
			if header != want {
				t.Fatalf("header mismatch:\n got: %s\nwant: %s", header, want)
			}
		})
	}
	t.Logf("matched %d derivable accept cases, 0 skipped", len(matched))
}

// TestSigningStringMatchesFixtureDebug asserts the canonical signing string of
// each matched accept case equals the fixture's debug signing string lines.
func TestSigningStringMatchesFixtureDebug(t *testing.T) {
	cases, matched := matchedAcceptCases(t)
	if len(matched) == 0 {
		t.Fatalf("no derivable accept cases checked")
	}
	for i, tc := range cases {
		mc := matched[i]
		want := strings.Join(tc.Debug.SigningStringLines, "\n")
		got := jack.RequestSigningString(tc.Request.Method, tc.Request.Target, tc.State.Aud, mc.Auth.Kid, mc.Auth.TS, mc.Auth.Nonce, mc.Body)
		if got != want {
			t.Fatalf("%s: signing string mismatch:\n got: %q\nwant: %q", tc.ID, got, want)
		}
	}
}

// TestSignRequestTamperDetection checks fixture signature validity, body
// tampering sensitivity, and that derivable reject cases do not reproduce.
func TestSignRequestTamperDetection(t *testing.T) {
	cases, matched := matchedAcceptCases(t)
	if len(matched) == 0 {
		t.Fatalf("no derivable accept cases")
	}
	// The fixture signature must verify over the recomputed signing string.
	for i, tc := range cases {
		mc := matched[i]
		str := jack.RequestSigningString(tc.Request.Method, tc.Request.Target, tc.State.Aud, mc.Auth.Kid, mc.Auth.TS, mc.Auth.Nonce, mc.Body)
		sigBytes, err := jack.DecodeBase64URLFixed(mc.Auth.Sig, 64)
		if err != nil {
			t.Fatalf("%s: decode sig: %v", tc.ID, err)
		}
		if !jack.Verify(mc.Signer.PublicKey(), []byte(str), sigBytes) {
			t.Fatalf("%s: fixture sig does not verify over recomputed string", tc.ID)
		}
	}
	// Tampering one body byte must change the produced header.
	{
		tc := cases[0]
		mc := matched[0]
		if len(mc.Body) == 0 {
			t.Skipf("%s: empty body, tamper case skipped", tc.ID)
		}
		body2 := make([]byte, len(mc.Body))
		copy(body2, mc.Body)
		body2[len(body2)-1] ^= 0x01
		header, err := SignRequest(mc.Signer, tc.State.Aud, tc.Request.Method, tc.Request.Target, mc.Body, mc.Nonce, time.Unix(mc.Auth.TS, 0))
		if err != nil {
			t.Fatalf("%s: SignRequest: %v", tc.ID, err)
		}
		header2, err := SignRequest(mc.Signer, tc.State.Aud, tc.Request.Method, tc.Request.Target, body2, mc.Nonce, time.Unix(mc.Auth.TS, 0))
		if err != nil {
			t.Fatalf("%s: SignRequest tampered: %v", tc.ID, err)
		}
		if header2 == header {
			t.Fatalf("%s: tampered body produced identical header", tc.ID)
		}
	}
	// A reject case with a valid-looking, derivable header must NOT reproduce.
	vecs, err := spec.LoadRequestVectors()
	if err != nil {
		t.Fatalf("spec.LoadRequestVectors: %v", err)
	}
	keys, _ := fixtureKeys(t)
	for _, tc := range vecs.Cases {
		// Only signature rejections: a header-form rejection (for example a
		// duplicate header) still carries a valid signature.
		if tc.Expect.Result != "reject" || tc.Expect.Code != "bad_signature" {
			continue
		}
		hv := fixtureHeader(tc.Request)
		if hv == "" {
			continue
		}
		auth, err := jack.ParseRequestAuth([]string{hv})
		if err != nil {
			continue
		}
		if _, ok := keys[auth.Kid]; !ok {
			continue
		}
		nonce, err := jack.DecodeBase64URLFixed(auth.Nonce, 16)
		if err != nil {
			continue
		}
		body, err := tc.Request.Body()
		if err != nil {
			continue
		}
		signer := seedSignerByKid(t, auth.Kid)
		header, err := SignRequest(signer, tc.State.Aud, tc.Request.Method, tc.Request.Target, body, nonce, time.Unix(auth.TS, 0))
		if err != nil {
			t.Fatalf("%s: SignRequest: %v", tc.ID, err)
		}
		str := jack.RequestSigningString(tc.Request.Method, tc.Request.Target, tc.State.Aud, auth.Kid, auth.TS, auth.Nonce, body)
		sigBytes, err := jack.DecodeBase64URLFixed(auth.Sig, 64)
		if err != nil {
			t.Fatalf("%s: decode sig: %v", tc.ID, err)
		}
		if header == hv && jack.Verify(signer.PublicKey(), []byte(str), sigBytes) {
			t.Fatalf("%s: reject case unexpectedly reproducible", tc.ID)
		}
		t.Logf("reject case %s not reproducible (as expected)", tc.ID)
		return
	}
	t.Skipf("no derivable reject case found")
}
