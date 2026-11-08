package client

import (
	"bytes"
	"net/url"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// Pinned public-key literals from spec/fixtures/keys.json (the same oracle
// values used by the userkey transfer tests), so the seed profile's
// server_public_key passes jack.ValidatePublicKey deterministically.
const (
	fuzzServerPubB64 = "kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"
	fuzzServerKid    = "TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs"
)

var fuzzValidProfile = []byte(`{"url":"https://svc.example.test/mcp","aud":"https://svc.example.test","server_public_key":"` +
	fuzzServerPubB64 + `","kid":"` + fuzzServerKid + `","name":"alice-laptop"}`)

var fuzzUnknownFieldProfile = []byte(`{"url":"https://svc.example.test/mcp","aud":"https://svc.example.test","server_public_key":"` +
	fuzzServerPubB64 + `","kid":"` + fuzzServerKid + `","name":"x","extra":1}`)

var fuzzBadBase64Profile = []byte(`{"url":"https://svc.example.test/mcp","aud":"https://svc.example.test","server_public_key":"not base64"}`)

var fuzzTrailingDocsProfile = append(append([]byte{}, fuzzValidProfile...), fuzzValidProfile...)

// FuzzLoadProfile checks that the strict profile loader never panics, refuses
// trailing data, unknown fields and invalid keys, and that every accepted
// profile is an absolute http/https URL with a non-empty aud and a 32-byte
// server key that survive a save/load round trip unchanged (spec 01 section 6).
func FuzzLoadProfile(f *testing.F) {
	f.Add(fuzzValidProfile)
	f.Add(fuzzUnknownFieldProfile)
	f.Add([]byte(`{"url":"https://svc.example.test/mcp","server_public_key":"` + fuzzServerPubB64 + `"}`))
	f.Add(fuzzBadBase64Profile)
	f.Add([]byte(`[]`))
	f.Add(fuzzTrailingDocsProfile)
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := LoadProfile(bytes.NewReader(data))
		if bytes.Equal(data, fuzzValidProfile) && err != nil {
			t.Fatalf("acceptance witness: the valid profile seed must load, got %v", err)
		}
		// Rejection witnesses: unknown fields, malformed keys and trailing
		// documents must fail; a loader that accepts everything would
		// otherwise pass every invariant below.
		for _, invalid := range [][]byte{fuzzUnknownFieldProfile, fuzzBadBase64Profile, fuzzTrailingDocsProfile} {
			if bytes.Equal(data, invalid) && err == nil {
				t.Fatalf("rejection witness: invalid profile seed accepted")
			}
		}
		if err != nil {
			return
		}
		u, err := url.Parse(p.URL)
		if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			t.Fatalf("accepted a profile whose URL does not parse to an absolute http/https URL with a host")
		}
		if p.Aud == "" {
			t.Fatalf("accepted a profile with an empty aud")
		}
		key, err := p.ServerKeyBytes()
		if err != nil || len(key) != 32 {
			t.Fatalf("accepted profile server key does not decode to 32 bytes: %v", err)
		}
		if err := jack.ValidatePublicKey(key); err != nil {
			t.Fatalf("accepted an invalid server public key: %v", err)
		}
		if p.KID != "" {
			if _, err := jack.DecodeBase64URLFixed(p.KID, 32); err != nil {
				t.Fatalf("accepted kid does not decode to 32 bytes: %v", err)
			}
		}
		var buf bytes.Buffer
		if err := SaveProfile(&buf, p); err != nil {
			t.Fatalf("SaveProfile: %v", err)
		}
		again, err := LoadProfile(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("round-tripped profile failed to load: %v", err)
		}
		if again != p {
			t.Fatalf("profile round trip changed it")
		}
	})
}
