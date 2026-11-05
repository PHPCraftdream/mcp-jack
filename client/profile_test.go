package client

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
)

func newValidTestProfile(t *testing.T) (Profile, ed25519.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p := Profile{
		URL:             "https://svc.example.test/mcp",
		Aud:             "https://svc.example.test",
		ServerPublicKey: jack.EncodeBase64URL(pub),
		KID:             jack.KeyID(pub),
		Name:            "alice-laptop",
	}
	return p, pub
}

func newValidProfileDoc(t *testing.T) string {
	t.Helper()
	p, _ := newValidTestProfile(t)
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal profile: %v", err)
	}
	return string(b)
}

func TestProfileRoundTrip(t *testing.T) {
	p, pub := newValidTestProfile(t)
	var buf bytes.Buffer
	if err := SaveProfile(&buf, p); err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Fatalf("SaveProfile output does not end with newline: %q", buf.String())
	}
	got, err := LoadProfile(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}
	want, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(want) != string(gotJSON) {
		t.Fatalf("round trip mismatch: got %s want %s", gotJSON, want)
	}
	key, err := got.ServerKeyBytes()
	if err != nil {
		t.Fatalf("ServerKeyBytes: %v", err)
	}
	if !bytes.Equal(key, pub) {
		t.Fatalf("ServerKeyBytes mismatch: got %x want %x", key, pub)
	}
}

func TestProfileJSONHasNoPrivateKey(t *testing.T) {
	p, _ := newValidTestProfile(t)
	var buf bytes.Buffer
	if err := SaveProfile(&buf, p); err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}
	s := buf.String()
	if strings.Contains(s, "private") {
		t.Fatalf("profile JSON contains 'private': %s", s)
	}
	if strings.Contains(s, "seed") {
		t.Fatalf("profile JSON contains 'seed': %s", s)
	}
}

func TestLoadProfileRejects(t *testing.T) {
	shortKey := jack.EncodeBase64URL(make([]byte, 16))
	p, pub := newValidTestProfile(t)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal profile: %v", err)
	}
	// One key for every case: the Replace calls below must find it in base.
	base := string(raw)
	paddedKey := jack.EncodeBase64URL(pub) + "="
	cases := []struct {
		name string
		doc  string
	}{
		{
			name: "unknown field",
			doc:  strings.TrimSuffix(base, "}") + `,"extra":1}`,
		},
		{
			name: "server key wrong length",
			doc:  strings.Replace(base, jack.EncodeBase64URL(pub), shortKey, 1),
		},
		{
			name: "padded server key",
			doc:  strings.Replace(base, jack.EncodeBase64URL(pub), paddedKey, 1),
		},
		{
			name: "kid not 32-byte base64url",
			doc:  strings.Replace(base, `"kid":"`+jack.KeyID(pub)+`"`, `"kid":"short"`, 1),
		},
		{
			name: "url missing host",
			doc:  strings.Replace(base, `"url":"https://svc.example.test/mcp"`, `"url":"https:///mcp"`, 1),
		},
		{
			name: "aud empty",
			doc:  strings.Replace(base, `"aud":"https://svc.example.test"`, `"aud":""`, 1),
		},
		{
			name: "trailing data",
			doc:  base + " {}",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadProfile(strings.NewReader(tc.doc)); err == nil {
				t.Fatalf("LoadProfile accepted invalid document %q", tc.doc)
			}
		})
	}
}

func TestNewClientFromProfile(t *testing.T) {
	p, _ := newValidTestProfile(t)
	c, err := NewClientFromProfile(p, seedSignerByName(t, "alice"), nil)
	if err != nil {
		t.Fatalf("NewClientFromProfile: %v", err)
	}
	if c == nil {
		t.Fatal("NewClientFromProfile returned nil client")
	}

	if _, err := NewClientFromProfile(Profile{
		URL:             "https://svc.example.test/mcp",
		Aud:             "https://svc.example.test",
		ServerPublicKey: jack.EncodeBase64URL(make([]byte, 16)),
	}, seedSignerByName(t, "alice"), nil); err == nil {
		t.Fatal("expected error for invalid server public key")
	}
}

func TestLocalKeyValidationHasNoHTTPStatus(t *testing.T) {
	// The identity-point encoding {1,0,...,0} decodes to exactly 32 bytes but
	// fails the spec 03 section 2 key rules, exercising the local pinned-key
	// rejection path of LoadProfile, NewClientFromProfile and NewClient.
	identity := make([]byte, 32)
	identity[0] = 1

	// assertClientSide requires err to be a *jack.Error coded key_rejected
	// with HTTPStatus 0: a client-side code never becomes an HTTP response
	// (Error.HTTPStatus contract), so the validator's wire 400 must not leak.
	assertClientSide := func(t *testing.T, err error) {
		t.Helper()
		var je *jack.Error
		if !errors.As(err, &je) {
			t.Fatalf("got error %v, not a *jack.Error", err)
		}
		if je.Code != jack.CodeKeyRejected {
			t.Fatalf("got code %q, want %q", je.Code, jack.CodeKeyRejected)
		}
		if je.HTTPStatus != 0 {
			t.Fatalf("HTTPStatus = %d, want 0", je.HTTPStatus)
		}
	}

	p := Profile{
		URL:             "https://svc.example.test/mcp",
		Aud:             "https://svc.example.test",
		ServerPublicKey: jack.EncodeBase64URL(identity),
	}
	doc, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal profile: %v", err)
	}

	_, err = LoadProfile(bytes.NewReader(doc))
	assertClientSide(t, err)

	_, err = NewClientFromProfile(p, seedSignerByName(t, "alice"), nil)
	assertClientSide(t, err)

	_, err = NewClient(Config{
		BaseURL:   p.URL,
		Aud:       p.Aud,
		Signer:    seedSignerByName(t, "alice"),
		ServerKey: identity,
	})
	assertClientSide(t, err)
}
