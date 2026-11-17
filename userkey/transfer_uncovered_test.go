package userkey

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
)

const transferTestSeed = "0123456789abcdef0123456789abcdef"

type transferPublicProbe struct{ pub []byte }

func (p *transferPublicProbe) PublicKey() []byte { return p.pub }

func transferTestIdentity() ExpectedIdentity {
	seed := []byte(transferTestSeed)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return ExpectedIdentity{URL: "https://transfer.example.test", Aud: "aud", ServerPublicKey: append([]byte(nil), pub...), ServerKID: jack.KeyID(pub)}
}

func transferTestPrivate(seed []byte) []byte {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return marshalPrivateEnvelope(seed, pub, jack.KeyID(pub))
}

func transferAssertError(t *testing.T, err error, class, member string, observed int) {
	t.Helper()
	var got *jack.Error
	if !errors.As(err, &got) {
		t.Fatalf("error type = %T, want *jack.Error: %v", err, err)
	}
	message := class
	if member != "" {
		message += " member=" + member
	}
	message += " length=" + strconv.Itoa(observed)
	if got.Code != class || got.HTTPStatus != 0 || got.Message != message {
		t.Fatalf("error = {Code:%q HTTPStatus:%d Message:%q}, want {Code:%q HTTPStatus:0 Message:%q}", got.Code, got.HTTPStatus, got.Message, class, message)
	}
}

func transferObject(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return data
}

func transferEnvelopeMap(private bool) map[string]any {
	seed := []byte(transferTestSeed)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	doc := map[string]any{
		"crv": "Ed25519", "kid": jack.KeyID(pub), "kty": "OKP",
		"type": publicEnvelopeType, "v": 1, "x": jack.EncodeBase64URL(pub),
	}
	if private {
		doc["d"] = jack.EncodeBase64URL(seed)
		doc["type"] = privateEnvelopeType
	}
	return doc
}

func transferCredentialMap(expected ExpectedIdentity, clientKey string) map[string]any {
	return map[string]any{
		"aud": expected.Aud, "client_key": clientKey,
		"server_kid":        expected.ServerKID,
		"server_public_key": jack.EncodeBase64URL(expected.ServerPublicKey),
		"type":              credentialEnvelopeType, "url": expected.URL, "v": 1,
	}
}

func TestTransferExportIssuanceFailuresAndRedaction(t *testing.T) {
	var nilIdentity *PublicIdentity
	if nilIdentity.PublicKey() != nil || nilIdentity.KID() != "" || nilIdentity.Verify(nil, nil) {
		t.Fatal("nil PublicIdentity methods did not fail closed")
	}
	transferAssertError(t, func() error { _, err := nilIdentity.Sign(nil); return err }(), ClassNotPrivate, "d", 0)
	zeroIdentity := PublicIdentity{}
	if got := zeroIdentity.String(); got != "userkey.PublicIdentity{kid:}" || zeroIdentity.GoString() != got || fmt.Sprintf("%#v", zeroIdentity) != got {
		t.Fatalf("zero identity formatting = %q", got)
	}
	if got, err := json.Marshal(zeroIdentity); err != nil || string(got) != "{}" {
		t.Fatalf("zero identity JSON = %q, %v", got, err)
	}
	transferAssertError(t, func() error { _, err := ExportPublicEnvelope(nil); return err }(), ClassBadEncoding, "x", 0)
	var typedNil *transferPublicProbe
	transferAssertError(t, func() error { _, err := ExportPublicEnvelope(typedNil); return err }(), ClassBadEncoding, "x", 0)
	transferAssertError(t, func() error { _, err := ExportPublicEnvelope(&transferPublicProbe{}); return err }(), ClassBadEncoding, "x", 0)
	transferAssertError(t, func() error {
		_, err := ExportPublicEnvelope(&transferPublicProbe{pub: make([]byte, PublicKeySize)})
		return err
	}(), ClassInvalidPublicKey, "x", PublicKeySize)

	identity := transferTestIdentity()
	key := &transferPublicProbe{pub: append([]byte(nil), identity.ServerPublicKey...)}
	envelope, err := ExportPublicEnvelope(key)
	if err != nil || !bytes.Equal(envelope, marshalPublicEnvelope(key.pub, identity.ServerKID)) {
		t.Fatalf("valid public export = %s, %v", envelope, err)
	}

	var nilIssuance *UserKeyIssuance
	zeroIssuance := UserKeyIssuance{}
	if nilIssuance.CredentialBytes() != nil || zeroIssuance.CredentialBytes() != nil {
		t.Fatal("empty issuance returned credential bytes")
	}
	issuedValue := UserKeyIssuance{credential: func() []byte { return []byte("private credential bytes") }}
	wantRedacted := "userkey.UserKeyIssuance{kid:}"
	if issuedValue.String() != wantRedacted || issuedValue.GoString() != wantRedacted || fmt.Sprintf("%#v", issuedValue) != wantRedacted {
		t.Fatalf("issuance formatting leaked or changed: %q", fmt.Sprintf("%#v", issuedValue))
	}
	if got, err := json.Marshal(issuedValue); err != nil || string(got) != "{}" {
		t.Fatalf("issuance JSON = %q, %v", got, err)
	}
	first := issuedValue.CredentialBytes()
	first[0] ^= 0xff
	if got := issuedValue.CredentialBytes(); string(got) != "private credential bytes" {
		t.Fatal("CredentialBytes did not return an independently owned copy")
	}

	base := transferTestIdentity()
	invalidCases := []struct {
		name   string
		edit   func(*ExpectedIdentity)
		class  string
		member string
		length int
	}{
		{"url", func(v *ExpectedIdentity) { v.URL = "file:///tmp/key" }, ClassBadURL, "url", len("file:///tmp/key")},
		{"empty-audience", func(v *ExpectedIdentity) { v.Aud = "" }, ClassWrongFieldType, "aud", 0},
		{"invalid-audience-utf8", func(v *ExpectedIdentity) { v.Aud = string([]byte{0xff}) }, ClassWrongFieldType, "aud", 1},
		{"short-server-key", func(v *ExpectedIdentity) { v.ServerPublicKey = v.ServerPublicKey[:31] }, ClassBadEncoding, "server_public_key", 31},
		{"invalid-server-key", func(v *ExpectedIdentity) { v.ServerPublicKey = make([]byte, PublicKeySize) }, ClassInvalidPublicKey, "server_public_key", PublicKeySize},
		{"bad-server-kid-encoding", func(v *ExpectedIdentity) { v.ServerKID = "!" }, ClassBadEncoding, "server_kid", 1},
		{"server-kid-mismatch", func(v *ExpectedIdentity) { v.ServerKID = strings.Repeat("A", 43) }, ClassKIDMismatch, "server_kid", 43},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			got := base
			got.ServerPublicKey = append([]byte(nil), base.ServerPublicKey...)
			tc.edit(&got)
			_, err := validateExpected(got)
			transferAssertError(t, err, tc.class, tc.member, tc.length)
			issued, err := IssueUserKey(got, bytes.NewReader(make([]byte, SeedSize)))
			if issued != nil {
				t.Fatal("IssueUserKey returned a handle for invalid expected identity")
			}
			transferAssertError(t, err, tc.class, tc.member, tc.length)
		})
	}
	if _, err := IssueUserKey(base, nil); err == nil || err.Error() != "userkey: nil credential random source" {
		t.Fatalf("nil random error = %v", err)
	}
	if _, err := IssueUserKey(base, bytes.NewReader(make([]byte, SeedSize-1))); err == nil || err.Error() != "userkey: credential random source failed" {
		t.Fatalf("short random error = %v", err)
	}
	largeAudience := base
	largeAudience.Aud = strings.Repeat("a", maxTransferBytes*2)
	if got, err := IssueUserKey(largeAudience, bytes.NewReader(make([]byte, SeedSize))); got != nil {
		t.Fatal("oversized issuance returned a handle")
	} else {
		transferAssertError(t, err, ClassOversizedEnvelope, "input", len(marshalCredential(credentialDoc{
			aud: largeAudience.Aud, clientKey: string(transferTestPrivate(make([]byte, SeedSize))),
			serverKID: base.ServerKID, serverPub: base.ServerPublicKey, url: base.URL,
		})))
	}
}

func TestTransferEnvelopeParsingRefusalBranches(t *testing.T) {
	goodPublic := transferEnvelopeMap(false)
	goodPrivate := transferEnvelopeMap(true)
	type parseCase struct {
		name   string
		doc    map[string]any
		sink   importSink
		class  string
		member string
		length int
	}
	cases := []parseCase{
		{"missing-type", map[string]any{"v": json.Number("1")}, sinkClientPublic, ClassUnknownType, "type", 0},
		{"type-wrong-type", map[string]any{"v": json.Number("1"), "type": 7}, sinkClientPublic, ClassWrongFieldType, "type", 1},
		{"unknown-type", map[string]any{"v": json.Number("1"), "type": "private-ish"}, sinkClientPublic, ClassUnknownType, "type", len("private-ish")},
		{"known-but-wrong-type", goodPrivate, sinkClientPublic, ClassWrongEnvelopeType, "type", len(privateEnvelopeType)},
		{"server-rejects-private", goodPrivate, sinkServerPublic, ClassPrivateMaterialRejected, "type", len(privateEnvelopeType)},
		{"server-rejects-credential", map[string]any{"v": json.Number("1"), "type": credentialEnvelopeType}, sinkServerPublic, ClassPrivateMaterialRejected, "type", len(credentialEnvelopeType)},
		{"bad-members", map[string]any{"v": json.Number("1"), "type": publicEnvelopeType}, sinkClientPublic, ClassBadMemberSet, "", 0},
		{"wrong-literal-type", func() map[string]any {
			d := goodPublic
			c := make(map[string]any)
			for k, v := range d {
				c[k] = v
			}
			c["kty"] = 9
			return c
		}(), sinkClientPublic, ClassWrongFieldType, "kty", 1},
		{"unknown-curve", func() map[string]any {
			d := make(map[string]any)
			for k, v := range goodPublic {
				d[k] = v
			}
			d["crv"] = "Ed448"
			return d
		}(), sinkClientPublic, ClassUnknownType, "crv", len("Ed448")},
		{"wrong-field-type", func() map[string]any {
			d := make(map[string]any)
			for k, v := range goodPublic {
				d[k] = v
			}
			d["kid"] = 12
			return d
		}(), sinkClientPublic, ClassWrongFieldType, "kid", 2},
		{"bad-public-encoding", func() map[string]any {
			d := make(map[string]any)
			for k, v := range goodPublic {
				d[k] = v
			}
			d["x"] = "!"
			return d
		}(), sinkClientPublic, ClassBadEncoding, "x", 1},
		{"bad-kid-encoding", func() map[string]any {
			d := make(map[string]any)
			for k, v := range goodPublic {
				d[k] = v
			}
			d["kid"] = "!"
			return d
		}(), sinkClientPublic, ClassBadEncoding, "kid", 1},
		{"invalid-public-key", func() map[string]any {
			d := make(map[string]any)
			for k, v := range goodPublic {
				d[k] = v
			}
			pub := make([]byte, PublicKeySize)
			d["x"] = jack.EncodeBase64URL(pub)
			d["kid"] = jack.KeyID(pub)
			return d
		}(), sinkClientPublic, ClassInvalidPublicKey, "x", PublicKeySize},
		{"seed-public-mismatch", func() map[string]any {
			d := make(map[string]any)
			for k, v := range goodPrivate {
				d[k] = v
			}
			other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, SeedSize)).Public().(ed25519.PublicKey)
			d["x"] = jack.EncodeBase64URL(other)
			d["kid"] = jack.KeyID(other)
			return d
		}(), sinkClientPrivate, ClassSeedPubMismatch, "x", PublicKeySize},
		{"kid-mismatch", func() map[string]any {
			d := make(map[string]any)
			for k, v := range goodPublic {
				d[k] = v
			}
			d["kid"] = jack.EncodeBase64URL(bytes.Repeat([]byte{2}, PublicKeySize))
			return d
		}(), sinkClientPublic, ClassKIDMismatch, "kid", 43},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := transferObject(t, tc.doc)
			_, err := parseEnvelope(data, tc.sink)
			observed := tc.length
			if tc.class == ClassBadMemberSet {
				observed = len(data)
			}
			transferAssertError(t, err, tc.class, tc.member, observed)
		})
	}
	canonical := transferTestPrivate([]byte(transferTestSeed))
	if _, err := parseEnvelope(canonical, sinkClientPrivate); err != nil {
		t.Fatalf("canonical private envelope rejected: %v", err)
	}
	if _, err := parseEnvelope(marshalPublicEnvelope(ed25519.NewKeyFromSeed([]byte(transferTestSeed)).Public().(ed25519.PublicKey), jack.KeyID(ed25519.NewKeyFromSeed([]byte(transferTestSeed)).Public().(ed25519.PublicKey))), sinkServerPublic); err != nil {
		t.Fatalf("canonical server public envelope rejected: %v", err)
	}
	spaced := append(append([]byte(nil), canonical...), ' ')
	transferAssertError(t, func() error { _, err := parseEnvelope(spaced, sinkClientPrivate); return err }(), ClassNonCanonicalBytes, "", len(spaced))
}

func TestTransferJSONScalarAndVersionParsing(t *testing.T) {
	for _, tc := range []struct {
		name  string
		data  []byte
		class string
	}{
		{"oversized", bytes.Repeat([]byte{' '}, maxTransferBytes+1), ClassOversizedEnvelope},
		{"invalid-utf8", []byte{'"', 0xff, '"'}, ClassMalformedJSON},
		{"malformed-json", []byte(`{"x":`), ClassMalformedJSON},
		{"trailing-json", []byte(`{} {}`), ClassMalformedJSON},
		{"array-root", []byte(`[]`), ClassWrongRootType},
		{"null-root", []byte(`null`), ClassWrongRootType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseObject(tc.data)
			member := "input"
			if tc.class == ClassWrongRootType {
				member = ""
			}
			transferAssertError(t, err, tc.class, member, len(tc.data))
		})
	}
	for _, tc := range []struct {
		name string
		data string
		want bool
	}{
		{"empty", ``, true},
		{"ordinary", `{"x":"a"}`, true},
		{"escaped-quote", `{"x":"\""}`, true},
		{"dangling-backslash", `"abc\`, true},
		{"short-unicode-escape", `"\u12`, true},
		{"invalid-unicode-hex", `"\u12xz"`, true},
		{"high-without-low", `"\ud800"`, false},
		{"high-followed-by-text", `"\ud800x"`, false},
		{"high-followed-by-high", `"\ud800\ud801"`, false},
		{"low-after-high-invalid", `"\ud800\u0041"`, false},
		{"lone-low", `"\udc00"`, false},
		{"valid-surrogate-pair", `"\ud83d\ude00"`, true},
		{"ordinary-unicode-escape", `"\u20ac"`, true},
	} {
		if got := validRawStringScalars([]byte(tc.data)); got != tc.want {
			t.Errorf("validRawStringScalars(%q) = %t, want %t", tc.data, got, tc.want)
		}
	}
	for _, tc := range []struct {
		input string
		want  uint16
		ok    bool
	}{
		{"0000", 0, true}, {"1234", 0x1234, true}, {"abcd", 0xabcd, true}, {"ABCD", 0xabcd, true}, {"12x4", 0, false}, {"123", 0, false},
	} {
		got, ok := hexUnit([]byte(tc.input))
		if got != tc.want || ok != tc.ok {
			t.Errorf("hexUnit(%q) = (%04x,%t), want (%04x,%t)", tc.input, got, ok, tc.want, tc.ok)
		}
	}
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"", false}, {"-1", false}, {"1", true}, {"10e-1", true}, {"1.0", true}, {"100e-2", true}, {"0.1e1", true},
		{"0", false}, {"000", false}, {"2", false}, {"1e999999", false}, {"1e+9999", false}, {"1e-9999", false}, {"0.10e1", true},
	} {
		if got := numberEqualsOne(tc.value); got != tc.want {
			t.Errorf("numberEqualsOne(%q) = %t, want %t", tc.value, got, tc.want)
		}
	}
	for _, tc := range []struct {
		name  string
		value any
		want  string
	}{
		{"missing", nil, ClassUnknownVersion},
		{"wrong-type", "1", ClassUnknownVersion},
		{"wrong-number", json.Number("2"), ClassUnknownVersion},
		{"non-one-number", json.Number("1.1"), ClassUnknownVersion},
	} {
		err := checkVersion(map[string]any{"v": tc.value})
		transferAssertError(t, err, tc.want, "v", valueLength(tc.value))
	}
	if err := checkVersion(map[string]any{"v": json.Number("10e-1")}); err != nil {
		t.Fatalf("mathematically-one version rejected: %v", err)
	}
	if !exactMembers(map[string]any{"x": nil, "y": nil}, []string{"x", "y"}) || exactMembers(map[string]any{"x": nil, "y": nil}, []string{"x", "z"}) || exactMembers(map[string]any{"x": nil}, []string{"x", "y"}) {
		t.Fatal("exactMembers did not enforce the exact key set")
	}
	if got := quoteJCS("\b\t\n\f\r\x01\"\\<>&é"); got != `"\b\t\n\f\r\u0001\"\\<>&é"` {
		t.Fatalf("quoteJCS control and Unicode encoding = %q", got)
	}
}

func TestTransferCredentialAndExpectedIdentityBranches(t *testing.T) {
	expected := transferTestIdentity()
	clientKey := string(transferTestPrivate(bytes.Repeat([]byte{3}, SeedSize)))
	goodDoc := credentialDoc{aud: expected.Aud, clientKey: clientKey, serverKID: expected.ServerKID, serverPub: expected.ServerPublicKey, url: expected.URL}
	good := marshalCredential(goodDoc)
	if _, err := parseCredential(good); err != nil {
		t.Fatalf("canonical credential rejected: %v", err)
	}
	if err := ValidateCredential(good, expected); err != nil {
		t.Fatalf("ValidateCredential rejected trusted identity: %v", err)
	}
	imported, err := ImportCredential(good, expected)
	if err != nil || imported == nil || imported.Signer.KID() != jack.KeyID(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, SeedSize)).Public().(ed25519.PublicKey)) {
		t.Fatalf("ImportCredential result = %#v, %v", imported, err)
	}

	goodMap := transferCredentialMap(expected, clientKey)
	mutated := func(edit func(map[string]any)) map[string]any {
		out := make(map[string]any, len(goodMap))
		for k, v := range goodMap {
			out[k] = v
		}
		edit(out)
		return out
	}
	cases := []struct {
		name   string
		doc    map[string]any
		class  string
		member string
		length int
	}{
		{"missing-type", map[string]any{"v": json.Number("1")}, ClassUnknownType, "type", 0},
		{"type-wrong-type", map[string]any{"v": json.Number("1"), "type": false}, ClassWrongFieldType, "type", 5},
		{"unknown-type", map[string]any{"v": json.Number("1"), "type": "unknown"}, ClassUnknownType, "type", 7},
		{"wrong-known-type", mutated(func(d map[string]any) { d["type"] = privateEnvelopeType }), ClassWrongEnvelopeType, "type", len(privateEnvelopeType)},
		{"bad-members", map[string]any{"v": json.Number("1"), "type": credentialEnvelopeType}, ClassBadMemberSet, "", 0},
		{"wrong-audience-type", mutated(func(d map[string]any) { d["aud"] = 4 }), ClassWrongFieldType, "aud", 1},
		{"wrong-client-key-type", mutated(func(d map[string]any) { d["client_key"] = nil }), ClassWrongFieldType, "client_key", 0},
		{"empty-audience", mutated(func(d map[string]any) { d["aud"] = "" }), ClassWrongFieldType, "aud", 0},
		{"bad-url", mutated(func(d map[string]any) { d["url"] = "http://remote.example.test" }), ClassBadURL, "url", len("http://remote.example.test")},
		{"bad-server-kid-encoding", mutated(func(d map[string]any) { d["server_kid"] = "!" }), ClassBadEncoding, "server_kid", 1},
		{"bad-server-public-encoding", mutated(func(d map[string]any) { d["server_public_key"] = "!" }), ClassBadEncoding, "server_public_key", 1},
		{"invalid-server-public-key", mutated(func(d map[string]any) {
			d["server_public_key"] = jack.EncodeBase64URL(make([]byte, PublicKeySize))
			d["server_kid"] = jack.KeyID(make([]byte, PublicKeySize))
		}), ClassInvalidPublicKey, "server_public_key", PublicKeySize},
		{"server-kid-mismatch", mutated(func(d map[string]any) { d["server_kid"] = jack.EncodeBase64URL(bytes.Repeat([]byte{4}, PublicKeySize)) }), ClassKIDMismatch, "server_kid", 43},
		{"inner-public-envelope", mutated(func(d map[string]any) {
			d["client_key"] = string(marshalPublicEnvelope(expected.ServerPublicKey, expected.ServerKID))
		}), ClassWrongEnvelopeType, "type", len(publicEnvelopeType)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := transferObject(t, tc.doc)
			_, err := parseCredential(data)
			observed := tc.length
			if tc.class == ClassBadMemberSet {
				observed = len(data)
			}
			transferAssertError(t, err, tc.class, tc.member, observed)
		})
	}
	transferAssertError(t, func() error { _, err := parseCredential(append(append([]byte(nil), good...), ' ')); return err }(), ClassNonCanonicalBytes, "", len(good)+1)

	for _, tc := range []struct {
		name string
		edit func(*ExpectedIdentity)
	}{
		{"url", func(v *ExpectedIdentity) { v.URL = "https://other.example.test" }},
		{"audience", func(v *ExpectedIdentity) { v.Aud = "different" }},
		{"server-key", func(v *ExpectedIdentity) {
			v.ServerPublicKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, SeedSize)).Public().(ed25519.PublicKey)
			v.ServerKID = jack.KeyID(v.ServerPublicKey)
		}},
		{"invalid-expected", func(v *ExpectedIdentity) { v.ServerKID = "bad" }},
	} {
		t.Run("trust-mismatch/"+tc.name, func(t *testing.T) {
			mismatch := expected
			mismatch.ServerPublicKey = append([]byte(nil), expected.ServerPublicKey...)
			tc.edit(&mismatch)
			transferAssertError(t, func() error { _, err := ImportCredential(good, mismatch); return err }(), ClassServerIdentityMismatch, "expected", len(mismatch.ServerPublicKey))
			transferAssertError(t, ValidateCredential(good, mismatch), ClassServerIdentityMismatch, "expected", len(mismatch.ServerPublicKey))
		})
	}
}

func TestTransferURLPolicyAndUtilityBranches(t *testing.T) {
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"https://example.test", true}, {"HTTPS://example.test:443/path?q=1#f", true},
		{"http://127.0.0.1", true}, {"http://127.9.8.7:65535/path", true}, {"http://[::1]", true}, {"http://[::A]:80", false},
		{"", false}, {"ftp://example.test", false}, {"https://", false}, {"https://user@example.test", false},
		{"https://example.test%2f@evil.test", false}, {"https://bad_host^", false}, {"https://[::1]x", false},
		{"http://localhost", false}, {"http://127.00.0.1", false}, {"http://127.0.0.256", false},
		{"http://[::1]:0", false}, {"https://example.test:65536", false}, {"https://example.test:abc", false},
		{"https://example.test\\path", false}, {"https://example.test\n", false}, {"https://é.example", false},
	} {
		if got := checkURLPolicy(tc.url); got != tc.want {
			t.Errorf("checkURLPolicy(%q) = %t, want %t", tc.url, got, tc.want)
		}
	}
	for _, tc := range []struct {
		authority string
		host      string
		bracketed bool
		bad       bool
	}{
		{"host", "host", false, false}, {"host:443", "host", false, false}, {"[::1]", "::1", true, false}, {"[ABCD::1]:80", "abcd::1", true, false},
		{"[::1", "", false, true}, {"[a[b]", "", false, true}, {"[::1]]", "", false, true}, {"[]", "", false, true},
		{"[::1]x", "", false, true}, {"[g::1]", "", false, true}, {"::1", "", false, true}, {"a:b:c", "", false, true},
		{":80", "", false, true}, {"a[", "", false, true}, {"a]", "", false, true}, {"a^", "", false, true},
		{"a:", "", false, true}, {"a:123456", "", false, true}, {"a:1x", "", false, true}, {"a:0", "", false, true},
		{"a:65536", "", false, true}, {"a:65535", "a", false, false}, {"[::1]:1", "::1", true, false},
	} {
		host, bracketed, err := policySplitHostPort(tc.authority)
		if tc.bad {
			if !errors.Is(err, errPolicyMalformedDestination) {
				t.Errorf("policySplitHostPort(%q) error = %v, want malformed destination", tc.authority, err)
			}
		} else if err != nil || host != tc.host || bracketed != tc.bracketed {
			t.Errorf("policySplitHostPort(%q) = (%q,%t,%v), want (%q,%t,nil)", tc.authority, host, bracketed, err, tc.host, tc.bracketed)
		}
	}
	for _, tc := range []struct {
		value string
		want  string
	}{
		{"", ""}, {"no-upper", "no-upper"}, {"AbC-1", "abc-1"},
	} {
		if got := policyAsciiLower(tc.value); got != tc.want {
			t.Errorf("policyAsciiLower(%q) = %q, want %q", tc.value, got, tc.want)
		}
	}
	for c, want := range map[byte]bool{'0': true, '9': true, 'a': true, 'f': true, 'A': true, 'F': true, 'g': false, 'G': false, ':': false} {
		if got := policyIsHexDigit(c); got != want {
			t.Errorf("policyIsHexDigit(%q) = %t, want %t", c, got, want)
		}
	}
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true}, {"127.255.255.255", true}, {"127.00.0.1", false}, {"127.0.0", false}, {"127.0.0.1.2", false},
		{"126.0.0.1", false}, {"127.256.0.1", false}, {"127.a.0.1", false}, {"127..0.1", false}, {"127.0000.0.1", false},
	} {
		if got := policyIsLoopbackIPv4(tc.host); got != tc.want {
			t.Errorf("policyIsLoopbackIPv4(%q) = %t, want %t", tc.host, got, tc.want)
		}
	}
	if policyHasPrefixFold("HTTPs://host", "https://") != true || policyHasPrefixFold("http", "https://") || policyHasPrefixFold("https://host", "ftp://") {
		t.Fatal("policyHasPrefixFold mishandled case, short input, or unequal prefix")
	}
}

func TestTransferValueLengthNilDetectionAndSnapshot(t *testing.T) {
	for _, tc := range []struct {
		value any
		want  int
	}{
		{"text", 4}, {json.Number("123"), 3}, {nil, 0}, {map[string]any{"a": 1}, len(`{"a":1}`)},
		{make(chan int), 0},
	} {
		if got := valueLength(tc.value); got != tc.want {
			t.Errorf("valueLength(%T) = %d, want %d", tc.value, got, tc.want)
		}
	}
	if !isNilInterface((*transferPublicProbe)(nil)) || !isNilInterface((chan int)(nil)) || !isNilInterface((func())(nil)) || !isNilInterface((map[string]int)(nil)) || !isNilInterface(([]byte)(nil)) {
		t.Fatal("typed nil interface was not detected")
	}
	if isNilInterface(&transferPublicProbe{}) || isNilInterface(1) {
		t.Fatal("non-nil value was detected as nil")
	}
	input := []byte("snapshot")
	copyOfInput, err := boundedSnapshot(input)
	if err != nil || !bytes.Equal(copyOfInput, input) {
		t.Fatalf("boundedSnapshot = %q, %v", copyOfInput, err)
	}
	copyOfInput[0] = 'X'
	if string(input) != "snapshot" {
		t.Fatal("boundedSnapshot did not own its copy")
	}
	if got, err := boundedSnapshot(bytes.Repeat([]byte{'x'}, maxTransferBytes)); err != nil || len(got) != maxTransferBytes {
		t.Fatalf("boundary boundedSnapshot length = %d, %v", len(got), err)
	}
	transferAssertError(t, func() error { _, err := boundedSnapshot(bytes.Repeat([]byte{'x'}, maxTransferBytes+1)); return err }(), ClassOversizedEnvelope, "input", maxTransferBytes+1)
	if _, err := parseObject(nil); err == nil {
		t.Fatal("parseObject accepted empty input")
	} else {
		transferAssertError(t, err, ClassMalformedJSON, "input", 0)
	}
}
