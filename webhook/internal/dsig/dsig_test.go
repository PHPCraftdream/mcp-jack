package dsig_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/dsig"
)

// Inputs of this test package only; no vector-file secret or key is reused.
const (
	testWebhookID  = "msg_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f"
	testTimestamp  = "1767225600"
	testEndpointID = "sub_a3f1c8e2b0d49f7e"
	testAudience   = "https://svc.example.test"
	testCallBack   = "https://hooks.example.test/hooks/alice"
)

var (
	testSecretA = []byte("0123456789abcdef0123456789abcdef")
	testSecretB = []byte("fedcba9876543210fedcba9876543210")
	testBody    = []byte(`{"eventId":"evt_1","name":"incident.created","data":{"severity":"P1"}}`)

	testSeedA = bytes.Repeat([]byte{0x11}, ed25519.SeedSize)
	testSeedB = bytes.Repeat([]byte{0x22}, ed25519.SeedSize)
	testSeedC = bytes.Repeat([]byte{0x33}, ed25519.SeedSize)
)

// refV1Content is the content of R2.2 written out by hand.
func refV1Content(webhookID, timestamp string, body []byte) []byte {
	out := []byte(webhookID + "." + timestamp + ".")
	return append(out, body...)
}

// refV2Content is the pre-hash content of R2.6 written out by hand.
func refV2Content(endpointID, webhookID, timestamp string, body []byte) []byte {
	out := []byte(endpointID + "." + webhookID + "." + timestamp + ".")
	return append(out, body...)
}

func refHMAC(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func refSHA256(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func refStd(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func refURL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func testKey(seed []byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(seed) }

func testKID(pub ed25519.PublicKey) string { return refURL(refSHA256(pub)) }

func testAsym(seed []byte) dsig.AsymKey {
	priv := testKey(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return dsig.AsymKey{KID: testKID(pub), Raw: append([]byte(nil), pub...)}
}

func refV1Entry(secret []byte, webhookID, timestamp string, body []byte) string {
	return "v1," + refStd(refHMAC(secret, refV1Content(webhookID, timestamp, body)))
}

func refV1aEntry(key ed25519.PrivateKey, webhookID, timestamp string, body []byte) string {
	return "v1a," + refStd(ed25519.Sign(key, refV1Content(webhookID, timestamp, body)))
}

func refV2aEntry(key ed25519.PrivateKey, endpointID, webhookID, timestamp string, body []byte) string {
	return "v2a," + refStd(ed25519.Sign(key, refSHA256(refV2Content(endpointID, webhookID, timestamp, body))))
}

func TestDSigV1Kat(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"ascii", testBody},
		{"trailing newline", append(append([]byte(nil), testBody...), '\n')},
		{"unicode", []byte(`{"name":"café — 世界"}`)},
		{"empty body", []byte{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantContent := refV1Content(testWebhookID, testTimestamp, tc.body)
			content := dsig.V1Content(testWebhookID, testTimestamp, tc.body)
			if !bytes.Equal(content, wantContent) {
				t.Fatalf("V1Content = %q, want %q", content, wantContent)
			}
			want := "v1," + refStd(refHMAC(testSecretA, wantContent))
			if got := dsig.V1Sign(testSecretA, testWebhookID, testTimestamp, tc.body); got != want {
				t.Fatalf("V1Sign = %q, want %q", got, want)
			}
			// R2.2: a 32-byte MAC always renders as 44 characters ending '='.
			value := strings.TrimPrefix(want, "v1,")
			if len(value) != 44 || !strings.HasSuffix(value, "=") {
				t.Fatalf("v1 value %q is not 44 characters ending '='", value)
			}
		})
	}
}

func TestDSigV1ContentUsesRawBodyOnly(t *testing.T) {
	original := append([]byte(nil), testBody...)
	content := dsig.V1Content(testWebhookID, testTimestamp, testBody)
	content[len(content)-1] ^= 0xff
	if !bytes.Equal(testBody, original) {
		t.Fatal("V1Content aliases the caller's body slice")
	}
	// R2.3: identical body bytes give identical content, whatever they mean.
	if !bytes.Equal(
		dsig.V1Content(testWebhookID, testTimestamp, []byte("{}")),
		dsig.V1Content(testWebhookID, testTimestamp, []byte("{}")),
	) {
		t.Fatal("V1Content is not deterministic")
	}
}

func TestDSigV1aV2aKat(t *testing.T) {
	key := testKey(testSeedA)
	pub := key.Public().(ed25519.PublicKey)
	wantContent := refV1Content(testWebhookID, testTimestamp, testBody)

	// R2.5: v1a content is the same raw content as v1.
	if got, want := dsig.V1aContent(testWebhookID, testTimestamp, testBody), wantContent; !bytes.Equal(got, want) {
		t.Fatalf("V1aContent = %q, want %q", got, want)
	}
	if !bytes.Equal(dsig.V1aContent(testWebhookID, testTimestamp, testBody), dsig.V1Content(testWebhookID, testTimestamp, testBody)) {
		t.Fatal("V1aContent differs from V1Content")
	}

	wantV1a := "v1a," + refStd(ed25519.Sign(key, wantContent))
	gotV1a, err := dsig.V1aSign(key, testWebhookID, testTimestamp, testBody)
	if err != nil {
		t.Fatalf("V1aSign returned error: %v", err)
	}
	if gotV1a != wantV1a {
		t.Fatalf("V1aSign = %q, want %q", gotV1a, wantV1a)
	}
	assertEntryVerifies(t, gotV1a, "v1a,", pub, wantContent)

	// R2.6: v2a signs the SHA-256 of endpoint id, id, timestamp and body.
	wantDigest := refSHA256(refV2Content(testEndpointID, testWebhookID, testTimestamp, testBody))
	if got := dsig.V2aDigest(testEndpointID, testWebhookID, testTimestamp, testBody); !bytes.Equal(got, wantDigest) {
		t.Fatalf("V2aDigest = %x, want %x", got, wantDigest)
	}
	if got := len(dsig.V2aDigest(testEndpointID, testWebhookID, testTimestamp, testBody)); got != sha256.Size {
		t.Fatalf("V2aDigest length = %d, want %d", got, sha256.Size)
	}
	wantV2a := "v2a," + refStd(ed25519.Sign(key, wantDigest))
	gotV2a, err := dsig.V2aSign(key, testEndpointID, testWebhookID, testTimestamp, testBody)
	if err != nil {
		t.Fatalf("V2aSign returned error: %v", err)
	}
	if gotV2a != wantV2a {
		t.Fatalf("V2aSign = %q, want %q", gotV2a, wantV2a)
	}
	assertEntryVerifies(t, gotV2a, "v2a,", pub, wantDigest)

	// A different endpoint id must change the v2a digest but not the v1a one.
	if bytes.Equal(
		dsig.V2aDigest("sub_0123456789abcdef", testWebhookID, testTimestamp, testBody),
		wantDigest,
	) {
		t.Fatal("V2aDigest does not cover the endpoint id")
	}
}

func assertEntryVerifies(t *testing.T, entry, scheme string, pub ed25519.PublicKey, message []byte) {
	t.Helper()
	if !strings.HasPrefix(entry, scheme) {
		t.Fatalf("entry %q does not start with %q", entry, scheme)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(entry, scheme))
	if err != nil {
		t.Fatalf("entry %q value is not standard base64: %v", entry, err)
	}
	if !ed25519.Verify(pub, message, sig) {
		t.Fatalf("entry %q does not verify", entry)
	}
}

func TestDSigSignRejectsBadKey(t *testing.T) {
	if _, err := dsig.V1aSign(nil, testWebhookID, testTimestamp, testBody); err == nil {
		t.Fatal("V1aSign accepted a nil key")
	}
	short := ed25519.PrivateKey(bytes.Repeat([]byte{0x01}, ed25519.PrivateKeySize-1))
	if _, err := dsig.V1aSign(short, testWebhookID, testTimestamp, testBody); err == nil {
		t.Fatal("V1aSign accepted a short key")
	}
	if _, err := dsig.V2aSign(nil, testEndpointID, testWebhookID, testTimestamp, testBody); err == nil {
		t.Fatal("V2aSign accepted a nil key")
	}
	if _, err := dsig.V2aSign(short, testEndpointID, testWebhookID, testTimestamp, testBody); err == nil {
		t.Fatal("V2aSign accepted a short key")
	}
}

func TestDSigHeaderGrammar(t *testing.T) {
	cases := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"leading space", " v1,AAAA"},
		{"trailing space", "v1,AAAA "},
		{"double space", "v1,AAAA  v1,BBBB"},
		{"no comma", "v1AAAA"},
		{"empty scheme", ",AAAA"},
		{"empty value", "v1,"},
		{"comma inside value", "v1,AAAA,BBBB"},
		{"non-alphanumeric scheme", "v1!,AAAA"},
		{"hyphen in scheme", "v1-a,AAAA"},
		{"underscore in scheme", "v1_a,AAAA"},
		{"space inside an entry", "v1 ,AAAA"},
		{"tab in value", "v1,AA\tAA"},
		{"tab leading", "\tv1,AAAA"},
		{"newline leading", "\nv1,AAAA"},
		{"carriage return trailing", "v1,AAAA\r"},
		{"non-breaking space trailing", "v1,AAAA\u00a0"},
		{"ideographic space leading", "\u3000v1,AAAA"},
		{"second entry without scheme", "v1,AAAA ,BBBB"},
		{"scheme only", "v1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries, code := dsig.ParseHeader(tc.value)
			if code != "malformed_signature_header" {
				t.Fatalf("ParseHeader(%q) code = %q, want malformed_signature_header", tc.value, code)
			}
			if entries != nil {
				t.Fatalf("ParseHeader(%q) returned entries %v alongside a code", tc.value, entries)
			}
		})
	}

	ok := []struct {
		name  string
		value string
		want  []dsig.Entry
	}{
		{
			name:  "single entry",
			value: "v1,AAAA",
			want:  []dsig.Entry{{Scheme: "v1", Value: "AAAA"}},
		},
		{
			name:  "three schemes",
			value: "v1,AAAA v1a,BBBB v2a,CCCC",
			want: []dsig.Entry{
				{Scheme: "v1", Value: "AAAA"},
				{Scheme: "v1a", Value: "BBBB"},
				{Scheme: "v2a", Value: "CCCC"},
			},
		},
		{
			name:  "unknown scheme is preserved",
			value: "v9,AAAA",
			want:  []dsig.Entry{{Scheme: "v9", Value: "AAAA"}},
		},
		{
			name:  "digits in scheme are allowed by the grammar",
			value: "2v1,AAAA",
			want:  []dsig.Entry{{Scheme: "2v1", Value: "AAAA"}},
		},
		{
			name:  "non-base64 value is not the grammar's business",
			value: "v1,%%%%",
			want:  []dsig.Entry{{Scheme: "v1", Value: "%%%%"}},
		},
	}
	for _, tc := range ok {
		t.Run(tc.name, func(t *testing.T) {
			entries, code := dsig.ParseHeader(tc.value)
			if code != "" {
				t.Fatalf("ParseHeader(%q) code = %q, want none", tc.value, code)
			}
			if len(entries) != len(tc.want) {
				t.Fatalf("ParseHeader(%q) returned %d entries, want %d", tc.value, len(entries), len(tc.want))
			}
			for i := range tc.want {
				if entries[i].Scheme != tc.want[i].Scheme || entries[i].Value != tc.want[i].Value {
					t.Fatalf("entry %d = %+v, want %+v", i, entries[i], tc.want[i])
				}
				if entries[i].Sig != nil {
					t.Fatalf("entry %d has Sig filled before decoding", i)
				}
			}
		})
	}
}

func TestDSigSchemeSet(t *testing.T) {
	cases := []struct {
		name    string
		schemes []string
		want    string
	}{
		{"none", nil, ""},
		{"v1", []string{"v1"}, ""},
		{"v1 and v1a", []string{"v1", "v1a"}, ""},
		{"all three", []string{"v1", "v1a", "v2a"}, ""},
		{"unknown scheme", []string{"v9"}, "unsupported_signature_scheme"},
		{"uppercase v1", []string{"V1"}, "unsupported_signature_scheme"},
		{"uppercase v2a", []string{"v2A"}, "unsupported_signature_scheme"},
		{"one bad among good", []string{"v1", "v2a", "sha256"}, "unsupported_signature_scheme"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries := make([]dsig.Entry, 0, len(tc.schemes))
			for _, scheme := range tc.schemes {
				entries = append(entries, dsig.Entry{Scheme: scheme, Value: "AAAA"})
			}
			if got := dsig.CheckSchemes(entries); got != tc.want {
				t.Fatalf("CheckSchemes(%v) = %q, want %q", tc.schemes, got, tc.want)
			}
		})
	}
}

func TestDSigValueLengths(t *testing.T) {
	b64Of32 := strings.Repeat("A", 43) + "="
	b64Of64 := strings.Repeat("A", 86) + "=="
	// The low two bits of the final data character of a 32-byte value are
	// unused, so 'B' there is decodable but not canonical (R2.1, R3.12).
	nonCanonical32 := strings.Repeat("A", 42) + "B="
	// 63 bytes: 84 characters, no padding.
	b64Of63 := strings.Repeat("A", 84)

	cases := []struct {
		name  string
		entry dsig.Entry
		code  string
		want  int
	}{
		{"v1 32 bytes", dsig.Entry{Scheme: "v1", Value: b64Of32}, "", 32},
		{"v1a 64 bytes", dsig.Entry{Scheme: "v1a", Value: b64Of64}, "", 64},
		{"v2a 64 bytes", dsig.Entry{Scheme: "v2a", Value: b64Of64}, "", 64},
		{"v1 with 64 bytes", dsig.Entry{Scheme: "v1", Value: b64Of64}, "malformed_signature", 0},
		{"v1a with 32 bytes", dsig.Entry{Scheme: "v1a", Value: b64Of32}, "malformed_signature", 0},
		{"v2a with 63 bytes", dsig.Entry{Scheme: "v2a", Value: b64Of63}, "malformed_signature", 0},
		{"empty value", dsig.Entry{Scheme: "v1", Value: ""}, "malformed_signature", 0},
		{"missing padding", dsig.Entry{Scheme: "v1", Value: strings.Repeat("A", 43)}, "malformed_signature", 0},
		{"misplaced padding", dsig.Entry{Scheme: "v1", Value: "AA==" + strings.Repeat("A", 40)}, "malformed_signature", 0},
		{"three pad characters", dsig.Entry{Scheme: "v1", Value: strings.Repeat("A", 41) + "==="}, "malformed_signature", 0},
		{"base64url alphabet", dsig.Entry{Scheme: "v1", Value: strings.Repeat("A", 42) + "_="}, "malformed_signature", 0},
		{"whitespace inside", dsig.Entry{Scheme: "v1", Value: strings.Repeat("A", 21) + " " + strings.Repeat("A", 21) + "="}, "malformed_signature", 0},
		{"non-zero trailing bits", dsig.Entry{Scheme: "v1", Value: nonCanonical32}, "malformed_signature", 0},
		{"unknown scheme uses the 64-byte rule", dsig.Entry{Scheme: "v9", Value: b64Of32}, "malformed_signature", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := []dsig.Entry{tc.entry}
			decoded, code := dsig.DecodeValues(input)
			if code != tc.code {
				t.Fatalf("DecodeValues(%q, %q) code = %q, want %q", tc.entry.Scheme, tc.entry.Value, code, tc.code)
			}
			if code != "" {
				if decoded != nil {
					t.Fatalf("DecodeValues returned entries alongside code %q", code)
				}
				return
			}
			if len(decoded) != 1 {
				t.Fatalf("DecodeValues returned %d entries, want 1", len(decoded))
			}
			if len(decoded[0].Sig) != tc.want {
				t.Fatalf("DecodeValues returned %d sig bytes, want %d", len(decoded[0].Sig), tc.want)
			}
			if decoded[0].Scheme != tc.entry.Scheme || decoded[0].Value != tc.entry.Value {
				t.Fatalf("DecodeValues lost the scheme or value: %+v", decoded[0])
			}
			want, err := base64.StdEncoding.DecodeString(tc.entry.Value)
			if err != nil {
				t.Fatalf("test value %q is not standard base64: %v", tc.entry.Value, err)
			}
			if !bytes.Equal(decoded[0].Sig, want) {
				t.Fatalf("DecodeValues Sig = %x, want %x", decoded[0].Sig, want)
			}
			if input[0].Sig != nil {
				t.Fatal("DecodeValues modified its input")
			}
		})
	}
}

func TestDSigMultiSignatureAcceptance(t *testing.T) {
	key := testKey(testSeedA)
	keyB := testKey(testSeedB)
	goodV1 := refV1Entry(testSecretA, testWebhookID, testTimestamp, testBody)
	badV1 := refV1Entry(testSecretB, testWebhookID, testTimestamp, testBody)
	v1a := refV1aEntry(key, testWebhookID, testTimestamp, testBody)
	v2a := refV2aEntry(key, testEndpointID, testWebhookID, testTimestamp, testBody)
	goodKey := testAsym(testSeedA)
	wrongKey := testAsym(testSeedB)

	verify := func(t *testing.T, header string, secrets [][]byte) (int, bool) {
		t.Helper()
		entries, code := dsig.ParseHeader(header)
		if code != "" {
			t.Fatalf("ParseHeader(%q) code = %q", header, code)
		}
		decoded, code := dsig.DecodeValues(entries)
		if code != "" {
			t.Fatalf("DecodeValues code = %q", code)
		}
		return dsig.VerifyV1(decoded, secrets, testWebhookID, testTimestamp, testBody)
	}

	t.Run("second entry accepts", func(t *testing.T) {
		if index, ok := verify(t, badV1+" "+goodV1, [][]byte{testSecretA}); !ok || index != 0 {
			t.Fatalf("VerifyV1 = (%d, %v), want (0, true)", index, ok)
		}
	})

	t.Run("none accepts", func(t *testing.T) {
		if index, ok := verify(t, badV1, [][]byte{testSecretA}); ok || index != -1 {
			t.Fatalf("VerifyV1 = (%d, %v), want (-1, false)", index, ok)
		}
	})

	t.Run("no v1 entry at all", func(t *testing.T) {
		if index, ok := verify(t, v1a+" "+v2a, [][]byte{testSecretA}); ok || index != -1 {
			t.Fatalf("VerifyV1 = (%d, %v), want (-1, false)", index, ok)
		}
	})

	t.Run("second secret index accepts", func(t *testing.T) {
		if index, ok := verify(t, goodV1, [][]byte{testSecretB, testSecretA}); !ok || index != 1 {
			t.Fatalf("VerifyV1 = (%d, %v), want (1, true)", index, ok)
		}
	})

	t.Run("first secret index wins", func(t *testing.T) {
		if index, ok := verify(t, goodV1, [][]byte{testSecretA, testSecretA}); !ok || index != 0 {
			t.Fatalf("VerifyV1 = (%d, %v), want (0, true)", index, ok)
		}
	})

	t.Run("no secret at all", func(t *testing.T) {
		if index, ok := verify(t, goodV1, nil); ok || index != -1 {
			t.Fatalf("VerifyV1 = (%d, %v), want (-1, false)", index, ok)
		}
	})

	// R2.7: v1a and v2a are ignored by the HMAC path and vice versa.
	t.Run("v1a and v2a ignored without enforcement", func(t *testing.T) {
		entries, _ := dsig.ParseHeader(v1a + " " + v2a)
		decoded, _ := dsig.DecodeValues(entries)
		if _, ok := dsig.VerifyV1(decoded, [][]byte{testSecretA}, testWebhookID, testTimestamp, testBody); ok {
			t.Fatal("VerifyV1 accepted asymmetric entries")
		}
	})

	verifyAsym := func(t *testing.T, header string, keys []dsig.AsymKey) (dsig.AsymKey, string) {
		t.Helper()
		entries, code := dsig.ParseHeader(header)
		if code != "" {
			t.Fatalf("ParseHeader(%q) code = %q", header, code)
		}
		decoded, code := dsig.DecodeValues(entries)
		if code != "" {
			t.Fatalf("DecodeValues code = %q", code)
		}
		return dsig.VerifyAsym(decoded, keys, testEndpointID, testWebhookID, testTimestamp, testBody)
	}

	t.Run("with no asymmetric entry", func(t *testing.T) {
		got, code := verifyAsym(t, goodV1, []dsig.AsymKey{goodKey})
		if code != "bad_server_signature" {
			t.Fatalf("VerifyAsym code = %q, want bad_server_signature", code)
		}
		if got.KID != "" || got.Raw != nil {
			t.Fatalf("VerifyAsym returned a key %+v with a code", got)
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		if _, code := verifyAsym(t, v1a+" "+v2a, []dsig.AsymKey{wrongKey}); code != "bad_server_signature" {
			t.Fatalf("VerifyAsym code = %q, want bad_server_signature", code)
		}
	})

	t.Run("no key", func(t *testing.T) {
		if _, code := verifyAsym(t, v1a+" "+v2a, nil); code != "bad_server_signature" {
			t.Fatalf("VerifyAsym code = %q, want bad_server_signature", code)
		}
	})

	t.Run("every key is tried", func(t *testing.T) {
		got, code := verifyAsym(t, v1a, []dsig.AsymKey{wrongKey, {KID: "short", Raw: []byte{1, 2, 3}}, goodKey})
		if code != "" {
			t.Fatalf("VerifyAsym code = %q, want none", code)
		}
		if got.KID != goodKey.KID || !bytes.Equal(got.Raw, goodKey.Raw) {
			t.Fatalf("VerifyAsym returned %+v, want %+v", got, goodKey)
		}
	})

	t.Run("v2a entry accepts", func(t *testing.T) {
		if got, code := verifyAsym(t, v2a, []dsig.AsymKey{goodKey}); code != "" || got.KID != goodKey.KID {
			t.Fatalf("VerifyAsym = (%+v, %q), want the accepted key and no code", got, code)
		}
	})

	t.Run("second asymmetric entry accepts", func(t *testing.T) {
		other := refV1aEntry(keyB, testWebhookID, testTimestamp, testBody)
		if got, code := verifyAsym(t, other+" "+v1a, []dsig.AsymKey{goodKey}); code != "" || got.KID != goodKey.KID {
			t.Fatalf("VerifyAsym = (%+v, %q), want the accepted key and no code", got, code)
		}
	})

	t.Run("both schemes present, only one verifies", func(t *testing.T) {
		badV2a := refV2aEntry(keyB, testEndpointID, testWebhookID, testTimestamp, testBody)
		if got, code := verifyAsym(t, badV2a+" "+v1a, []dsig.AsymKey{goodKey}); code != "" || got.KID != goodKey.KID {
			t.Fatalf("VerifyAsym = (%+v, %q), want the accepted key and no code", got, code)
		}
	})
}

func TestDSigEmissionOrder(t *testing.T) {
	keyA := testKey(testSeedA)
	keyB := testKey(testSeedB)

	t.Run("hmac only", func(t *testing.T) {
		header, err := dsig.EmissionHeader(dsig.Emission{
			WebhookID:  testWebhookID,
			Timestamp:  testTimestamp,
			EndpointID: testEndpointID,
			Body:       testBody,
			Secrets:    []dsig.EmissionSecret{{Secret: testSecretA, Current: true}},
		})
		if err != nil {
			t.Fatalf("EmissionHeader returned error: %v", err)
		}
		want := refV1Entry(testSecretA, testWebhookID, testTimestamp, testBody)
		if header != want {
			t.Fatalf("header = %q, want %q", header, want)
		}
		if got := len(strings.Split(header, " ")); got != 1 {
			t.Fatalf("header has %d entries, want 1", got)
		}
	})

	t.Run("one key", func(t *testing.T) {
		header, err := dsig.EmissionHeader(dsig.Emission{
			WebhookID:  testWebhookID,
			Timestamp:  testTimestamp,
			EndpointID: testEndpointID,
			Body:       testBody,
			Secrets:    []dsig.EmissionSecret{{Secret: testSecretA, Current: true}},
			Keys:       []dsig.EmissionKey{{Key: keyA, KID: "kid-a", Current: true}},
		})
		if err != nil {
			t.Fatalf("EmissionHeader returned error: %v", err)
		}
		want := strings.Join([]string{
			refV1Entry(testSecretA, testWebhookID, testTimestamp, testBody),
			refV1aEntry(keyA, testWebhookID, testTimestamp, testBody),
			refV2aEntry(keyA, testEndpointID, testWebhookID, testTimestamp, testBody),
		}, " ")
		if header != want {
			t.Fatalf("header = %q, want %q", header, want)
		}
	})

	t.Run("rotating", func(t *testing.T) {
		header, err := dsig.EmissionHeader(dsig.Emission{
			WebhookID:  testWebhookID,
			Timestamp:  testTimestamp,
			EndpointID: testEndpointID,
			Body:       testBody,
			Secrets: []dsig.EmissionSecret{
				{Secret: testSecretA, Current: true},
				{Secret: testSecretB, Current: false},
			},
			Keys: []dsig.EmissionKey{
				{Key: keyA, KID: "kid-a", Current: true},
				{Key: keyB, KID: "kid-b", Current: false},
			},
		})
		if err != nil {
			t.Fatalf("EmissionHeader returned error: %v", err)
		}
		want := strings.Join([]string{
			refV1Entry(testSecretA, testWebhookID, testTimestamp, testBody),
			refV1Entry(testSecretB, testWebhookID, testTimestamp, testBody),
			refV1aEntry(keyA, testWebhookID, testTimestamp, testBody),
			refV2aEntry(keyA, testEndpointID, testWebhookID, testTimestamp, testBody),
			refV1aEntry(keyB, testWebhookID, testTimestamp, testBody),
			refV2aEntry(keyB, testEndpointID, testWebhookID, testTimestamp, testBody),
		}, " ")
		if header != want {
			t.Fatalf("header = %q, want %q", header, want)
		}
		entries := strings.Split(header, " ")
		if len(entries) != 6 {
			t.Fatalf("header has %d entries, want 6", len(entries))
		}
		wantSchemes := []string{"v1", "v1", "v1a", "v2a", "v1a", "v2a"}
		for i, entry := range entries {
			if !strings.HasPrefix(entry, wantSchemes[i]+",") {
				t.Fatalf("entry %d = %q, want scheme %q", i, entry, wantSchemes[i])
			}
		}
	})

	t.Run("key without previous secret", func(t *testing.T) {
		header, err := dsig.EmissionHeader(dsig.Emission{
			WebhookID:  testWebhookID,
			Timestamp:  testTimestamp,
			EndpointID: testEndpointID,
			Body:       testBody,
			Keys:       []dsig.EmissionKey{{Key: keyA, KID: "kid-a", Current: true}},
		})
		if err != nil {
			t.Fatalf("EmissionHeader returned error: %v", err)
		}
		want := strings.Join([]string{
			refV1aEntry(keyA, testWebhookID, testTimestamp, testBody),
			refV2aEntry(keyA, testEndpointID, testWebhookID, testTimestamp, testBody),
		}, " ")
		if header != want {
			t.Fatalf("header = %q, want %q", header, want)
		}
	})

	t.Run("empty emission", func(t *testing.T) {
		header, err := dsig.EmissionHeader(dsig.Emission{WebhookID: testWebhookID, Timestamp: testTimestamp})
		if err != nil {
			t.Fatalf("EmissionHeader returned error: %v", err)
		}
		if header != "" {
			t.Fatalf("header = %q, want the empty string", header)
		}
	})

	t.Run("nil private key is an error", func(t *testing.T) {
		header, err := dsig.EmissionHeader(dsig.Emission{
			WebhookID:  testWebhookID,
			Timestamp:  testTimestamp,
			EndpointID: testEndpointID,
			Body:       testBody,
			Secrets:    []dsig.EmissionSecret{{Secret: testSecretA, Current: true}},
			Keys:       []dsig.EmissionKey{{KID: "kid-a", Current: true}},
		})
		if err == nil {
			t.Fatal("EmissionHeader accepted a nil private key")
		}
		if header != "" {
			t.Fatalf("EmissionHeader returned %q alongside an error", header)
		}
	})
}
