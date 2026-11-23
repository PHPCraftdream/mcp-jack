package dsig_test

import (
	"crypto/ed25519"
	"strconv"
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/dsig"
)

const urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

const testNow = int64(1767225600)

func testW1Parts() dsig.W1Parts {
	return dsig.W1Parts{
		Aud:            testAudience,
		SubscriptionID: testEndpointID,
		WebhookID:      testWebhookID,
		Timestamp:      testTimestamp,
		CallbackURL:    testCallBack,
		Body:           testBody,
	}
}

// refW1SigningString is the seven-line signing string of R4.2 written out by
// hand, independent of the implementation under test.
func refW1SigningString(p dsig.W1Parts) string {
	return strings.Join([]string{
		"mcp-jack/webhook1/delivery",
		p.Aud,
		p.SubscriptionID,
		p.WebhookID,
		p.Timestamp,
		p.CallbackURL,
		refURL(refSHA256(p.Body)),
	}, "\n")
}

func refW1Header(key ed25519.PrivateKey, kid string, p dsig.W1Parts) string {
	return "w1 kid=" + kid + ",sig=" + refURL(ed25519.Sign(key, []byte(refW1SigningString(p))))
}

func TestW1SigningStringAndHeader(t *testing.T) {
	parts := testW1Parts()
	keyA := testKey(testSeedA)
	asymA := testAsym(testSeedA)

	t.Run("signing string", func(t *testing.T) {
		got := dsig.W1SigningString(parts)
		if got != refW1SigningString(parts) {
			t.Fatalf("W1SigningString = %q, want %q", got, refW1SigningString(parts))
		}
		if strings.HasSuffix(got, "\n") {
			t.Fatal("signing string has a trailing LF")
		}
		lines := strings.Split(got, "\n")
		if len(lines) != 7 {
			t.Fatalf("signing string has %d lines, want 7", len(lines))
		}
		wantLines := []string{
			"mcp-jack/webhook1/delivery",
			testAudience,
			testEndpointID,
			testWebhookID,
			testTimestamp,
			testCallBack,
			refURL(refSHA256(testBody)),
		}
		for i := range wantLines {
			if lines[i] != wantLines[i] {
				t.Fatalf("line %d = %q, want %q", i, lines[i], wantLines[i])
			}
		}
		if len(lines[6]) != 43 {
			t.Fatalf("body hash %q is %d characters, want 43", lines[6], len(lines[6]))
		}
	})

	t.Run("header value", func(t *testing.T) {
		if got, want := dsig.W1HeaderValue("abc", "def"), "w1 kid=abc,sig=def"; got != want {
			t.Fatalf("W1HeaderValue = %q, want %q", got, want)
		}
	})

	t.Run("sign", func(t *testing.T) {
		got, err := dsig.W1Sign(keyA, asymA.KID, parts)
		if err != nil {
			t.Fatalf("W1Sign returned error: %v", err)
		}
		want := refW1Header(keyA, asymA.KID, parts)
		if got != want {
			t.Fatalf("W1Sign = %q, want %q", got, want)
		}
	})

	t.Run("sign rejects bad key", func(t *testing.T) {
		if _, err := dsig.W1Sign(nil, asymA.KID, parts); err == nil {
			t.Fatal("W1Sign accepted a nil key")
		}
		short := ed25519.PrivateKey([]byte{0x01, 0x02})
		if _, err := dsig.W1Sign(short, asymA.KID, parts); err == nil {
			t.Fatal("W1Sign accepted a short key")
		}
	})

	// R4.1 grammar refusals.
	kid := asymA.KID
	good := refW1Header(keyA, kid, parts)
	sig := strings.TrimPrefix(good, "w1 kid="+kid+",sig=")
	if len(kid) != 43 || len(sig) != 86 {
		t.Fatalf("test header has kid %d and sig %d characters, want 43 and 86", len(kid), len(sig))
	}
	bad := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"no space after scheme", "w1kid=" + kid + ",sig=" + sig},
		{"scheme only", "w1"},
		{"scheme and space only", "w1 "},
		{"wrong scheme", "w2 kid=" + kid + ",sig=" + sig},
		{"uppercase scheme", "W1 kid=" + kid + ",sig=" + sig},
		{"leading space", " w1 kid=" + kid + ",sig=" + sig},
		{"no scheme", "kid=" + kid + ",sig=" + sig},
		{"extra param", "w1 kid=" + kid + ",sig=" + sig + ",extra=1"},
		{"duplicate kid", "w1 kid=" + kid + ",kid=" + kid + ",sig=" + sig},
		{"duplicate sig", "w1 sig=" + sig + ",sig=" + sig + ",kid=" + kid},
		{"short kid", "w1 kid=" + kid[:42] + ",sig=" + sig},
		{"long kid", "w1 kid=" + kid + "A,sig=" + sig},
		{"short sig", "w1 kid=" + kid + ",sig=" + sig[:85]},
		{"long sig", "w1 kid=" + kid + ",sig=" + sig + "A"},
		{"foreign character in kid", "w1 kid=" + kid[:42] + "!,sig=" + sig},
		{"standard base64 plus in sig", "w1 kid=" + kid + ",sig=" + sig[:85] + "+"},
		{"padding in sig", "w1 kid=" + kid + ",sig=" + sig[:85] + "="},
		{"padding in kid", "w1 kid=" + kid[:42] + "=,sig=" + sig},
		{"dot in sig", "w1 kid=" + kid + ",sig=" + sig[:85] + "."},
		{"double space", "w1  kid=" + kid + ",sig=" + sig},
		{"space after comma", "w1 kid=" + kid + ", sig=" + sig},
		{"space inside param", "w1 kid=" + kid + ",sig=" + sig[:42] + " " + sig[43:]},
		{"trailing space", "w1 kid=" + kid + ",sig=" + sig + " "},
		{"tab after scheme", "w1\tkid=" + kid + ",sig=" + sig},
		{"newline trailing", "w1 kid=" + kid + ",sig=" + sig + "\n"},
		{"trailing comma", "w1 kid=" + kid + ",sig=" + sig + ","},
		{"empty param", "w1 kid=" + kid + ",,sig=" + sig},
		{"empty name", "w1 kid=" + kid + ",sig=" + sig + ",=x"},
		{"empty kid value", "w1 kid=,sig=" + sig},
		{"empty sig value", "w1 kid=" + kid + ",sig="},
		{"wrong param case", "w1 Kid=" + kid + ",sig=" + sig},
		{"missing sig", "w1 kid=" + kid},
		{"missing kid", "w1 sig=" + sig},
	}
	for _, tc := range bad {
		t.Run("refuse "+tc.name, func(t *testing.T) {
			gotKid, gotSig, ok := dsig.ParseW1Header(tc.value)
			if ok {
				t.Fatalf("ParseW1Header(%q) accepted it as (%q, %q)", tc.value, gotKid, gotSig)
			}
			if gotKid != "" || gotSig != "" {
				t.Fatalf("ParseW1Header(%q) returned (%q, %q) with ok false", tc.value, gotKid, gotSig)
			}
		})
	}

	good2 := []struct {
		name  string
		value string
	}{
		{"kid first", "w1 kid=" + kid + ",sig=" + sig},
		{"sig first", "w1 sig=" + sig + ",kid=" + kid},
	}
	for _, tc := range good2 {
		t.Run("accept "+tc.name, func(t *testing.T) {
			gotKid, gotSig, ok := dsig.ParseW1Header(tc.value)
			if !ok {
				t.Fatalf("ParseW1Header(%q) refused it", tc.value)
			}
			if gotKid != kid || gotSig != sig {
				t.Fatalf("ParseW1Header(%q) = (%q, %q), want (%q, %q)", tc.value, gotKid, gotSig, kid, sig)
			}
		})
	}
}

func TestW1VerifyOrder(t *testing.T) {
	keyA := testKey(testSeedA)
	asymA := testAsym(testSeedA)
	asymB := testAsym(testSeedB)
	asymC := testAsym(testSeedC) // stands in for the MCP server response key
	parts := testW1Parts()
	good := refW1Header(keyA, asymA.KID, parts)
	sig := strings.TrimPrefix(good, "w1 kid="+asymA.KID+",sig=")

	opts := dsig.W1Keys{Keys: []dsig.AsymKey{asymA}, Now: testNow, Window: 30, MCPServerKID: asymC.KID}

	t.Run("success", func(t *testing.T) {
		kid, code := dsig.W1Verify(good, parts, opts)
		if code != "" || kid != asymA.KID {
			t.Fatalf("W1Verify = (%q, %q), want (%q, \"\")", kid, code, asymA.KID)
		}
	})

	t.Run("round trip through W1Sign", func(t *testing.T) {
		header, err := dsig.W1Sign(keyA, asymA.KID, parts)
		if err != nil {
			t.Fatalf("W1Sign returned error: %v", err)
		}
		if kid, code := dsig.W1Verify(header, parts, opts); code != "" || kid != asymA.KID {
			t.Fatalf("W1Verify = (%q, %q), want (%q, \"\")", kid, code, asymA.KID)
		}
	})

	t.Run("malformed header", func(t *testing.T) {
		for _, value := range []string{"", "w1 kid=" + asymA.KID + ",sig=" + sig[:85], "w2 kid=" + asymA.KID + ",sig=" + sig} {
			if _, code := dsig.W1Verify(value, parts, opts); code != "malformed_jack_auth" {
				t.Fatalf("W1Verify(%q) code = %q, want malformed_jack_auth", value, code)
			}
		}
	})

	t.Run("malformed before server key", func(t *testing.T) {
		value := "w1 kid=" + asymC.KID + ",sig=" + sig[:85]
		if _, code := dsig.W1Verify(value, parts, opts); code != "malformed_jack_auth" {
			t.Fatalf("W1Verify code = %q, want malformed_jack_auth", code)
		}
	})

	t.Run("server key kid", func(t *testing.T) {
		// The server kid is not in Keys: the refusal still happens first.
		value := "w1 kid=" + asymC.KID + ",sig=" + sig
		if _, code := dsig.W1Verify(value, parts, opts); code != "webhook_key_is_server_key" {
			t.Fatalf("W1Verify code = %q, want webhook_key_is_server_key", code)
		}
		// An empty MCPServerKID leaves the bound unset.
		withoutServer := dsig.W1Keys{Keys: []dsig.AsymKey{asymC}, Now: testNow, Window: 30}
		byServer := refW1Header(testKey(testSeedC), asymC.KID, parts)
		if kid, code := dsig.W1Verify(byServer, parts, withoutServer); code != "" || kid != asymC.KID {
			t.Fatalf("W1Verify = (%q, %q), want (%q, \"\")", kid, code, asymC.KID)
		}
	})

	t.Run("server key before unknown key", func(t *testing.T) {
		empty := dsig.W1Keys{Now: testNow, Window: 30, MCPServerKID: asymC.KID}
		value := "w1 kid=" + asymC.KID + ",sig=" + sig
		if _, code := dsig.W1Verify(value, parts, empty); code != "webhook_key_is_server_key" {
			t.Fatalf("W1Verify code = %q, want webhook_key_is_server_key", code)
		}
	})

	t.Run("unknown kid", func(t *testing.T) {
		stale := parts
		stale.Timestamp = strconv.FormatInt(testNow-1000, 10)
		value := refW1Header(testKey(testSeedB), asymB.KID, stale)
		if _, code := dsig.W1Verify(value, stale, opts); code != "unknown_webhook_key" {
			t.Fatalf("W1Verify code = %q, want unknown_webhook_key", code)
		}
	})

	t.Run("window past boundary", func(t *testing.T) {
		atBoundary := parts
		atBoundary.Timestamp = strconv.FormatInt(testNow-30, 10)
		if _, code := dsig.W1Verify(refW1Header(keyA, asymA.KID, atBoundary), atBoundary, opts); code != "" {
			t.Fatalf("W1Verify at the past boundary code = %q, want none", code)
		}
		beyond := parts
		beyond.Timestamp = strconv.FormatInt(testNow-31, 10)
		if _, code := dsig.W1Verify(refW1Header(keyA, asymA.KID, beyond), beyond, opts); code != "jack_timestamp_out_of_window" {
			t.Fatalf("W1Verify one second past the window code = %q, want jack_timestamp_out_of_window", code)
		}
	})

	t.Run("window future boundary", func(t *testing.T) {
		atBoundary := parts
		atBoundary.Timestamp = strconv.FormatInt(testNow+30, 10)
		if _, code := dsig.W1Verify(refW1Header(keyA, asymA.KID, atBoundary), atBoundary, opts); code != "" {
			t.Fatalf("W1Verify at the future boundary code = %q, want none", code)
		}
		beyond := parts
		beyond.Timestamp = strconv.FormatInt(testNow+31, 10)
		if _, code := dsig.W1Verify(refW1Header(keyA, asymA.KID, beyond), beyond, opts); code != "jack_timestamp_out_of_window" {
			t.Fatalf("W1Verify one second past the future window code = %q, want jack_timestamp_out_of_window", code)
		}
	})

	t.Run("unparsable timestamp", func(t *testing.T) {
		broken := parts
		broken.Timestamp = "not-a-timestamp"
		value := refW1Header(keyA, asymA.KID, broken)
		if _, code := dsig.W1Verify(value, broken, opts); code != "jack_timestamp_out_of_window" {
			t.Fatalf("W1Verify code = %q, want jack_timestamp_out_of_window", code)
		}
	})

	t.Run("window before signature", func(t *testing.T) {
		stale := parts
		stale.Timestamp = strconv.FormatInt(testNow-31, 10)
		value := refW1Header(testKey(testSeedB), asymA.KID, stale)
		if _, code := dsig.W1Verify(value, stale, opts); code != "jack_timestamp_out_of_window" {
			t.Fatalf("W1Verify code = %q, want jack_timestamp_out_of_window", code)
		}
	})

	t.Run("bad signature", func(t *testing.T) {
		value := refW1Header(testKey(testSeedB), asymA.KID, parts)
		if _, code := dsig.W1Verify(value, parts, opts); code != "bad_jack_signature" {
			t.Fatalf("W1Verify code = %q, want bad_jack_signature", code)
		}
	})

	t.Run("bad signature for another body", func(t *testing.T) {
		other := parts
		other.Body = append(append([]byte(nil), testBody...), ' ')
		if _, code := dsig.W1Verify(good, other, opts); code != "bad_jack_signature" {
			t.Fatalf("W1Verify code = %q, want bad_jack_signature", code)
		}
	})

	t.Run("non-canonical sig", func(t *testing.T) {
		// The final character of an 86-character signature carries four unused
		// bits in canonical unpadded base64url (R4.1, R7.3).
		index := strings.IndexByte(urlAlphabet, sig[85])
		if index < 0 || index%16 != 0 {
			t.Fatalf("test signature %q is not canonical", sig)
		}
		broken := "w1 kid=" + asymA.KID + ",sig=" + sig[:85] + string(urlAlphabet[index+1])
		if _, code := dsig.W1Verify(broken, parts, opts); code != "bad_jack_signature" {
			t.Fatalf("W1Verify code = %q, want bad_jack_signature", code)
		}
	})

	t.Run("unusable public key", func(t *testing.T) {
		short := dsig.W1Keys{Keys: []dsig.AsymKey{{KID: asymA.KID, Raw: asymA.Raw[:31]}}, Now: testNow, Window: 30}
		if _, code := dsig.W1Verify(good, parts, short); code != "bad_jack_signature" {
			t.Fatalf("W1Verify code = %q, want bad_jack_signature", code)
		}
	})

	t.Run("no keys", func(t *testing.T) {
		empty := dsig.W1Keys{Now: testNow, Window: 30}
		if _, code := dsig.W1Verify(good, parts, empty); code != "unknown_webhook_key" {
			t.Fatalf("W1Verify code = %q, want unknown_webhook_key", code)
		}
	})
}
