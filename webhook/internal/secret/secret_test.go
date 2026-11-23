package secret_test

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/secret"
)

func TestParseAcceptedBoundaries(t *testing.T) {
	sizes := []int{24, 25, 32, 63, 64}
	for _, size := range sizes {
		key := bytes.Repeat([]byte{0x5a}, size)
		value := "whsec_" + base64.StdEncoding.EncodeToString(key)
		got, reason := secret.Parse(value)
		if reason != "" {
			t.Fatalf("Parse(%d bytes): reason = %q, want %q", size, reason, "")
		}
		if !bytes.Equal(got, key) {
			t.Fatalf("Parse(%d bytes): key mismatch", size)
		}
	}
}

func TestParseReasons(t *testing.T) {
	key23 := "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 23))
	key65 := "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 65))
	cases := []struct {
		name   string
		value  string
		reason string
	}{
		{"empty", "", "prefix"},
		{"no prefix", "AAAA", "prefix"},
		{"upper prefix", "WHSEC_AAAA", "prefix"},
		{"other prefix", "whsk_AAAA", "prefix"},
		{"prefix without underscore", "whsecAAAA", "prefix"},
		{"prefix only", "whsec_", "length"},
		{"dash in alphabet", "whsec_AAA-", "alphabet"},
		{"underscore in alphabet", "whsec_AAA_", "alphabet"},
		{"space in alphabet", "whsec_AA A", "alphabet"},
		{"dot in alphabet", "whsec_AA.A", "alphabet"},
		{"newline in alphabet", "whsec_AAAA\n", "alphabet"},
		{"length not a multiple of four", "whsec_AAAAA", "padding"},
		{"length five", "whsec_AAAAAAA", "padding"},
		{"misplaced padding", "whsec_A=AA", "padding"},
		{"three pads", "whsec_A===", "padding"},
		{"pads then data", "whsec_AAAA=AAA", "padding"},
		{"non canonical trailing bits one byte", "whsec_AB==", "canonical"},
		{"non canonical trailing bits two bytes", "whsec_AAB=", "canonical"},
		{"non canonical trailing bits padded", "whsec_AAAAAB==", "canonical"},
		{"twenty three bytes", key23, "length"},
		{"sixty five bytes", key65, "length"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			key, reason := secret.Parse(testCase.value)
			if reason != testCase.reason {
				t.Fatalf("Parse(%q): reason = %q, want %q", testCase.value, reason, testCase.reason)
			}
			if key != nil {
				t.Fatalf("Parse(%q): key = %x, want nil", testCase.value, key)
			}
		})
	}
}

func TestEncodeRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x01, 0x02, 0x03}, 11)
	value := secret.Encode(key)
	if value != "whsec_"+base64.StdEncoding.EncodeToString(key) {
		t.Fatalf("Encode: %q is not the prefix plus canonical padded standard base64", value)
	}
	if len(value) < len("whsec_") || value[:len("whsec_")] != "whsec_" {
		t.Fatalf("Encode: %q does not start with whsec_", value)
	}
	got, reason := secret.Parse(value)
	if reason != "" {
		t.Fatalf("Parse(Encode(key)): reason = %q, want %q", reason, "")
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("Parse(Encode(key)): key mismatch")
	}
}

func TestEncodeEmptyIsRejected(t *testing.T) {
	value := secret.Encode(nil)
	if value != "whsec_" {
		t.Fatalf("Encode(nil) = %q, want %q", value, "whsec_")
	}
	if _, reason := secret.Parse(value); reason != "length" {
		t.Fatalf("Parse(Encode(nil)): reason = %q, want %q", reason, "length")
	}
}

func TestEqual(t *testing.T) {
	a := bytes.Repeat([]byte{0x11}, 32)
	b := bytes.Repeat([]byte{0x11}, 32)
	c := bytes.Repeat([]byte{0x11}, 31)
	d := bytes.Repeat([]byte{0x12}, 32)
	if !secret.Equal(a, b) {
		t.Fatal("Equal: identical keys differ")
	}
	if secret.Equal(a, c) {
		t.Fatal("Equal: different lengths compare equal")
	}
	if secret.Equal(a, d) {
		t.Fatal("Equal: different contents compare equal")
	}
	if secret.Equal(nil, []byte{0x00}) {
		t.Fatal("Equal: nil and a one byte key compare equal")
	}
	// Equal checks the length first, so two zero-length keys compare equal.
	if !secret.Equal(nil, []byte{}) {
		t.Fatal("Equal: two empty keys differ")
	}
}

func TestDecodeStd(t *testing.T) {
	accepted := []struct {
		value string
		want  []byte
	}{
		{"", []byte{}},
		{"AA==", []byte{0x00}},
		{"AAA=", []byte{0x00, 0x00}},
		{"AAAA", []byte{0x00, 0x00, 0x00}},
		{"AQID", []byte{0x01, 0x02, 0x03}},
		{"+/+/", []byte{0xfb, 0xff, 0xbf}},
	}
	for _, testCase := range accepted {
		got, ok := secret.DecodeStd(testCase.value)
		if !ok {
			t.Fatalf("DecodeStd(%q): refused", testCase.value)
		}
		if !bytes.Equal(got, testCase.want) {
			t.Fatalf("DecodeStd(%q): got %x, want %x", testCase.value, got, testCase.want)
		}
	}
	refused := []string{
		"AAA",
		"A",
		"AA=A",
		"A===",
		"AAAA=",
		"AAAA====",
		"AB==",
		"AAB=",
		"AA-_",
		"AA AA",
		"AA\nAA",
		"AA==" + "\x00",
		"AA._",
	}
	for _, value := range refused {
		if _, ok := secret.DecodeStd(value); ok {
			t.Fatalf("DecodeStd(%q): accepted, want refused", value)
		}
	}
}

func TestEncodeStd(t *testing.T) {
	if got := secret.EncodeStd([]byte{0x00}); got != "AA==" {
		t.Fatalf("EncodeStd({0x00}) = %q, want %q", got, "AA==")
	}
	if got := secret.EncodeStd(nil); got != "" {
		t.Fatalf("EncodeStd(nil) = %q, want %q", got, "")
	}
	key := bytes.Repeat([]byte{0x5a}, 32)
	if got := secret.EncodeStd(key); got != base64.StdEncoding.EncodeToString(key) {
		t.Fatalf("EncodeStd: not canonical padded standard base64")
	}
}

func TestDecodeURL(t *testing.T) {
	accepted := []struct {
		value string
		want  []byte
	}{
		{"", []byte{}},
		{"AA", []byte{0x00}},
		{"AAA", []byte{0x00, 0x00}},
		{"AAAA", []byte{0x00, 0x00, 0x00}},
		{"AA-_", []byte{0x00, 0x0f, 0xbf}},
		{"AAAAAA", []byte{0x00, 0x00, 0x00, 0x00}},
	}
	for _, testCase := range accepted {
		got, ok := secret.DecodeURL(testCase.value)
		if !ok {
			t.Fatalf("DecodeURL(%q): refused", testCase.value)
		}
		if !bytes.Equal(got, testCase.want) {
			t.Fatalf("DecodeURL(%q): got %x, want %x", testCase.value, got, testCase.want)
		}
	}
	refused := []string{
		"A",
		"AAAAA",
		"AB",
		"AAB",
		"AA==",
		"AAA=",
		"AA+/",
		"AA AA",
		"AA\n",
		"AA._",
	}
	for _, value := range refused {
		if _, ok := secret.DecodeURL(value); ok {
			t.Fatalf("DecodeURL(%q): accepted, want refused", value)
		}
	}
}

func TestEncodeURL(t *testing.T) {
	if got := secret.EncodeURL([]byte{0xfb, 0xff, 0xbf}); got != "-_-_" {
		t.Fatalf("EncodeURL: got %q, want %q", got, "-_-_")
	}
	if got := secret.EncodeURL(nil); got != "" {
		t.Fatalf("EncodeURL(nil) = %q, want %q", got, "")
	}
	key := bytes.Repeat([]byte{0x5a}, 32)
	if got := secret.EncodeURL(key); got != base64.RawURLEncoding.EncodeToString(key) {
		t.Fatalf("EncodeURL: not canonical unpadded base64url")
	}
	if got := secret.EncodeURL(key); len(got) != 43 {
		t.Fatalf("EncodeURL: %d characters, want 43", len(got))
	}
}
