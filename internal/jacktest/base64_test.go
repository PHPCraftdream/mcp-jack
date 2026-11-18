package jack_test

import (
	"bytes"
	"testing"

	"github.com/PHPCraftdream/mcp-jack"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	sizes := []int{16, 32, 64}
	inputs := [][]byte{{}, []byte("x")}
	for _, n := range sizes {
		b := make([]byte, n)
		for i := 0; i < n; i++ {
			b[i] = byte(i*7 + 1)
		}
		inputs = append(inputs, b)
	}

	for _, in := range inputs {
		enc := jack.EncodeBase64URL(in)
		dec, err := jack.DecodeBase64URL(enc)
		if err != nil {
			t.Fatalf("DecodeBase64URL(%q) error: %v", enc, err)
		}
		if !bytes.Equal(dec, in) {
			t.Fatalf("round trip mismatch: got %v, want %v", dec, in)
		}
	}
}

func TestDecodeBase64URLStrict(t *testing.T) {
	failCases := []struct {
		name string
		in   string
	}{
		{"padding1", "ab="},
		{"padding2", "ab=="},
		{"space", "a b"},
		{"newline", "ab\n"},
		{"nonAlphabet", "?"},
		{"lengthMod4One", "a"},
		// "aa_" is alphabet-legal but non-canonical: 'a'=26, '_'=63 gives
		// bits 011010 011010 111111 -> bytes {0x69, 0xAF} plus two non-zero
		// unused bits; the canonical encoding of those bytes is "aa8".
		{"nonCanonicalTrailingBits", "aa_"},
		// "ab": 011010 011011 -> byte 0x69 plus four non-zero unused bits.
		{"nonCanonicalTwoChars", "ab"},
	}
	for _, c := range failCases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if _, err := jack.DecodeBase64URL(c.in); err == nil {
				t.Fatalf("DecodeBase64URL(%q): expected error, got nil", c.in)
			}
		})
	}

	okCases := []struct {
		in   string
		want []byte
	}{
		{"aw", []byte{0x6B}},        // 011010 110000: unused bits are zero
		{"aag", []byte{0x69, 0xA8}}, // 011010 011010 100000
		{"aa8", []byte{0x69, 0xAF}}, // 011010 011010 111100
	}
	for _, c := range okCases {
		c := c
		t.Run("ok_"+c.in, func(t *testing.T) {
			got, err := jack.DecodeBase64URL(c.in)
			if err != nil {
				t.Fatalf("DecodeBase64URL(%q) error: %v", c.in, err)
			}
			if !bytes.Equal(got, c.want) {
				t.Fatalf("DecodeBase64URL(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestDecodeBase64URLFixed(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		size    int
		wantErr bool
	}{
		{"ok", "aw", 1, false},
		{"wrongSize", "aw", 2, true},
		{"zeroSize", "aw", 0, true},
		{"badLength", "a", 1, true},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			got, err := jack.DecodeBase64URLFixed(c.in, c.size)
			if c.wantErr {
				if err == nil {
					t.Fatalf("DecodeBase64URLFixed(%q, %d): expected error, got nil", c.in, c.size)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeBase64URLFixed(%q, %d) error: %v", c.in, c.size, err)
			}
			if len(got) != c.size {
				t.Fatalf("len = %d, want %d", len(got), c.size)
			}
		})
	}
}

func TestKeyIDAndBodyHashDeterminism(t *testing.T) {
	pub := make([]byte, 32)
	for i := 0; i < 32; i++ {
		pub[i] = byte(i*7 + 1)
	}

	id1 := jack.KeyID(pub)
	id2 := jack.KeyID(pub)
	if id1 != id2 {
		t.Fatalf("KeyID not deterministic: %q != %q", id1, id2)
	}
	if len(id1) != 43 {
		t.Fatalf("KeyID length = %d, want 43", len(id1))
	}

	h1 := jack.BodyHash([]byte("payload"))
	h2 := jack.BodyHash([]byte("payload"))
	if h1 != h2 {
		t.Fatalf("BodyHash not deterministic: %q != %q", h1, h2)
	}
	if len(h1) != 43 {
		t.Fatalf("BodyHash length = %d, want 43", len(h1))
	}

	empty1 := jack.KeyID([]byte{})
	empty2 := jack.KeyID([]byte{})
	if empty1 != empty2 {
		t.Fatalf("KeyID(empty) not deterministic: %q != %q", empty1, empty2)
	}
	if len(empty1) != 43 {
		t.Fatalf("KeyID(empty) length = %d, want 43", len(empty1))
	}
}
