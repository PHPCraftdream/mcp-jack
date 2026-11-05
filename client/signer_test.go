package client

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	spec "github.com/PHPCraftdream/mcp-jack/spec"
)

// TestSignerFromFixtureKeys derives signers from every key in the conformance
// fixture and checks the public key, KID and validity against the fixture data.
func TestSignerFromFixtureKeys(t *testing.T) {
	keys, err := spec.LoadKeys()
	if err != nil {
		t.Fatalf("spec.LoadKeys() error: %v", err)
	}
	for _, k := range keys.Keys {
		t.Run(k.Name, func(t *testing.T) {
			if len(k.SeedHex) != 64 {
				t.Fatalf("key %s: SeedHex must be 64 hex chars, got %d (%q)", k.Name, len(k.SeedHex), k.SeedHex)
			}
			seed, err := hex.DecodeString(k.SeedHex)
			if err != nil {
				t.Fatalf("key %s: hex.DecodeString(%q) error: %v", k.Name, k.SeedHex, err)
			}
			if len(seed) != 32 {
				t.Fatalf("key %s: decoded seed is %d bytes, want 32", k.Name, len(seed))
			}
			signer, err := NewInMemorySigner(seed)
			if err != nil {
				t.Fatalf("key %s: NewInMemorySigner error: %v", k.Name, err)
			}
			pub := signer.PublicKey()
			if len(pub) != 32 {
				t.Fatalf("key %s: PublicKey length = %d, want 32", k.Name, len(pub))
			}
			if got := base64.RawURLEncoding.EncodeToString(pub); got != k.PublicKey {
				t.Errorf("key %s: PublicKey base64url = %q, want %q", k.Name, got, k.PublicKey)
			}
			if got := signer.KID(); got != k.Kid {
				t.Errorf("key %s: KID = %q, want %q", k.Name, got, k.Kid)
			}
			if err := jack.ValidatePublicKey(pub); err != nil {
				t.Errorf("key %s: ValidatePublicKey error: %v", k.Name, err)
			}
		})
	}
}

// TestGenerateSigner checks random signer generation: valid 32-byte key,
// distinct KIDs across calls.
func TestGenerateSigner(t *testing.T) {
	s1, err := GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner error: %v", err)
	}
	pub1 := s1.PublicKey()
	if len(pub1) != 32 {
		t.Fatalf("first signer: PublicKey length = %d, want 32", len(pub1))
	}
	if err := jack.ValidatePublicKey(pub1); err != nil {
		t.Fatalf("first signer: ValidatePublicKey error: %v", err)
	}

	s2, err := GenerateSigner()
	if err != nil {
		t.Fatalf("second GenerateSigner error: %v", err)
	}
	pub2 := s2.PublicKey()
	if len(pub2) != 32 {
		t.Fatalf("second signer: PublicKey length = %d, want 32", len(pub2))
	}
	if err := jack.ValidatePublicKey(pub2); err != nil {
		t.Fatalf("second signer: ValidatePublicKey error: %v", err)
	}
	if s1.KID() == s2.KID() {
		t.Errorf("two generated signers share KID %q; want distinct keys", s1.KID())
	}
}

// TestNewInMemorySignerRejectsBadSeed checks seed-length validation.
func TestNewInMemorySignerRejectsBadSeed(t *testing.T) {
	tests := []struct {
		name string
		seed []byte
	}{
		{"nil seed", nil},
		{"31-byte seed", make([]byte, 31)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := NewInMemorySigner(tc.seed)
			if err == nil {
				t.Fatalf("NewInMemorySigner(%s) succeeded; want error", tc.name)
			}
			if signer != nil {
				t.Errorf("NewInMemorySigner(%s) returned non-nil signer with error", tc.name)
			}
		})
	}
}

// TestInMemorySignerSignRoundTrip checks signing, verification, tamper
// detection and that PublicKey returns a copy.
func TestInMemorySignerSignRoundTrip(t *testing.T) {
	keys, err := spec.LoadKeys()
	if err != nil {
		t.Fatalf("spec.LoadKeys() error: %v", err)
	}
	if len(keys.Keys) == 0 {
		t.Fatalf("spec.LoadKeys() returned no keys")
	}
	k := keys.Keys[0]
	seed, err := hex.DecodeString(k.SeedHex)
	if err != nil {
		t.Fatalf("key %s: hex.DecodeString error: %v", k.Name, err)
	}
	signer, err := NewInMemorySigner(seed)
	if err != nil {
		t.Fatalf("key %s: NewInMemorySigner error: %v", k.Name, err)
	}

	msg := []byte("mcp-jack signer round trip test message")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("key %s: Sign error: %v", k.Name, err)
	}
	if len(sig) != 64 {
		t.Fatalf("key %s: signature length = %d, want 64", k.Name, len(sig))
	}
	if !jack.Verify(signer.PublicKey(), msg, sig) {
		t.Errorf("key %s: jack.Verify failed for the signer's own signature", k.Name)
	}
	tampered := append([]byte(nil), msg...)
	tampered[0] ^= 0x01
	if jack.Verify(signer.PublicKey(), tampered, sig) {
		t.Errorf("key %s: jack.Verify accepted a tampered message", k.Name)
	}

	pub := signer.PublicKey()
	for i := range pub {
		pub[i] = 0xAA
	}
	if !jack.Verify(signer.PublicKey(), msg, sig) {
		t.Errorf("key %s: mutation of the returned PublicKey slice corrupted the signer's key", k.Name)
	}
	if got := signer.KID(); got != k.Kid {
		t.Errorf("key %s: KID after mutating returned PublicKey = %q, want %q", k.Name, got, k.Kid)
	}
	if want := base64.RawURLEncoding.EncodeToString(signer.PublicKey()); want != k.PublicKey {
		t.Errorf("key %s: PublicKey base64url after mutation = %q, want %q", k.Name, want, k.PublicKey)
	}
}
