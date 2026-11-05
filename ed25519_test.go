package jack_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

func findKeyByName(t *testing.T, name string) spec.TestKey {
	t.Helper()
	keys, err := spec.LoadKeys()
	if err != nil {
		t.Fatalf("LoadKeys: %v", err)
	}
	for _, k := range keys.Keys {
		if k.Name == name {
			return k
		}
	}
	if len(keys.Keys) == 0 {
		t.Fatalf("no keys loaded")
	}
	return keys.Keys[0]
}

func leBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[len(b)-1-i] = v
	}
	return out
}

func paddedLE(s *big.Int, size int) []byte {
	be := s.FillBytes(make([]byte, size))
	return leBytes(be)
}

func TestPublicKeyVectors(t *testing.T) {
	vectors, err := spec.LoadKeyVectors()
	if err != nil {
		t.Fatalf("LoadKeyVectors: %v", err)
	}
	for _, c := range vectors.Cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			pub, err := hex.DecodeString(c.PublicKeyHex)
			if err != nil {
				t.Fatalf("hex decode public key: %v", err)
			}
			verr := jack.ValidatePublicKey(pub)
			if c.Expect == "valid" {
				if verr != nil {
					t.Fatalf("expected valid, got error: %v", verr)
				}
				return
			}
			if verr == nil {
				t.Fatalf("expected rejection, got nil error")
			}
			var jerr *jack.Error
			if !errors.As(verr, &jerr) {
				t.Fatalf("expected *jack.Error, got %T", verr)
			}
			if jerr.HTTPStatus != 400 {
				t.Fatalf("HTTPStatus = %d, want 400", jerr.HTTPStatus)
			}
			if jerr.Code != jack.CodeKeyRejected {
				t.Fatalf("Code = %q, want %q", jerr.Code, jack.CodeKeyRejected)
			}
		})
	}
}

func TestVerifyAcceptsValidSignature(t *testing.T) {
	k := findKeyByName(t, "alice")
	seed, err := hex.DecodeString(k.SeedHex)
	if err != nil {
		t.Fatalf("hex decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	msg := []byte("mcp-jack test message")
	sig := ed25519.Sign(priv, msg)
	if !jack.Verify([]byte(pub), msg, sig) {
		t.Fatalf("Verify returned false for a valid signature")
	}
	if bytes.Equal(msg, []byte("other message")) {
		t.Fatalf("test message collision")
	}
	if jack.Verify([]byte(pub), []byte("other message"), sig) {
		t.Fatalf("Verify returned true for a different message")
	}
}

func TestVerifyRejectsMalleatedSPlusL(t *testing.T) {
	// Spec 01 section 2 requires rejecting S >= L even though the
	// verification equation would hold.
	k := findKeyByName(t, "alice")
	seed, err := hex.DecodeString(k.SeedHex)
	if err != nil {
		t.Fatalf("hex decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	msg := []byte("mcp-jack test message")
	sig := ed25519.Sign(priv, msg)

	s := new(big.Int).SetBytes(leBytes(sig[32:64]))
	s.Add(s, new(big.Int).Lsh(big.NewInt(1), 252))
	low, ok := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	if !ok {
		t.Fatal("failed to parse low constant")
	}
	s.Add(s, low)
	if s.BitLen() > 254 {
		t.Fatalf("S+L does not fit in 32 bytes: BitLen = %d", s.BitLen())
	}
	malleated := append([]byte(nil), sig...)
	copy(malleated[32:64], paddedLE(s, 32))
	if jack.Verify([]byte(pub), msg, malleated) {
		t.Fatalf("Verify accepted a malleated signature with S >= L")
	}
}

func TestVerifyRejectsBadLengths(t *testing.T) {
	k := findKeyByName(t, "alice")
	seed, err := hex.DecodeString(k.SeedHex)
	if err != nil {
		t.Fatalf("hex decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	msg := []byte("mcp-jack test message")
	sig := ed25519.Sign(priv, msg)

	if jack.Verify(pub[:31], msg, sig) {
		t.Fatal("Verify accepted a 31-byte public key")
	}
	if jack.Verify([]byte(pub), msg, sig[:63]) {
		t.Fatal("Verify accepted a 63-byte signature")
	}
	if jack.Verify([]byte(pub), msg, append(append([]byte(nil), sig...), 0)) {
		t.Fatal("Verify accepted a 65-byte signature")
	}
}
