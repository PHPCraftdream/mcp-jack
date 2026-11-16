package jack_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
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

func TestVerifyRejectsSmallOrderRIdentity(t *testing.T) {
	// Spec 01 section 2: a signature whose R is a small-order point is
	// invalid. A key holder can craft one: with R = identity encoding,
	// k = SHA-512(R || A || M) mod L and S = k*a mod L satisfy
	// [S]B = R + [k]A, so the equation holds and only the small-order R
	// rule can reject it. Before that rule, Verify accepted this signature.
	key := findKeyByName(t, "alice")
	seed, err := hex.DecodeString(key.SeedHex)
	if err != nil {
		t.Fatalf("hex decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	msg := []byte("mcp-jack strict small-order R")

	// a = clamp(SHA-512(seed)[:32]) (RFC 8032 section 5.1.5), little-endian.
	seedHash := sha512.Sum512(seed)
	aBytes := seedHash[:32]
	aBytes[0] &= 248
	aBytes[31] &= 63
	aBytes[31] |= 64
	a := new(big.Int).SetBytes(leBytes(aBytes))

	sig := make([]byte, 64)
	sig[0] = 1 // R = identity encoding: y = 1, x = 0, clear sign bit
	h := sha512.New()
	h.Write(sig[:32])
	h.Write(pub)
	h.Write(msg)
	kHash := h.Sum(nil)

	l := new(big.Int).Lsh(big.NewInt(1), 252)
	low, ok := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	if !ok {
		t.Fatal("failed to parse low constant")
	}
	l.Add(l, low)
	k := new(big.Int).Mod(new(big.Int).SetBytes(leBytes(kHash)), l)
	s := new(big.Int).Mul(k, a)
	s.Mod(s, l)
	if s.Cmp(l) >= 0 {
		t.Fatalf("S is not below L: BitLen = %d", s.BitLen())
	}
	copy(sig[32:], paddedLE(s, 32))

	// The verification equation holds: crypto/ed25519 accepts the same
	// bytes, so only the SDK's small-order R rule can reject them.
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("crypto/ed25519 rejected the crafted signature; the recipe is stale")
	}
	if jack.Verify([]byte(pub), msg, sig) {
		t.Fatal("Verify accepted a signature whose R is a small-order point")
	}

	// An ordinary signature over the same message still verifies.
	ordinary := ed25519.Sign(priv, msg)
	if !jack.Verify([]byte(pub), msg, ordinary) {
		t.Fatal("Verify rejected an ordinary signature over the same message")
	}
}

func TestVerifyRejectsSmallOrderROrder2(t *testing.T) {
	// Second small-order point. With a prime-order public key, [S]B - [k]A
	// lies in the prime-order subgroup, so R = identity is the only
	// small-order value the equation can produce there; the identity test
	// covers that recipe. This test uses a small-order public key A: with
	// R = A = the order-2 point and S = 0, [S]B = R + [k]A holds for every
	// odd k, and the pre-change verifier accepted such signatures. Order-4
	// and order-8 points are reachable the same way (k = -1 mod the point's
	// order), so they need no separate recipe here.
	order2Hex := "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
	order2, err := hex.DecodeString(order2Hex)
	if err != nil {
		t.Fatalf("hex decode order-2 encoding: %v", err)
	}

	// Pick the first message whose k = SHA-512(R || A || M) mod L is odd:
	// the low bit of k equals the low bit of the last hash byte because L
	// is odd. The search is deterministic and the first hit is stable.
	var msg []byte
	var kHash []byte
	found := false
	for i := 0; i < 256 && !found; i++ {
		msg = append([]byte("mcp-jack strict small-order R order2 #"), byte(i))
		h := sha512.New()
		h.Write(order2)
		h.Write(order2)
		h.Write(msg)
		kHash = h.Sum(nil)
		found = kHash[63]&1 == 1
	}
	if !found {
		t.Fatal("no message with odd k found among 256 candidates")
	}

	sig := make([]byte, 64)
	copy(sig[:32], order2) // S stays all zero: [0]B = R + [k]A for odd k

	if !ed25519.Verify(ed25519.PublicKey(order2), msg, sig) {
		t.Fatal("crypto/ed25519 rejected the crafted order-2 signature; the recipe is stale")
	}
	if jack.Verify(order2, msg, sig) {
		t.Fatal("Verify accepted a signature whose R is a small-order point")
	}
}
