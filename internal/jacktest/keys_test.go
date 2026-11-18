package jack_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

func TestKeysJSONDerivation(t *testing.T) {
	kf, err := spec.LoadKeys()
	if err != nil {
		t.Fatalf("LoadKeys: %v", err)
	}

	for _, k := range kf.Keys {
		k := k
		t.Run(k.Name, func(t *testing.T) {
			seed, err := hex.DecodeString(k.SeedHex)
			if err != nil {
				t.Fatalf("hex.DecodeString: %v", err)
			}
			if len(seed) != 32 {
				t.Fatalf("seed length = %d, want 32", len(seed))
			}
			priv := ed25519.NewKeyFromSeed(seed)
			pub := priv.Public().(ed25519.PublicKey)
			wantPub, err := jack.DecodeBase64URLFixed(k.PublicKey, 32)
			if err != nil {
				t.Fatalf("DecodeBase64URLFixed(PublicKey): %v", err)
			}
			if !bytes.Equal([]byte(pub), wantPub) {
				t.Fatalf("public key mismatch: got %x, want %x", pub, wantPub)
			}
			if got := jack.KeyID(wantPub); got != k.Kid {
				t.Fatalf("KeyID = %q, want %q", got, k.Kid)
			}
		})
	}
}
