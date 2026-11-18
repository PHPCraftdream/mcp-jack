//go:build !linux

package platform_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

func TestTrustStoreUnsupportedPlatformDoesNotSampleClock(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{72}, 32))
	public := key.Public().(ed25519.PublicKey)
	checkpoint := rotation.Checkpoint{Hash: "-", KID: jack.KeyID(public)}
	copy(checkpoint.PublicKey[:], public)
	options := durable.TrustOptions{Binding: rotation.Binding{Endpoint: "https://public.invalid/mcp", Audience: "public"}, Window: 30, Checkpoint: checkpoint, Now: func() int64 { panic("unsupported platform sampled raw clock") }}
	if err := durable.InitializeTrustUnused("not-opened", options); !errors.Is(err, durable.ErrUnsupported) {
		t.Fatal("unsupported initialization did not fail closed")
	}
	if owner, err := durable.OpenTrust("not-opened", options); !errors.Is(err, durable.ErrUnsupported) || owner != nil {
		t.Fatal("unsupported open did not fail closed")
	}
}
