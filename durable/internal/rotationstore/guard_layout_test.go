package rotationstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/durable/internal/ownedfile"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

// Static fuzz identity for the guard codec: the profile derives from a public
// constant, never a secret.
var (
	fuzzGuardBinding = rotation.Binding{Endpoint: "https://svc.example.test/mcp", Audience: "https://svc.example.test"}
	fuzzGuardProfile = sha256.Sum256([]byte("mcp-jack public durable guard fuzz profile"))
)

func fuzzGuardOptions() TrustOptions {
	return TrustOptions{Binding: fuzzGuardBinding, Window: 30}
}

func fuzzValidGuard() trustGuard {
	guard := trustGuard{Profile: fuzzGuardProfile, Owner: 1, Clock: rotation.ClockTuple{Binding: fuzzGuardBinding, Window: 30, HighWater: 100, Revision: 1}}
	guard.StoreID[0] = 1
	return guard
}

// FuzzDecodeTrustGuard checks the owner-checked guard decoder over fuzzed
// guard bytes: no panic, only ErrInvalidStore rejections, a bound profile and
// clock options, and every accepted guard is the exact canonical encoding of
// its decoded value.
func FuzzDecodeTrustGuard(f *testing.F) {
	options := fuzzGuardOptions()
	profile := fuzzGuardProfile
	valid := encodeTrustGuard(fuzzValidGuard())
	recovery := fuzzValidGuard()
	recovery.Dirty, recovery.Fenced, recovery.Clock.Unsafe = true, true, true
	recoveryEncoded := encodeTrustGuard(recovery)
	foreign := fuzzValidGuard()
	foreign.Profile[0] ^= 1
	foreignEncoded := encodeTrustGuard(foreign)
	ownerless := fuzzValidGuard()
	ownerless.Owner = 0
	ownerlessEncoded := encodeTrustGuard(ownerless)
	f.Add(valid)
	f.Add(recoveryEncoded)
	f.Add(foreignEncoded)
	f.Add(ownerlessEncoded)
	f.Add([]byte{})
	f.Add(valid[:len(valid)/2])

	f.Fuzz(func(t *testing.T, data []byte) {
		guard, err := decodeTrustGuard(data, options, profile)
		if bytes.Equal(data, valid) && err != nil {
			t.Fatalf("acceptance witness: canonical guard rejected: %v", err)
		}
		if bytes.Equal(data, foreignEncoded) && err == nil {
			t.Fatalf("rejection witness: foreign profile accepted")
		}
		if bytes.Equal(data, ownerlessEncoded) && err == nil {
			t.Fatalf("rejection witness: zero owner accepted")
		}
		if err != nil {
			if !errors.Is(err, ownedfile.ErrInvalidStore) {
				t.Fatalf("error %v is not ErrInvalidStore", err)
			}
			return
		}
		if guard.Profile != profile || guard.Clock.Binding != options.Binding || guard.Clock.Window != options.Window {
			t.Fatalf("accepted guard ignored the bound profile or clock options")
		}
		if guard.Owner == 0 || guard.StoreID == ([16]byte{}) || guard.Clock.HighWater < 0 || guard.Clock.HighWater > rotation.MaxTimestamp || guard.Clock.Revision > rotation.MaxOrdinal {
			t.Fatalf("accepted guard with out-of-domain identity scalars")
		}
		if bytes.Equal(data, recoveryEncoded) && (!guard.Dirty || !guard.Fenced || !guard.Clock.Unsafe) {
			t.Fatalf("accepted guard lost its recovery flags")
		}
		if again := encodeTrustGuard(guard); !bytes.Equal(again, data) {
			t.Fatalf("accepted guard is not the canonical encoding of its value")
		}
	})
}

// server_layout.go: publication intent stores exact local bytes, never aliases
// them, rejects corrupt checksums, invalid lengths, and foreign domains.
func TestServerPublicationIntentExactBytesAndStrictLengths(t *testing.T) {
	previous, next := []byte("expected exact bytes"), []byte("desired exact bytes")
	encoded := encodeServerIntent(previous, next)
	before, after, err := decodeServerIntent(encoded)
	if err != nil || !bytes.Equal(before, previous) || !bytes.Equal(after, next) {
		t.Fatal("intent roundtrip changed exact bytes")
	}
	before[0] ^= 1
	after[0] ^= 1
	before, after, err = decodeServerIntent(encoded)
	if err != nil || !bytes.Equal(before, previous) || !bytes.Equal(after, next) {
		t.Fatal("decoded intent aliases protected bytes")
	}
	corrupt := append([]byte{}, encoded...)
	corrupt[len(corrupt)-1] ^= 1
	if _, _, err := decodeServerIntent(corrupt); err == nil {
		t.Fatal("corrupt checksum accepted")
	}
	for _, length := range []uint64{0, uint64(len(previous) + len(next)), ^uint64(0)} {
		payload := append([]byte{}, serverIntentDomain...)
		payload = binary.BigEndian.AppendUint64(payload, length)
		payload = append(payload, previous...)
		payload = append(payload, next...)
		if _, _, err := decodeServerIntent(ownedfile.SealPayload(payload)); err == nil {
			t.Fatal("invalid length accepted")
		}
	}
	if _, _, err := decodeServerIntent(ownedfile.SealPayload([]byte("other domain"))); err == nil {
		t.Fatal("foreign domain accepted")
	}
}
