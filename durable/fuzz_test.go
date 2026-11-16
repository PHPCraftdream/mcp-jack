package durable

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	"github.com/PHPCraftdream/mcp-jack/server"
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

// FuzzDecodeMetadata checks the store-header decoder over fuzzed header
// bytes: no panic, only ErrInvalidStore rejections, and every accepted header
// is the exact canonical encoding of its decoded metadata.
func FuzzDecodeMetadata(f *testing.F) {
	valid := encodeMetadata(validTestMetadata())
	payload, err := checkedPayload(valid)
	if err != nil {
		f.Fatalf("fixture header invalid: %v", err)
	}
	unknownFlags := append([]byte(nil), payload...)
	unknownFlags[len(unknownFlags)-1] |= 4
	unknown := sealPayload(unknownFlags)
	f.Add(valid)
	f.Add(unknown)
	f.Add([]byte{})
	f.Add(valid[:len(valid)/2])
	f.Add(bytes.Repeat([]byte{0x41}, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := decodeMetadata(data)
		// Witnesses: the canonical header must keep decoding and unknown
		// flag bits must fail even with a valid checksum.
		if bytes.Equal(data, valid) && err != nil {
			t.Fatalf("acceptance witness: canonical store header rejected: %v", err)
		}
		if bytes.Equal(data, unknown) && err == nil {
			t.Fatalf("rejection witness: unknown header flags accepted")
		}
		if err != nil {
			if !errors.Is(err, ErrInvalidStore) {
				t.Fatalf("error %v is not ErrInvalidStore", err)
			}
			return
		}
		if decoded.Generation == 0 || decoded.Owner == 0 || decoded.Window < 1 || decoded.Window > 120 || decoded.HighWater < 0 || decoded.HighWater > maxTimestamp {
			t.Fatalf("accepted header with out-of-domain scalars")
		}
		if again := encodeMetadata(decoded); !bytes.Equal(again, data) {
			t.Fatalf("accepted header is not the canonical encoding of its metadata")
		}
	})
}

// fuzzValidRecord builds a static receipt row whose intent identity matches
// storageIntentID, the same oracle the unit tests exercise through real
// signing.
func fuzzValidRecord(m metadata) nonceRecord {
	var key [48]byte
	for index := range key {
		key[index] = byte(index)
	}
	signature := bytes.Repeat([]byte{0x66}, 64)
	requestHash := bytes.Repeat([]byte{0x77}, 32)
	var operation [16]byte
	operation[0] = 1
	row := nonceRecord{kind: liveRecord, storeID: m.StoreID, key: key}
	row.receipt = server.NonceReceipt{
		Version: formatVersion, DeploymentID: m.Deployment, StoreGeneration: m.Generation, OwnerGeneration: m.Owner,
		KID: jack.EncodeBase64URL(key[:32]), Nonce: jack.EncodeBase64URL(key[32:]),
		Signature: jack.EncodeBase64URL(signature), RequestHash: jack.EncodeBase64URL(requestHash),
		OperationID: operation, Timestamp: 100, RetainUntil: 100 + m.Window, HighWater: 100,
	}
	row.receipt.IntentID = storageIntentID(m, key, signature, requestHash, operation)
	return row
}

// FuzzDecodeRecord checks the nonce-row decoder over fuzzed rows read back
// from disk framing: no panic, only ErrInvalidStore rejections, and every
// accepted row is the exact canonical encoding of its decoded record.
func FuzzDecodeRecord(f *testing.F) {
	m := validTestMetadata()
	row := fuzzValidRecord(m)
	encoded, err := encodeRecord(row, m)
	if err != nil {
		f.Fatalf("encode fixture record: %v", err)
	}
	payload, err := checkedPayload(encoded)
	if err != nil {
		f.Fatalf("fixture record invalid: %v", err)
	}
	unknownKind := append([]byte(nil), payload...)
	unknownKind[1] = 4
	f.Add(encoded)
	f.Add(sealPayload(unknownKind))
	f.Add([]byte{})
	f.Add(encoded[:recordBytes/2])
	f.Add(sealPayload(append(append([]byte(nil), payload...), 0)))

	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := decodeRecord(data, m)
		if bytes.Equal(data, encoded) && err != nil {
			t.Fatalf("acceptance witness: canonical record rejected: %v", err)
		}
		if bytes.Equal(data, sealPayload(unknownKind)) && err == nil {
			t.Fatalf("rejection witness: unknown record kind accepted")
		}
		if err != nil {
			if !errors.Is(err, ErrInvalidStore) {
				t.Fatalf("error %v is not ErrInvalidStore", err)
			}
			return
		}
		if decoded.storeID != m.StoreID || decoded.kind < intentRecord || decoded.kind > tombstoneRecord {
			t.Fatalf("accepted record is foreign or has an unknown kind")
		}
		reEncoded, err := encodeRecord(decoded, m)
		if err != nil || !bytes.Equal(reEncoded, data) {
			t.Fatalf("accepted record is not canonically re-encodable: %v", err)
		}
	})
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
			if !errors.Is(err, ErrInvalidStore) {
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
