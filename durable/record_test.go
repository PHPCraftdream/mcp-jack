package durable

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
)

func testRecord(t *testing.T, m metadata, kind byte) nonceRecord {
	t.Helper()
	seed := sha256.Sum256([]byte("mcp-jack public durable record test"))
	key := ed25519.NewKeyFromSeed(seed[:])
	kid := jack.KeyID(key.Public().(ed25519.PublicKey))
	nonce := jack.EncodeBase64URL(make([]byte, 16))
	signing := jack.RequestSigningString("GET", "/mcp", "public-row-test", kid, 100, nonce, nil)
	signature := jack.EncodeBase64URL(ed25519.Sign(key, []byte(signing)))
	request := server.NonceAdmission{KID: kid, Nonce: nonce, Signature: signature, SigningBytes: signing, Timestamp: 100, Window: m.Window}
	row := nonceRecord{kind: kind, storeID: m.StoreID}
	kidBytes, err := jack.DecodeBase64URLFixed(kid, 32)
	if err != nil {
		t.Fatal(err)
	}
	copy(row.key[:32], kidBytes)
	row.receipt = server.NonceReceipt{
		Version: 1, DeploymentID: m.Deployment, StoreGeneration: m.Generation, OwnerGeneration: m.Owner,
		KID: kid, Nonce: nonce, Signature: signature, RequestHash: jack.BodyHash([]byte(signing)),
		Timestamp: 100, RetainUntil: 100 + m.Window, HighWater: 100,
	}
	row.receipt.OperationID[0] = 1
	row.receipt.IntentID, err = server.NonceIntentID(m.Deployment, request, row.receipt.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func TestRecordCodecMatchesSDKOperationIdentity(t *testing.T) {
	m := validTestMetadata()
	for _, kind := range []byte{intentRecord, liveRecord, tombstoneRecord} {
		original := testRecord(t, m, kind)
		encoded, err := encodeRecord(original, m)
		if err != nil || len(encoded) != recordBytes {
			t.Fatalf("record encoding: %v", err)
		}
		decoded, err := decodeRecord(encoded, m)
		if err != nil || decoded != original {
			t.Fatalf("record identity/bytes changed: %v", err)
		}
		for index := range encoded {
			corrupt := append([]byte(nil), encoded...)
			corrupt[index] ^= 1
			if _, err := decodeRecord(corrupt, m); err == nil {
				t.Fatalf("corrupt record accepted at %d", index)
			}
		}
		advanced := m
		advanced.HighWater = 200
		if _, err := decodeRecord(encoded, advanced); err != nil {
			t.Fatal("loader implicitly expired historical receipt")
		}
	}
}

func TestRecordSemanticValidationSurvivesValidChecksum(t *testing.T) {
	m := validTestMetadata()
	original := testRecord(t, m, liveRecord)
	for _, mutate := range []func(*nonceRecord){
		func(r *nonceRecord) { r.kind = 0 },
		func(r *nonceRecord) { r.kind = 4 },
		func(r *nonceRecord) { r.storeID[0] ^= 1 },
		func(r *nonceRecord) { r.key[0] ^= 1 },
		func(r *nonceRecord) { r.receipt.Version = 2 },
		func(r *nonceRecord) { r.receipt.DeploymentID += "other" },
		func(r *nonceRecord) { r.receipt.StoreGeneration++ },
		func(r *nonceRecord) { r.receipt.OwnerGeneration = 0 },
		func(r *nonceRecord) { r.receipt.OwnerGeneration++ },
		func(r *nonceRecord) { r.receipt.OperationID[0] ^= 1 },
		func(r *nonceRecord) { r.receipt.IntentID = jack.BodyHash([]byte("other intent")) },
		func(r *nonceRecord) { r.receipt.Signature = jack.EncodeBase64URL(make([]byte, 64)) },
		func(r *nonceRecord) { r.receipt.RequestHash = jack.BodyHash([]byte("other request")) },
		func(r *nonceRecord) { r.receipt.RetainUntil++ },
		func(r *nonceRecord) { r.receipt.HighWater = -1 },
		func(r *nonceRecord) { r.receipt.HighWater = m.HighWater + 1 },
	} {
		invalid := original
		mutate(&invalid)
		if _, err := encodeRecord(invalid, m); err == nil {
			t.Fatal("inconsistent receipt encoded")
		}
	}
	encoded, err := encodeRecord(original, m)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := checkedPayload(encoded)
	if err != nil {
		t.Fatal(err)
	}
	unknownKind := append([]byte(nil), payload...)
	unknownKind[1] = 4
	if _, err := decodeRecord(sealPayload(unknownKind), m); err == nil {
		t.Fatal("unknown kind accepted with valid checksum")
	}
	for _, offset := range []int{2, 18, 65, 66, 81, 82, 98, 130, 194, 233, 241, 249} {
		mutated := append([]byte(nil), payload...)
		mutated[offset] ^= 1
		if _, err := decodeRecord(sealPayload(mutated), m); err == nil {
			t.Fatalf("inconsistent schema accepted with valid checksum at %d", offset)
		}
	}
	if _, err := decodeRecord(sealPayload(append(payload, 0)), m); err == nil {
		t.Fatal("extra record bytes accepted")
	}
}
