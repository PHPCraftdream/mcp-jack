package durable

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
)

func validTestMetadata() metadata {
	m := metadata{Deployment: "public-test-deployment", Generation: 1, Owner: 2, Window: 30, HighWater: 100}
	m.StoreID[0] = 1
	return m
}

func TestMetadataChecksumRejectsSingleByteCorruption(t *testing.T) {
	encoded := encodeMetadata(validTestMetadata())
	for index := range encoded {
		corrupt := append([]byte(nil), encoded...)
		corrupt[index] ^= 1
		if _, err := decodeMetadata(corrupt); err == nil {
			t.Fatalf("corrupt header accepted at byte %d", index)
		}
	}
}

func TestMetadataStrictCodec(t *testing.T) {
	original := validTestMetadata()
	got, err := decodeMetadata(encodeMetadata(original))
	if err != nil || got != original {
		t.Fatalf("metadata roundtrip: %v", err)
	}
	for _, mutate := range []func(*metadata){
		func(m *metadata) { m.Generation = 0 },
		func(m *metadata) { m.Owner = 0 },
		func(m *metadata) { m.Window = 0 },
		func(m *metadata) { m.Window = 121 },
		func(m *metadata) { m.HighWater = -1 },
		func(m *metadata) { m.HighWater = maxTimestamp + 1 },
		func(m *metadata) { m.Live = 4097 },
		func(m *metadata) { m.Live = 4096; m.Intents = 1 },
		func(m *metadata) { m.Tombstones = 65 },
		func(m *metadata) { m.StoreID = [16]byte{} },
		func(m *metadata) { m.Deployment = "" },
		func(m *metadata) { m.Deployment = "\xff" },
		func(m *metadata) { m.Deployment = strings.Repeat("x", 1025) },
	} {
		invalid := original
		mutate(&invalid)
		if _, err := decodeMetadata(encodeMetadata(invalid)); !errors.Is(err, ErrInvalidStore) {
			t.Fatal("invalid metadata accepted")
		}
	}
	valid := encodeMetadata(original)
	for length := 0; length < len(valid); length++ {
		if _, err := decodeMetadata(valid[:length]); err == nil {
			t.Fatalf("truncated header accepted at %d", length)
		}
	}
	payload, err := checkedPayload(valid)
	if err != nil {
		t.Fatal(err)
	}
	for length := 0; length < len(payload); length++ {
		if _, err := decodeMetadata(sealPayload(append([]byte(nil), payload[:length]...))); err == nil {
			t.Fatalf("truncated schema with valid checksum accepted at %d", length)
		}
	}
	if _, err := decodeMetadata(sealPayload(append(append([]byte(nil), payload...), 0))); err == nil {
		t.Fatal("trailing bytes with valid checksum accepted")
	}
	unknownFlags := append([]byte(nil), payload...)
	unknownFlags[len(unknownFlags)-1] |= 4
	if _, err := decodeMetadata(sealPayload(unknownFlags)); err == nil {
		t.Fatal("unknown flags accepted")
	}
}

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
