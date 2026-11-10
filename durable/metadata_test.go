package durable

import (
	"errors"
	"strings"
	"testing"
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
	if err != nil { t.Fatal(err) }
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
