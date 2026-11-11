package durable

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestServerPublicationIntentExactBytesAndStrictLengths(t *testing.T) {
	previous, next := []byte("expected exact bytes"), []byte("desired exact bytes")
	encoded := encodeServerIntent(previous, next)
	before, after, err := decodeServerIntent(encoded)
	if err != nil || !bytes.Equal(before, previous) || !bytes.Equal(after, next) { t.Fatal("intent roundtrip changed exact bytes") }
	before[0] ^= 1
	after[0] ^= 1
	before, after, err = decodeServerIntent(encoded)
	if err != nil || !bytes.Equal(before, previous) || !bytes.Equal(after, next) { t.Fatal("decoded intent aliases protected bytes") }
	corrupt := append([]byte{}, encoded...)
	corrupt[len(corrupt)-1] ^= 1
	if _, _, err := decodeServerIntent(corrupt); err == nil { t.Fatal("corrupt checksum accepted") }
	for _, length := range []uint64{0, uint64(len(previous)+len(next)), ^uint64(0)} {
		payload := append([]byte{}, serverIntentDomain...)
		payload = binary.BigEndian.AppendUint64(payload, length)
		payload = append(payload, previous...)
		payload = append(payload, next...)
		if _, _, err := decodeServerIntent(sealPayload(payload)); err == nil { t.Fatal("invalid length accepted") }
	}
	if _, _, err := decodeServerIntent(sealPayload([]byte("other domain"))); err == nil { t.Fatal("foreign domain accepted") }
}
