package durable

import (
	"bytes"
	"encoding/binary"

	"github.com/PHPCraftdream/mcp-jack/rotation"
	bolt "go.etcd.io/bbolt"
)

var serverBucket = []byte("server-ring-v1")
var serverGuardKey = []byte("guard")
var serverSnapshotKey = []byte("snapshot")
var serverIntentKey = []byte("publication")
var serverGuardDomain = []byte("mcp-jack/server-ring/guard/v1\n")
var serverIntentDomain = []byte("mcp-jack/server-ring/publication/v1\n")

// Внутренний guard codec общий; внешний domain исключает подмену client store.
func encodeServerGuard(guard trustGuard) []byte {
	return sealPayload(append(append([]byte{}, serverGuardDomain...), encodeTrustGuard(guard)...))
}

func decodeServerGuard(data []byte, options TrustOptions, profile [32]byte) (trustGuard, error) {
	payload, err := checkedPayload(data)
	if err != nil || !bytes.HasPrefix(payload, serverGuardDomain) {
		return trustGuard{}, ErrInvalidStore
	}
	return decodeTrustGuard(payload[len(serverGuardDomain):], options, profile)
}

// Intent хранит точные локальные bytes; сам по себе он не разрешает publication.
func encodeServerIntent(previous, next []byte) []byte {
	var out bytes.Buffer
	out.Write(serverIntentDomain)
	_ = binary.Write(&out, binary.BigEndian, uint64(len(previous)))
	out.Write(previous)
	out.Write(next)
	return sealPayload(out.Bytes())
}

func decodeServerIntent(data []byte) ([]byte, []byte, error) {
	payload, err := checkedPayload(data)
	prefix := len(serverIntentDomain)
	if err != nil || len(payload) < prefix+8 || !bytes.HasPrefix(payload, serverIntentDomain) {
		return nil, nil, ErrInvalidStore
	}
	length := binary.BigEndian.Uint64(payload[prefix:])
	remaining := payload[prefix+8:]
	if length == 0 || length > rotation.MaxTrustSnapshotBytes || length >= uint64(len(remaining)) || uint64(len(remaining))-length > rotation.MaxTrustSnapshotBytes {
		return nil, nil, ErrInvalidStore
	}
	return append([]byte{}, remaining[:int(length)]...), append([]byte{}, remaining[int(length):]...), nil
}

func readServerRows(tx *bolt.Tx) (guard, snapshot, intent []byte, result error) {
	roots := 0
	if err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		roots++
		if !bytes.Equal(name, serverBucket) {
			return ErrInvalidStore
		}
		return nil
	}); err != nil || roots != 1 {
		return nil, nil, nil, ErrInvalidStore
	}
	bucket := tx.Bucket(serverBucket)
	if bucket == nil {
		return nil, nil, nil, ErrInvalidStore
	}
	count := 0
	if err := bucket.ForEach(func(key, value []byte) error {
		if value == nil || (!bytes.Equal(key, serverGuardKey) && !bytes.Equal(key, serverSnapshotKey) && !bytes.Equal(key, serverIntentKey)) {
			return ErrInvalidStore
		}
		count++
		return nil
	}); err != nil || count != 3 {
		return nil, nil, nil, ErrInvalidStore
	}
	corrupt := false
	for err := range tx.Check() {
		if err != nil {
			corrupt = true
		}
	}
	if corrupt {
		return nil, nil, nil, ErrInvalidStore
	}
	encoded := bucket.Get(serverSnapshotKey)
	if len(encoded) > rotation.MaxTrustSnapshotBytes+32 {
		return nil, nil, nil, ErrInvalidStore
	}
	snapshot, result = checkedPayload(encoded)
	if result != nil {
		return nil, nil, nil, result
	}
	guard = append([]byte{}, bucket.Get(serverGuardKey)...)
	snapshot = append([]byte{}, snapshot...)
	intent = append([]byte{}, bucket.Get(serverIntentKey)...)
	if len(intent) > 2*rotation.MaxTrustSnapshotBytes+len(serverIntentDomain)+40 {
		return nil, nil, nil, ErrInvalidStore
	}
	return guard, snapshot, intent, nil
}
