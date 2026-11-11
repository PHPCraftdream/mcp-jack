package durable

import (
	"bytes"
	"encoding/binary"

	"github.com/PHPCraftdream/mcp-jack/rotation"
	bolt "go.etcd.io/bbolt"
)

var trustBucket = []byte("client-trust-v1")
var trustGuardKey = []byte("guard")
var trustSnapshotKey = []byte("snapshot")
var trustGuardMagic = []byte("mcp-jack/client-trust/guard/v1\n")

type trustGuard struct {
	StoreID [16]byte
	Profile [32]byte
	Owner uint64
	Dirty bool
	Fenced bool
	Clock rotation.ClockTuple
}

func encodeTrustGuard(guard trustGuard) []byte {
	var out bytes.Buffer
	out.Write(trustGuardMagic)
	out.Write(guard.StoreID[:])
	out.Write(guard.Profile[:])
	for _, number := range []uint64{guard.Owner, uint64(guard.Clock.Window), uint64(guard.Clock.HighWater), guard.Clock.Revision} {
		_ = binary.Write(&out, binary.BigEndian, number)
	}
	var flags byte
	if guard.Dirty { flags |= 1 }
	if guard.Fenced { flags |= 2 }
	if guard.Clock.Unsafe { flags |= 4 }
	out.WriteByte(flags)
	return sealPayload(out.Bytes())
}

func decodeTrustGuard(data []byte, options TrustOptions, profile [32]byte) (trustGuard, error) {
	var guard trustGuard
	payload, err := checkedPayload(data)
	if err != nil || len(payload) != len(trustGuardMagic)+16+32+32+1 || !bytes.HasPrefix(payload, trustGuardMagic) {
		return guard, ErrInvalidStore
	}
	position := len(trustGuardMagic)
	copy(guard.StoreID[:], payload[position:position+16]); position += 16
	copy(guard.Profile[:], payload[position:position+32]); position += 32
	guard.Owner = binary.BigEndian.Uint64(payload[position:]); position += 8
	window := binary.BigEndian.Uint64(payload[position:]); position += 8
	highWater := binary.BigEndian.Uint64(payload[position:]); position += 8
	revision := binary.BigEndian.Uint64(payload[position:]); position += 8
	flags := payload[position]
	if guard.StoreID == [16]byte{} || guard.Profile != profile || guard.Owner == 0 || window != uint64(options.Window) || highWater > uint64(rotation.MaxTimestamp) || revision > rotation.MaxOrdinal || flags &^ 7 != 0 {
		return trustGuard{}, ErrInvalidStore
	}
	guard.Dirty, guard.Fenced = flags&1 != 0, flags&2 != 0
	guard.Clock = rotation.ClockTuple{Binding: options.Binding, Window: options.Window, HighWater: int64(highWater), Revision: revision, Unsafe: flags&4 != 0}
	return guard, nil
}

func readTrustRows(tx *bolt.Tx) ([]byte, []byte, error) {
	rootCount := 0
	if err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		rootCount++
		if !bytes.Equal(name, trustBucket) {
			return ErrInvalidStore
		}
		return nil
	}); err != nil || rootCount != 1 {
		return nil, nil, ErrInvalidStore
	}
	bucket := tx.Bucket(trustBucket)
	if bucket == nil {
		return nil, nil, ErrInvalidStore
	}
	count := 0
	cursor := bucket.Cursor()
	for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
		if value == nil || (!bytes.Equal(key, trustGuardKey) && !bytes.Equal(key, trustSnapshotKey)) {
			return nil, nil, ErrInvalidStore
		}
		count++
	}
	if count != 2 {
		return nil, nil, ErrInvalidStore
	}
	corrupt := false
	for err := range tx.Check() {
		if err != nil { corrupt = true }
	}
	if corrupt { return nil, nil, ErrInvalidStore }
	guard := append([]byte(nil), bucket.Get(trustGuardKey)...)
	encoded := bucket.Get(trustSnapshotKey)
	if len(encoded) > rotation.MaxTrustSnapshotBytes+32 {
		return nil, nil, ErrInvalidStore
	}
	payload, err := checkedPayload(encoded)
	if err != nil {
		return nil, nil, err
	}
	return guard, append([]byte(nil), payload...), nil
}
