package durable

import (
	"bytes"

	bolt "go.etcd.io/bbolt"
)

// Проверяется весь ограниченный граф, без исправления, expiry или удаления history.
func validateRows(tx *bolt.Tx, m metadata) error {
	expiry := tx.Bucket([]byte("expiry"))
	operations := tx.Bucket([]byte("operation"))
	if expiry == nil || operations == nil {
		return ErrInvalidStore
	}
	seenKeys := make(map[[48]byte]struct{})
	seenOperations := make(map[[16]byte]struct{})
	var total uint32
	for _, group := range []struct {
		name  string
		kind  byte
		count uint32
	}{
		{"live", liveRecord, m.Live},
		{"intent", intentRecord, m.Intents},
		{"tombstone", tombstoneRecord, m.Tombstones},
	} {
		var count uint32
		bucket := tx.Bucket([]byte(group.name))
		if bucket == nil {
			return ErrInvalidStore
		}
		if err := bucket.ForEach(func(key, value []byte) error {
			count++
			if count > group.count || len(key) != 48 || len(value) != recordBytes {
				return ErrInvalidStore
			}
			row, err := decodeRecord(value, m)
			if err != nil || row.kind != group.kind || !bytes.Equal(key, row.key[:]) {
				return ErrInvalidStore
			}
			if _, found := seenKeys[row.key]; found {
				return ErrInvalidStore
			}
			if _, found := seenOperations[row.receipt.OperationID]; found {
				return ErrInvalidStore
			}
			seenKeys[row.key] = struct{}{}
			seenOperations[row.receipt.OperationID] = struct{}{}
			indexed := operations.Get(row.receipt.OperationID[:])
			if !bytes.Equal(indexed, key) {
				return ErrInvalidStore
			}
			if row.kind == liveRecord {
				index := expiryKey(row)
				actualKey, actualValue := expiry.Cursor().Seek(index[:])
				if !bytes.Equal(actualKey, index[:]) || len(actualValue) != 0 || expiry.Bucket(actualKey) != nil {
					return ErrInvalidStore
				}
			}
			return nil
		}); err != nil {
			return err
		}
		if count != group.count {
			return ErrInvalidStore
		}
		total += count
	}
	var indexedLive uint32
	if err := expiry.ForEach(func(key, value []byte) error {
		indexedLive++
		if indexedLive > m.Live || len(key) != 56 || len(value) != 0 || expiry.Bucket(key) != nil {
			return ErrInvalidStore
		}
		return nil
	}); err != nil {
		return err
	}
	if indexedLive != m.Live {
		return ErrInvalidStore
	}
	var indexedOperations uint32
	if err := operations.ForEach(func(key, value []byte) error {
		indexedOperations++
		if indexedOperations > total || len(key) != 16 || len(value) != 48 || operations.Bucket(key) != nil {
			return ErrInvalidStore
		}
		return nil
	}); err != nil {
		return err
	}
	if indexedOperations != total {
		return ErrInvalidStore
	}
	return nil
}
