//go:build linux

package durable

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func preparedSnapshot(t *testing.T, change func(*bolt.Tx, *metadata, nonceRecord) error) (string, Options, nonceRecord) {
	t.Helper()
	now := int64(100)
	opts := testOptions(&now)
	path := filepath.Join(privateTestDirectory(t), "history.db")
	if err := InitializeUnused(path, opts); err != nil { t.Fatal(err) }
	db, err := bolt.Open(path, 0600, dbOptions(false))
	if err != nil { t.Fatal(err) }
	defer db.Close()
	var m metadata
	if err := db.View(func(tx *bolt.Tx) error {
		var err error
		m, err = decodeMetadata(tx.Bucket([]byte("metadata")).Get(headerKey))
		return err
	}); err != nil { t.Fatal(err) }
	row := testRecord(t, m, liveRecord)
	encoded, err := encodeRecord(row, m)
	if err != nil { t.Fatal(err) }
	index := expiryKey(row)
	if err := db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket([]byte("live")).Put(row.key[:], encoded); err != nil { return err }
		if err := tx.Bucket([]byte("expiry")).Put(index[:], []byte{}); err != nil { return err }
		if err := tx.Bucket([]byte("operation")).Put(row.receipt.OperationID[:], row.key[:]); err != nil { return err }
		m.Live = 1
		if change != nil { if err := change(tx, &m, row); err != nil { return err } }
		return tx.Bucket([]byte("metadata")).Put(headerKey, encodeMetadata(m))
	}); err != nil { t.Fatal(err) }
	if err := db.Close(); err != nil { t.Fatal(err) }
	return path, opts, row
}

func TestPopulatedHistoryValidatedWithoutImplicitExpiry(t *testing.T) {
	path, opts, row := preparedSnapshot(t, nil)
	opts.Now = func() int64 { return 200 }
	owner, err := Open(path, opts)
	if err != nil { t.Fatal(err) }
	defer owner.Close()
	if owner.meta.Live != 1 || owner.meta.HighWater != 200 { t.Fatal("loader discarded history or skipped H") }
	if err := owner.db.View(func(tx *bolt.Tx) error {
		got, err := decodeRecord(tx.Bucket([]byte("live")).Get(row.key[:]), owner.meta)
		if err != nil { return err }
		if got != row { return errors.New("startup rewrote historical receipt") }
		return nil
	}); err != nil { t.Fatal(err) }
}

func TestBrokenHistoryGraphRejected(t *testing.T) {
	cases := map[string]func(*bolt.Tx, *metadata, nonceRecord) error{
		"missing-expiry": func(tx *bolt.Tx, _ *metadata, row nonceRecord) error {
			index := expiryKey(row)
			return tx.Bucket([]byte("expiry")).Delete(index[:])
		},
		"extra-expiry": func(tx *bolt.Tx, _ *metadata, row nonceRecord) error {
			index := expiryKey(row)
			index[7] ^= 1
			return tx.Bucket([]byte("expiry")).Put(index[:], []byte{})
		},
		"nonempty-expiry-value": func(tx *bolt.Tx, _ *metadata, row nonceRecord) error {
			index := expiryKey(row)
			return tx.Bucket([]byte("expiry")).Put(index[:], []byte{1})
		},
		"missing-operation": func(tx *bolt.Tx, _ *metadata, row nonceRecord) error {
			return tx.Bucket([]byte("operation")).Delete(row.receipt.OperationID[:])
		},
		"wrong-operation-target": func(tx *bolt.Tx, _ *metadata, row nonceRecord) error {
			return tx.Bucket([]byte("operation")).Put(row.receipt.OperationID[:], make([]byte, 48))
		},
		"extra-operation": func(tx *bolt.Tx, _ *metadata, row nonceRecord) error {
			id := row.receipt.OperationID
			id[0] ^= 2
			return tx.Bucket([]byte("operation")).Put(id[:], row.key[:])
		},
		"wrong-counter": func(_ *bolt.Tx, m *metadata, _ nonceRecord) error { m.Live++; return nil },
		"damaged-receipt": func(tx *bolt.Tx, _ *metadata, row nonceRecord) error {
			data := append([]byte(nil), tx.Bucket([]byte("live")).Get(row.key[:])...)
			data[20] ^= 1
			return tx.Bucket([]byte("live")).Put(row.key[:], data)
		},
		"extra-bucket": func(tx *bolt.Tx, _ *metadata, _ nonceRecord) error { _, err := tx.CreateBucket([]byte("extra")); return err },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			path, opts, _ := preparedSnapshot(t, change)
			if owner, err := Open(path, opts); !errors.Is(err, ErrInvalidStore) {
				if owner != nil { owner.Fence(); _ = owner.Close() }
				t.Fatalf("invalid graph admitted: %v", err)
			}
		})
	}
}

func TestUnsettledIntentCannotBecomeReadyThroughCleanHeader(t *testing.T) {
	path, opts, _ := preparedSnapshot(t, func(tx *bolt.Tx, m *metadata, row nonceRecord) error {
		index := expiryKey(row)
		if err := tx.Bucket([]byte("live")).Delete(row.key[:]); err != nil { return err }
		if err := tx.Bucket([]byte("expiry")).Delete(index[:]); err != nil { return err }
		row.kind = intentRecord
		encoded, err := encodeRecord(row, *m)
		if err != nil { return err }
		m.Live, m.Intents = 0, 1
		return tx.Bucket([]byte("intent")).Put(row.key[:], encoded)
	})
	if owner, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
		if owner != nil { owner.Fence(); _ = owner.Close() }
		t.Fatalf("unsettled intent admitted: %v", err)
	}
}

func TestExpiryIndexHasExactBigEndianDeadlineAndPair(t *testing.T) {
	m := validTestMetadata()
	row := testRecord(t, m, liveRecord)
	index := expiryKey(row)
	if !bytes.Equal(index[:8], []byte{0, 0, 0, 0, 0, 0, 0, 130}) || !bytes.Equal(index[8:], row.key[:]) {
		t.Fatal("expiry key changed from uint64be(retainUntil)||kid||nonce")
	}
}
