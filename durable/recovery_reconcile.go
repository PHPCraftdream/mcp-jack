package durable

import (
	"errors"
	"os"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
	bolt "go.etcd.io/bbolt"
)

// ReconcileUnknown — явная OOB операция над закрытым dirty store.
// Exact snapshot/receipt переводятся в terminal tombstone без dispatch/retry/reopen.
// Отсутствие записи не является доказательством abort и не снимает startup fence.
func ReconcileUnknown(path string, opts Options, expectedHash string, receipt server.NonceReceipt) error {
	return reconcileUnknown(path, opts, expectedHash, receipt, nil)
}

func reconcileUnknown(path string, opts Options, expectedHash string, receipt server.NonceReceipt, transact func(*bolt.DB, func(*bolt.Tx) error) error) (result error) {
	opts, err := normalizedOptions(opts)
	if err != nil {
		return err
	}
	if _, err := jack.DecodeBase64URLFixed(expectedHash, 32); err != nil {
		return ErrRecoveryRequired
	}
	kid, err := jack.DecodeBase64URLFixed(receipt.KID, 32)
	if err != nil {
		return ErrRecoveryRequired
	}
	nonce, err := jack.DecodeBase64URLFixed(receipt.Nonce, 16)
	if err != nil {
		return ErrRecoveryRequired
	}
	var pair [48]byte
	copy(pair[:32], kid)
	copy(pair[32:], nonce)
	if err := privateDirectory(path); err != nil {
		return err
	}
	options := dbOptions(false)
	openFile := options.OpenFile
	var file *os.File
	options.OpenFile = func(name string, flags int, mode os.FileMode) (*os.File, error) {
		opened, err := openFile(name, flags, mode)
		if err == nil {
			file = opened
		}
		return opened, err
	}
	db, err := bolt.Open(path, 0600, options)
	if err != nil {
		return ErrUnavailable
	}
	defer func() {
		if err := db.Close(); err != nil {
			result = ErrUnavailable
		}
	}()
	if transact == nil {
		transact = func(db *bolt.DB, apply func(*bolt.Tx) error) error { return db.Update(apply) }
	}
	var callbackErr error
	err = transact(db, func(tx *bolt.Tx) error {
		callbackErr = reconcileRow(tx, opts, expectedHash, pair, receipt)
		return callbackErr
	})
	if err != nil {
		if errors.Is(callbackErr, ErrRecoveryRequired) || errors.Is(callbackErr, ErrInvalidStore) {
			return callbackErr
		}
		return ErrUnavailable
	}
	info, err := file.Stat()
	if err != nil || info.Size() > maxFileBytes || info.Size() < 4*pageBytes {
		return ErrUnavailable
	}
	return nil
}

func reconcileRow(tx *bolt.Tx, opts Options, expectedHash string, pair [48]byte, receipt server.NonceReceipt) error {
	var snapshot RecoverySnapshot
	if err := loadRecoverySnapshot(tx, opts, &snapshot); err != nil {
		return err
	}
	if !snapshot.Dirty || snapshot.Hash != expectedHash {
		return ErrRecoveryRequired
	}
	m, err := decodeMetadata(tx.Bucket([]byte("metadata")).Get(headerKey))
	if err != nil {
		return err
	}
	for _, group := range []struct {
		name string
		kind byte
	}{{"live", liveRecord}, {"intent", intentRecord}, {"tombstone", tombstoneRecord}} {
		row, err := readRecord(tx.Bucket([]byte(group.name)), pair, m, group.kind)
		if err != nil {
			return err
		}
		if row == nil {
			continue
		}
		if row.receipt != receipt {
			return ErrRecoveryRequired
		}
		if group.kind == tombstoneRecord {
			return nil
		}
		if m.Tombstones >= 64 {
			return ErrRecoveryRequired
		}
		terminal := *row
		terminal.kind = tombstoneRecord
		encoded, err := encodeRecord(terminal, m)
		if err != nil {
			return err
		}
		if err := tx.Bucket([]byte("tombstone")).Put(pair[:], encoded); err != nil {
			return err
		}
		if err := tx.Bucket([]byte(group.name)).Delete(pair[:]); err != nil {
			return err
		}
		if group.kind == liveRecord {
			index := expiryKey(*row)
			if err := tx.Bucket([]byte("expiry")).Delete(index[:]); err != nil {
				return err
			}
			m.Live--
		} else {
			m.Intents--
		}
		m.Tombstones++
		if err := validateRows(tx, m); err != nil {
			return err
		}
		return tx.Bucket([]byte("metadata")).Put(headerKey, encodeMetadata(m))
	}
	return ErrRecoveryRequired
}
