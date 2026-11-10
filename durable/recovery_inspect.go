package durable

import (
	"crypto/sha256"
	"encoding/binary"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
	bolt "go.etcd.io/bbolt"
)

// RecoverySnapshot — owned diagnostic values, не admission receipt и не разрешение reopen.
// Hash связывает полный logical graph; это не MAC и не доказательство отсутствия rollback.
type RecoverySnapshot struct {
	Version         uint32
	DeploymentID    string
	StoreID         string
	StoreGeneration uint64
	OwnerGeneration uint64
	Window          int64
	HighWater       int64
	Dirty           bool
	Unsafe          bool
	Hash            string
	Live            []server.NonceReceipt
	Intents         []server.NonceReceipt
	Tombstones      []server.NonceReceipt
}

// InspectRecovery не создаёт store, не вызывает Now и не меняет metadata/history.
// Exclusive owner lock обязателен даже для inspection; serving admission не открывается.
func InspectRecovery(path string, opts Options) (report RecoverySnapshot, result error) {
	opts, err := normalizedOptions(opts)
	if err != nil {
		return report, err
	}
	if err := privateDirectory(path); err != nil {
		return report, err
	}
	db, err := bolt.Open(path, 0600, dbOptions(false))
	if err != nil {
		return report, ErrUnavailable
	}
	defer func() {
		if err := db.Close(); err != nil {
			report = RecoverySnapshot{}
			result = ErrUnavailable
		}
	}()
	err = db.View(func(tx *bolt.Tx) error {
		var m metadata
		if err := readStoreSnapshot(tx, opts, false, &m); err != nil {
			return err
		}
		report = RecoverySnapshot{
			Version: formatVersion, DeploymentID: m.Deployment,
			StoreID: jack.EncodeBase64URL(m.StoreID[:]),
			StoreGeneration: m.Generation, OwnerGeneration: m.Owner,
			Window: m.Window, HighWater: m.HighWater,
			Dirty: m.Dirty, Unsafe: m.Unsafe,
		}
		// Length framing исключает неоднозначность между именами, ключами и значениями.
		hash := sha256.New()
		_, _ = hash.Write([]byte("mcp-jack/durable-nonce/recovery-snapshot/v1\n"))
		field := func(value []byte) {
			var length [4]byte
			binary.BigEndian.PutUint32(length[:], uint32(len(value)))
			_, _ = hash.Write(length[:])
			_, _ = hash.Write(value)
		}
		for _, name := range bucketNames {
			_, _ = hash.Write([]byte{0})
			field([]byte(name))
			bucket := tx.Bucket([]byte(name))
			if err := bucket.ForEach(func(key, value []byte) error {
				if bucket.Bucket(key) != nil || len(key) > maxFileBytes || len(value) > maxFileBytes {
					return ErrInvalidStore
				}
				_, _ = hash.Write([]byte{1})
				field(key)
				field(value)
				if name != "live" && name != "intent" && name != "tombstone" {
					return nil
				}
				row, err := decodeRecord(value, m)
				if err != nil {
					return err
				}
				switch name {
				case "live":
					report.Live = append(report.Live, row.receipt)
				case "intent":
					report.Intents = append(report.Intents, row.receipt)
				case "tombstone":
					report.Tombstones = append(report.Tombstones, row.receipt)
				}
				return nil
			}); err != nil {
				return err
			}
		}
		report.Hash = jack.EncodeBase64URL(hash.Sum(nil))
		return nil
	})
	if err != nil {
		return RecoverySnapshot{}, err
	}
	return report, nil
}
