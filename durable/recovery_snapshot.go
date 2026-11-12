package durable

import (
	"crypto/sha256"
	"encoding/binary"

	jack "github.com/PHPCraftdream/mcp-jack"
	bolt "go.etcd.io/bbolt"
)

func loadRecoverySnapshot(tx *bolt.Tx, opts Options, snapshot *RecoverySnapshot) error {
	var report RecoverySnapshot
	var m metadata
	if err := readStoreSnapshot(tx, opts, false, &m); err != nil {
		return err
	}
	report = RecoverySnapshot{
		Version: formatVersion, DeploymentID: m.Deployment,
		StoreID:         jack.EncodeBase64URL(m.StoreID[:]),
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
	*snapshot = report
	return nil
}
