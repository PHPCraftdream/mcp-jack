package durable

import (
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
		return loadRecoverySnapshot(tx, opts, &report)
	})
	if err != nil {
		return RecoverySnapshot{}, err
	}
	return report, nil
}
