package durable

import (
	"github.com/PHPCraftdream/mcp-jack/server"
	bolt "go.etcd.io/bbolt"
)

// RecoverySnapshot holds owned diagnostic values; it is not an admission receipt or permission to reopen.
// Hash binds the full logical graph; it is not a MAC and not proof of absence of rollback.
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

// InspectRecovery does not create a store, call Now, or change metadata/history.
// The exclusive owner lock is required even for inspection; serving admission is not opened.
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
