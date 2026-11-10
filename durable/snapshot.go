package durable

import bolt "go.etcd.io/bbolt"

// Serving требует ready; recovery inspection всё равно проверяет полный graph.
func readStoreSnapshot(tx *bolt.Tx, opts Options, requireReady bool, snapshot *metadata) error {
	var m metadata
	var found int
	if err := tx.ForEach(func(name []byte, bucket *bolt.Bucket) error {
		if bucket == nil {
			return ErrInvalidStore
		}
		known := false
		for _, expected := range bucketNames {
			if string(name) == expected {
				known = true
				break
			}
		}
		if !known {
			return ErrInvalidStore
		}
		found++
		return nil
	}); err != nil || found != len(bucketNames) {
		return ErrInvalidStore
	}
	header := tx.Bucket([]byte("metadata"))
	if err := header.ForEach(func(key, value []byte) error {
		if string(key) != string(headerKey) || value == nil {
			return ErrInvalidStore
		}
		return nil
	}); err != nil {
		return err
	}
	var err error
	m, err = decodeMetadata(header.Get(headerKey))
	if err != nil {
		return err
	}
	if m.Deployment != opts.DeploymentID || m.Window != opts.Window || m.Owner == ^uint64(0) {
		return ErrInvalidStore
	}
	if requireReady && (m.Dirty || m.Unsafe) {
		return ErrRecoveryRequired
	}
	if err := validateRows(tx, m); err != nil {
		return err
	}
	if requireReady && (m.Intents != 0 || m.Tombstones >= 64) {
		return ErrRecoveryRequired
	}
	var invalid bool
	for checkErr := range tx.Check() {
		if checkErr != nil {
			invalid = true
		}
	}
	if invalid {
		return ErrInvalidStore
	}
	*snapshot = m
	return nil
}
