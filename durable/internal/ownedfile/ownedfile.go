package ownedfile

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	ErrUnavailable      = errors.New("durable: store unavailable")
	ErrInvalidStore     = errors.New("durable: invalid store")
	ErrRecoveryRequired = errors.New("durable: explicit recovery required")
	ErrUnsupported      = errors.New("durable: unsupported platform or filesystem")
)

const (
	MaxFileBytes = 16 << 20
	PageBytes    = 4096
)

func DBOptions(create bool) *bolt.Options {
	return &bolt.Options{
		Timeout:  time.Second,
		PageSize: PageBytes,
		MaxSize:  MaxFileBytes,
		OpenFile: func(name string, flags int, mode os.FileMode) (*os.File, error) {
			flags &^= os.O_CREATE | os.O_TRUNC
			if create {
				flags |= os.O_CREATE | os.O_EXCL
			}
			return openPrivateFile(name, flags, mode, create)
		},
	}
}

func SyncDirectory(path string) error {
	parent, err := os.Open(path)
	if err != nil {
		return ErrUnavailable
	}
	syncErr := parent.Sync()
	closeErr := parent.Close()
	if syncErr != nil || closeErr != nil {
		return ErrUnavailable
	}
	return nil
}

// Checksum detects accidental corruption, not malicious-host tampering or backup rollback.
func SealPayload(payload []byte) []byte {
	sum := sha256.Sum256(payload)
	return append(payload, sum[:]...)
}

func CheckedPayload(data []byte) ([]byte, error) {
	if len(data) < sha256.Size {
		return nil, ErrInvalidStore
	}
	payload := data[:len(data)-sha256.Size]
	sum := sha256.Sum256(payload)
	if !bytes.Equal(sum[:], data[len(payload):]) {
		return nil, ErrInvalidStore
	}
	return payload, nil
}

func OpenDB(path string, create bool) (*bolt.DB, *os.File, error) {
	if err := PrivateDirectory(path); err != nil {
		return nil, nil, err
	}
	options := DBOptions(create)
	open := options.OpenFile
	var file *os.File
	options.OpenFile = func(name string, flags int, mode os.FileMode) (*os.File, error) {
		opened, err := open(name, flags, mode)
		if err == nil {
			file = opened
		}
		return opened, err
	}
	db, err := bolt.Open(path, 0600, options)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	if file == nil {
		_ = db.Close()
		return nil, nil, ErrUnavailable
	}
	return db, file, nil
}
