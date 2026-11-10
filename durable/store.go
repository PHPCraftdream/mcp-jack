// Package durable содержит transactional backend с единственным lifetime owner.
// Поддержка filesystem и crash recovery требует отдельных qualification gates.
package durable

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	bolt "go.etcd.io/bbolt"
)

var (
	ErrUnavailable      = errors.New("durable: store unavailable")
	ErrInvalidStore     = errors.New("durable: invalid store")
	ErrRecoveryRequired = errors.New("durable: explicit recovery required")
	ErrUnsupported      = errors.New("durable: unsupported platform or filesystem")
)

// Options связывает backend с независимо заданным deployment и immutable W.
type Options struct {
	DeploymentID string
	Window       int64
	Now          func() int64
}

// Store удерживает exclusive bbolt lock; handle никогда не экспортируется.
type Store struct {
	mu        sync.Mutex
	db        *bolt.DB
	meta      metadata
	opts      Options
	fenced    atomic.Bool
	closing   atomic.Bool
	closed    atomic.Bool
	leases    sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

func normalizedOptions(opts Options) (Options, error) {
	if !utf8.ValidString(opts.DeploymentID) || len(opts.DeploymentID) == 0 || len(opts.DeploymentID) > 1024 || opts.Window < 1 || opts.Window > 120 {
		return opts, ErrInvalidStore
	}
	if opts.Now == nil {
		opts.Now = func() int64 { return time.Now().Unix() }
	}
	return opts, nil
}

func dbOptions(create bool) *bolt.Options {
	return &bolt.Options{
		Timeout:  time.Second,
		PageSize: pageBytes,
		MaxSize:  maxFileBytes,
		OpenFile: func(name string, flags int, mode os.FileMode) (*os.File, error) {
			flags &^= os.O_CREATE | os.O_TRUNC
			if create {
				flags |= os.O_CREATE | os.O_EXCL
			}
			return openPrivateFile(name, flags, mode, create)
		},
	}
}

// InitializeUnused — отдельная OOB операция только для доказанно неиспользованного
// deployment. Не мигрирует volatile history и никогда не заменяет существующий файл.
// При неизвестной ошибке файл сохраняется для recovery, а не удаляется/создаётся заново.
func InitializeUnused(path string, opts Options) error {
	return initializeUnused(path, opts, syncDirectory)
}

func syncDirectory(path string) error {
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

func initializeUnused(path string, opts Options, syncParent func(string) error) error {
	opts, err := normalizedOptions(opts)
	if err != nil {
		return err
	}
	if err := privateDirectory(path); err != nil {
		return err
	}
	now := opts.Now()
	if now < 0 || now > maxTimestamp {
		return ErrInvalidStore
	}
	m := metadata{Deployment: opts.DeploymentID, Generation: 1, Owner: 1, Window: opts.Window, HighWater: now, Dirty: true}
	if _, err := rand.Read(m.StoreID[:]); err != nil || m.StoreID == [16]byte{} {
		return ErrUnavailable
	}
	db, err := bolt.Open(path, 0600, dbOptions(true))
	if err != nil {
		return ErrUnavailable
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range bucketNames {
			if _, err := tx.CreateBucket([]byte(name)); err != nil {
				return err
			}
		}
		return tx.Bucket([]byte("metadata")).Put(headerKey, encodeMetadata(m))
	})
	if err != nil {
		_ = db.Close()
		return ErrUnavailable
	}
	if err := syncParent(filepath.Dir(path)); err != nil {
		_ = db.Close()
		return ErrUnavailable
	}
	m.Dirty = false
	if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("metadata")).Put(headerKey, encodeMetadata(m)) }); err != nil {
		_ = db.Close()
		return ErrUnavailable
	}
	if err := db.Close(); err != nil {
		return ErrUnavailable
	}
	return nil
}

// Open открывает только существующий initialized store без implicit create/reset.
// Dirty/unsafe startup всегда закрыт до отдельной явной recovery операции.
func Open(path string, opts Options) (*Store, error) {
	return openStore(path, opts, dbOptions(false))
}

func openStore(path string, opts Options, options *bolt.Options) (*Store, error) {
	opts, err := normalizedOptions(opts)
	if err != nil {
		return nil, err
	}
	if err := privateDirectory(path); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0600, options)
	if err != nil {
		return nil, ErrUnavailable
	}
	handedOff := false
	defer func() {
		if !handedOff {
			_ = db.Close()
		}
	}()
	var m metadata
	err = db.View(func(tx *bolt.Tx) error {
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
		if m.Dirty || m.Unsafe {
			return ErrRecoveryRequired
		}
		// Пока доступны только ownership/initialization операции, populated rows
		// требуют ещё не доставленного reservation/recovery codec, а не reset.
		for _, name := range bucketNames[1:] {
			key, _ := tx.Bucket([]byte(name)).Cursor().First()
			if key != nil {
				return ErrInvalidStore
			}
		}
		if m.Live != 0 || m.Intents != 0 || m.Tombstones != 0 {
			return ErrInvalidStore
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
		return nil
	})
	if err != nil {
		return nil, err
	}
	m.Owner++
	m.Dirty = true
	if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("metadata")).Put(headerKey, encodeMetadata(m)) }); err != nil {
		return nil, ErrUnavailable
	}
	// Сначала подтверждаем dirty marker, затем наблюдаем startup clock.
	// Неопределённый unsafe-latch больше не может открыть clean restart.
	now := opts.Now()
	if now < 0 || now > maxTimestamp || now < m.HighWater {
		m.Unsafe = true
		_ = db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("metadata")).Put(headerKey, encodeMetadata(m)) })
		return nil, ErrRecoveryRequired
	}
	m.HighWater = now
	if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("metadata")).Put(headerKey, encodeMetadata(m)) }); err != nil {
		return nil, ErrUnavailable
	}
	owner := &Store{db: db, meta: m, opts: opts}
	handedOff = true
	return owner, nil
}

// Fence не ждёт leases и не повторяет uncertain transaction.
// Уже подтверждённый dirty marker закрывает следующий startup.
func (s *Store) Fence() { s.fenced.Store(true) }

// Close прекращает admission, дожидается leases и очищает dirty только без fence.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closing.Store(true)
		s.mu.Unlock()
		s.leases.Wait()
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.fenced.Load() {
			m := s.meta
			m.Dirty = false
			if err := s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("metadata")).Put(headerKey, encodeMetadata(m)) }); err != nil {
				s.fenced.Store(true)
				s.closeErr = ErrUnavailable
			}
		}
		if err := s.db.Close(); err != nil {
			s.closeErr = ErrUnavailable
		}
		s.closed.Store(true)
	})
	return s.closeErr
}
