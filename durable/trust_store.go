package durable

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PHPCraftdream/mcp-jack/rotation"
	bolt "go.etcd.io/bbolt"
)

// TrustOptions задаются независимо от remote response и существующего DB.
type TrustOptions struct {
	Binding rotation.Binding
	Window int64
	Checkpoint rotation.Checkpoint
	Now func() int64
}

// TrustStore владеет отдельным lifetime-exclusive trust/clock domain.
type TrustStore struct {
	mu sync.Mutex
	db *bolt.DB
	file *os.File
	options TrustOptions
	identity trustGuard
	transact func(func(*bolt.Tx) error) error
	fenced atomic.Bool
	closing bool
	active sync.WaitGroup
	closeOnce sync.Once
	closeErr error
}

func trustError(code string) error { return &rotation.Error{Code: code} }

// Provider обязан ограничивать время callback; panic не раскрывается caller.
func sampleTrustNow(now func() int64) (sample int64, complete bool) {
	defer func() { if !complete { _ = recover() } }()
	sample = now()
	complete = true
	return sample, complete
}

func normalizedTrustOptions(options TrustOptions) (TrustOptions, []byte, [32]byte, error) {
	if options.Now == nil {
		options.Now = func() int64 { return time.Now().Unix() }
	}
	key := rotation.TrustKey{Ordinal: options.Checkpoint.Ordinal, KID: options.Checkpoint.KID, PublicKey: options.Checkpoint.PublicKey}
	if key.Ordinal != 0 {
		if options.Checkpoint.PublishedAt < 0 || options.Checkpoint.PublishedAt > rotation.MaxTimestamp-rotation.GraceSeconds {
			return options, nil, [32]byte{}, ErrInvalidStore
		}
		key.NotBefore = options.Checkpoint.PublishedAt + rotation.GraceSeconds
	}
	anchor := rotation.TrustSnapshot{
		FormatVersion: 1, Binding: options.Binding, Window: options.Window, Checkpoint: options.Checkpoint,
		Head: rotation.ResultCursor{Ordinal: options.Checkpoint.Ordinal, Hash: options.Checkpoint.Hash}, Keys: []rotation.TrustKey{key}, Revision: 1,
		Clock: rotation.ClockTuple{Binding: options.Binding, Window: options.Window},
	}
	encoded, err := rotation.EncodeTrustSnapshot(anchor, options.Binding, options.Window, options.Checkpoint)
	if err != nil {
		return options, nil, [32]byte{}, ErrInvalidStore
	}
	return options, encoded, sha256.Sum256(encoded), nil
}

func openTrustDB(path string, create bool) (*bolt.DB, *os.File, error) {
	if err := privateDirectory(path); err != nil {
		return nil, nil, err
	}
	options := dbOptions(create)
	open := options.OpenFile
	var file *os.File
	options.OpenFile = func(name string, flags int, mode os.FileMode) (*os.File, error) {
		opened, err := open(name, flags, mode)
		if err == nil { file = opened }
		return opened, err
	}
	db, err := bolt.Open(path, 0600, options)
	if err != nil { return nil, nil, ErrUnavailable }
	if file == nil { _ = db.Close(); return nil, nil, ErrUnavailable }
	return db, file, nil
}

// InitializeTrustUnused — только явное OOB создание нового binding, не восстановление.
func InitializeTrustUnused(path string, options TrustOptions) (result error) {
	options, encoded, profile, err := normalizedTrustOptions(options)
	if err != nil { return err }
	if err := privateDirectory(path); err != nil { return err }
	now, sampled := sampleTrustNow(options.Now)
	if !sampled { return ErrUnavailable }
	if now < 0 || now > rotation.MaxTimestamp { return ErrInvalidStore }
	var snapshot rotation.TrustSnapshot
	snapshot, err = rotation.DecodeTrustSnapshot(encoded, options.Binding, options.Window, options.Checkpoint)
	if err != nil { return ErrInvalidStore }
	snapshot.Clock.HighWater, snapshot.Clock.Revision = now, 1
	encoded, err = rotation.EncodeTrustSnapshot(snapshot, options.Binding, options.Window, options.Checkpoint)
	if err != nil { return ErrInvalidStore }
	guard := trustGuard{Profile: profile, Owner: 1, Dirty: true, Clock: snapshot.Clock}
	if _, err := rand.Read(guard.StoreID[:]); err != nil || guard.StoreID == [16]byte{} { return ErrUnavailable }
	db, file, err := openTrustDB(path, true)
	if err != nil { return err }
	defer func() { if db.Close() != nil { result = ErrUnavailable } }()
	if err := db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucket(trustBucket)
		if err != nil { return err }
		if err := bucket.Put(trustGuardKey, encodeTrustGuard(guard)); err != nil { return err }
		return bucket.Put(trustSnapshotKey, sealPayload(encoded))
	}); err != nil { return ErrUnavailable }
	if err := syncDirectory(filepath.Dir(path)); err != nil { return err }
	guard.Dirty = false
	if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket(trustBucket).Put(trustGuardKey, encodeTrustGuard(guard)) }); err != nil { return ErrUnavailable }
	if info, err := file.Stat(); err != nil || info.Size() > maxFileBytes { return ErrUnavailable }
	return nil
}

// OpenTrust не создаёт DB и не снимает dirty/fenced/unsafe при startup.
func OpenTrust(path string, options TrustOptions) (*TrustStore, error) {
	options, _, profile, err := normalizedTrustOptions(options)
	if err != nil { return nil, err }
	db, file, err := openTrustDB(path, false)
	if err != nil { return nil, err }
	store := &TrustStore{db: db, file: file, options: options, transact: db.Update}
	ready := false
	defer func() { if !ready { _ = db.Close() } }()
	var guardData, snapshotData []byte
	if err := db.View(func(tx *bolt.Tx) error {
		var err error
		guardData, snapshotData, err = readTrustRows(tx)
		return err
	}); err != nil { return nil, err }
	guard, err := decodeTrustGuard(guardData, options, profile)
	if err != nil { return nil, err }
	snapshot, err := rotation.DecodeTrustSnapshot(snapshotData, options.Binding, options.Window, options.Checkpoint)
	if err != nil { return nil, ErrInvalidStore }
	if guard.Dirty || guard.Fenced || guard.Clock.Unsafe || !rotation.TrustClockCompatible(snapshot, guard.Clock) { return nil, ErrRecoveryRequired }
	if guard.Owner == ^uint64(0) { return nil, ErrInvalidStore }
	guard.Owner++
	guard.Dirty = true
	store.identity = guard
	if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket(trustBucket).Put(trustGuardKey, encodeTrustGuard(guard)) }); err != nil { return nil, ErrUnavailable }
	if _, err := store.AdvanceAndCheck(); err != nil { return nil, err }
	ready = true
	return store, nil
}

func (store *TrustStore) begin() (func(), error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closing || store.fenced.Load() { return nil, ErrUnavailable }
	store.active.Add(1)
	return store.active.Done, nil
}

func (store *TrustStore) ownedGuard(tx *bolt.Tx) (trustGuard, error) {
	bucket := tx.Bucket(trustBucket)
	if bucket == nil { return trustGuard{}, ErrInvalidStore }
	guard, err := decodeTrustGuard(bucket.Get(trustGuardKey), store.options, store.identity.Profile)
	if err != nil || guard.StoreID != store.identity.StoreID || guard.Owner != store.identity.Owner || !guard.Dirty || guard.Fenced {
		return trustGuard{}, ErrInvalidStore
	}
	return guard, nil
}

func (store *TrustStore) failed() error {
	store.fenced.Store(true)
	return ErrUnavailable
}

// Close прекращает новые операции и не очищает dirty после неизвестного результата.
func (store *TrustStore) Close() error {
	store.closeOnce.Do(func() {
		store.mu.Lock(); store.closing = true; store.mu.Unlock()
		store.active.Wait()
		if !store.fenced.Load() {
			var snapshot rotation.TrustSnapshot
			var guard trustGuard
			var data []byte
			err := store.db.View(func(tx *bolt.Tx) error {
				var raw []byte
				var err error
				raw, data, err = readTrustRows(tx)
				if err != nil { return err }
				guard, err = decodeTrustGuard(raw, store.options, store.identity.Profile)
				return err
			})
			if err == nil { snapshot, err = rotation.DecodeTrustSnapshot(data, store.options.Binding, store.options.Window, store.options.Checkpoint) }
			if err == nil && !rotation.TrustClockCompatible(snapshot, guard.Clock) { err = ErrRecoveryRequired }
			if err == nil {
				err = store.transact(func(tx *bolt.Tx) error {
					current, err := store.ownedGuard(tx)
					if err != nil || current.Clock.Unsafe { return ErrInvalidStore }
					current.Dirty = false
					return tx.Bucket(trustBucket).Put(trustGuardKey, encodeTrustGuard(current))
				})
			}
			if err != nil { store.closeErr = store.failed() }
		}
		if store.fenced.Load() && store.closeErr == nil { store.closeErr = ErrUnavailable }
		if err := store.db.Close(); err != nil { store.closeErr = ErrUnavailable }
	})
	return store.closeErr
}

var errTrustConflict = errors.New("durable: exact trust or clock conflict")
