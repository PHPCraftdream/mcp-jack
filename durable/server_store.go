package durable

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/PHPCraftdream/mcp-jack/rotation"
	bolt "go.etcd.io/bbolt"
)

// ServerOptions — независимый OOB binding и protected anchor handle.
type ServerOptions struct {
	TrustOptions
	AnchorReference string
}

// ServerStore не владеет nonce/client domain и не разрешает serving без provider.
type ServerStore struct {
	mu        sync.Mutex
	db        *bolt.DB
	file      *os.File
	options   ServerOptions
	identity  trustGuard
	transact  func(func(*bolt.Tx) error) error
	fenced    atomic.Bool
	closing   bool
	active    sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

func normalizedServerOptions(options ServerOptions) (ServerOptions, []byte, [32]byte, error) {
	base, encoded, _, err := normalizedTrustOptions(options.TrustOptions)
	if err != nil {
		return options, nil, [32]byte{}, err
	}
	options.TrustOptions = base
	public, err := rotation.DecodeTrustSnapshot(encoded, base.Binding, base.Window, base.Checkpoint)
	if err != nil {
		return options, nil, [32]byte{}, ErrInvalidStore
	}
	initial := rotation.ServerSnapshot{FormatVersion: 1, Public: public, SignerReferences: []rotation.SignerReference{{KID: base.Checkpoint.KID, Reference: options.AnchorReference}}}
	encoded, err = rotation.EncodeServerSnapshot(initial, base.Binding, base.Window, base.Checkpoint)
	if err != nil {
		return options, nil, [32]byte{}, ErrInvalidStore
	}
	return options, encoded, sha256.Sum256(encoded), nil
}

// InitializeServerUnused не заменяет существующий store и не является recovery.
func InitializeServerUnused(path string, options ServerOptions) (result error) {
	options, encoded, profile, err := normalizedServerOptions(options)
	if err != nil {
		return err
	}
	if err := privateDirectory(path); err != nil {
		return err
	}
	now, sampled := sampleTrustNow(options.Now)
	if !sampled || now < 0 || now > rotation.MaxTimestamp {
		return ErrUnavailable
	}
	snapshot, err := rotation.DecodeServerSnapshot(encoded, options.Binding, options.Window, options.Checkpoint)
	if err != nil {
		return ErrInvalidStore
	}
	snapshot.Public.Clock.HighWater, snapshot.Public.Clock.Revision = now, 1
	encoded, err = rotation.EncodeServerSnapshot(snapshot, options.Binding, options.Window, options.Checkpoint)
	if err != nil {
		return ErrInvalidStore
	}
	guard := trustGuard{Profile: profile, Owner: 1, Dirty: true, Clock: snapshot.Public.Clock}
	if _, err := rand.Read(guard.StoreID[:]); err != nil || guard.StoreID == [16]byte{} {
		return ErrUnavailable
	}
	db, file, err := openTrustDB(path, true)
	if err != nil {
		return err
	}
	defer func() {
		if db.Close() != nil {
			result = ErrUnavailable
		}
	}()
	if err := db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucket(serverBucket)
		if err != nil {
			return err
		}
		if err := bucket.Put(serverGuardKey, encodeServerGuard(guard)); err != nil {
			return err
		}
		if err := bucket.Put(serverSnapshotKey, sealPayload(encoded)); err != nil {
			return err
		}
		return bucket.Put(serverIntentKey, []byte{})
	}); err != nil {
		return ErrUnavailable
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if info, err := file.Stat(); err != nil || info.Size() > maxFileBytes {
		return ErrUnavailable
	}
	guard.Dirty = false
	if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket(serverBucket).Put(serverGuardKey, encodeServerGuard(guard)) }); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (store *ServerStore) validateRows(tx *bolt.Tx) (rotation.ServerSnapshot, trustGuard, error) {
	raw, encoded, intent, err := readServerRows(tx)
	if err != nil {
		return rotation.ServerSnapshot{}, trustGuard{}, err
	}
	guard, err := decodeServerGuard(raw, store.options.TrustOptions, store.identity.Profile)
	if err != nil {
		return rotation.ServerSnapshot{}, trustGuard{}, err
	}
	snapshot, err := rotation.DecodeServerSnapshot(encoded, store.options.Binding, store.options.Window, store.options.Checkpoint)
	if err != nil || !rotation.TrustClockCompatible(snapshot.Public, guard.Clock) {
		return rotation.ServerSnapshot{}, guard, ErrRecoveryRequired
	}
	if len(intent) == 0 && (len(snapshot.Public.Records) != 0 || snapshot.Public.Revision != 1) {
		return rotation.ServerSnapshot{}, guard, ErrInvalidStore
	}
	if len(intent) != 0 {
		previous, next, err := decodeServerIntent(intent)
		if err != nil || !bytes.Equal(next, encoded) {
			return rotation.ServerSnapshot{}, guard, ErrInvalidStore
		}
		before, err := rotation.DecodeServerSnapshot(previous, store.options.Binding, store.options.Window, store.options.Checkpoint)
		if err != nil {
			return rotation.ServerSnapshot{}, guard, ErrInvalidStore
		}
		if _, err := rotation.ValidateServerPublication(before, snapshot, store.options.Binding, store.options.Window, store.options.Checkpoint); err != nil {
			return rotation.ServerSnapshot{}, guard, ErrInvalidStore
		}
	}
	return snapshot, guard, nil
}

// OpenServer не очищает dirty/unknown; signer readiness проверяется отдельно provider.
func OpenServer(path string, options ServerOptions) (*ServerStore, error) {
	options, _, profile, err := normalizedServerOptions(options)
	if err != nil {
		return nil, err
	}
	db, file, err := openTrustDB(path, false)
	if err != nil {
		return nil, err
	}
	store := &ServerStore{db: db, file: file, options: options, transact: db.Update, identity: trustGuard{Profile: profile}}
	ready := false
	defer func() {
		if !ready {
			_ = db.Close()
		}
	}()
	var guard trustGuard
	if err := db.View(func(tx *bolt.Tx) error { var err error; _, guard, err = store.validateRows(tx); return err }); err != nil {
		return nil, err
	}
	if guard.Dirty || guard.Fenced || guard.Clock.Unsafe {
		return nil, ErrRecoveryRequired
	}
	if guard.Owner == ^uint64(0) {
		return nil, ErrInvalidStore
	}
	guard.Owner++
	guard.Dirty = true
	store.identity = guard
	if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket(serverBucket).Put(serverGuardKey, encodeServerGuard(guard)) }); err != nil {
		return nil, ErrUnavailable
	}
	if _, err := store.AdvanceAndCheck(); err != nil {
		return nil, err
	}
	ready = true
	return store, nil
}

func (store *ServerStore) begin() (func(), error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closing || store.fenced.Load() {
		return nil, ErrUnavailable
	}
	store.active.Add(1)
	return store.active.Done, nil
}

func (store *ServerStore) ownedGuard(tx *bolt.Tx) (trustGuard, error) {
	bucket := tx.Bucket(serverBucket)
	if bucket == nil {
		return trustGuard{}, ErrInvalidStore
	}
	guard, err := decodeServerGuard(bucket.Get(serverGuardKey), store.options.TrustOptions, store.identity.Profile)
	if err != nil || guard.StoreID != store.identity.StoreID || guard.Owner != store.identity.Owner || !guard.Dirty || guard.Fenced {
		return trustGuard{}, ErrInvalidStore
	}
	return guard, nil
}

func (store *ServerStore) failed() error { store.fenced.Store(true); return ErrUnavailable }
func (store *ServerStore) Fence()        { store.fenced.Store(true) }

// Close дожидается store operations; будущий provider обязан удерживать lease до wire completion.
func (store *ServerStore) Close() error {
	store.closeOnce.Do(func() {
		store.mu.Lock()
		store.closing = true
		store.mu.Unlock()
		store.active.Wait()
		if !store.fenced.Load() {
			err := store.transact(func(tx *bolt.Tx) error {
				if _, _, err := store.validateRows(tx); err != nil {
					return err
				}
				guard, err := store.ownedGuard(tx)
				if err != nil || guard.Clock.Unsafe {
					return ErrRecoveryRequired
				}
				guard.Dirty = false
				return tx.Bucket(serverBucket).Put(serverGuardKey, encodeServerGuard(guard))
			})
			if err != nil {
				store.closeErr = store.failed()
			}
		}
		if store.fenced.Load() {
			store.closeErr = ErrUnavailable
		}
		if store.db.Close() != nil {
			store.closeErr = ErrUnavailable
		}
	})
	return store.closeErr
}
