package rotationstore

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PHPCraftdream/mcp-jack/durable/internal/ownedfile"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	bolt "go.etcd.io/bbolt"
)

var trustBucket = []byte("client-trust-v1")
var trustGuardKey = []byte("guard")
var trustSnapshotKey = []byte("snapshot")
var trustGuardMagic = []byte("mcp-jack/client-trust/guard/v1\n")

type trustGuard struct {
	StoreID [16]byte
	Profile [32]byte
	Owner   uint64
	Dirty   bool
	Fenced  bool
	Clock   rotation.ClockTuple
}

func encodeTrustGuard(guard trustGuard) []byte {
	var out bytes.Buffer
	out.Write(trustGuardMagic)
	out.Write(guard.StoreID[:])
	out.Write(guard.Profile[:])
	for _, number := range []uint64{guard.Owner, uint64(guard.Clock.Window), uint64(guard.Clock.HighWater), guard.Clock.Revision} {
		_ = binary.Write(&out, binary.BigEndian, number)
	}
	var flags byte
	if guard.Dirty {
		flags |= 1
	}
	if guard.Fenced {
		flags |= 2
	}
	if guard.Clock.Unsafe {
		flags |= 4
	}
	out.WriteByte(flags)
	return ownedfile.SealPayload(out.Bytes())
}

func decodeTrustGuard(data []byte, options TrustOptions, profile [32]byte) (trustGuard, error) {
	var guard trustGuard
	payload, err := ownedfile.CheckedPayload(data)
	if err != nil || len(payload) != len(trustGuardMagic)+16+32+32+1 || !bytes.HasPrefix(payload, trustGuardMagic) {
		return guard, ownedfile.ErrInvalidStore
	}
	position := len(trustGuardMagic)
	copy(guard.StoreID[:], payload[position:position+16])
	position += 16
	copy(guard.Profile[:], payload[position:position+32])
	position += 32
	guard.Owner = binary.BigEndian.Uint64(payload[position:])
	position += 8
	window := binary.BigEndian.Uint64(payload[position:])
	position += 8
	highWater := binary.BigEndian.Uint64(payload[position:])
	position += 8
	revision := binary.BigEndian.Uint64(payload[position:])
	position += 8
	flags := payload[position]
	if guard.StoreID == [16]byte{} || guard.Profile != profile || guard.Owner == 0 || window != uint64(options.Window) || highWater > uint64(rotation.MaxTimestamp) || revision > rotation.MaxOrdinal || flags&^7 != 0 {
		return trustGuard{}, ownedfile.ErrInvalidStore
	}
	guard.Dirty, guard.Fenced = flags&1 != 0, flags&2 != 0
	guard.Clock = rotation.ClockTuple{Binding: options.Binding, Window: options.Window, HighWater: int64(highWater), Revision: revision, Unsafe: flags&4 != 0}
	return guard, nil
}

func readTrustRows(tx *bolt.Tx) ([]byte, []byte, error) {
	rootCount := 0
	if err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		rootCount++
		if !bytes.Equal(name, trustBucket) {
			return ownedfile.ErrInvalidStore
		}
		return nil
	}); err != nil || rootCount != 1 {
		return nil, nil, ownedfile.ErrInvalidStore
	}
	bucket := tx.Bucket(trustBucket)
	if bucket == nil {
		return nil, nil, ownedfile.ErrInvalidStore
	}
	count := 0
	cursor := bucket.Cursor()
	for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
		if value == nil || (!bytes.Equal(key, trustGuardKey) && !bytes.Equal(key, trustSnapshotKey)) {
			return nil, nil, ownedfile.ErrInvalidStore
		}
		count++
	}
	if count != 2 {
		return nil, nil, ownedfile.ErrInvalidStore
	}
	corrupt := false
	for err := range tx.Check() {
		if err != nil {
			corrupt = true
		}
	}
	if corrupt {
		return nil, nil, ownedfile.ErrInvalidStore
	}
	guard := append([]byte(nil), bucket.Get(trustGuardKey)...)
	encoded := bucket.Get(trustSnapshotKey)
	if len(encoded) > rotation.MaxTrustSnapshotBytes+32 {
		return nil, nil, ownedfile.ErrInvalidStore
	}
	payload, err := ownedfile.CheckedPayload(encoded)
	if err != nil {
		return nil, nil, err
	}
	return guard, append([]byte(nil), payload...), nil
}

// RawClock is only a sample for outer checks, not a durable time authority.
func (store *TrustStore) RawClock() (int64, error) {
	done, err := store.begin()
	if err != nil {
		return 0, err
	}
	defer done()
	now, sampled := sampleTrustNow(store.options.Now)
	if !sampled || store.fenced.Load() {
		return 0, store.failed()
	}
	return now, nil
}

// AdvanceAndCheck is the only operation that changes authoritative H/revision/unsafe.
func (store *TrustStore) AdvanceAndCheck() (rotation.ClockTuple, error) {
	return store.advanceTrustClock(nil)
}

// CheckSnapshotClock atomically checks the whole trust together with a fresh guard operation.
func (store *TrustStore) CheckSnapshotClock(expected rotation.TrustSnapshot) (rotation.ClockTuple, error) {
	encoded, err := rotation.EncodeTrustSnapshot(expected, store.options.Binding, store.options.Window, store.options.Checkpoint)
	if err != nil {
		return rotation.ClockTuple{}, err
	}
	return store.advanceTrustClock(encoded)
}

func (store *TrustStore) advanceTrustClock(expected []byte) (rotation.ClockTuple, error) {
	done, err := store.begin()
	if err != nil {
		return rotation.ClockTuple{}, trustError("rotation_clock_unavailable")
	}
	defer done()
	var result rotation.ClockTuple
	conflict := false
	err = store.write(func(tx *bolt.Tx) error {
		guard, err := store.ownedGuard(tx)
		if err != nil {
			return err
		}
		if expected != nil {
			payload, err := ownedfile.CheckedPayload(tx.Bucket(trustBucket).Get(trustSnapshotKey))
			if err != nil {
				return err
			}
			conflict = !bytes.Equal(payload, expected)
		}
		result = guard.Clock
		if result.Unsafe {
			return nil
		}
		now, sampled := sampleTrustNow(store.options.Now)
		if !sampled {
			return ownedfile.ErrUnavailable
		}
		unsafe := now < result.HighWater || now < 0 || now > rotation.MaxTimestamp
		if !unsafe && now == result.HighWater {
			return nil
		}
		if result.Revision == rotation.MaxOrdinal {
			return ownedfile.ErrUnavailable
		}
		result.Revision++
		if unsafe {
			result.Unsafe = true
		} else {
			result.HighWater = now
		}
		guard.Clock = result
		return tx.Bucket(trustBucket).Put(trustGuardKey, encodeTrustGuard(guard))
	})
	if err != nil {
		store.failed()
		return rotation.ClockTuple{}, trustError("rotation_clock_unavailable")
	}
	if info, err := store.file.Stat(); err != nil || info.Size() > ownedfile.MaxFileBytes {
		store.failed()
		return rotation.ClockTuple{}, trustError("rotation_clock_unavailable")
	}
	if store.fenced.Load() {
		return rotation.ClockTuple{}, trustError("rotation_clock_unavailable")
	}
	if result.Unsafe {
		return rotation.ClockTuple{}, trustError("rotation_clock_unsafe")
	}
	if conflict {
		return rotation.ClockTuple{}, trustError("rotation_state_changed")
	}
	return result, nil
}

// Snapshot reads committed state; it does not perform a fresh clock operation or ACK.
func (store *TrustStore) Snapshot() (rotation.TrustSnapshot, rotation.ClockTuple, error) {
	done, err := store.begin()
	if err != nil {
		return rotation.TrustSnapshot{}, rotation.ClockTuple{}, err
	}
	defer done()
	var data []byte
	var guard trustGuard
	err = store.viewChecked(func(tx *bolt.Tx) error {
		var raw []byte
		var err error
		raw, data, err = readTrustRows(tx)
		if err != nil {
			return err
		}
		guard, err = store.ownedGuard(tx)
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, encodeTrustGuard(guard)) {
			return ownedfile.ErrInvalidStore
		}
		return nil
	})
	if err != nil {
		return rotation.TrustSnapshot{}, rotation.ClockTuple{}, store.failed()
	}
	snapshot, err := rotation.DecodeTrustSnapshot(data, store.options.Binding, store.options.Window, store.options.Checkpoint)
	if err != nil || !rotation.TrustClockCompatible(snapshot, guard.Clock) {
		return rotation.TrustSnapshot{}, rotation.ClockTuple{}, store.failed()
	}
	if store.fenced.Load() {
		return rotation.TrustSnapshot{}, rotation.ClockTuple{}, ownedfile.ErrUnavailable
	}
	return snapshot, guard.Clock, nil
}

// CompareAndSwap changes the whole trust exactly once, leaving guard bytes unchanged.
func (store *TrustStore) CompareAndSwap(expected, desired rotation.TrustSnapshot, clock rotation.ClockTuple) error {
	previous, err := rotation.EncodeTrustSnapshot(expected, store.options.Binding, store.options.Window, store.options.Checkpoint)
	if err != nil {
		return err
	}
	next, err := rotation.EncodeTrustSnapshot(desired, store.options.Binding, store.options.Window, store.options.Checkpoint)
	if err != nil {
		return err
	}
	if expected.Revision == rotation.MaxOrdinal || desired.Revision != expected.Revision+1 || expected.Fenced || desired.Fenced || desired.Clock != clock ||
		!rotation.TrustClockCompatible(expected, clock) || len(desired.Records) <= len(expected.Records) {
		return trustError("rotation_state_changed")
	}
	for index, wire := range expected.Records {
		if desired.Records[index] != wire {
			return trustError("rotation_state_changed")
		}
	}
	done, err := store.begin()
	if err != nil {
		return err
	}
	defer done()
	err = store.write(func(tx *bolt.Tx) error {
		guard, err := store.ownedGuard(tx)
		if err != nil {
			return err
		}
		if guard.Clock != clock || guard.Clock.Unsafe {
			return errTrustConflict
		}
		bucket := tx.Bucket(trustBucket)
		payload, err := ownedfile.CheckedPayload(bucket.Get(trustSnapshotKey))
		if err != nil {
			return err
		}
		if !bytes.Equal(payload, previous) {
			return errTrustConflict
		}
		return bucket.Put(trustSnapshotKey, ownedfile.SealPayload(next))
	})
	if errors.Is(err, errTrustConflict) {
		return trustError("rotation_state_changed")
	}
	if err != nil {
		store.failed()
		return trustError("rotation_state_unknown")
	}
	if info, err := store.file.Stat(); err != nil || info.Size() > ownedfile.MaxFileBytes {
		store.failed()
		return trustError("rotation_state_unknown")
	}
	if store.fenced.Load() {
		return trustError("rotation_state_unknown")
	}
	return nil
}

// Fence closes the current owner; a previously confirmed dirty marker blocks restart.
func (store *TrustStore) Fence() { store.fenced.Store(true) }

// TrustOptions are specified independently of the remote response and the existing DB.
type TrustOptions struct {
	Binding    rotation.Binding
	Window     int64
	Checkpoint rotation.Checkpoint
	// Now is a plain clock sample: the store calls it with its write lock held, so it must not call back into the store.
	Now func() int64
}

// TrustStore owns a separate lifetime-exclusive trust/clock domain.
type TrustStore struct {
	mu        sync.Mutex
	check     sync.RWMutex
	db        *bolt.DB
	file      *os.File
	options   TrustOptions
	identity  trustGuard
	transact  func(func(*bolt.Tx) error) error
	fenced    atomic.Bool
	closing   bool
	active    sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

func trustError(code string) error { return &rotation.Error{Code: code} }

// Provider must bound callback time; a panic is not exposed to the caller.
func sampleTrustNow(now func() int64) (sample int64, complete bool) {
	defer func() {
		if !complete {
			_ = recover()
		}
	}()
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
			return options, nil, [32]byte{}, ownedfile.ErrInvalidStore
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
		return options, nil, [32]byte{}, ownedfile.ErrInvalidStore
	}
	return options, encoded, sha256.Sum256(encoded), nil
}

// InitializeTrustUnused is only explicit OOB creation of a new binding, not recovery.
func InitializeTrustUnused(path string, options TrustOptions) (result error) {
	options, encoded, profile, err := normalizedTrustOptions(options)
	if err != nil {
		return err
	}
	if err := ownedfile.PrivateDirectory(path); err != nil {
		return err
	}
	now, sampled := sampleTrustNow(options.Now)
	if !sampled {
		return ownedfile.ErrUnavailable
	}
	if now < 0 || now > rotation.MaxTimestamp {
		return ownedfile.ErrInvalidStore
	}
	var snapshot rotation.TrustSnapshot
	snapshot, err = rotation.DecodeTrustSnapshot(encoded, options.Binding, options.Window, options.Checkpoint)
	if err != nil {
		return ownedfile.ErrInvalidStore
	}
	snapshot.Clock.HighWater, snapshot.Clock.Revision = now, 1
	encoded, err = rotation.EncodeTrustSnapshot(snapshot, options.Binding, options.Window, options.Checkpoint)
	if err != nil {
		return ownedfile.ErrInvalidStore
	}
	guard := trustGuard{Profile: profile, Owner: 1, Dirty: true, Clock: snapshot.Clock}
	if _, err := rand.Read(guard.StoreID[:]); err != nil || guard.StoreID == [16]byte{} {
		return ownedfile.ErrUnavailable
	}
	db, file, err := ownedfile.OpenDB(path, true)
	if err != nil {
		return err
	}
	defer func() {
		if db.Close() != nil {
			result = ownedfile.ErrUnavailable
		}
	}()
	if err := db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucket(trustBucket)
		if err != nil {
			return err
		}
		if err := bucket.Put(trustGuardKey, encodeTrustGuard(guard)); err != nil {
			return err
		}
		return bucket.Put(trustSnapshotKey, ownedfile.SealPayload(encoded))
	}); err != nil {
		return ownedfile.ErrUnavailable
	}
	if err := ownedfile.SyncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	guard.Dirty = false
	if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket(trustBucket).Put(trustGuardKey, encodeTrustGuard(guard)) }); err != nil {
		return ownedfile.ErrUnavailable
	}
	if info, err := file.Stat(); err != nil || info.Size() > ownedfile.MaxFileBytes {
		return ownedfile.ErrUnavailable
	}
	return nil
}

// OpenTrust does not create a DB and does not clear dirty/fenced/unsafe at startup.
func OpenTrust(path string, options TrustOptions) (*TrustStore, error) {
	options, _, profile, err := normalizedTrustOptions(options)
	if err != nil {
		return nil, err
	}
	db, file, err := ownedfile.OpenDB(path, false)
	if err != nil {
		return nil, err
	}
	store := &TrustStore{db: db, file: file, options: options, transact: db.Update}
	ready := false
	defer func() {
		if !ready {
			_ = db.Close()
		}
	}()
	var guardData, snapshotData []byte
	if err := db.View(func(tx *bolt.Tx) error {
		var err error
		guardData, snapshotData, err = readTrustRows(tx)
		return err
	}); err != nil {
		return nil, err
	}
	guard, err := decodeTrustGuard(guardData, options, profile)
	if err != nil {
		return nil, err
	}
	snapshot, err := rotation.DecodeTrustSnapshot(snapshotData, options.Binding, options.Window, options.Checkpoint)
	if err != nil {
		return nil, ownedfile.ErrInvalidStore
	}
	if guard.Dirty || guard.Fenced || guard.Clock.Unsafe || !rotation.TrustClockCompatible(snapshot, guard.Clock) {
		return nil, ownedfile.ErrRecoveryRequired
	}
	if guard.Owner == ^uint64(0) {
		return nil, ownedfile.ErrInvalidStore
	}
	guard.Owner++
	guard.Dirty = true
	store.identity = guard
	if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket(trustBucket).Put(trustGuardKey, encodeTrustGuard(guard)) }); err != nil {
		return nil, ownedfile.ErrUnavailable
	}
	if _, err := store.AdvanceAndCheck(); err != nil {
		return nil, err
	}
	ready = true
	return store, nil
}

func (store *TrustStore) begin() (func(), error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closing || store.fenced.Load() {
		return nil, ownedfile.ErrUnavailable
	}
	store.active.Add(1)
	return store.active.Done, nil
}

// read-only Check is unsafe while a writer commits (bbolt tx_check.go); the
// write side serializes committing transactions against views that reach it.
func (store *TrustStore) write(apply func(*bolt.Tx) error) error {
	store.check.Lock()
	defer store.check.Unlock()
	return store.transact(apply)
}

func (store *TrustStore) viewChecked(apply func(*bolt.Tx) error) error {
	store.check.RLock()
	defer store.check.RUnlock()
	return store.db.View(apply)
}

func (store *TrustStore) ownedGuard(tx *bolt.Tx) (trustGuard, error) {
	bucket := tx.Bucket(trustBucket)
	if bucket == nil {
		return trustGuard{}, ownedfile.ErrInvalidStore
	}
	guard, err := decodeTrustGuard(bucket.Get(trustGuardKey), store.options, store.identity.Profile)
	if err != nil || guard.StoreID != store.identity.StoreID || guard.Owner != store.identity.Owner || !guard.Dirty || guard.Fenced {
		return trustGuard{}, ownedfile.ErrInvalidStore
	}
	return guard, nil
}

func (store *TrustStore) failed() error {
	store.fenced.Store(true)
	return ownedfile.ErrUnavailable
}

// Close stops new operations and does not clear dirty after an unknown result.
func (store *TrustStore) Close() error {
	store.closeOnce.Do(func() {
		store.mu.Lock()
		store.closing = true
		store.mu.Unlock()
		store.active.Wait()
		if !store.fenced.Load() {
			var snapshot rotation.TrustSnapshot
			var guard trustGuard
			var data []byte
			err := store.viewChecked(func(tx *bolt.Tx) error {
				var raw []byte
				var err error
				raw, data, err = readTrustRows(tx)
				if err != nil {
					return err
				}
				guard, err = decodeTrustGuard(raw, store.options, store.identity.Profile)
				return err
			})
			if err == nil {
				snapshot, err = rotation.DecodeTrustSnapshot(data, store.options.Binding, store.options.Window, store.options.Checkpoint)
			}
			if err == nil && !rotation.TrustClockCompatible(snapshot, guard.Clock) {
				err = ownedfile.ErrRecoveryRequired
			}
			if err == nil {
				err = store.write(func(tx *bolt.Tx) error {
					current, err := store.ownedGuard(tx)
					if err != nil || current.Clock.Unsafe {
						return ownedfile.ErrInvalidStore
					}
					current.Dirty = false
					return tx.Bucket(trustBucket).Put(trustGuardKey, encodeTrustGuard(current))
				})
			}
			if err != nil {
				store.closeErr = store.failed()
			}
		}
		if store.fenced.Load() && store.closeErr == nil {
			store.closeErr = ownedfile.ErrUnavailable
		}
		if err := store.db.Close(); err != nil {
			store.closeErr = ownedfile.ErrUnavailable
		}
	})
	return store.closeErr
}

var errTrustConflict = errors.New("durable: exact trust or clock conflict")
