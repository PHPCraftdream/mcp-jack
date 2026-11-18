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

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable/internal/ownedfile"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	bolt "go.etcd.io/bbolt"
)

var serverBucket = []byte("server-ring-v1")
var serverGuardKey = []byte("guard")
var serverSnapshotKey = []byte("snapshot")
var serverIntentKey = []byte("publication")
var serverGuardDomain = []byte("mcp-jack/server-ring/guard/v1\n")
var serverIntentDomain = []byte("mcp-jack/server-ring/publication/v1\n")

// The inner guard codec is shared; the outer domain prevents substitution of a client store.
func encodeServerGuard(guard trustGuard) []byte {
	return ownedfile.SealPayload(append(append([]byte{}, serverGuardDomain...), encodeTrustGuard(guard)...))
}

func decodeServerGuard(data []byte, options TrustOptions, profile [32]byte) (trustGuard, error) {
	payload, err := ownedfile.CheckedPayload(data)
	if err != nil || !bytes.HasPrefix(payload, serverGuardDomain) {
		return trustGuard{}, ownedfile.ErrInvalidStore
	}
	return decodeTrustGuard(payload[len(serverGuardDomain):], options, profile)
}

// Intent stores the exact local bytes; by itself it does not permit publication.
func encodeServerIntent(previous, next []byte) []byte {
	var out bytes.Buffer
	out.Write(serverIntentDomain)
	_ = binary.Write(&out, binary.BigEndian, uint64(len(previous)))
	out.Write(previous)
	out.Write(next)
	return ownedfile.SealPayload(out.Bytes())
}

func decodeServerIntent(data []byte) ([]byte, []byte, error) {
	payload, err := ownedfile.CheckedPayload(data)
	prefix := len(serverIntentDomain)
	if err != nil || len(payload) < prefix+8 || !bytes.HasPrefix(payload, serverIntentDomain) {
		return nil, nil, ownedfile.ErrInvalidStore
	}
	length := binary.BigEndian.Uint64(payload[prefix:])
	remaining := payload[prefix+8:]
	if length == 0 || length > rotation.MaxTrustSnapshotBytes || length >= uint64(len(remaining)) || uint64(len(remaining))-length > rotation.MaxTrustSnapshotBytes {
		return nil, nil, ownedfile.ErrInvalidStore
	}
	return append([]byte{}, remaining[:int(length)]...), append([]byte{}, remaining[int(length):]...), nil
}

// Shared exact intent check for serving startup and offline inspection.
func validateServerPublicationRows(encoded, intent []byte, snapshot rotation.ServerSnapshot, options TrustOptions) error {
	if len(intent) == 0 {
		if len(snapshot.Public.Records) != 0 || snapshot.Public.Revision != 1 {
			return ownedfile.ErrInvalidStore
		}
		return nil
	}
	previous, next, err := decodeServerIntent(intent)
	if err != nil || !bytes.Equal(next, encoded) {
		return ownedfile.ErrInvalidStore
	}
	before, err := rotation.DecodeServerSnapshot(previous, options.Binding, options.Window, options.Checkpoint)
	if err != nil {
		return ownedfile.ErrInvalidStore
	}
	if _, err := rotation.ValidateServerPublication(before, snapshot, options.Binding, options.Window, options.Checkpoint); err != nil {
		return ownedfile.ErrInvalidStore
	}
	return nil
}

func readServerRows(tx *bolt.Tx) (guard, snapshot, intent []byte, result error) {
	roots := 0
	if err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		roots++
		if !bytes.Equal(name, serverBucket) {
			return ownedfile.ErrInvalidStore
		}
		return nil
	}); err != nil || roots != 1 {
		return nil, nil, nil, ownedfile.ErrInvalidStore
	}
	bucket := tx.Bucket(serverBucket)
	if bucket == nil {
		return nil, nil, nil, ownedfile.ErrInvalidStore
	}
	count := 0
	if err := bucket.ForEach(func(key, value []byte) error {
		if value == nil || (!bytes.Equal(key, serverGuardKey) && !bytes.Equal(key, serverSnapshotKey) && !bytes.Equal(key, serverIntentKey)) {
			return ownedfile.ErrInvalidStore
		}
		count++
		return nil
	}); err != nil || count != 3 {
		return nil, nil, nil, ownedfile.ErrInvalidStore
	}
	corrupt := false
	for err := range tx.Check() {
		if err != nil {
			corrupt = true
		}
	}
	if corrupt {
		return nil, nil, nil, ownedfile.ErrInvalidStore
	}
	encoded := bucket.Get(serverSnapshotKey)
	if len(encoded) > rotation.MaxTrustSnapshotBytes+32 {
		return nil, nil, nil, ownedfile.ErrInvalidStore
	}
	snapshot, result = ownedfile.CheckedPayload(encoded)
	if result != nil {
		return nil, nil, nil, result
	}
	guard = append([]byte{}, bucket.Get(serverGuardKey)...)
	snapshot = append([]byte{}, snapshot...)
	intent = append([]byte{}, bucket.Get(serverIntentKey)...)
	if len(intent) > 2*rotation.MaxTrustSnapshotBytes+len(serverIntentDomain)+40 {
		return nil, nil, nil, ownedfile.ErrInvalidStore
	}
	return guard, snapshot, intent, nil
}

// RawClock is only a sample for outer checks, not a durable time authority.
func (store *ServerStore) RawClock() (int64, error) {
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
func (store *ServerStore) AdvanceAndCheck() (rotation.ClockTuple, error) {
	return store.advanceServerClock(nil)
}

// CheckSnapshotClock checks the exact ring together with a fresh server ClockGuard.
func (store *ServerStore) CheckSnapshotClock(expected rotation.ServerSnapshot) (rotation.ClockTuple, error) {
	encoded, err := rotation.EncodeServerSnapshot(expected, store.options.Binding, store.options.Window, store.options.Checkpoint)
	if err != nil {
		return rotation.ClockTuple{}, err
	}
	return store.advanceServerClock(encoded)
}

func (store *ServerStore) advanceServerClock(expected []byte) (rotation.ClockTuple, error) {
	done, err := store.begin()
	if err != nil {
		return rotation.ClockTuple{}, trustError("rotation_clock_unavailable")
	}
	defer done()
	var result rotation.ClockTuple
	conflict := false
	err = store.transact(func(tx *bolt.Tx) error {
		guard, err := store.ownedGuard(tx)
		if err != nil {
			return err
		}
		if expected != nil {
			payload, err := ownedfile.CheckedPayload(tx.Bucket(serverBucket).Get(serverSnapshotKey))
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
		return tx.Bucket(serverBucket).Put(serverGuardKey, encodeServerGuard(guard))
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
func (store *ServerStore) Snapshot() (rotation.ServerSnapshot, rotation.ClockTuple, error) {
	done, err := store.begin()
	if err != nil {
		return rotation.ServerSnapshot{}, rotation.ClockTuple{}, err
	}
	defer done()
	var snapshot rotation.ServerSnapshot
	var guard trustGuard
	err = store.db.View(func(tx *bolt.Tx) error {
		var err error
		snapshot, guard, err = store.validateRows(tx)
		if err != nil {
			return err
		}
		_, err = store.ownedGuard(tx)
		return err
	})
	if err != nil {
		return rotation.ServerSnapshot{}, rotation.ClockTuple{}, store.failed()
	}
	if store.fenced.Load() {
		return rotation.ServerSnapshot{}, rotation.ClockTuple{}, ownedfile.ErrUnavailable
	}
	return snapshot, guard.Clock, nil
}

// CompareAndSwap atomically writes one fixed-P transition and the exact intent; the guard is unchanged.
func (store *ServerStore) CompareAndSwap(expected, desired rotation.ServerSnapshot, clock rotation.ClockTuple) error {
	previous, err := rotation.EncodeServerSnapshot(expected, store.options.Binding, store.options.Window, store.options.Checkpoint)
	if err != nil {
		return err
	}
	next, err := rotation.EncodeServerSnapshot(desired, store.options.Binding, store.options.Window, store.options.Checkpoint)
	if err != nil {
		return err
	}
	if desired.Public.Clock != clock {
		return trustError("rotation_state_changed")
	}
	if _, err := rotation.ValidateServerPublication(expected, desired, store.options.Binding, store.options.Window, store.options.Checkpoint); err != nil {
		return err
	}
	done, err := store.begin()
	if err != nil {
		return err
	}
	defer done()
	err = store.transact(func(tx *bolt.Tx) error {
		guard, err := store.ownedGuard(tx)
		if err != nil {
			return err
		}
		if guard.Clock != clock || guard.Clock.Unsafe {
			return errTrustConflict
		}
		bucket := tx.Bucket(serverBucket)
		payload, err := ownedfile.CheckedPayload(bucket.Get(serverSnapshotKey))
		if err != nil {
			return err
		}
		if !bytes.Equal(payload, previous) {
			return errTrustConflict
		}
		if err := bucket.Put(serverIntentKey, encodeServerIntent(previous, next)); err != nil {
			return err
		}
		return bucket.Put(serverSnapshotKey, ownedfile.SealPayload(next))
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

// ServerInspection holds public diagnostics, not serving permission or rollback evidence.
// Protected references and the complete private snapshot are not exposed.
type ServerInspection struct {
	StoreID            string `json:"store_id"`
	OwnerGeneration    uint64 `json:"owner_generation"`
	Window             int64  `json:"window"`
	HighWater          int64  `json:"high_water"`
	ClockRevision      uint64 `json:"clock_revision"`
	Unsafe             bool   `json:"unsafe"`
	Dirty              bool   `json:"dirty"`
	Fenced             bool   `json:"fenced"`
	StateRevision      uint64 `json:"state_revision"`
	HeadOrdinal        uint64 `json:"head_ordinal"`
	HeadHash           string `json:"head_hash"`
	RetainedKeys       int    `json:"retained_keys"`
	PublicationPresent bool   `json:"publication_present"`
}

// InspectServer requires the exclusive owner even offline; it does not create a DB or call the clock.
func InspectServer(path string, options ServerOptions) (report ServerInspection, result error) {
	options, _, profile, err := normalizedServerOptions(options)
	if err != nil {
		return report, err
	}
	db, _, err := ownedfile.OpenDB(path, false)
	if err != nil {
		return report, err
	}
	defer func() {
		if db.Close() != nil {
			report, result = ServerInspection{}, ownedfile.ErrUnavailable
		}
	}()
	err = db.View(func(tx *bolt.Tx) error {
		raw, encoded, intent, err := readServerRows(tx)
		if err != nil {
			return err
		}
		guard, err := decodeServerGuard(raw, options.TrustOptions, profile)
		if err != nil {
			return err
		}
		snapshot, err := rotation.DecodeServerSnapshot(encoded, options.Binding, options.Window, options.Checkpoint)
		if err != nil {
			return ownedfile.ErrInvalidStore
		}
		// Flags are preserved as diagnostics; an incompatible clock dependency is not hidden.
		if snapshot.Public.Clock.HighWater > guard.Clock.HighWater || snapshot.Public.Clock.Revision > guard.Clock.Revision {
			return ownedfile.ErrInvalidStore
		}
		if err := validateServerPublicationRows(encoded, intent, snapshot, options.TrustOptions); err != nil {
			return err
		}
		report = ServerInspection{
			StoreID: jack.EncodeBase64URL(guard.StoreID[:]), OwnerGeneration: guard.Owner,
			Window: guard.Clock.Window, HighWater: guard.Clock.HighWater, ClockRevision: guard.Clock.Revision,
			Unsafe: guard.Clock.Unsafe || snapshot.Public.Clock.Unsafe, Dirty: guard.Dirty, Fenced: guard.Fenced || snapshot.Public.Fenced,
			StateRevision: snapshot.Public.Revision, HeadOrdinal: snapshot.Public.Head.Ordinal, HeadHash: snapshot.Public.Head.Hash,
			RetainedKeys: len(snapshot.Public.Keys), PublicationPresent: len(intent) != 0,
		}
		return nil
	})
	if err != nil {
		return ServerInspection{}, err
	}
	return report, nil
}

// ServerOptions holds an independent OOB binding and a protected anchor handle.
type ServerOptions struct {
	TrustOptions
	AnchorReference string
}

// ServerStore does not own the nonce/client domain and does not permit serving without a provider.
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
		return options, nil, [32]byte{}, ownedfile.ErrInvalidStore
	}
	initial := rotation.ServerSnapshot{FormatVersion: 1, Public: public, SignerReferences: []rotation.SignerReference{{KID: base.Checkpoint.KID, Reference: options.AnchorReference}}}
	encoded, err = rotation.EncodeServerSnapshot(initial, base.Binding, base.Window, base.Checkpoint)
	if err != nil {
		return options, nil, [32]byte{}, ownedfile.ErrInvalidStore
	}
	return options, encoded, sha256.Sum256(encoded), nil
}

// InitializeServerUnused does not replace an existing store and is not recovery.
func InitializeServerUnused(path string, options ServerOptions) (result error) {
	options, encoded, profile, err := normalizedServerOptions(options)
	if err != nil {
		return err
	}
	if err := ownedfile.PrivateDirectory(path); err != nil {
		return err
	}
	now, sampled := sampleTrustNow(options.Now)
	if !sampled || now < 0 || now > rotation.MaxTimestamp {
		return ownedfile.ErrUnavailable
	}
	snapshot, err := rotation.DecodeServerSnapshot(encoded, options.Binding, options.Window, options.Checkpoint)
	if err != nil {
		return ownedfile.ErrInvalidStore
	}
	snapshot.Public.Clock.HighWater, snapshot.Public.Clock.Revision = now, 1
	encoded, err = rotation.EncodeServerSnapshot(snapshot, options.Binding, options.Window, options.Checkpoint)
	if err != nil {
		return ownedfile.ErrInvalidStore
	}
	guard := trustGuard{Profile: profile, Owner: 1, Dirty: true, Clock: snapshot.Public.Clock}
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
		bucket, err := tx.CreateBucket(serverBucket)
		if err != nil {
			return err
		}
		if err := bucket.Put(serverGuardKey, encodeServerGuard(guard)); err != nil {
			return err
		}
		if err := bucket.Put(serverSnapshotKey, ownedfile.SealPayload(encoded)); err != nil {
			return err
		}
		return bucket.Put(serverIntentKey, []byte{})
	}); err != nil {
		return ownedfile.ErrUnavailable
	}
	if err := ownedfile.SyncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if info, err := file.Stat(); err != nil || info.Size() > ownedfile.MaxFileBytes {
		return ownedfile.ErrUnavailable
	}
	guard.Dirty = false
	if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket(serverBucket).Put(serverGuardKey, encodeServerGuard(guard)) }); err != nil {
		return ownedfile.ErrUnavailable
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
		return rotation.ServerSnapshot{}, guard, ownedfile.ErrRecoveryRequired
	}
	if err := validateServerPublicationRows(encoded, intent, snapshot, store.options.TrustOptions); err != nil {
		return rotation.ServerSnapshot{}, guard, err
	}
	return snapshot, guard, nil
}

// OpenServer does not clear dirty/unknown; signer readiness is checked separately by the provider.
func OpenServer(path string, options ServerOptions) (*ServerStore, error) {
	options, _, profile, err := normalizedServerOptions(options)
	if err != nil {
		return nil, err
	}
	db, file, err := ownedfile.OpenDB(path, false)
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
		return nil, ownedfile.ErrRecoveryRequired
	}
	if guard.Owner == ^uint64(0) {
		return nil, ownedfile.ErrInvalidStore
	}
	guard.Owner++
	guard.Dirty = true
	store.identity = guard
	if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket(serverBucket).Put(serverGuardKey, encodeServerGuard(guard)) }); err != nil {
		return nil, ownedfile.ErrUnavailable
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
		return nil, ownedfile.ErrUnavailable
	}
	store.active.Add(1)
	return store.active.Done, nil
}

func (store *ServerStore) ownedGuard(tx *bolt.Tx) (trustGuard, error) {
	bucket := tx.Bucket(serverBucket)
	if bucket == nil {
		return trustGuard{}, ownedfile.ErrInvalidStore
	}
	guard, err := decodeServerGuard(bucket.Get(serverGuardKey), store.options.TrustOptions, store.identity.Profile)
	if err != nil || guard.StoreID != store.identity.StoreID || guard.Owner != store.identity.Owner || !guard.Dirty || guard.Fenced {
		return trustGuard{}, ownedfile.ErrInvalidStore
	}
	return guard, nil
}

func (store *ServerStore) failed() error { store.fenced.Store(true); return ownedfile.ErrUnavailable }
func (store *ServerStore) Fence()        { store.fenced.Store(true) }

// AcquireServingLease holds the dirty epoch until the response write physically completes.
func (store *ServerStore) AcquireServingLease() (func(), error) {
	done, err := store.begin()
	if err != nil {
		return nil, err
	}
	var once sync.Once
	return func() { once.Do(done) }, nil
}

// Close waits for store operations and serving leases; new final gates are refused.
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
					return ownedfile.ErrRecoveryRequired
				}
				guard.Dirty = false
				return tx.Bucket(serverBucket).Put(serverGuardKey, encodeServerGuard(guard))
			})
			if err != nil {
				store.closeErr = store.failed()
			}
		}
		if store.fenced.Load() {
			store.closeErr = ownedfile.ErrUnavailable
		}
		if store.db.Close() != nil {
			store.closeErr = ownedfile.ErrUnavailable
		}
	})
	return store.closeErr
}
