// Package durable contains a transactional backend with a single lifetime owner.
// Filesystem support and crash recovery require separate qualification gates.
// Nonce-store tx.Check call sites run only under lifetime exclusivity (open, offline inspection, recovery), never beside a writer; only the rotation stores need a check lock.
package durable

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable/internal/ownedfile"
	"github.com/PHPCraftdream/mcp-jack/durable/internal/rotationstore"
	"github.com/PHPCraftdream/mcp-jack/server"
	bolt "go.etcd.io/bbolt"
)

var (
	ErrUnavailable      = ownedfile.ErrUnavailable
	ErrInvalidStore     = ownedfile.ErrInvalidStore
	ErrRecoveryRequired = ownedfile.ErrRecoveryRequired
	ErrUnsupported      = ownedfile.ErrUnsupported
)

const (
	maxFileBytes = ownedfile.MaxFileBytes
	pageBytes    = ownedfile.PageBytes
)

// Options binds the backend to an independently specified deployment and immutable W.
type Options struct {
	DeploymentID string
	Window       int64
	Now          func() int64
}

// Store holds the exclusive bbolt lock; the handle is never exported.
type Store struct {
	mu        sync.Mutex
	db        *bolt.DB
	file      *os.File
	transact  func(func(*bolt.Tx) error) error
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

func dbOptions(create bool) *bolt.Options { return ownedfile.DBOptions(create) }

// InitializeUnused is a separate OOB operation only for a provably unused
// deployment. It does not migrate volatile history and never replaces an existing file.
// On an unknown error the file is kept for recovery, not deleted/recreated.
func InitializeUnused(path string, opts Options) error {
	return initializeUnused(path, opts, syncDirectory)
}

func syncDirectory(path string) error { return ownedfile.SyncDirectory(path) }

func privateDirectory(path string) error { return ownedfile.PrivateDirectory(path) }

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

// Open opens only an existing initialized store, without implicit create/reset.
// Dirty/unsafe startup is always closed until a separate explicit recovery operation.
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
	if options == nil || options.OpenFile == nil {
		return nil, ErrInvalidStore
	}
	opening := *options
	originalOpen := opening.OpenFile
	var ownedFile *os.File
	opening.OpenFile = func(name string, flags int, mode os.FileMode) (*os.File, error) {
		file, err := originalOpen(name, flags, mode)
		if err == nil {
			ownedFile = file
		}
		return file, err
	}
	db, err := bolt.Open(path, 0600, &opening)
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
		return readStoreSnapshot(tx, opts, true, &m)
	})
	if err != nil {
		return nil, err
	}
	m.Owner++
	m.Dirty = true
	if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("metadata")).Put(headerKey, encodeMetadata(m)) }); err != nil {
		return nil, ErrUnavailable
	}
	// First confirm the dirty marker, then observe the startup clock.
	// An indeterminate unsafe-latch can no longer open a clean restart.
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
	owner := &Store{db: db, file: ownedFile, transact: db.Update, meta: m, opts: opts}
	handedOff = true
	return owner, nil
}

// Fence does not wait for leases and does not retry an uncertain transaction.
// An already confirmed dirty marker closes the next startup.
func (s *Store) Fence() { s.fenced.Store(true) }

// Close stops admission, waits for leases, and clears dirty only when not fenced.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closing.Store(true)
		s.mu.Unlock()
		s.leases.Wait()
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.meta.Intents != 0 || s.meta.Tombstones >= 64 || s.meta.Unsafe {
			s.fenced.Store(true)
			s.closeErr = ErrRecoveryRequired
		}
		// A store fenced during the drain keeps its dirty epoch: report it so the
		// caller knows the next open needs recovery instead of seeing a clean close.
		if s.fenced.Load() && s.closeErr == nil {
			s.closeErr = ErrRecoveryRequired
		}
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

var _ server.DurableNonceStore = (*Store)(nil)

type reservationLease struct {
	owner    *Store
	epoch    uint64
	released atomic.Bool
}

func (lease *reservationLease) Valid() bool {
	s := lease.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	return !lease.released.Load() && !s.fenced.Load() && !s.closing.Load() && !s.closed.Load() && s.meta.Owner == lease.epoch
}

func (lease *reservationLease) Release() {
	if lease.released.CompareAndSwap(false, true) {
		lease.owner.leases.Done()
	}
}

// Reserve is called only after authentication, under the coordinated registry gate.
// DB callbacks do not call clock/validator/handler/signer; the final commit is not retried.
func (s *Store) Reserve(request server.NonceAdmission) (server.NonceReceipt, server.NonceLease, *jack.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	normal := false
	defer func() {
		if !normal {
			s.fenced.Store(true)
		}
	}()
	receipt, lease, err := s.reserveLocked(request)
	normal = true
	return receipt, lease, err
}

func (s *Store) reserveLocked(request server.NonceAdmission) (server.NonceReceipt, server.NonceLease, *jack.Error) {
	refuse := func(err *jack.Error) (server.NonceReceipt, server.NonceLease, *jack.Error) {
		return server.NonceReceipt{}, nil, err
	}
	if s.db == nil || s.file == nil || s.transact == nil || s.opts.Now == nil || s.fenced.Load() || s.closing.Load() || s.closed.Load() {
		return refuse(unavailable())
	}
	if request.Window != s.meta.Window || request.Validate == nil {
		return refuse(admissionError(503, "state_changed"))
	}
	if request.Timestamp < 0 || request.Timestamp > maxTimestamp-s.meta.Window {
		return refuse(admissionError(401, jack.CodeTimestampOutOfWindow))
	}
	kid, err := jack.DecodeBase64URLFixed(request.KID, 32)
	if err != nil {
		s.fenced.Store(true)
		return refuse(unavailable())
	}
	nonce, err := jack.DecodeBase64URLFixed(request.Nonce, 16)
	if err != nil {
		s.fenced.Store(true)
		return refuse(unavailable())
	}
	if _, err := jack.DecodeBase64URLFixed(request.Signature, 64); err != nil {
		s.fenced.Store(true)
		return refuse(unavailable())
	}
	var key [48]byte
	copy(key[:32], kid)
	copy(key[32:], nonce)
	entryNow := s.opts.Now()
	if rejection := s.checkSample(request, entryNow, nil); rejection != nil {
		return refuse(rejection)
	}
	if err := s.db.View(func(tx *bolt.Tx) error { return replayLookup(tx, s.meta, key, entryNow) }); err != nil {
		var rejection *jack.Error
		if errors.As(err, &rejection) && rejection != nil {
			if rejection.Code == "durability_unavailable" {
				s.fenced.Store(true)
			}
			return refuse(rejection)
		}
		s.fenced.Store(true)
		return refuse(unavailable())
	}
	var operation [16]byte
	unique := false
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := rand.Read(operation[:]); err != nil {
			s.fenced.Store(true)
			return refuse(unavailable())
		}
		if err := s.db.View(func(tx *bolt.Tx) error {
			actual, value := tx.Bucket([]byte("operation")).Cursor().Seek(operation[:])
			unique = !bytes.Equal(actual, operation[:])
			if !unique && len(value) != 48 {
				return ErrInvalidStore
			}
			return nil
		}); err != nil {
			s.fenced.Store(true)
			return refuse(unavailable())
		}
		if unique {
			break
		}
	}
	if !unique {
		s.fenced.Store(true)
		return refuse(unavailable())
	}
	intentID, err := server.NonceIntentID(s.meta.Deployment, request, operation)
	if err != nil {
		s.fenced.Store(true)
		return refuse(unavailable())
	}
	intentNow := s.opts.Now()
	if rejection := s.checkSample(request, intentNow, nil); rejection != nil {
		return refuse(rejection)
	}
	prepared := nonceRecord{kind: intentRecord, storeID: s.meta.StoreID, key: key, receipt: server.NonceReceipt{
		Version: formatVersion, DeploymentID: s.meta.Deployment, StoreGeneration: s.meta.Generation, OwnerGeneration: s.meta.Owner,
		IntentID: intentID, OperationID: operation, KID: request.KID, Nonce: request.Nonce, Signature: request.Signature,
		RequestHash: jack.BodyHash([]byte(request.SigningBytes)), Timestamp: request.Timestamp,
		RetainUntil: request.Timestamp + request.Window, HighWater: intentNow,
	}}
	if rejection := s.update(func(tx *bolt.Tx, m *metadata) error {
		if err := replayLookup(tx, *m, key, intentNow); err != nil {
			return err
		}
		if err := purgeExpired(tx, m, intentNow, key); err != nil {
			return err
		}
		if uint64(m.Live)+uint64(m.Intents) >= 4096 || m.Tombstones >= 64 {
			return admissionError(503, "capacity_exhausted")
		}
		actual, _ := tx.Bucket([]byte("operation")).Cursor().Seek(operation[:])
		if bytes.Equal(actual, operation[:]) {
			return ErrInvalidStore
		}
		encoded, err := encodeRecord(prepared, *m)
		if err != nil {
			return err
		}
		if err := tx.Bucket([]byte("intent")).Put(key[:], encoded); err != nil {
			return err
		}
		if err := tx.Bucket([]byte("operation")).Put(operation[:], key[:]); err != nil {
			return err
		}
		m.Intents++
		return nil
	}); rejection != nil {
		return refuse(rejection)
	}
	finalNow := s.opts.Now()
	if rejection := s.checkSample(request, finalNow, &prepared); rejection != nil {
		return refuse(rejection)
	}
	committed := prepared
	committed.kind = liveRecord
	committed.receipt.HighWater = finalNow
	if rejection := s.update(func(tx *bolt.Tx, m *metadata) error {
		if err := exactIntent(tx, *m, prepared); err != nil {
			return err
		}
		if m.Intents == 0 || m.Live >= 4096 {
			return ErrInvalidStore
		}
		m.HighWater = finalNow
		encoded, err := encodeRecord(committed, *m)
		if err != nil {
			return err
		}
		if err := tx.Bucket([]byte("intent")).Delete(key[:]); err != nil {
			return err
		}
		if err := tx.Bucket([]byte("live")).Put(key[:], encoded); err != nil {
			return err
		}
		index := expiryKey(committed)
		if err := tx.Bucket([]byte("expiry")).Put(index[:], []byte{}); err != nil {
			return err
		}
		m.Intents--
		m.Live++
		return nil
	}); rejection != nil {
		return refuse(rejection)
	}
	s.leases.Add(1)
	lease := &reservationLease{owner: s, epoch: s.meta.Owner}
	return committed.receipt, lease, nil
}

func exactIntent(tx *bolt.Tx, m metadata, prepared nonceRecord) error {
	actual, err := readRecord(tx.Bucket([]byte("intent")), prepared.key, m, intentRecord)
	if err != nil || actual == nil || *actual != prepared {
		return ErrInvalidStore
	}
	if !bytes.Equal(tx.Bucket([]byte("operation")).Get(prepared.receipt.OperationID[:]), prepared.key[:]) {
		return ErrInvalidStore
	}
	return nil
}

func removeIntent(tx *bolt.Tx, m *metadata, prepared nonceRecord) error {
	if err := exactIntent(tx, *m, prepared); err != nil {
		return err
	}
	if m.Intents == 0 {
		return ErrInvalidStore
	}
	if err := tx.Bucket([]byte("intent")).Delete(prepared.key[:]); err != nil {
		return err
	}
	if err := tx.Bucket([]byte("operation")).Delete(prepared.receipt.OperationID[:]); err != nil {
		return err
	}
	m.Intents--
	return nil
}

func (s *Store) checkSample(request server.NonceAdmission, now int64, prepared *nonceRecord) *jack.Error {
	if s.fenced.Load() || s.closing.Load() || s.closed.Load() {
		return unavailable()
	}
	if now < 0 || now > maxTimestamp || now < s.meta.HighWater {
		rejection := s.update(func(tx *bolt.Tx, m *metadata) error {
			if prepared != nil {
				if err := removeIntent(tx, m, *prepared); err != nil {
					return err
				}
			}
			m.Unsafe = true
			return nil
		})
		s.fenced.Store(true)
		if rejection != nil {
			return unavailable()
		}
		return admissionError(503, "clock_unsafe")
	}
	var rejection *jack.Error
	if !request.Validate(now) {
		rejection = admissionError(503, "state_changed")
	} else if difference := now - request.Timestamp; difference > request.Window || -difference > request.Window {
		rejection = admissionError(401, jack.CodeTimestampOutOfWindow)
	}
	if rejection != nil && prepared != nil {
		if cleanup := s.update(func(tx *bolt.Tx, m *metadata) error { return removeIntent(tx, m, *prepared) }); cleanup != nil {
			return unavailable()
		}
	}
	return rejection
}

func admissionError(status int, code string) *jack.Error {
	return &jack.Error{HTTPStatus: status, Code: code, Message: "durable admission refused"}
}

func unavailable() *jack.Error { return admissionError(503, "durability_unavailable") }

// Only callback rejection is a definite abort. A commit error remains unknown.
func (s *Store) update(apply func(*bolt.Tx, *metadata) error) *jack.Error {
	next := s.meta
	var callbackErr error
	err := s.transact(func(tx *bolt.Tx) error {
		if s.fenced.Load() || s.closing.Load() || s.closed.Load() {
			callbackErr = unavailable()
			return callbackErr
		}
		current, err := decodeMetadata(tx.Bucket([]byte("metadata")).Get(headerKey))
		if err != nil || current != s.meta {
			callbackErr = ErrInvalidStore
			return callbackErr
		}
		callbackErr = apply(tx, &next)
		if callbackErr != nil {
			return callbackErr
		}
		callbackErr = tx.Bucket([]byte("metadata")).Put(headerKey, encodeMetadata(next))
		return callbackErr
	})
	if err != nil {
		var rejection *jack.Error
		if callbackErr != nil && errors.As(callbackErr, &rejection) && rejection != nil {
			if rejection.Code == "durability_unavailable" || rejection.Code == "clock_unsafe" {
				s.fenced.Store(true)
			}
			return rejection
		}
		s.fenced.Store(true)
		return unavailable()
	}
	info, statErr := s.file.Stat()
	if statErr != nil || info.Size() > maxFileBytes || info.Size() < 4*pageBytes {
		s.fenced.Store(true)
		return unavailable()
	}
	s.meta = next
	return nil
}

func readRecord(bucket *bolt.Bucket, key [48]byte, m metadata, kind byte) (*nonceRecord, error) {
	if bucket == nil {
		return nil, ErrInvalidStore
	}
	actual, data := bucket.Cursor().Seek(key[:])
	if !bytes.Equal(actual, key[:]) {
		return nil, nil
	}
	row, err := decodeRecord(data, m)
	if err != nil || row.kind != kind || row.key != key {
		return nil, ErrInvalidStore
	}
	return &row, nil
}

func replayLookup(tx *bolt.Tx, m metadata, key [48]byte, now int64) error {
	row, err := readRecord(tx.Bucket([]byte("live")), key, m, liveRecord)
	if err != nil {
		return err
	}
	if row != nil && now <= row.receipt.RetainUntil {
		return admissionError(401, jack.CodeReplayedNonce)
	}
	for _, group := range []struct {
		name string
		kind byte
	}{{"intent", intentRecord}, {"tombstone", tombstoneRecord}} {
		row, err := readRecord(tx.Bucket([]byte(group.name)), key, m, group.kind)
		if err != nil {
			return err
		}
		if row != nil {
			return unavailable()
		}
	}
	return nil
}

// The index is built before deletion: Cursor.Next after Delete may skip a record.
// The exact pair shares the 128-key batch cap and is never deleted beyond it.
func purgeExpired(tx *bolt.Tx, m *metadata, now int64, exact [48]byte) error {
	if now < m.HighWater {
		return ErrInvalidStore
	}
	m.HighWater = now
	live := tx.Bucket([]byte("live"))
	expiry := tx.Bucket([]byte("expiry"))
	operations := tx.Bucket([]byte("operation"))
	keys := make([][56]byte, 0, 128)
	exactRow, err := readRecord(live, exact, *m, liveRecord)
	if err != nil {
		return err
	}
	if exactRow != nil && exactRow.receipt.RetainUntil < now {
		keys = append(keys, expiryKey(*exactRow))
	}
	cursor := expiry.Cursor()
	for key, value := cursor.First(); key != nil && len(keys) < 128; key, value = cursor.Next() {
		if len(key) != 56 || len(value) != 0 || expiry.Bucket(key) != nil {
			return ErrInvalidStore
		}
		if binary.BigEndian.Uint64(key[:8]) >= uint64(now) {
			break
		}
		var index [56]byte
		copy(index[:], key)
		if len(keys) > 0 && index == keys[0] {
			continue
		}
		keys = append(keys, index)
	}
	for _, index := range keys {
		var pair [48]byte
		copy(pair[:], index[8:])
		actual, value := expiry.Cursor().Seek(index[:])
		if !bytes.Equal(actual, index[:]) || len(value) != 0 || expiry.Bucket(actual) != nil {
			return ErrInvalidStore
		}
		row, err := readRecord(live, pair, *m, liveRecord)
		if err != nil || row == nil || expiryKey(*row) != index || row.receipt.RetainUntil >= now || m.Live == 0 {
			return ErrInvalidStore
		}
		if !bytes.Equal(operations.Get(row.receipt.OperationID[:]), pair[:]) {
			return ErrInvalidStore
		}
		if err := live.Delete(pair[:]); err != nil {
			return err
		}
		if err := expiry.Delete(index[:]); err != nil {
			return err
		}
		if err := operations.Delete(row.receipt.OperationID[:]); err != nil {
			return err
		}
		m.Live--
	}
	return nil
}

// TrustOptions are specified independently of the remote response and the existing DB.
type TrustOptions = rotationstore.TrustOptions

// TrustStore owns a separate lifetime-exclusive trust/clock domain.
type TrustStore = rotationstore.TrustStore

// ServerOptions holds an independent OOB binding and a protected anchor handle.
type ServerOptions = rotationstore.ServerOptions

// ServerStore does not own the nonce/client domain and does not permit serving without a provider.
type ServerStore = rotationstore.ServerStore

// ServerInspection holds public diagnostics, not serving permission or rollback evidence.
// Protected references and the complete private snapshot are not exposed.
type ServerInspection = rotationstore.ServerInspection

// InitializeTrustUnused is only explicit OOB creation of a new binding, not recovery.
func InitializeTrustUnused(path string, options TrustOptions) error {
	return rotationstore.InitializeTrustUnused(path, options)
}

// OpenTrust does not create a DB and does not clear dirty/fenced/unsafe at startup.
func OpenTrust(path string, options TrustOptions) (*TrustStore, error) {
	return rotationstore.OpenTrust(path, options)
}

// InitializeServerUnused does not replace an existing store and is not recovery.
func InitializeServerUnused(path string, options ServerOptions) error {
	return rotationstore.InitializeServerUnused(path, options)
}

// OpenServer does not clear dirty/unknown; signer readiness is checked separately by the provider.
func OpenServer(path string, options ServerOptions) (*ServerStore, error) {
	return rotationstore.OpenServer(path, options)
}

// InspectServer requires the exclusive owner even offline; it does not create a DB or call the clock.
func InspectServer(path string, options ServerOptions) (report ServerInspection, result error) {
	return rotationstore.InspectServer(path, options)
}
