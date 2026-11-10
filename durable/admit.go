package durable

import (
	"bytes"
	"crypto/rand"
	"errors"
	"sync/atomic"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
	bolt "go.etcd.io/bbolt"
)

var _ server.DurableNonceStore = (*Store)(nil)

type reservationLease struct {
	owner *Store
	epoch uint64
	released atomic.Bool
}

func (lease *reservationLease) Valid() bool {
	s := lease.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	return !lease.released.Load() && !s.fenced.Load() && !s.closing.Load() && !s.closed.Load() && s.meta.Owner == lease.epoch
}

func (lease *reservationLease) Release() {
	if lease.released.CompareAndSwap(false, true) { lease.owner.leases.Done() }
}

// Reserve вызывается только после authentication, под coordinated registry gate.
// DB callbacks не вызывают clock/validator/handler/signer; final commit не повторяется.
func (s *Store) Reserve(request server.NonceAdmission) (server.NonceReceipt, server.NonceLease, *jack.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	normal := false
	defer func() { if !normal { s.fenced.Store(true) } }()
	receipt, lease, err := s.reserveLocked(request)
	normal = true
	return receipt, lease, err
}

func (s *Store) reserveLocked(request server.NonceAdmission) (server.NonceReceipt, server.NonceLease, *jack.Error) {
	refuse := func(err *jack.Error) (server.NonceReceipt, server.NonceLease, *jack.Error) { return server.NonceReceipt{}, nil, err }
	if s.db == nil || s.file == nil || s.transact == nil || s.opts.Now == nil || s.fenced.Load() || s.closing.Load() || s.closed.Load() { return refuse(unavailable()) }
	if request.Window != s.meta.Window || request.Validate == nil { return refuse(admissionError(503, "state_changed")) }
	if request.Timestamp < 0 || request.Timestamp > maxTimestamp-s.meta.Window { return refuse(admissionError(401, jack.CodeTimestampOutOfWindow)) }
	kid, err := jack.DecodeBase64URLFixed(request.KID, 32)
	if err != nil { s.fenced.Store(true); return refuse(unavailable()) }
	nonce, err := jack.DecodeBase64URLFixed(request.Nonce, 16)
	if err != nil { s.fenced.Store(true); return refuse(unavailable()) }
	if _, err := jack.DecodeBase64URLFixed(request.Signature, 64); err != nil { s.fenced.Store(true); return refuse(unavailable()) }
	var key [48]byte
	copy(key[:32], kid)
	copy(key[32:], nonce)
	entryNow := s.opts.Now()
	if rejection := s.checkSample(request, entryNow, nil); rejection != nil { return refuse(rejection) }
	if err := s.db.View(func(tx *bolt.Tx) error { return replayLookup(tx, s.meta, key, entryNow) }); err != nil {
		var rejection *jack.Error
		if errors.As(err, &rejection) && rejection != nil {
			if rejection.Code == "durability_unavailable" { s.fenced.Store(true) }
			return refuse(rejection)
		}
		s.fenced.Store(true)
		return refuse(unavailable())
	}
	var operation [16]byte
	unique := false
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := rand.Read(operation[:]); err != nil { s.fenced.Store(true); return refuse(unavailable()) }
		if err := s.db.View(func(tx *bolt.Tx) error {
			actual, value := tx.Bucket([]byte("operation")).Cursor().Seek(operation[:])
			unique = !bytes.Equal(actual, operation[:])
			if !unique && len(value) != 48 { return ErrInvalidStore }
			return nil
		}); err != nil { s.fenced.Store(true); return refuse(unavailable()) }
		if unique { break }
	}
	if !unique { s.fenced.Store(true); return refuse(unavailable()) }
	intentID, err := server.NonceIntentID(s.meta.Deployment, request, operation)
	if err != nil { s.fenced.Store(true); return refuse(unavailable()) }
	intentNow := s.opts.Now()
	if rejection := s.checkSample(request, intentNow, nil); rejection != nil { return refuse(rejection) }
	prepared := nonceRecord{kind: intentRecord, storeID: s.meta.StoreID, key: key, receipt: server.NonceReceipt{
		Version: formatVersion, DeploymentID: s.meta.Deployment, StoreGeneration: s.meta.Generation, OwnerGeneration: s.meta.Owner,
		IntentID: intentID, OperationID: operation, KID: request.KID, Nonce: request.Nonce, Signature: request.Signature,
		RequestHash: jack.BodyHash([]byte(request.SigningBytes)), Timestamp: request.Timestamp,
		RetainUntil: request.Timestamp+request.Window, HighWater: intentNow,
	}}
	if rejection := s.update(func(tx *bolt.Tx, m *metadata) error {
		if err := replayLookup(tx, *m, key, intentNow); err != nil { return err }
		if err := purgeExpired(tx, m, intentNow, key); err != nil { return err }
		if uint64(m.Live)+uint64(m.Intents) >= 4096 || m.Tombstones >= 64 { return admissionError(503, "capacity_exhausted") }
		actual, _ := tx.Bucket([]byte("operation")).Cursor().Seek(operation[:])
		if bytes.Equal(actual, operation[:]) { return ErrInvalidStore }
		encoded, err := encodeRecord(prepared, *m)
		if err != nil { return err }
		if err := tx.Bucket([]byte("intent")).Put(key[:], encoded); err != nil { return err }
		if err := tx.Bucket([]byte("operation")).Put(operation[:], key[:]); err != nil { return err }
		m.Intents++
		return nil
	}); rejection != nil { return refuse(rejection) }
	finalNow := s.opts.Now()
	if rejection := s.checkSample(request, finalNow, &prepared); rejection != nil { return refuse(rejection) }
	committed := prepared
	committed.kind = liveRecord
	committed.receipt.HighWater = finalNow
	if rejection := s.update(func(tx *bolt.Tx, m *metadata) error {
		if err := exactIntent(tx, *m, prepared); err != nil { return err }
		if m.Intents == 0 || m.Live >= 4096 { return ErrInvalidStore }
		m.HighWater = finalNow
		encoded, err := encodeRecord(committed, *m)
		if err != nil { return err }
		if err := tx.Bucket([]byte("intent")).Delete(key[:]); err != nil { return err }
		if err := tx.Bucket([]byte("live")).Put(key[:], encoded); err != nil { return err }
		index := expiryKey(committed)
		if err := tx.Bucket([]byte("expiry")).Put(index[:], []byte{}); err != nil { return err }
		m.Intents--
		m.Live++
		return nil
	}); rejection != nil { return refuse(rejection) }
	s.leases.Add(1)
	lease := &reservationLease{owner: s, epoch: s.meta.Owner}
	return committed.receipt, lease, nil
}

func exactIntent(tx *bolt.Tx, m metadata, prepared nonceRecord) error {
	actual, err := readRecord(tx.Bucket([]byte("intent")), prepared.key, m, intentRecord)
	if err != nil || actual == nil || *actual != prepared { return ErrInvalidStore }
	if !bytes.Equal(tx.Bucket([]byte("operation")).Get(prepared.receipt.OperationID[:]), prepared.key[:]) { return ErrInvalidStore }
	return nil
}

func removeIntent(tx *bolt.Tx, m *metadata, prepared nonceRecord) error {
	if err := exactIntent(tx, *m, prepared); err != nil { return err }
	if m.Intents == 0 { return ErrInvalidStore }
	if err := tx.Bucket([]byte("intent")).Delete(prepared.key[:]); err != nil { return err }
	if err := tx.Bucket([]byte("operation")).Delete(prepared.receipt.OperationID[:]); err != nil { return err }
	m.Intents--
	return nil
}

func (s *Store) checkSample(request server.NonceAdmission, now int64, prepared *nonceRecord) *jack.Error {
	if s.fenced.Load() || s.closing.Load() || s.closed.Load() { return unavailable() }
	if now < 0 || now > maxTimestamp || now < s.meta.HighWater {
		rejection := s.update(func(tx *bolt.Tx, m *metadata) error {
			if prepared != nil { if err := removeIntent(tx, m, *prepared); err != nil { return err } }
			m.Unsafe = true
			return nil
		})
		s.fenced.Store(true)
		if rejection != nil { return unavailable() }
		return admissionError(503, "clock_unsafe")
	}
	var rejection *jack.Error
	if !request.Validate(now) { rejection = admissionError(503, "state_changed")
	} else if difference := now-request.Timestamp; difference > request.Window || -difference > request.Window {
		rejection = admissionError(401, jack.CodeTimestampOutOfWindow)
	}
	if rejection != nil && prepared != nil {
		if cleanup := s.update(func(tx *bolt.Tx, m *metadata) error { return removeIntent(tx, m, *prepared) }); cleanup != nil { return unavailable() }
	}
	return rejection
}
