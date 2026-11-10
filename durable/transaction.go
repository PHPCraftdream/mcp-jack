package durable

import (
	"bytes"
	"encoding/binary"
	"errors"

	jack "github.com/PHPCraftdream/mcp-jack"
	bolt "go.etcd.io/bbolt"
)

func admissionError(status int, code string) *jack.Error {
	return &jack.Error{HTTPStatus: status, Code: code, Message: "durable admission refused"}
}

func unavailable() *jack.Error { return admissionError(503, "durability_unavailable") }

// Только callback rejection — definite abort. Commit error остаётся unknown.
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
		if callbackErr != nil { return callbackErr }
		callbackErr = tx.Bucket([]byte("metadata")).Put(headerKey, encodeMetadata(next))
		return callbackErr
	})
	if err != nil {
		var rejection *jack.Error
		if callbackErr != nil && errors.As(callbackErr, &rejection) && rejection != nil {
			if rejection.Code == "durability_unavailable" || rejection.Code == "clock_unsafe" { s.fenced.Store(true) }
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
	if bucket == nil { return nil, ErrInvalidStore }
	actual, data := bucket.Cursor().Seek(key[:])
	if !bytes.Equal(actual, key[:]) { return nil, nil }
	row, err := decodeRecord(data, m)
	if err != nil || row.kind != kind || row.key != key { return nil, ErrInvalidStore }
	return &row, nil
}

func replayLookup(tx *bolt.Tx, m metadata, key [48]byte, now int64) error {
	row, err := readRecord(tx.Bucket([]byte("live")), key, m, liveRecord)
	if err != nil { return err }
	if row != nil && now <= row.receipt.RetainUntil { return admissionError(401, jack.CodeReplayedNonce) }
	for _, group := range []struct { name string; kind byte }{{"intent", intentRecord}, {"tombstone", tombstoneRecord}} {
		row, err := readRecord(tx.Bucket([]byte(group.name)), key, m, group.kind)
		if err != nil { return err }
		if row != nil { return unavailable() }
	}
	return nil
}

// Индекс собирается до удаления: Cursor.Next после Delete может пропустить запись.
// Exact pair входит в тот же общий лимит128, а не удаляется сверх него.
func purgeExpired(tx *bolt.Tx, m *metadata, now int64, exact [48]byte) error {
	if now < m.HighWater { return ErrInvalidStore }
	m.HighWater = now
	live := tx.Bucket([]byte("live"))
	expiry := tx.Bucket([]byte("expiry"))
	operations := tx.Bucket([]byte("operation"))
	keys := make([][56]byte, 0, 128)
	exactRow, err := readRecord(live, exact, *m, liveRecord)
	if err != nil { return err }
	if exactRow != nil && exactRow.receipt.RetainUntil < now { keys = append(keys, expiryKey(*exactRow)) }
	cursor := expiry.Cursor()
	for key, value := cursor.First(); key != nil && len(keys) < 128; key, value = cursor.Next() {
		if len(key) != 56 || len(value) != 0 || expiry.Bucket(key) != nil { return ErrInvalidStore }
		if binary.BigEndian.Uint64(key[:8]) >= uint64(now) { break }
		var index [56]byte
		copy(index[:], key)
		if len(keys) > 0 && index == keys[0] { continue }
		keys = append(keys, index)
	}
	for _, index := range keys {
		var pair [48]byte
		copy(pair[:], index[8:])
		actual, value := expiry.Cursor().Seek(index[:])
		if !bytes.Equal(actual, index[:]) || len(value) != 0 || expiry.Bucket(actual) != nil { return ErrInvalidStore }
		row, err := readRecord(live, pair, *m, liveRecord)
		if err != nil || row == nil || expiryKey(*row) != index || row.receipt.RetainUntil >= now || m.Live == 0 { return ErrInvalidStore }
		if !bytes.Equal(operations.Get(row.receipt.OperationID[:]), pair[:]) { return ErrInvalidStore }
		if err := live.Delete(pair[:]); err != nil { return err }
		if err := expiry.Delete(index[:]); err != nil { return err }
		if err := operations.Delete(row.receipt.OperationID[:]); err != nil { return err }
		m.Live--
	}
	return nil
}
