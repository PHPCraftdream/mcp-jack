package durable

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"unicode/utf8"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable/internal/ownedfile"
	"github.com/PHPCraftdream/mcp-jack/server"
	bolt "go.etcd.io/bbolt"
)

// The entire bounded graph is checked, without repair, expiry, or deletion of history.
func validateRows(tx *bolt.Tx, m metadata) error {
	expiry := tx.Bucket([]byte("expiry"))
	operations := tx.Bucket([]byte("operation"))
	if expiry == nil || operations == nil {
		return ErrInvalidStore
	}
	seenKeys := make(map[[48]byte]struct{})
	seenOperations := make(map[[16]byte]struct{})
	var total uint32
	for _, group := range []struct {
		name  string
		kind  byte
		count uint32
	}{
		{"live", liveRecord, m.Live},
		{"intent", intentRecord, m.Intents},
		{"tombstone", tombstoneRecord, m.Tombstones},
	} {
		var count uint32
		bucket := tx.Bucket([]byte(group.name))
		if bucket == nil {
			return ErrInvalidStore
		}
		if err := bucket.ForEach(func(key, value []byte) error {
			count++
			if count > group.count || len(key) != 48 || len(value) != recordBytes {
				return ErrInvalidStore
			}
			row, err := decodeRecord(value, m)
			if err != nil || row.kind != group.kind || !bytes.Equal(key, row.key[:]) {
				return ErrInvalidStore
			}
			if _, found := seenKeys[row.key]; found {
				return ErrInvalidStore
			}
			if _, found := seenOperations[row.receipt.OperationID]; found {
				return ErrInvalidStore
			}
			seenKeys[row.key] = struct{}{}
			seenOperations[row.receipt.OperationID] = struct{}{}
			indexed := operations.Get(row.receipt.OperationID[:])
			if !bytes.Equal(indexed, key) {
				return ErrInvalidStore
			}
			if row.kind == liveRecord {
				index := expiryKey(row)
				actualKey, actualValue := expiry.Cursor().Seek(index[:])
				if !bytes.Equal(actualKey, index[:]) || len(actualValue) != 0 || expiry.Bucket(actualKey) != nil {
					return ErrInvalidStore
				}
			}
			return nil
		}); err != nil {
			return err
		}
		if count != group.count {
			return ErrInvalidStore
		}
		total += count
	}
	var indexedLive uint32
	if err := expiry.ForEach(func(key, value []byte) error {
		indexedLive++
		if indexedLive > m.Live || len(key) != 56 || len(value) != 0 || expiry.Bucket(key) != nil {
			return ErrInvalidStore
		}
		return nil
	}); err != nil {
		return err
	}
	if indexedLive != m.Live {
		return ErrInvalidStore
	}
	var indexedOperations uint32
	if err := operations.ForEach(func(key, value []byte) error {
		indexedOperations++
		if indexedOperations > total || len(key) != 16 || len(value) != 48 || operations.Bucket(key) != nil {
			return ErrInvalidStore
		}
		return nil
	}); err != nil {
		return err
	}
	if indexedOperations != total {
		return ErrInvalidStore
	}
	return nil
}

const (
	formatVersion       = 1
	maxTimestamp  int64 = 999999999999
)

var headerMagic = []byte("mcp-jack/nonce-store\n")
var bucketNames = []string{"metadata", "live", "expiry", "intent", "tombstone", "operation"}
var headerKey = []byte("header")

type metadata struct {
	Deployment string
	StoreID    [16]byte
	Generation uint64
	Owner      uint64
	Window     int64
	HighWater  int64
	Live       uint32
	Intents    uint32
	Tombstones uint32
	Dirty      bool
	Unsafe     bool
}

// Checksum detects accidental corruption, not malicious-host tampering or backup rollback.
func sealPayload(payload []byte) []byte { return ownedfile.SealPayload(payload) }

func checkedPayload(data []byte) ([]byte, error) { return ownedfile.CheckedPayload(data) }

func encodeMetadata(m metadata) []byte {
	var out bytes.Buffer
	out.Write(headerMagic)
	out.WriteByte(formatVersion)
	_ = binary.Write(&out, binary.BigEndian, uint16(len(m.Deployment)))
	out.WriteString(m.Deployment)
	out.Write(m.StoreID[:])
	for _, value := range []uint64{m.Generation, m.Owner, uint64(m.Window), uint64(m.HighWater)} {
		_ = binary.Write(&out, binary.BigEndian, value)
	}
	for _, count := range []uint32{m.Live, m.Intents, m.Tombstones} {
		_ = binary.Write(&out, binary.BigEndian, count)
	}
	var flags byte
	if m.Dirty {
		flags |= 1
	}
	if m.Unsafe {
		flags |= 2
	}
	out.WriteByte(flags)
	return sealPayload(out.Bytes())
}

func decodeMetadata(data []byte) (metadata, error) {
	var m metadata
	if len(data) > 2048 {
		return m, ErrInvalidStore
	}
	payload, err := checkedPayload(data)
	if err != nil {
		return m, err
	}
	data = payload
	if !bytes.HasPrefix(data, headerMagic) {
		return m, ErrInvalidStore
	}
	r := bytes.NewReader(data[len(headerMagic):])
	version, err := r.ReadByte()
	if err != nil || version != formatVersion {
		return m, ErrInvalidStore
	}
	var length uint16
	if binary.Read(r, binary.BigEndian, &length) != nil || length == 0 || length > 1024 {
		return m, ErrInvalidStore
	}
	deployment := make([]byte, int(length))
	if _, err := io.ReadFull(r, deployment); err != nil || !utf8.Valid(deployment) {
		return m, ErrInvalidStore
	}
	m.Deployment = string(deployment)
	if _, err := io.ReadFull(r, m.StoreID[:]); err != nil || m.StoreID == [16]byte{} {
		return m, ErrInvalidStore
	}
	var values [4]uint64
	for index := range values {
		if binary.Read(r, binary.BigEndian, &values[index]) != nil {
			return m, ErrInvalidStore
		}
	}
	if values[0] == 0 || values[1] == 0 || values[2] < 1 || values[2] > 120 || values[3] > uint64(maxTimestamp) {
		return m, ErrInvalidStore
	}
	m.Generation, m.Owner, m.Window, m.HighWater = values[0], values[1], int64(values[2]), int64(values[3])
	for _, count := range []*uint32{&m.Live, &m.Intents, &m.Tombstones} {
		if binary.Read(r, binary.BigEndian, count) != nil {
			return m, ErrInvalidStore
		}
	}
	if uint64(m.Live)+uint64(m.Intents) > 4096 || m.Tombstones > 64 {
		return m, ErrInvalidStore
	}
	flags, err := r.ReadByte()
	if err != nil || flags > 3 || r.Len() != 0 {
		return m, ErrInvalidStore
	}
	m.Dirty, m.Unsafe = flags&1 != 0, flags&2 != 0
	return m, nil
}

const (
	intentRecord       byte = 1
	liveRecord         byte = 2
	tombstoneRecord    byte = 3
	recordPayloadBytes      = 250
	recordBytes             = recordPayloadBytes + sha256.Size
)

type nonceRecord struct {
	kind    byte
	storeID [16]byte
	key     [48]byte
	receipt server.NonceReceipt
}

func storageIntentID(m metadata, key [48]byte, signature, requestHash []byte, operation [16]byte) string {
	hash := sha256.New()
	hash.Write([]byte("mcp-jack/durable-nonce/intent/v1\n"))
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(m.Deployment)))
	hash.Write(length[:])
	hash.Write([]byte(m.Deployment))
	hash.Write(key[:])
	hash.Write(signature)
	hash.Write(requestHash)
	hash.Write(operation[:])
	return jack.EncodeBase64URL(hash.Sum(nil))
}

func validateRecord(row nonceRecord, m metadata) error {
	r := row.receipt
	if row.kind < intentRecord || row.kind > tombstoneRecord || row.storeID != m.StoreID ||
		r.Version != formatVersion || r.DeploymentID != m.Deployment || r.StoreGeneration != m.Generation ||
		r.OwnerGeneration == 0 || r.OwnerGeneration > m.Owner || m.Window < 1 || m.Window > 120 {
		return ErrInvalidStore
	}
	kid, err := jack.DecodeBase64URLFixed(r.KID, 32)
	if err != nil || !bytes.Equal(kid, row.key[:32]) {
		return ErrInvalidStore
	}
	nonce, err := jack.DecodeBase64URLFixed(r.Nonce, 16)
	if err != nil || !bytes.Equal(nonce, row.key[32:]) {
		return ErrInvalidStore
	}
	signature, err := jack.DecodeBase64URLFixed(r.Signature, 64)
	if err != nil {
		return ErrInvalidStore
	}
	requestHash, err := jack.DecodeBase64URLFixed(r.RequestHash, 32)
	if err != nil || r.IntentID != storageIntentID(m, row.key, signature, requestHash, r.OperationID) {
		return ErrInvalidStore
	}
	if r.Timestamp < 0 || r.Timestamp > maxTimestamp-m.Window || r.RetainUntil != r.Timestamp+m.Window ||
		r.HighWater < 0 || r.HighWater > m.HighWater || r.HighWater > maxTimestamp {
		return ErrInvalidStore
	}
	if difference := r.HighWater - r.Timestamp; difference > m.Window || -difference > m.Window {
		return ErrInvalidStore
	}
	return nil
}

func encodeRecord(row nonceRecord, m metadata) ([]byte, error) {
	if err := validateRecord(row, m); err != nil {
		return nil, err
	}
	r := row.receipt
	var out bytes.Buffer
	out.Grow(recordBytes)
	out.WriteByte(formatVersion)
	out.WriteByte(row.kind)
	out.Write(row.storeID[:])
	out.Write(row.key[:])
	for _, value := range []uint64{r.StoreGeneration, r.OwnerGeneration} {
		_ = binary.Write(&out, binary.BigEndian, value)
	}
	out.Write(r.OperationID[:])
	for _, field := range []string{r.IntentID, r.Signature, r.RequestHash} {
		raw, _ := jack.DecodeBase64URL(field)
		out.Write(raw)
	}
	for _, value := range []int64{r.Timestamp, r.RetainUntil, r.HighWater} {
		_ = binary.Write(&out, binary.BigEndian, uint64(value))
	}
	return sealPayload(out.Bytes()), nil
}

func decodeRecord(data []byte, m metadata) (nonceRecord, error) {
	var row nonceRecord
	if len(data) != recordBytes {
		return row, ErrInvalidStore
	}
	payload, err := checkedPayload(data)
	if err != nil || payload[0] != formatVersion {
		return row, ErrInvalidStore
	}
	row.kind = payload[1]
	reader := bytes.NewReader(payload[2:])
	if _, err := io.ReadFull(reader, row.storeID[:]); err != nil {
		return row, ErrInvalidStore
	}
	if _, err := io.ReadFull(reader, row.key[:]); err != nil {
		return row, ErrInvalidStore
	}
	r := &row.receipt
	r.Version, r.DeploymentID = formatVersion, m.Deployment
	if binary.Read(reader, binary.BigEndian, &r.StoreGeneration) != nil ||
		binary.Read(reader, binary.BigEndian, &r.OwnerGeneration) != nil {
		return row, ErrInvalidStore
	}
	if _, err := io.ReadFull(reader, r.OperationID[:]); err != nil {
		return row, ErrInvalidStore
	}
	for _, target := range []struct {
		text *string
		size int
	}{
		{&r.IntentID, 32}, {&r.Signature, 64}, {&r.RequestHash, 32},
	} {
		value := make([]byte, target.size)
		if _, err := io.ReadFull(reader, value); err != nil {
			return row, ErrInvalidStore
		}
		*target.text = jack.EncodeBase64URL(value)
	}
	r.KID, r.Nonce = jack.EncodeBase64URL(row.key[:32]), jack.EncodeBase64URL(row.key[32:])
	for _, target := range []*int64{&r.Timestamp, &r.RetainUntil, &r.HighWater} {
		var value uint64
		if binary.Read(reader, binary.BigEndian, &value) != nil || value > uint64(maxTimestamp) {
			return row, ErrInvalidStore
		}
		*target = int64(value)
	}
	if reader.Len() != 0 {
		return row, ErrInvalidStore
	}
	if err := validateRecord(row, m); err != nil {
		return nonceRecord{}, err
	}
	return row, nil
}

func expiryKey(row nonceRecord) [56]byte {
	var key [56]byte
	binary.BigEndian.PutUint64(key[:8], uint64(row.receipt.RetainUntil))
	copy(key[8:], row.key[:])
	return key
}

// The entire bounded graph is checked, without repair, expiry, or deletion of history.
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

// RecoverySnapshot holds owned diagnostic values; it is not an admission receipt or permission to reopen.
// Hash binds the full logical graph; it is not a MAC and not proof of absence of rollback.
type RecoverySnapshot struct {
	Version         uint32
	DeploymentID    string
	StoreID         string
	StoreGeneration uint64
	OwnerGeneration uint64
	Window          int64
	HighWater       int64
	Dirty           bool
	Unsafe          bool
	Hash            string
	Live            []server.NonceReceipt
	Intents         []server.NonceReceipt
	Tombstones      []server.NonceReceipt
}

// InspectRecovery does not create a store, call Now, or change metadata/history.
// The exclusive owner lock is required even for inspection; serving admission is not opened.
func InspectRecovery(path string, opts Options) (report RecoverySnapshot, result error) {
	opts, err := normalizedOptions(opts)
	if err != nil {
		return report, err
	}
	if err := privateDirectory(path); err != nil {
		return report, err
	}
	db, err := bolt.Open(path, 0600, dbOptions(false))
	if err != nil {
		return report, ErrUnavailable
	}
	defer func() {
		if err := db.Close(); err != nil {
			report = RecoverySnapshot{}
			result = ErrUnavailable
		}
	}()
	err = db.View(func(tx *bolt.Tx) error {
		return loadRecoverySnapshot(tx, opts, &report)
	})
	if err != nil {
		return RecoverySnapshot{}, err
	}
	return report, nil
}

func loadRecoverySnapshot(tx *bolt.Tx, opts Options, snapshot *RecoverySnapshot) error {
	var report RecoverySnapshot
	var m metadata
	if err := readStoreSnapshot(tx, opts, false, &m); err != nil {
		return err
	}
	report = RecoverySnapshot{
		Version: formatVersion, DeploymentID: m.Deployment,
		StoreID:         jack.EncodeBase64URL(m.StoreID[:]),
		StoreGeneration: m.Generation, OwnerGeneration: m.Owner,
		Window: m.Window, HighWater: m.HighWater,
		Dirty: m.Dirty, Unsafe: m.Unsafe,
	}
	// Length framing eliminates ambiguity between names, keys, and values.
	hash := sha256.New()
	_, _ = hash.Write([]byte("mcp-jack/durable-nonce/recovery-snapshot/v1\n"))
	field := func(value []byte) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(value)
	}
	for _, name := range bucketNames {
		_, _ = hash.Write([]byte{0})
		field([]byte(name))
		bucket := tx.Bucket([]byte(name))
		if err := bucket.ForEach(func(key, value []byte) error {
			if bucket.Bucket(key) != nil || len(key) > maxFileBytes || len(value) > maxFileBytes {
				return ErrInvalidStore
			}
			_, _ = hash.Write([]byte{1})
			field(key)
			field(value)
			if name != "live" && name != "intent" && name != "tombstone" {
				return nil
			}
			row, err := decodeRecord(value, m)
			if err != nil {
				return err
			}
			switch name {
			case "live":
				report.Live = append(report.Live, row.receipt)
			case "intent":
				report.Intents = append(report.Intents, row.receipt)
			case "tombstone":
				report.Tombstones = append(report.Tombstones, row.receipt)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	report.Hash = jack.EncodeBase64URL(hash.Sum(nil))
	*snapshot = report
	return nil
}

// ReconcileUnknown is an explicit OOB operation on a closed dirty store.
// The exact snapshot/receipt is moved to a terminal tombstone without dispatch/retry/reopen.
// A missing record is not proof of abort and does not clear the startup fence.
func ReconcileUnknown(path string, opts Options, expectedHash string, receipt server.NonceReceipt) error {
	return reconcileUnknown(path, opts, expectedHash, receipt, nil)
}

func reconcileUnknown(path string, opts Options, expectedHash string, receipt server.NonceReceipt, transact func(*bolt.DB, func(*bolt.Tx) error) error) (result error) {
	opts, err := normalizedOptions(opts)
	if err != nil {
		return err
	}
	if _, err := jack.DecodeBase64URLFixed(expectedHash, 32); err != nil {
		return ErrRecoveryRequired
	}
	kid, err := jack.DecodeBase64URLFixed(receipt.KID, 32)
	if err != nil {
		return ErrRecoveryRequired
	}
	nonce, err := jack.DecodeBase64URLFixed(receipt.Nonce, 16)
	if err != nil {
		return ErrRecoveryRequired
	}
	var pair [48]byte
	copy(pair[:32], kid)
	copy(pair[32:], nonce)
	if err := privateDirectory(path); err != nil {
		return err
	}
	options := dbOptions(false)
	openFile := options.OpenFile
	var file *os.File
	options.OpenFile = func(name string, flags int, mode os.FileMode) (*os.File, error) {
		opened, err := openFile(name, flags, mode)
		if err == nil {
			file = opened
		}
		return opened, err
	}
	db, err := bolt.Open(path, 0600, options)
	if err != nil {
		return ErrUnavailable
	}
	defer func() {
		if err := db.Close(); err != nil {
			result = ErrUnavailable
		}
	}()
	if transact == nil {
		transact = func(db *bolt.DB, apply func(*bolt.Tx) error) error { return db.Update(apply) }
	}
	var callbackErr error
	err = transact(db, func(tx *bolt.Tx) error {
		callbackErr = reconcileRow(tx, opts, expectedHash, pair, receipt)
		return callbackErr
	})
	if err != nil {
		if errors.Is(callbackErr, ErrRecoveryRequired) || errors.Is(callbackErr, ErrInvalidStore) {
			return callbackErr
		}
		return ErrUnavailable
	}
	info, err := file.Stat()
	if err != nil || info.Size() > maxFileBytes || info.Size() < 4*pageBytes {
		return ErrUnavailable
	}
	return nil
}

func reconcileRow(tx *bolt.Tx, opts Options, expectedHash string, pair [48]byte, receipt server.NonceReceipt) error {
	var snapshot RecoverySnapshot
	if err := loadRecoverySnapshot(tx, opts, &snapshot); err != nil {
		return err
	}
	if !snapshot.Dirty || snapshot.Hash != expectedHash {
		return ErrRecoveryRequired
	}
	m, err := decodeMetadata(tx.Bucket([]byte("metadata")).Get(headerKey))
	if err != nil {
		return err
	}
	for _, group := range []struct {
		name string
		kind byte
	}{{"live", liveRecord}, {"intent", intentRecord}, {"tombstone", tombstoneRecord}} {
		row, err := readRecord(tx.Bucket([]byte(group.name)), pair, m, group.kind)
		if err != nil {
			return err
		}
		if row == nil {
			continue
		}
		if row.receipt != receipt {
			return ErrRecoveryRequired
		}
		if group.kind == tombstoneRecord {
			return nil
		}
		if m.Tombstones >= 64 {
			return ErrRecoveryRequired
		}
		terminal := *row
		terminal.kind = tombstoneRecord
		encoded, err := encodeRecord(terminal, m)
		if err != nil {
			return err
		}
		if err := tx.Bucket([]byte("tombstone")).Put(pair[:], encoded); err != nil {
			return err
		}
		if err := tx.Bucket([]byte(group.name)).Delete(pair[:]); err != nil {
			return err
		}
		if group.kind == liveRecord {
			index := expiryKey(*row)
			if err := tx.Bucket([]byte("expiry")).Delete(index[:]); err != nil {
				return err
			}
			m.Live--
		} else {
			m.Intents--
		}
		m.Tombstones++
		if err := validateRows(tx, m); err != nil {
			return err
		}
		return tx.Bucket([]byte("metadata")).Put(headerKey, encodeMetadata(m))
	}
	return ErrRecoveryRequired
}
