package durable

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
)

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
