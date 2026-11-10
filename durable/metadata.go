package durable

import (
	"bytes"
	"encoding/binary"
	"io"
	"unicode/utf8"
)

const (
	formatVersion = 1
	maxTimestamp int64 = 999999999999
	maxFileBytes = 16 << 20
	pageBytes = 4096
)

var headerMagic = []byte("mcp-jack/nonce-store\n")
var bucketNames = []string{"metadata", "live", "expiry", "intent", "tombstone", "operation"}
var headerKey = []byte("header")

type metadata struct {
	Deployment string
	StoreID [16]byte
	Generation uint64
	Owner uint64
	Window int64
	HighWater int64
	Live uint32
	Intents uint32
	Tombstones uint32
	Dirty bool
	Unsafe bool
}

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
	if m.Dirty { flags |= 1 }
	if m.Unsafe { flags |= 2 }
	out.WriteByte(flags)
	return out.Bytes()
}

func decodeMetadata(data []byte) (metadata, error) {
	var m metadata
	if len(data) > 2048 || !bytes.HasPrefix(data, headerMagic) { return m, ErrInvalidStore }
	r := bytes.NewReader(data[len(headerMagic):])
	version, err := r.ReadByte()
	if err != nil || version != formatVersion { return m, ErrInvalidStore }
	var length uint16
	if binary.Read(r, binary.BigEndian, &length) != nil || length == 0 || length > 1024 { return m, ErrInvalidStore }
	deployment := make([]byte, int(length))
	if _, err := io.ReadFull(r, deployment); err != nil || !utf8.Valid(deployment) { return m, ErrInvalidStore }
	m.Deployment = string(deployment)
	if _, err := io.ReadFull(r, m.StoreID[:]); err != nil || m.StoreID == [16]byte{} { return m, ErrInvalidStore }
	var values [4]uint64
	for index := range values {
		if binary.Read(r, binary.BigEndian, &values[index]) != nil { return m, ErrInvalidStore }
	}
	if values[0] == 0 || values[1] == 0 || values[2] < 1 || values[2] > 120 || values[3] > uint64(maxTimestamp) { return m, ErrInvalidStore }
	m.Generation, m.Owner, m.Window, m.HighWater = values[0], values[1], int64(values[2]), int64(values[3])
	for _, count := range []*uint32{&m.Live, &m.Intents, &m.Tombstones} {
		if binary.Read(r, binary.BigEndian, count) != nil { return m, ErrInvalidStore }
	}
	if uint64(m.Live)+uint64(m.Intents) > 4096 || m.Tombstones > 64 { return m, ErrInvalidStore }
	flags, err := r.ReadByte()
	if err != nil || flags > 3 || r.Len() != 0 { return m, ErrInvalidStore }
	m.Dirty, m.Unsafe = flags&1 != 0, flags&2 != 0
	return m, nil
}
