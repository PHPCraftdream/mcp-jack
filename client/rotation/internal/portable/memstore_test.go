package portable

import (
	"bytes"

	rotationclient "github.com/PHPCraftdream/mcp-jack/client/rotation"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

// *durable.TrustStore is the Linux reference implementation.
var _ rotationclient.ClientTrustState = (*durable.TrustStore)(nil)

// Compile-time check against the portable client boundary.
var _ rotationclient.ClientTrustState = (*memStore)(nil)

type memStore struct {
	binding                       rotation.Binding
	window                        int64
	checkpoint                    rotation.Checkpoint
	encoded                       []byte
	current                       rotation.TrustSnapshot
	clock                         rotation.ClockTuple
	snapshotErr, rawErr, clockErr *rotation.Error
	casConflict                   bool
	drift                         bool
	raw                           int64
}

func newMemStore(binding rotation.Binding, window int64, checkpoint rotation.Checkpoint, signer interface{ PublicKey() []byte }, now int64) *memStore {
	var pk [32]byte
	copy(pk[:], signer.PublicKey())
	clock := rotation.ClockTuple{Binding: binding, Window: window, HighWater: now, Revision: 1}
	snapshot := rotation.TrustSnapshot{FormatVersion: 1, Binding: binding, Window: window, Checkpoint: checkpoint, Head: rotation.ResultCursor{Ordinal: checkpoint.Ordinal, Hash: checkpoint.Hash}, Keys: []rotation.TrustKey{{Ordinal: checkpoint.Ordinal, KID: checkpoint.KID, PublicKey: pk}}, Revision: 1, Clock: clock}
	encoded, _ := rotation.EncodeTrustSnapshot(snapshot, binding, window, checkpoint)
	return &memStore{binding: binding, window: window, checkpoint: checkpoint, encoded: encoded, current: snapshot, clock: clock, raw: now}
}

func (s *memStore) Snapshot() (rotation.TrustSnapshot, rotation.ClockTuple, error) {
	if s.snapshotErr != nil {
		return rotation.TrustSnapshot{}, rotation.ClockTuple{}, s.snapshotErr
	}
	v := s.current
	if s.drift {
		v.Binding = rotation.Binding{Endpoint: "https://drift.invalid/mcp", Audience: s.binding.Audience}
	}
	return v, s.clock, nil
}
func (s *memStore) CheckSnapshotClock(expected rotation.TrustSnapshot) (rotation.ClockTuple, error) {
	if s.clockErr != nil {
		return rotation.ClockTuple{}, s.clockErr
	}
	b, err := rotation.EncodeTrustSnapshot(expected, s.binding, s.window, s.checkpoint)
	if err != nil || !bytes.Equal(b, s.encoded) {
		return rotation.ClockTuple{}, &rotation.Error{Code: "rotation_state_changed"}
	}
	return s.clock, nil
}
func (s *memStore) RawClock() (int64, error) {
	if s.rawErr != nil {
		return 0, s.rawErr
	}
	return s.raw, nil
}
func (s *memStore) CompareAndSwap(expected, desired rotation.TrustSnapshot, clock rotation.ClockTuple) error {
	if s.casConflict {
		return &rotation.Error{Code: "rotation_state_changed"}
	}
	a, ea := rotation.EncodeTrustSnapshot(expected, s.binding, s.window, s.checkpoint)
	b, eb := rotation.EncodeTrustSnapshot(s.current, s.binding, s.window, s.checkpoint)
	if ea != nil || eb != nil || !bytes.Equal(a, b) || !bytes.Equal(b, s.encoded) || desired.Revision != expected.Revision+1 || clock != s.clock {
		return &rotation.Error{Code: "rotation_state_changed"}
	}
	encoded, err := rotation.EncodeTrustSnapshot(desired, s.binding, s.window, s.checkpoint)
	if err != nil {
		return err
	}
	s.current, s.encoded, s.clock = desired, encoded, desired.Clock
	return nil
}
