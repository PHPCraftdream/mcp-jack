package rotationclient

import "github.com/PHPCraftdream/mcp-jack/rotation"

// ClientTrustState is the security boundary between the controller and trust storage.
// The controller pins binding, window, and checkpoint from its initial snapshot and
// refuses drift as rotation_state_unknown. It enforces single-flight writes, rereads
// and compares snapshots by rotation.EncodeTrustSnapshot before CAS, capacity limits,
// timestamp windows, and key intervals.
//
// Implementations must provide whole-snapshot atomic CAS. CompareAndSwap refuses with
// rotation_state_changed unless expected.Revision is not rotation.MaxOrdinal, desired
// has the next revision, neither snapshot is Fenced, desired.Clock equals clock,
// rotation.TrustClockCompatible(expected, clock) holds, desired.Records strictly extends
// expected.Records as an exact prefix, the stored guard clock equals clock and is not
// Unsafe, and the stored snapshot bytes equal the encoding of expected. The guard is left
// untouched and the commit happens exactly once. An I/O or fence failure after an uncertain
// write returns rotation_state_unknown and fences the store.
//
// Snapshot reads committed state only: it does not perform a fresh clock operation or ACK.
// It decodes the stored snapshot under the pinned binding, window, and checkpoint and
// requires rotation.TrustClockCompatible with the stored guard, failing closed otherwise.
//
// CheckSnapshotClock must compare the stored snapshot bytes with the encoding of expected
// and perform a fresh guard-clock operation atomically, in one step; separate operations
// leave a race at the controller's final trust gate. Outcome precedence: an unavailable
// guard or sample, or a revision increment needed at rotation.MaxOrdinal, is
// rotation_clock_unavailable; an Unsafe clock is rotation_clock_unsafe; a snapshot
// mismatch is rotation_state_changed.
//
// ClockTuple carries Binding, Window, HighWater, Revision, and Unsafe. HighWater is
// monotonic; a sample below it or outside the valid range latches Unsafe and thereafter
// fails with rotation_clock_unsafe. Unsafe is never cleared automatically. Revision is
// bounded by rotation.MaxOrdinal and advances only when HighWater advances or Unsafe
// latches; a sample equal to HighWater on a clock that is not Unsafe changes nothing and
// needs no revision. RawClock is only a bounded sample for outer checks, has no authority,
// and changes no state.
//
// Dirty, fenced, unknown-owner, and closed state, and any uncertain outcome, must fail
// closed with a *rotation.Error coded rotation_state_unknown or
// rotation_clock_unavailable as applicable. Dirty, fenced, and unsafe state is never
// auto-cleared. Only one live owner may operate a state; stale owners fail closed.
// Implementations make exactly one attempt per call, never retry internally, and report
// unknown outcomes. Errors use *rotation.Error with the documented codes.
//
// *durable.TrustStore implements this interface as the Linux reference implementation;
// Windows and macOS consumers provide their own implementation, for example encrypted
// storage.
type ClientTrustState interface {
	Snapshot() (rotation.TrustSnapshot, rotation.ClockTuple, error)
	CheckSnapshotClock(expected rotation.TrustSnapshot) (rotation.ClockTuple, error)
	RawClock() (int64, error)
	CompareAndSwap(expected, desired rotation.TrustSnapshot, clock rotation.ClockTuple) error
}
