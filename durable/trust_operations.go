package durable

import (
	"bytes"
	"errors"

	"github.com/PHPCraftdream/mcp-jack/rotation"
	bolt "go.etcd.io/bbolt"
)

// RawClock — только sample для outer checks, не durable time authority.
func (store *TrustStore) RawClock() (int64, error) {
	done, err := store.begin()
	if err != nil { return 0, err }
	defer done()
	now, sampled := sampleTrustNow(store.options.Now)
	if !sampled || store.fenced.Load() { return 0, store.failed() }
	return now, nil
}

// AdvanceAndCheck — единственная операция, меняющая authoritative H/revision/unsafe.
func (store *TrustStore) AdvanceAndCheck() (rotation.ClockTuple, error) {
	return store.advanceTrustClock(nil)
}

// CheckSnapshotClock атомарно проверяет whole trust вместе с fresh guard operation.
func (store *TrustStore) CheckSnapshotClock(expected rotation.TrustSnapshot) (rotation.ClockTuple, error) {
	encoded, err := rotation.EncodeTrustSnapshot(expected, store.options.Binding, store.options.Window, store.options.Checkpoint)
	if err != nil { return rotation.ClockTuple{}, err }
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
	err = store.transact(func(tx *bolt.Tx) error {
		guard, err := store.ownedGuard(tx)
		if err != nil {
			return err
		}
		if expected != nil {
			payload, err := checkedPayload(tx.Bucket(trustBucket).Get(trustSnapshotKey))
			if err != nil { return err }
			conflict = !bytes.Equal(payload, expected)
		}
		result = guard.Clock
		if result.Unsafe {
			return nil
		}
		now, sampled := sampleTrustNow(store.options.Now)
		if !sampled {
			return ErrUnavailable
		}
		unsafe := now < result.HighWater || now < 0 || now > rotation.MaxTimestamp
		if !unsafe && now == result.HighWater {
			return nil
		}
		if result.Revision == rotation.MaxOrdinal {
			return ErrUnavailable
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
	if info, err := store.file.Stat(); err != nil || info.Size() > maxFileBytes {
		store.failed()
		return rotation.ClockTuple{}, trustError("rotation_clock_unavailable")
	}
	if store.fenced.Load() {
		return rotation.ClockTuple{}, trustError("rotation_clock_unavailable")
	}
	if result.Unsafe {
		return rotation.ClockTuple{}, trustError("rotation_clock_unsafe")
	}
	if conflict { return rotation.ClockTuple{}, trustError("rotation_state_changed") }
	return result, nil
}

// Snapshot читает committed state; не выполняет fresh clock operation или ACK.
func (store *TrustStore) Snapshot() (rotation.TrustSnapshot, rotation.ClockTuple, error) {
	done, err := store.begin()
	if err != nil {
		return rotation.TrustSnapshot{}, rotation.ClockTuple{}, err
	}
	defer done()
	var data []byte
	var guard trustGuard
	err = store.db.View(func(tx *bolt.Tx) error {
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
			return ErrInvalidStore
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
		return rotation.TrustSnapshot{}, rotation.ClockTuple{}, ErrUnavailable
	}
	return snapshot, guard.Clock, nil
}

// CompareAndSwap меняет whole trust ровно один раз, оставляя guard bytes неизменными.
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
	err = store.transact(func(tx *bolt.Tx) error {
		guard, err := store.ownedGuard(tx)
		if err != nil {
			return err
		}
		if guard.Clock != clock || guard.Clock.Unsafe {
			return errTrustConflict
		}
		bucket := tx.Bucket(trustBucket)
		payload, err := checkedPayload(bucket.Get(trustSnapshotKey))
		if err != nil {
			return err
		}
		if !bytes.Equal(payload, previous) {
			return errTrustConflict
		}
		return bucket.Put(trustSnapshotKey, sealPayload(next))
	})
	if errors.Is(err, errTrustConflict) {
		return trustError("rotation_state_changed")
	}
	if err != nil {
		store.failed()
		return trustError("rotation_state_unknown")
	}
	if info, err := store.file.Stat(); err != nil || info.Size() > maxFileBytes {
		store.failed()
		return trustError("rotation_state_unknown")
	}
	if store.fenced.Load() {
		return trustError("rotation_state_unknown")
	}
	return nil
}

// Fence закрывает текущего owner; заранее подтверждённый dirty блокирует restart.
func (store *TrustStore) Fence() { store.fenced.Store(true) }
