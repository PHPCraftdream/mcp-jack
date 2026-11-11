package durable

import (
	"bytes"
	"errors"

	"github.com/PHPCraftdream/mcp-jack/rotation"
	bolt "go.etcd.io/bbolt"
)

// RawClock — только sample для outer checks, не durable time authority.
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

// AdvanceAndCheck — единственная операция, меняющая authoritative H/revision/unsafe.
func (store *ServerStore) AdvanceAndCheck() (rotation.ClockTuple, error) {
	return store.advanceServerClock(nil)
}

// CheckSnapshotClock проверяет exact ring вместе со свежим server ClockGuard.
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
			payload, err := checkedPayload(tx.Bucket(serverBucket).Get(serverSnapshotKey))
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
		return tx.Bucket(serverBucket).Put(serverGuardKey, encodeServerGuard(guard))
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
	if conflict {
		return rotation.ClockTuple{}, trustError("rotation_state_changed")
	}
	return result, nil
}

// Snapshot читает committed state; не выполняет fresh clock operation или ACK.
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
		if err != nil { return err }
		_, err = store.ownedGuard(tx)
		return err
	})
	if err != nil {
		return rotation.ServerSnapshot{}, rotation.ClockTuple{}, store.failed()
	}
	if store.fenced.Load() {
		return rotation.ServerSnapshot{}, rotation.ClockTuple{}, ErrUnavailable
	}
	return snapshot, guard.Clock, nil
}

// CompareAndSwap атомарно пишет один fixed-P переход и exact intent; guard не меняется.
func (store *ServerStore) CompareAndSwap(expected, desired rotation.ServerSnapshot, clock rotation.ClockTuple) error {
	previous, err := rotation.EncodeServerSnapshot(expected, store.options.Binding, store.options.Window, store.options.Checkpoint)
	if err != nil {
		return err
	}
	next, err := rotation.EncodeServerSnapshot(desired, store.options.Binding, store.options.Window, store.options.Checkpoint)
	if err != nil {
		return err
	}
	if desired.Public.Clock != clock { return trustError("rotation_state_changed") }
	if _, err := rotation.ValidateServerPublication(expected, desired, store.options.Binding, store.options.Window, store.options.Checkpoint); err != nil { return err }
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
		payload, err := checkedPayload(bucket.Get(serverSnapshotKey))
		if err != nil {
			return err
		}
		if !bytes.Equal(payload, previous) {
			return errTrustConflict
		}
		if err := bucket.Put(serverIntentKey, encodeServerIntent(previous, next)); err != nil { return err }
		return bucket.Put(serverSnapshotKey, sealPayload(next))
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
