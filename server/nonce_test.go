package server

import (
	"fmt"
	"sync"
	"testing"
)

// TestNonceStoreAtomicity checks that a concurrent first use of the same
// (kid, nonce) pair is accepted exactly once; distinct nonces each win once.
func TestNonceStoreAtomicity(t *testing.T) {
	t.Run("same nonce wins exactly once", func(t *testing.T) {
		store := NewNonceStore()
		const goroutines = 64
		results := make([]bool, goroutines)
		var wg sync.WaitGroup
		resultsCh := make(chan int, goroutines)
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				if !store.CheckAndRecord("kidA", "nonceX", 100, 130) {
					resultsCh <- idx
				}
			}(i)
		}
		wg.Wait()
		close(resultsCh)
		winners := 0
		for idx := range resultsCh {
			results[idx] = true
			winners++
		}
		if winners != 1 {
			t.Fatalf("got %d first-use wins, want 1", winners)
		}
		for i, got := range results {
			if got {
				t.Logf("goroutine %d won", i)
			}
		}
		if store.Len() != 1 {
			t.Fatalf("Len() = %d, want 1", store.Len())
		}
	})

	t.Run("distinct nonces each win once", func(t *testing.T) {
		store := NewNonceStore()
		const goroutines = 64
		var wg sync.WaitGroup
		wins := make(chan struct{}, goroutines)
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				if !store.CheckAndRecord("kidA", fmt.Sprintf("nonce-%d", idx), 100, 130) {
					wins <- struct{}{}
				}
			}(i)
		}
		wg.Wait()
		close(wins)
		if len(wins) != goroutines {
			t.Fatalf("got %d wins, want %d", len(wins), goroutines)
		}
	})
}

// TestNonceStoreRetention covers the retention boundary and the rule that a
// replay must not extend retention.
func TestNonceStoreRetention(t *testing.T) {
	t.Run("boundary now==retainUntil still blocks", func(t *testing.T) {
		store := NewNonceStore()
		if store.CheckAndRecord("kidA", "n1", 100, 130) {
			t.Fatal("first use reported as replay")
		}
		if !store.CheckAndRecord("kidA", "n1", 130, 500) {
			t.Fatal("replay at now==retainUntil was not detected")
		}
	})

	t.Run("past retention no longer blocks", func(t *testing.T) {
		store := NewNonceStore()
		store.CheckAndRecord("kidA", "n1", 100, 130)
		if store.CheckAndRecord("kidA", "n1", 131, 500) {
			t.Fatal("expired entry blocked a fresh record")
		}
	})

	t.Run("replay does not extend retention", func(t *testing.T) {
		store := NewNonceStore()
		if store.CheckAndRecord("kidA", "n1", 100, 130) {
			t.Fatal("first use reported as replay")
		}
		// Replay attempt with a far-future retainUntil must be rejected
		// without updating the stored retention.
		if !store.CheckAndRecord("kidA", "n1", 110, 1000) {
			t.Fatal("replay was not detected")
		}
		// Retention is still 130, so at now=131 the pair is usable again
		// even though a replay attempt asked for 1000.
		if store.CheckAndRecord("kidA", "n1", 131, 999) {
			t.Fatal("replay extended retention beyond the original window")
		}
	})
}

// TestNonceStorePerKidScoping checks the same nonce string under different
// kids is independent.
func TestNonceStorePerKidScoping(t *testing.T) {
	store := NewNonceStore()
	if store.CheckAndRecord("kidA", "shared-nonce", 100, 130) {
		t.Fatal("kidA first use reported as replay")
	}
	if store.CheckAndRecord("kidB", "shared-nonce", 100, 130) {
		t.Fatal("kidB first use blocked by kidA's live entry")
	}
	if !store.CheckAndRecord("kidA", "shared-nonce", 110, 130) {
		t.Fatal("kidA replay not detected")
	}
	if !store.CheckAndRecord("kidB", "shared-nonce", 110, 130) {
		t.Fatal("kidB replay not detected")
	}
	if store.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", store.Len())
	}
}

// TestNonceStorePurge covers explicit purge bounds and lazy purge on record.
func TestNonceStorePurge(t *testing.T) {
	t.Run("purge removes expired entries", func(t *testing.T) {
		store := NewNonceStore()
		for i := 0; i < 500; i++ {
			store.CheckAndRecord(fmt.Sprintf("kid-%d", i), fmt.Sprintf("nonce-%d", i), 100, 100)
		}
		if got := store.Len(); got != 500 {
			t.Fatalf("Len() = %d, want 500", got)
		}
		if got := store.Purge(101); got != 500 {
			t.Fatalf("Purge() = %d, want 500", got)
		}
		if got := store.Len(); got != 0 {
			t.Fatalf("Len() after purge = %d, want 0", got)
		}
		// Store remains usable.
		if store.CheckAndRecord("kidA", "nonceX", 200, 300) {
			t.Fatal("fresh record after purge reported as replay")
		}
		if store.Len() != 1 {
			t.Fatalf("Len() = %d, want 1", store.Len())
		}
	})

	t.Run("lazy purge on CheckAndRecord", func(t *testing.T) {
		store := NewNonceStore()
		for i := 0; i < 10; i++ {
			store.CheckAndRecord(fmt.Sprintf("kid-%d", i), fmt.Sprintf("nonce-%d", i), 10, 50)
		}
		// now=60 purges the expired entries before recording the new pair.
		if store.CheckAndRecord("kidNew", "nonceNew", 60, 120) {
			t.Fatal("fresh record reported as replay")
		}
		if got := store.Len(); got != 1 {
			t.Fatalf("Len() = %d, want 1", got)
		}
	})
}
