package server

import "sync"

// NonceStore provides replay protection: it remembers (kid, nonce) pairs for a
// caller-supplied retention window so a repeated pair is detected atomically.
// Times are Unix seconds supplied by the caller; the store never reads a clock.
// See 01-authentication.md section 4.
type NonceStore struct {
	mu        sync.Mutex
	seen      map[string]int64 // kid + "\x00" + nonce -> retainUntil
	lastPurge int64            // now of the last full purge; bounds the scan to once per second
}

// NewNonceStore returns an empty nonce store.
func NewNonceStore() *NonceStore {
	return &NonceStore{seen: make(map[string]int64)}
}

// CheckAndRecord atomically checks whether (kid, nonce) was already seen and
// records it if not. Callers derive retainUntil as ts + window: an entry is
// live while now <= retainUntil. Under a single mutex hold it purges entries
// with retainUntil < now; if the pair is present and still live it returns
// true (replay) without changing it — a replay must not extend retention —
// otherwise it stores retainUntil for the pair and returns false.
func (s *NonceStore) CheckAndRecord(kid, nonce string, now, retainUntil int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// A full scan on every request would make the cost quadratic in the number
	// of live entries; expired entries are never consulted below (the liveness
	// test is explicit), so purging once per second is enough to bound memory.
	if now > s.lastPurge {
		for k, until := range s.seen {
			if until < now {
				delete(s.seen, k)
			}
		}
		s.lastPurge = now
	}

	key := kid + "\x00" + nonce
	if until, ok := s.seen[key]; ok && now <= until {
		return true
	}
	s.seen[key] = retainUntil
	return false
}

// Purge deletes every entry whose retention has expired (retainUntil < now)
// and returns the number of deleted entries.
func (s *NonceStore) Purge(now int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	deleted := 0
	for k, until := range s.seen {
		if until < now {
			delete(s.seen, k)
			deleted++
		}
	}
	return deleted
}

// Len returns how many entries are currently held, including expired ones not
// yet purged.
func (s *NonceStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}
