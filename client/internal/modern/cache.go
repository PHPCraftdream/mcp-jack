package modern

import (
	"sync"
	"time"
)

// CacheKey is the exact request a cached result is bound to: method, request
// parameters and era.
type CacheKey struct {
	// Method is the request method.
	Method string
	// Params is the serialised request parameters.
	Params string
	// Era is the era the request was sent in.
	Era string
}

// cacheEntry is one stored result and the instant it stops being live.
type cacheEntry struct {
	// value is the caller's copy of the result bytes, never aliased.
	value []byte
	// deadline is the first instant the entry is no longer live.
	deadline time.Time
}

// maxTTLMs is the largest ttlMs whose duration does not overflow
// time.Duration; a longer hint is clamped to it, which is already far beyond
// any meaningful reuse window.
const maxTTLMs = int64(time.Duration(1<<63-1) / time.Millisecond)

// ResultCache is a private cache of verified results (C8). It is never shared
// and never an HTTP cache, and it never serves an entry under another key: a
// Jack response is signed over the answering request's signature.
//
// It is safe for concurrent use and holds no package-level state, so one cache
// never answers for another.
type ResultCache struct {
	// mu guards entries.
	mu sync.Mutex
	// entries maps a key to its stored result.
	entries map[CacheKey]cacheEntry
}

// NewResultCache returns an empty private result cache.
func NewResultCache() *ResultCache {
	return &ResultCache{entries: make(map[CacheKey]cacheEntry)}
}

// Get returns a copy of the cached result when it is still live at now.
//
// An entry is live while now is strictly before its deadline. An expired entry
// is deleted and reported as absent, as is a key that was never stored.
func (c *ResultCache) Get(key CacheKey, now time.Time) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !now.Before(entry.deadline) {
		delete(c.entries, key)
		return nil, false
	}
	return append([]byte(nil), entry.value...), true
}

// Put stores a copy for ttlMs milliseconds. ttlMs <= 0 stores nothing and
// drops any existing entry for key.
//
// The deadline is now plus ttlMs milliseconds, so a later Put with the same key
// replaces both the value and the deadline, and a result whose hint is zero is
// never reused.
func (c *ResultCache) Put(key CacheKey, value []byte, ttlMs int64, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ttlMs <= 0 {
		delete(c.entries, key)
		return
	}
	if ttlMs > maxTTLMs {
		ttlMs = maxTTLMs
	}
	c.entries[key] = cacheEntry{
		value:    append([]byte(nil), value...),
		deadline: now.Add(time.Duration(ttlMs) * time.Millisecond),
	}
}
